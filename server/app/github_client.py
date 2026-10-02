"""GitHub App client: Installation Access Tokens + REST helpers.

Secrets policy (hard requirements):
  * the App private key is read from the environment only
  * tokens/keys are NEVER logged, never put into exception messages
  * rate limits (403/429 + X-RateLimit-Remaining: 0) are handled with a
    bounded sleep-and-retry

Used by the publish pipeline (branch -> commit -> PR -> merge -> draft Release
-> .msext asset -> publish) and by the Releases-backed registry endpoint.
"""

from __future__ import annotations

import base64
import calendar
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import httpx
import jwt as pyjwt

log = logging.getLogger("server.github")

API_VERSION = "2022-11-28"
USER_AGENT = "MobileStudio-Extensions-Server"


class GitHubError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


@dataclass
class ReleasesResult:
    status: int                     # 200 or 304
    releases: List[dict]            # empty on 304
    etag: Optional[str]
    last_modified: Optional[str]


class GitHubClient:
    """Thin REST wrapper. `http` is injectable for tests."""

    def __init__(self, cfg, http: Optional[httpx.Client] = None):
        self.cfg = cfg
        self._http = http
        self._token: str = ""
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------ http
    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
        return self._http

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None

    # ------------------------------------------------------------- app auth
    def _app_jwt(self) -> str:
        now = int(time.time())
        key = self.cfg.private_key          # never logged
        try:
            return pyjwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": int(self.cfg.github_app_id)},
                key,
                algorithm="RS256",
            )
        except Exception as e:
            # message must not contain key material
            raise GitHubError(f"failed to sign GitHub App JWT: {type(e).__name__}") from None

    def installation_token(self, force: bool = False) -> str:
        if not self.cfg.app_configured and self.cfg.github_token:
            # Quick-start PAT mode: static token, no App JWT (never logged)
            return self.cfg.github_token
        if not force and self._token and time.time() < self._token_expires_at - 60:
            return self._token
        resp = self._request(
            "POST",
            f"https://api.github.com/app/installations/{self.cfg.github_installation_id}/access_tokens",
            auth_jwt=True,
            expected=(201,),
        )
        data = resp.json()
        self._token = data.get("token", "")
        # expires_at: 2026-01-01T00:00:00Z
        exp = data.get("expires_at", "")
        try:
            t = time.strptime(exp, "%Y-%m-%dT%H:%M:%SZ")
            self._token_expires_at = calendar.timegm(t)
        except Exception:
            self._token_expires_at = time.time() + 60 * 60
        if not self._token:
            raise GitHubError("installation access token response had no token", status=500)
        return self._token

    # ------------------------------------------------------------- requests
    def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[dict] = None,
        content: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        auth_jwt: bool = False,
        auth_installation: bool = True,
        expected: Sequence[int] = (200,),
        raw_upload: bool = False,
    ) -> httpx.Response:
        base_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if headers:
            base_headers.update(headers)

        last: Optional[httpx.Response] = None
        for attempt in range(2):
            h = dict(base_headers)
            if auth_jwt:
                h["Authorization"] = f"Bearer {self._app_jwt()}"
            elif auth_installation:
                h["Authorization"] = f"Bearer {self.installation_token(force=(attempt > 0))}"
            try:
                resp = self.http.request(
                    method, url, json=json_body, content=content, headers=h
                )
            except httpx.HTTPError as e:
                raise GitHubError(f"GitHub request failed: {type(e).__name__}") from None
            last = resp
            if resp.status_code in (403, 429) and attempt == 0 and _rate_limited(resp):
                delay = _rate_limit_delay(resp)
                log.warning("GitHub rate limit hit; sleeping %.0fs", delay)
                time.sleep(delay)
                continue
            break

        assert last is not None
        if last.status_code not in expected:
            raise GitHubError(
                f"GitHub {method} {url} -> HTTP {last.status_code}",
                status=last.status_code,
            )
        return last

    def _get(self, url: str, **kw) -> httpx.Response:
        kw.setdefault("expected", (200,))
        return self._request("GET", url, **kw)

    # ------------------------------------------------------------- releases
    def list_releases(self, if_none_match: Optional[str] = None) -> ReleasesResult:
        headers = {}
        if if_none_match:
            headers["If-None-Match"] = if_none_match
        resp = self._request(
            "GET",
            f"{self.cfg.releases_api_url}?per_page=100",
            headers=headers,
            expected=(200, 304),
        )
        if resp.status_code == 304:
            return ReleasesResult(304, [], resp.headers.get("ETag"), resp.headers.get("Last-Modified"))
        return ReleasesResult(
            200, resp.json(), resp.headers.get("ETag"), resp.headers.get("Last-Modified")
        )

    def get_release_by_tag(self, tag: str) -> Optional[dict]:
        resp = self._request(
            "GET",
            f"{self.cfg.releases_api_url}/releases/tags/{tag}",
            expected=(200, 404),
        )
        return None if resp.status_code == 404 else resp.json()

    def create_release(
        self,
        tag: str,
        name: str,
        body: str,
        *,
        target_commitish: str = "main",
        draft: bool = True,
        prerelease: bool = False,
    ) -> dict:
        try:
            resp = self._request(
                "POST",
                f"{self.cfg.releases_api_url}",
                json_body={
                    "tag_name": tag,
                    "name": name,
                    "body": body,
                    "target_commitish": target_commitish,
                    "draft": draft,
                    "prerelease": prerelease,
                },
                expected=(201,),
            )
        except GitHubError as e:
            if e.status == 422:
                raise GitHubError(f"release already exists (duplicate version): {tag}", status=422) from None
            raise
        return resp.json()

    def update_release(self, release_id: int, **fields) -> dict:
        resp = self._request(
            "PATCH",
            f"{self.cfg.releases_api_url}/releases/{release_id}",
            json_body=fields,
            expected=(200,),
        )
        return resp.json()

    def upload_asset(self, upload_url: str, name: str, data: bytes,
                     content_type: str = "application/zip") -> dict:
        url = upload_url.split("{")[0]
        sep = "&" if "?" in url else "?"
        resp = self._request(
            "POST",
            f"{url}{sep}name={name}",
            content=data,
            headers={"Content-Type": content_type},
            expected=(201, 202),
        )
        return resp.json()

    # ------------------------------------------------------------ git data
    def get_branch_sha(self, branch: str) -> str:
        resp = self._get(f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/ref/heads/{branch}")
        return resp.json()["object"]["sha"]

    def get_commit_tree(self, commit_sha: str) -> str:
        resp = self._get(
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/commits/{commit_sha}"
        )
        return resp.json()["tree"]["sha"]

    def create_blob(self, content: bytes) -> str:
        resp = self._request(
            "POST",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/blobs",
            json_body={"content": base64.b64encode(content).decode("ascii"),
                       "encoding": "base64"},
            expected=(201,),
        )
        return resp.json()["sha"]

    def create_tree(self, base_tree: str, entries: List[dict]) -> str:
        resp = self._request(
            "POST",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/trees",
            json_body={"base_tree": base_tree, "tree": entries},
            expected=(201,),
        )
        return resp.json()["sha"]

    def create_commit(self, message: str, tree_sha: str, parents: List[str]) -> str:
        resp = self._request(
            "POST",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/commits",
            json_body={"message": message, "tree": tree_sha, "parents": parents},
            expected=(201,),
        )
        return resp.json()["sha"]

    def create_branch(self, branch: str, from_sha: str) -> None:
        try:
            self._request(
                "POST",
                f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/refs",
                json_body={"ref": f"refs/heads/{branch}", "sha": from_sha},
                expected=(201,),
            )
        except GitHubError as e:
            if e.status == 422:
                raise GitHubError(f"branch already exists: {branch}", status=422) from None
            raise

    def delete_branch(self, branch: str) -> None:
        self._request(
            "DELETE",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/git/refs/heads/{branch}",
            expected=(204, 404),
        )

    # ------------------------------------------------------------------ PR
    def create_pr(self, head: str, base: str, title: str, body: str) -> dict:
        resp = self._request(
            "POST",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/pulls",
            json_body={"head": head, "base": base, "title": title, "body": body},
            expected=(201,),
        )
        return resp.json()

    def get_pr(self, number: int) -> dict:
        return self._get(
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/pulls/{number}"
        ).json()

    def merge_pr(self, number: int, sha: str) -> bool:
        resp = self._request(
            "PUT",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/pulls/{number}/merge",
            json_body={"sha": sha, "merge_method": "squash"},
            expected=(200, 405),
        )
        return resp.json().get("merged", False)

    def pr_comment(self, number: int, body: str) -> None:
        self._request(
            "POST",
            f"https://api.github.com/repos/{self.cfg.full_repo_name}/issues/{number}/comments",
            json_body={"body": body},
            expected=(201,),
        )

    # ----------------------------------------------------------------- CI
    def check_state(self, sha: str) -> str:
        """Aggregate commit checks: success | failure | pending."""
        base = f"https://api.github.com/repos/{self.cfg.full_repo_name}"
        runs = self._get(f"{base}/commits/{sha}/check-runs").json().get("check_runs", [])
        conclusions = [r.get("conclusion") for r in runs]
        statuses = self._get(f"{base}/commits/{sha}/status").json()
        state = statuses.get("state", "pending")

        pending_words = {None, "queued", "in_progress", "waiting", "pending"}
        ok_words = {"success", "neutral", "skipped"}
        bad_words = {"failure", "cancelled", "timed_out", "action_required", "error"}

        if runs:
            if any(c in pending_words for c in conclusions):
                return "pending"
            if any(c in bad_words for c in conclusions):
                return "failure"
            if all(c in ok_words for c in conclusions):
                # statuses may still be pending
                if state == "pending" and statuses.get("total_count", 0) > 0:
                    return "pending"
                return "success"
        if state == "success":
            return "success"
        if state in ("failure", "error"):
            return "failure"
        return "pending"

    def wait_for_checks(self, sha: str, timeout: float, interval: float) -> str:
        """Returns success | failure | timeout."""
        deadline = time.time() + timeout
        while True:
            state = self.check_state(sha)
            if state in ("success", "failure"):
                return state
            if time.time() >= deadline:
                return "timeout"
            time.sleep(max(interval, 0.05))

    # ------------------------------------------------------------- helpers
    def release_exists(self, tag: str) -> bool:
        return self.get_release_by_tag(tag) is not None


def _rate_limited(resp: httpx.Response) -> bool:
    if resp.status_code == 429:
        return True
    if resp.status_code != 403:
        return False
    if resp.headers.get("X-RateLimit-Remaining") == "0":
        return True
    return "rate limit" in resp.text.lower()


def _rate_limit_delay(resp: httpx.Response) -> float:
    reset = resp.headers.get("X-RateLimit-Reset")
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), 60.0)
        except ValueError:
            pass
    if reset:
        try:
            return min(max(float(reset) - time.time(), 1.0), 60.0)
        except ValueError:
            pass
    return 5.0
