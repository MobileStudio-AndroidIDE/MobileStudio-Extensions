"""Test helpers: .msext builders + a faithful in-memory GitHub fake."""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import time
import zipfile
from typing import Dict, List, Optional

from app.github_client import GitHubError, ReleasesResult

ID = "com.test.demo"
VERSION = "1.0.0"


def default_manifest(ext_id: str = ID, version: str = VERSION, **overrides) -> dict:
    m = {
        "id": ext_id,
        "name": "Demo Extension",
        "version": version,
        "author": "tester",
        "description": "A test extension used by the MobileStudio upload API tests.",
        "download": "https://github.com/MobileStudio-AndroidIDE/"
                    "MobileStudio-Extensions/releases/download/com.test.demo-v1.0.0/"
                    "com.test.demo-v1.0.0.msext",
        "minStudioVersion": "1.0.0",
        "permissions": ["editor"],
        "languages": ["json"],
    }
    m.update(overrides)
    return m


def make_msext(
    target,
    files: Optional[Dict[str, bytes]] = None,
    manifest: Optional[dict] = None,
    include_manifest: bool = True,
    include_readme: bool = True,
    readme: bytes = b"# Demo extension\n",
) -> Path:
    """Write a .msext (ZIP) package to *target*."""
    from pathlib import Path
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        if include_manifest:
            zf.writestr("extension.json",
                        json.dumps(manifest or default_manifest(), indent=2))
        if include_readme:
            zf.writestr("README.md", readme)
        for name, data in (files or {}).items():
            zf.writestr(name, data)
    return target


def make_zip_slip(target):
    """ZIP containing a ../ traversal entry."""
    target = __import__("pathlib").Path(target)
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("extension.json", json.dumps(default_manifest()))
        zf.writestr("README.md", b"# readme\n")
        zf.writestr("../../evil.txt", b"pwned")
    return target


def make_symlink_package(target):
    """ZIP containing a unix symlink entry."""
    target = __import__("pathlib").Path(target)
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("extension.json", json.dumps(default_manifest()))
        zf.writestr("README.md", b"# readme\n")
        info = zipfile.ZipInfo("link")
        info.create_system = 3                 # unix
        info.external_attr = (0o120777 << 16)   # S_IFLNK | 0777
        zf.writestr(info, "/etc/passwd")
    return target


def upload_file(client, path, filename: Optional[str] = None,
                extension_id: Optional[str] = None, extra: Optional[dict] = None):
    from pathlib import Path
    path = Path(path)
    data = {}
    if extension_id is not None:
        data["extensionId"] = extension_id
    if extra:
        data.update(extra)
    with open(path, "rb") as fh:
        return client.post(
            "/api/v1/extensions/upload",
            files={"file": (filename or path.name, fh, "application/octet-stream")},
            data=data,
        )


class FakeGitHub:
    """Implements the subset of GitHubClient used by pipeline + registry."""

    def __init__(self, cfg, releases: Optional[List[dict]] = None,
                 check_state: str = "success", merge_ok: bool = True):
        self.cfg = cfg
        self.releases: List[dict] = list(releases or [])
        self.calls: List[tuple] = []
        self._check_state = check_state
        self._merge_ok = merge_ok
        self.branches: Dict[str, str] = {"main": "sha-main-0"}
        self.blobs: Dict[str, bytes] = {}
        self.prs: Dict[int, dict] = {}
        self.comments: List[str] = []
        self.merged: List[int] = []
        self.assets: Dict[str, List[bytes]] = {}
        self._seq = itertools.count(1)

    # ------------------------------------------------------------- releases
    def _etag(self) -> str:
        basis = json.dumps(
            [(r.get("tag_name"), r.get("draft"), len(r.get("assets") or []),
              r.get("body")) for r in self.releases],
            sort_keys=True)
        return '"' + hashlib.sha256(basis.encode()).hexdigest()[:32] + '"'

    def list_releases(self, if_none_match: Optional[str] = None) -> ReleasesResult:
        self.calls.append(("list_releases", if_none_match))
        etag = self._etag()
        if if_none_match and if_none_match == etag:
            return ReleasesResult(304, [], etag, None)
        import copy
        return ReleasesResult(200, copy.deepcopy(self.releases), etag, None)

    def release_exists(self, tag: str) -> bool:
        self.calls.append(("release_exists", tag))
        return any(r.get("tag_name") == tag for r in self.releases)

    def get_release_by_tag(self, tag: str) -> Optional[dict]:
        self.calls.append(("get_release_by_tag", tag))
        return next((r for r in self.releases if r.get("tag_name") == tag), None)

    def create_release(self, tag, name, body, *, target_commitish="main",
                       draft=True, prerelease=False) -> dict:
        self.calls.append(("create_release", tag, draft))
        if self.get_release_by_tag(tag) is not None:
            raise GitHubError(f"release already exists: {tag}", status=422)
        rid = next(self._seq)
        rel = {
            "id": rid,
            "tag_name": tag,
            "name": name,
            "body": body,
            "draft": draft,
            "prerelease": prerelease,
            "html_url": f"https://github.com/{self.cfg.owner}/{self.cfg.repo}"
                        f"/releases/tag/{tag}",
            "upload_url": f"https://uploads.github.com/repos/{self.cfg.owner}/"
                          f"{self.cfg.repo}/releases/{rid}/assets{{?name,label}}",
            "assets": [],
            "author": {"login": "fake-dev"},
            "published_at": None if draft else time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_commitish": target_commitish,
        }
        self.releases.append(rel)
        return dict(rel)

    def update_release(self, release_id: int, **fields) -> dict:
        self.calls.append(("update_release", release_id, fields))
        rel = next(r for r in self.releases if r["id"] == release_id)
        rel.update(fields)
        if fields.get("draft") is False and not rel.get("published_at"):
            rel["published_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return dict(rel)

    def upload_asset(self, upload_url: str, name: str, data: bytes,
                     content_type: str = "application/zip") -> dict:
        rid = int(upload_url.split("/releases/")[1].split("/")[0])
        rel = next(r for r in self.releases if r["id"] == rid)
        self.calls.append(("upload_asset", name, len(data)))
        asset = {
            "id": next(self._seq),
            "name": name,
            "size": len(data),
            "browser_download_url": f"https://github.com/{self.cfg.owner}/"
                                    f"{self.cfg.repo}/releases/download/"
                                    f"{rel['tag_name']}/{name}",
            "content_type": content_type,
        }
        rel["assets"].append(asset)
        self.assets.setdefault(rel["tag_name"], []).append(data)
        return dict(asset)

    # ------------------------------------------------------------- git data
    def get_branch_sha(self, branch: str) -> str:
        self.calls.append(("get_branch_sha", branch))
        if branch not in self.branches:
            raise GitHubError(f"branch not found: {branch}", status=404)
        return self.branches[branch]

    def get_commit_tree(self, commit_sha: str) -> str:
        return f"tree-of-{commit_sha}"

    def create_blob(self, content: bytes) -> str:
        sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        self.blobs[sha] = content
        self.calls.append(("create_blob", sha[:8], len(content)))
        return sha

    def create_tree(self, base_tree: str, entries: List[dict]) -> str:
        for e in entries:
            if ".." in e["path"] or e["path"].startswith("/"):
                raise GitHubError(f"invalid tree path: {e['path']}")
        self.calls.append(("create_tree", len(entries)))
        return f"tree-{next(self._seq)}"

    def create_commit(self, message: str, tree_sha: str, parents: List[str]) -> str:
        sha = f"commit-{next(self._seq)}"
        self.calls.append(("create_commit", sha))
        return sha

    def create_branch(self, branch: str, from_sha: str) -> None:
        self.calls.append(("create_branch", branch))
        if branch in self.branches:
            raise GitHubError(f"branch already exists: {branch}", status=422)
        self.branches[branch] = from_sha

    def delete_branch(self, branch: str) -> None:
        self.calls.append(("delete_branch", branch))
        if branch != "main":
            self.branches.pop(branch, None)

    # ------------------------------------------------------------------ PR
    def create_pr(self, head, base, title, body) -> dict:
        number = next(self._seq)
        pr = {"number": number, "head": {"ref": head}, "base": {"ref": base},
              "title": title, "body": body,
              "html_url": f"https://github.com/{self.cfg.owner}/{self.cfg.repo}"
                          f"/pull/{number}"}
        self.prs[number] = pr
        self.calls.append(("create_pr", number, head))
        return dict(pr)

    def merge_pr(self, number: int, sha: str) -> bool:
        self.calls.append(("merge_pr", number))
        if not self._merge_ok:
            return False
        self.merged.append(number)
        self.branches["main"] = f"sha-merged-{number}"
        return True

    def pr_comment(self, number: int, body: str) -> None:
        self.comments.append(body)
        self.calls.append(("pr_comment", number))

    # ------------------------------------------------------------------ CI
    def check_state(self, sha: str) -> str:
        return self._check_state

    def wait_for_checks(self, sha: str, timeout: float, interval: float) -> str:
        deadline = time.time() + timeout
        while True:
            state = self.check_state(sha)
            if state in ("success", "failure"):
                return state
            if time.time() >= deadline:
                return "timeout"
            time.sleep(max(interval, 0.05))


def make_release(tag: str, *, body="", assets=None, draft=False, prerelease=False,
                 published="2026-01-01T00:00:00Z", login="someone") -> dict:
    return {
        "id": abs(hash(tag)) % 100000,
        "tag_name": tag,
        "name": tag,
        "body": body,
        "draft": draft,
        "prerelease": prerelease,
        "html_url": f"https://github.com/MobileStudio-AndroidIDE/"
                    f"MobileStudio-Extensions/releases/tag/{tag}",
        "assets": list(assets or []),
        "author": {"login": login},
        "published_at": published,
        "created_at": published,
    }


def make_asset(name: str, size: int = 1024, tag: str = "") -> dict:
    return {
        "name": name,
        "size": size,
        "browser_download_url": f"https://github.com/MobileStudio-AndroidIDE/"
                                f"MobileStudio-Extensions/releases/download/{tag}/{name}",
    }
