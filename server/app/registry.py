"""Registry built from GitHub Releases (the source of truth).

Rules:
  * one Release = one extension version
  * only .msext assets are extension packages (.zip/.apk/.jar/... ignored)
  * draft Releases are never listed
  * prereleases are listed only when include_prerelease=true
  * Release body carries the extension.json metadata as JSON, so clients never
    need to download a package just to render the store list
  * duplicate ids collapse to the highest SemVer

Caching / rate limits:
  * server side: TTL cache + conditional requests against the GitHub API
    (If-None-Match -> 304, which does not count against the rate limit)
  * cache is invalidated the moment a submission reaches "published"
  * client side: strong ETag + Last-Modified + Cache-Control: no-cache so the
    app can If-None-Match and receive 304 Not Modified when nothing changed
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from email.utils import format_datetime, parsedate_to_datetime
from typing import List, Optional, Tuple

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]*)*))?$"
)
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
TAG_RE = re.compile(r"^(?P<id>.+)-v(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def _ver_key(version: str):
    core = version.split("-", 1)[0].split("+", 1)[0]
    parts = [int(p) if p.isdigit() else 0 for p in core.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _parse_body(body: str) -> dict:
    text = (body or "").strip()
    if not text.startswith("{"):
        return {}
    try:
        data = json.loads(text)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _id_version(meta: dict, tag: str) -> Tuple[str, str]:
    ext_id = str(meta.get("id") or "").strip()
    version = str(meta.get("version") or "").strip()
    if ext_id and version and SEMVER.match(version):
        return ext_id, version
    m = TAG_RE.match(tag or "")
    if m:
        return m.group("id"), m.group("version")
    return ext_id or "", version or ""


def build_extensions(releases: List[dict], include_prerelease: bool) -> List[dict]:
    out: dict = {}
    for rel in releases:
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        if rel.get("prerelease") and not include_prerelease:
            continue
        assets = [a for a in (rel.get("assets") or []) if isinstance(a, dict)]
        msext_assets = [a for a in assets
                        if str(a.get("name", "")).lower().endswith(".msext")]
        if not msext_assets:
            continue
        tag = str(rel.get("tag_name") or "")
        meta = _parse_body(str(rel.get("body") or ""))
        ext_id, version = _id_version(meta, tag)
        if not ext_id or not ID_RE.match(ext_id) or not SEMVER.match(version):
            continue
        preferred = f"{ext_id}-v{version}.msext"
        asset = next((a for a in msext_assets if a.get("name") == preferred), msext_assets[0])
        download = str(asset.get("browser_download_url") or "")
        if not download.startswith("https://"):
            continue
        author = str(meta.get("author") or "") or \
            str((rel.get("author") or {}).get("login") or "")
        min_v = str(meta.get("minMobileStudioVersion")
                    or meta.get("minStudioVersion") or "1.0.0")
        entry = {
            "id": ext_id,
            "name": str(meta.get("name") or "") or tag,
            "version": version,
            "author": author,
            "description": str(meta.get("description") or ""),
            "type": str(meta.get("type") or ""),
            "minStudioVersion": min_v,
            "minMobileStudioVersion": min_v,
            "download": download,
            "size": int(asset.get("size") or meta.get("size") or 0),
            "sha256": str(meta.get("sha256") or ""),
            "permissions": list(meta.get("permissions") or []),
            "languages": list(meta.get("languages") or []),
            "prerelease": bool(rel.get("prerelease")),
            "tag": tag,
            "releaseUrl": str(rel.get("html_url") or ""),
            "publishedAt": str(rel.get("published_at") or rel.get("created_at") or ""),
        }
        prev = out.get(ext_id)
        if prev is None or _ver_key(version) > _ver_key(prev["version"]):
            out[ext_id] = entry
    return sorted(out.values(), key=lambda e: e["id"])


class ReleasesRegistry:
    def __init__(self, gh, cfg):
        self.gh = gh
        self.cfg = cfg
        self._lock = threading.Lock()
        # key: include_prerelease -> cache entry with raw releases + upstream validators
        self._cache: dict = {}

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------
    def _fresh_releases(self, include_prerelease: bool):
        """Returns (releases, etag, last_modified) using TTL + conditional GET."""
        now = time.time()
        entry = self._cache.get(include_prerelease)
        if entry and now - entry["built_at"] < self.cfg.registry_cache_ttl:
            return entry["releases"], entry.get("upstream_etag"), entry.get("upstream_lm")

        result = self.gh.list_releases(if_none_match=(entry or {}).get("upstream_etag"))
        if result.status == 304 and entry:
            entry["built_at"] = now
            return entry["releases"], entry.get("upstream_etag"), entry.get("upstream_lm")

        entry = {
            "releases": result.releases,
            "upstream_etag": result.etag,
            "upstream_lm": result.last_modified,
            "built_at": now,
        }
        self._cache[include_prerelease] = entry
        return entry["releases"], entry["upstream_etag"], entry["upstream_lm"]

    # ------------------------------------------------------------------
    def get(
        self,
        include_prerelease: bool = False,
        if_none_match: Optional[str] = None,
        if_modified_since: Optional[str] = None,
    ) -> Tuple[int, Optional[bytes], dict]:
        """Returns (status, body, headers). 304 comes with body=None."""
        with self._lock:
            releases, _up_etag, up_lm = self._fresh_releases(include_prerelease)
            extensions = build_extensions(releases, include_prerelease)

            payload = {
                "schemaVersion": "2.0.0",
                "source": "github-releases",
                "repository": self.cfg.full_repo_name,
                "count": len(extensions),
                "extensions": extensions,
            }
            body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
            etag = '"' + hashlib.sha256(
                json.dumps(extensions, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()[:32] + '"'
            last_modified = _pick_last_modified(extensions, up_lm)

            headers = {
                "ETag": etag,
                "Last-Modified": last_modified,
                "Cache-Control": "no-cache",
                "X-Registry-Source": "github-releases",
                "X-Registry-Count": str(len(extensions)),
            }

            if if_none_match and _etag_matches(if_none_match, etag):
                return 304, None, {"ETag": etag, "Cache-Control": "no-cache",
                                   "X-Registry-Source": "github-releases"}
            if if_modified_since and last_modified:
                try:
                    if parsedate_to_datetime(if_modified_since) >= \
                            parsedate_to_datetime(last_modified):
                        return 304, None, {"ETag": etag, "Cache-Control": "no-cache",
                                           "X-Registry-Source": "github-releases"}
                except Exception:
                    pass
            return 200, body, headers

    def find(self, ext_id: str, include_prerelease: bool = False) -> Optional[dict]:
        with self._lock:
            releases, _, _ = self._fresh_releases(include_prerelease)
            for entry in build_extensions(releases, include_prerelease):
                if entry["id"] == ext_id:
                    return entry
        return None


def _etag_matches(header_value: str, etag: str) -> bool:
    if header_value.strip() == "*":
        return True
    candidates = [c.strip() for c in header_value.split(",")]
    normalized = {c[2:] if c.startswith("W/") else c for c in candidates}
    return etag in normalized


def _pick_last_modified(extensions: List[dict], upstream_lm: Optional[str]) -> str:
    latest = None
    for e in extensions:
        ts = e.get("publishedAt") or ""
        if not ts:
            continue
        try:
            dt = parsedate_to_datetime(ts) if "GMT" in ts or "," in ts else None
        except Exception:
            dt = None
        if dt is None:
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
            except Exception:
                continue
        if latest is None or dt > latest:
            latest = dt
    if latest is not None:
        return format_datetime(latest, usegmt=True)
    if upstream_lm:
        return upstream_lm
    from datetime import datetime, timezone
    return format_datetime(datetime.now(timezone.utc), usegmt=True)
