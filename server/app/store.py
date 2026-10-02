"""Submission store: the realtime upload state machine.

    queued -> scanning -> publishing -> published
                     \\-> failed

"published" is only ever set after the GitHub Release (with the .msext asset)
exists and the registry cache has been invalidated, so a listed extension is
always downloadable. Results are persisted to DATA_DIR/submissions.json; a
submission that was in flight when the process died is marked failed on load.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

STATUSES = ("queued", "scanning", "failed", "publishing", "published")
PUBLIC_STATUSES = STATUSES


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Submission:
    submissionId: str
    status: str = "queued"
    extensionId: str = ""
    version: str = ""
    sha256: str = ""
    packagePath: str = ""            # transient (temp file), never serialized to clients
    size: int = 0
    prUrl: str = ""
    releaseUrl: str = ""
    downloadUrl: str = ""
    branch: str = ""
    errors: List[str] = field(default_factory=list)
    scan: Optional[dict] = None
    createdAt: str = field(default_factory=_now)
    updatedAt: str = field(default_factory=_now)
    events: List[str] = field(default_factory=list)

    def event(self, message: str) -> None:
        self.events.append(f"{_now()} {message}")
        self.updatedAt = _now()

    def fail(self, *errors: str) -> None:
        self.status = "failed"
        for e in errors:
            if e:
                self.errors.append(str(e))
        self.event("failed: " + "; ".join(self.errors[:3]))

    def to_public(self) -> dict:
        return {
            "submissionId": self.submissionId,
            "status": self.status,
            "extensionId": self.extensionId,
            "version": self.version,
            "sha256": self.sha256,
            "size": self.size,
            "prUrl": self.prUrl,
            "releaseUrl": self.releaseUrl,
            "downloadUrl": self.downloadUrl,
            "branch": self.branch,
            "errors": self.errors,
            "scan": self.scan,
            "createdAt": self.createdAt,
            "updatedAt": self.updatedAt,
            "events": self.events,
        }

    def to_row(self) -> dict:
        d = self.to_public()
        d.pop("scan")  # keep the persisted file small; errors carry the detail
        return d

    @classmethod
    def from_row(cls, row: dict) -> "Submission":
        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in row.items() if k in known}
        sub = cls(**{k: v for k, v in kwargs.items() if k != "scan"})
        sub.errors = list(row.get("errors") or [])
        sub.events = list(row.get("events") or [])
        return sub


class Store:
    def __init__(self, data_dir: Path):
        self._lock = threading.RLock()
        self._items: Dict[str, Submission] = {}
        self._path = Path(data_dir) / "submissions.json"
        self._load()

    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            rows = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return
        for row in rows if isinstance(rows, list) else []:
            try:
                sub = Submission.from_row(row)
            except Exception:
                continue
            if sub.status in ("queued", "scanning", "publishing"):
                # the worker died mid-flight: never pretend it can resume
                sub.fail("server restarted while processing; please re-upload")
            self._items[sub.submissionId] = sub

    def _persist(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            rows = [s.to_row() for s in self._items.values()]
            self._path.write_text(json.dumps(rows, indent=2, ensure_ascii=False),
                                  encoding="utf-8")
        except Exception:
            # persistence is best effort; the in-memory state stays authoritative
            pass

    # ------------------------------------------------------------------
    def create(self, extension_id: str, version: str, package_path: str, size: int) -> Submission:
        with self._lock:
            sub = Submission(
                submissionId=uuid.uuid4().hex,
                extensionId=extension_id,
                version=version,
                packagePath=package_path,
                size=size,
            )
            sub.event("queued")
            self._items[sub.submissionId] = sub
            self._persist()
            return sub

    def get(self, submission_id: str) -> Optional[Submission]:
        with self._lock:
            return self._items.get(submission_id)

    def save(self, sub: Submission) -> None:
        with self._lock:
            sub.updatedAt = _now()
            self._persist()

    def list(self, limit: int = 50) -> List[Submission]:
        with self._lock:
            items = sorted(self._items.values(), key=lambda s: s.createdAt, reverse=True)
        return items[:limit]
