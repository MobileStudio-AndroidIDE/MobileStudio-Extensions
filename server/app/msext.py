"""Upload gate for .msext packages.

.msext is a ZIP container, but ONLY .msext uploads are accepted. This module
performs the fast, upload-stage checks (extension, size, real ZIP structure,
required members, ZIP Slip, symlink, entry/file limits, SHA-256) before the
package ever reaches scripts/security_scan.py / scripts/validate.py.

MIME/content-type is never trusted; the ZIP magic and the central directory
are inspected directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from pathlib import Path
from typing import BinaryIO, Dict, Iterable, List, Tuple

PACKAGE_EXT = ".msext"
ZIP_MAGIC = b"PK\x03\x04"
EMPTY_ZIP_MAGIC = b"PK\x05\x06"

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
REQUIRED_MEMBERS = ("extension.json", "README.md")

# extensions that are always rejected as package payloads when found as members
FORBIDDEN_MEMBER_EXTS = (".zip", ".apk", ".aab", ".jar", ".exe", ".so", ".dll")

# DEX is the extension code format MobileStudio itself ships (ExtensionHost loads
# classes.dex from an installed .msext), so it is allowed as a payload -- but only
# as a genuine Dalvik executable. Anything else named .dex is a binary smuggling
# attempt and is rejected like every other forbidden type.
DEX_EXT = ".dex"
DEX_MAGIC = b"dex\n"
DEX_HEADER = 8  # "dex\n" + 3 ASCII version digits + NUL
DEX_VERSIONS = {"035", "037", "038", "039", "040", "041"}
DEX_MAX_BYTES = 8 * 1024 * 1024


def dex_magic_ok(data: bytes) -> bool:
    """True when *data* carries a real Dalvik header (magic + version + NUL)."""
    if data is None or len(data) < DEX_HEADER:
        return False
    if data[:4] != DEX_MAGIC:
        return False
    version = data[4:7]
    return data[7:8] == b"\x00" and version.decode("ascii", "ignore") in DEX_VERSIONS


class GateError(Exception):
    """Raised with a machine readable code plus detailed messages."""

    def __init__(self, code: str, errors: List[str], status_code: int = 400):
        super().__init__(code)
        self.code = code
        self.errors = errors
        self.status_code = status_code

    def payload(self) -> Dict:
        return {"error": self.code, "message": self.errors[0] if self.errors else self.code,
                "errors": self.errors}


def sanitize_filename(name: str | None) -> str:
    """Reject path traversal / separators in the client supplied filename."""
    if not name:
        raise GateError("invalid_filename", ["missing file name"])
    base = name.replace("\\", "/").split("/")[-1]
    if base != name.replace("\\", "/") or base in ("", ".", ".."):
        raise GateError("invalid_filename", [f"file name must be a plain name: {name!r}"])
    if "/" in base or "\\" in base or "\x00" in base:
        raise GateError("invalid_filename", [f"illegal characters in file name: {name!r}"])
    if not base.lower().endswith(PACKAGE_EXT):
        raise GateError(
            "unsupported_extension",
            [f"only {PACKAGE_EXT} packages are accepted (got: {base})"],
        )
    return base


def save_stream(stream: BinaryIO, target: Path, max_bytes: int, chunk: int = 1024 * 1024) -> int:
    """Copy the upload into *target*, aborting as soon as max_bytes is exceeded."""
    total = 0
    with open(target, "wb") as out:
        while True:
            data = stream.read(chunk)
            if not data:
                break
            total += len(data)
            if total > max_bytes:
                out.close()
                target.unlink(missing_ok=True)
                raise GateError(
                    "too_large",
                    [f"package exceeds the {max_bytes} byte upload limit"],
                    status_code=413,
                )
            out.write(data)
    if total == 0:
        target.unlink(missing_ok=True)
        raise GateError("empty_upload", ["uploaded file is empty"])
    return total


def _entry_mode(info: zipfile.ZipInfo) -> int:
    return info.external_attr >> 16


def is_symlink_entry(info: zipfile.ZipInfo) -> bool:
    # symlink iff unix mode says so (create_system 3 = UNIX)
    if info.create_system == 3:
        return stat.S_ISLNK(_entry_mode(info))
    return False


def check_package(path: Path, cfg) -> List[str]:
    """Full upload-stage package check. Returns [] when acceptable.

    Raises GateError for definite rejections (bad extension is handled before,
    this handles structural problems).
    """
    errors: List[str] = []
    size = path.stat().st_size
    if size <= 0:
        raise GateError("empty_upload", ["uploaded file is empty"])
    if size > cfg.max_upload_bytes:
        raise GateError(
            "too_large",
            [f"package is {size} bytes > {cfg.max_upload_bytes} byte limit"],
            status_code=413,
        )

    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == EMPTY_ZIP_MAGIC or magic != ZIP_MAGIC:
        raise GateError("invalid_package", [f"not a ZIP-based .msext package (magic: {magic!r})"])

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        raise GateError("invalid_package", [f"corrupt ZIP: {e}"])

    with zf:
        try:
            bad = zf.testzip()
        except Exception as e:  # decompression bomb / truncated central directory
            raise GateError("invalid_package", [f"corrupt ZIP: {e}"])
        if bad is not None:
            errors.append(f"corrupt ZIP entry: {bad}")

        infos = zf.infolist()
        if len(infos) > cfg.max_entries:
            errors.append(f"too many entries: {len(infos)} > {cfg.max_entries}")

        names = set()
        total = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise GateError("zip_slip", [f"ZIP slip / path traversal entry: {info.filename}"])
            if is_symlink_entry(info):
                raise GateError("symlink", [f"symlink entries are not allowed: {info.filename}"])
            if info.is_dir():
                continue
            names.add(name.lstrip("./"))
            total += info.file_size
            if info.file_size > cfg.max_file_bytes:
                errors.append(
                    f"file too large: {name} ({info.file_size} bytes > {cfg.max_file_bytes})"
                )
            ext = os.path.splitext(name.lower())[1]
            if ext in FORBIDDEN_MEMBER_EXTS:
                errors.append(f"forbidden payload type inside package: {name}")
            elif ext == DEX_EXT:
                # allowed extension code format, but only as a genuine DEX
                if info.file_size > DEX_MAX_BYTES:
                    errors.append(f"dex too large: {name} ({info.file_size} bytes > {DEX_MAX_BYTES})")
                else:
                    try:
                        head = zf.open(info).read(DEX_HEADER)
                    except Exception as e:  # unreadable member
                        errors.append(f"cannot read {name}: {type(e).__name__}")
                    else:
                        if not dex_magic_ok(head):
                            errors.append(
                                f"not a valid Dalvik dex file (bad header): {name}")
        if total > cfg.max_upload_bytes:
            errors.append(f"package content too large: {total} > {cfg.max_upload_bytes}")

        for required in REQUIRED_MEMBERS:
            if required not in names:
                errors.append(f"required file missing from package root: {required}")

        # extension.json must be readable JSON right away (cheap fail-fast)
        if "extension.json" in names:
            try:
                manifest = json.loads(zf.read("extension.json").decode("utf-8-sig"))
                if not isinstance(manifest, dict):
                    errors.append("extension.json must be a JSON object")
            except Exception as e:
                errors.append(f"extension.json is not valid JSON: {e}")

    if errors:
        raise GateError("package_rejected", errors)
    return []


def read_manifest(path: Path) -> Dict:
    with zipfile.ZipFile(path) as zf:
        return json.loads(zf.read("extension.json").decode("utf-8-sig"))


def safe_extract(path: Path, dest: Path) -> None:
    """Extract after re-validating every entry (defence in depth, never trusts
    the earlier gate alone)."""
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise GateError("zip_slip", [f"ZIP slip / path traversal entry: {info.filename}"])
            if is_symlink_entry(info):
                raise GateError("symlink", [f"symlink entries are not allowed: {info.filename}"])
            target = (dest_root / name.lstrip("./")).resolve()
            if not str(target).startswith(str(dest_root)):
                raise GateError("zip_slip", [f"entry escapes destination: {info.filename}"])
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_package_files(root: Path) -> Iterable[Tuple[str, Path]]:
    """Yield (posix relative path, absolute path) for every file under root."""
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            abs_path = Path(dirpath) / fn
            rel = abs_path.relative_to(root).as_posix()
            yield rel, abs_path
