"""Dalvik .dex payload policy.

MobileStudio loads `classes.dex` out of an installed .msext (ExtensionHost), so
Dalvik bytecode is the extension code format -- it has to survive the upload
gate. But a `.dex` name must never become a way to smuggle an arbitrary binary,
so both the upload gate and security_scan.py accept a .dex only when its header
proves it really is a Dalvik file, and still sniff for ELF/PE regardless of the
name.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app import msext
from app.config import Config
from tests.helpers import make_msext

REAL_DEX = b"dex\n035\x00" + b"\x00" * 64          # header d8 emits for class file 52.0
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN = REPO_ROOT / "scripts" / "security_scan.py"


def _gate(pkg: Path):
    """Returns [] when the upload gate accepts *pkg*, else the error list."""
    try:
        msext.check_package(Path(pkg), Config())
    except msext.GateError as e:
        return e.errors
    return []


# ------------------------------------------------------------------ headers
def test_dex_magic_accepts_real_dalvik_headers():
    assert msext.dex_magic_ok(REAL_DEX)
    for version in ("035", "037", "038", "039", "040", "041"):
        assert msext.dex_magic_ok(b"dex\n" + version.encode() + b"\x00" + b"\x00" * 8)


def test_dex_magic_rejects_spoofed_or_truncated_headers():
    assert not msext.dex_magic_ok(ELF)                  # ELF renamed to .dex
    assert not msext.dex_magic_ok(b"dex\n")             # truncated
    assert not msext.dex_magic_ok(b"dex\n035")          # no trailing NUL
    assert not msext.dex_magic_ok(b"dex\n999\x00")      # unknown version
    assert not msext.dex_magic_ok(b"")                  # empty
    assert not msext.dex_magic_ok(b"PK\x03\x04")        # a zip wearing a .dex name


# -------------------------------------------------------------- upload gate
def test_real_dex_payload_is_accepted(tmp_path):
    pkg = make_msext(tmp_path / "code.msext", files={"classes.dex": REAL_DEX})
    assert _gate(pkg) == []


def test_elf_renamed_to_dex_is_rejected(tmp_path):
    pkg = make_msext(tmp_path / "fake.msext", files={"classes.dex": ELF})
    errors = _gate(pkg)
    assert errors, "an ELF behind a .dex name must not pass the gate"
    assert any("not a valid Dalvik" in e for e in errors)


def test_dex_with_bad_version_is_rejected(tmp_path):
    pkg = make_msext(tmp_path / "ver.msext",
                     files={"classes.dex": b"dex\n999\x00" + b"\x00" * 8})
    assert any("not a valid Dalvik" in e for e in _gate(pkg))


def test_truncated_dex_is_rejected(tmp_path):
    pkg = make_msext(tmp_path / "short.msext", files={"classes.dex": b"dex\n035"})
    assert any("not a valid Dalvik" in e for e in _gate(pkg))


def test_oversized_dex_is_rejected(tmp_path):
    big = REAL_DEX + b"\x00" * (msext.DEX_MAX_BYTES + 1)
    pkg = make_msext(tmp_path / "big.msext", files={"classes.dex": big})
    assert any("dex too large" in e for e in _gate(pkg))


def test_other_binary_payloads_still_rejected(tmp_path):
    for name in ("evil.so", "evil.exe", "evil.dll", "evil.jar", "evil.apk", "evil.zip"):
        pkg = make_msext(tmp_path / f"{name}.msext", files={name: ELF})
        errors = _gate(pkg)
        assert errors, f"{name} must stay forbidden"


def test_real_dex_alongside_sources_is_accepted(tmp_path):
    pkg = make_msext(tmp_path / "mixed.msext", files={
        "classes.dex": REAL_DEX,
        "main.js": b"console.log('ok')\n",
    })
    assert _gate(pkg) == []


# --------------------------------------------------------- security scanner
def _scan(pkg: Path, tmp_path: Path) -> dict:
    out = tmp_path / "scan.json"
    proc = subprocess.run(
        [sys.executable, str(SCAN), str(pkg), "--ext-id", "com.test.dex",
         "--version", "1.0.0", "--out", str(out)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
    )
    assert out.is_file(), f"scanner produced no report (exit {proc.returncode}): {proc.stdout}"
    return json.loads(out.read_text(encoding="utf-8"))


def test_scanner_passes_a_real_dex(tmp_path):
    pkg = make_msext(tmp_path / "ok.msext", files={"classes.dex": REAL_DEX})
    report = _scan(pkg, tmp_path)
    assert report["passed"] is True, report


def test_scanner_fails_an_elf_behind_a_dex_name(tmp_path):
    pkg = make_msext(tmp_path / "fake.msext", files={"classes.dex": ELF})
    report = _scan(pkg, tmp_path)
    assert report["passed"] is False
    stage = next(s for s in report["stages"] if s["stage"] == "Executable scan")
    joined = " ".join(stage.get("findings", []))
    assert "not a valid Dalvik dex file" in joined
    assert "executable/binary files present" in joined


def test_scanner_still_fails_plain_binaries(tmp_path):
    pkg = make_msext(tmp_path / "so.msext", files={"libnative.so": ELF})
    report = _scan(pkg, tmp_path)
    assert report["passed"] is False
