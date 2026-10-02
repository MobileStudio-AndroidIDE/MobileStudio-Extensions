"""Upload-stage rejections: extension, size, ZIP structure, manifest gates."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

from app.config import Config
from tests.helpers import (
    ID, VERSION, default_manifest, make_msext, make_symlink_package, make_zip_slip,
    upload_file,
)


def test_valid_msext_accepted(client, tmp_path):
    pkg = make_msext(tmp_path / "ok.msext")
    resp = upload_file(client, pkg)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "processing"
    assert body["extensionId"] == ID
    assert body["version"] == VERSION
    assert body["submissionId"]


def test_zip_rejected(client, tmp_path):
    pkg = tmp_path / "evil.zip"
    make_msext(pkg)
    resp = upload_file(client, pkg, filename="evil.zip")
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_extension"


def test_apk_rejected(client, tmp_path):
    pkg = tmp_path / "evil.apk"
    make_msext(pkg)
    resp = upload_file(client, pkg, filename="evil.apk")
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_extension"


def test_aab_and_jar_rejected(client, tmp_path):
    for name in ("evil.aab", "evil.jar"):
        pkg = tmp_path / name
        make_msext(pkg)
        resp = upload_file(client, pkg, filename=name)
        assert resp.status_code == 400, name
        assert resp.json()["error"] == "unsupported_extension"


def test_filename_traversal_rejected(client, tmp_path):
    pkg = tmp_path / "x.msext"
    make_msext(pkg)
    resp = upload_file(client, pkg, filename="../../etc/x.msext")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_filename"


def test_upload_over_50mb_rejected(client, tmp_path, cfg):
    """Real 51 MB body against the default 50 MB package limit."""
    big = tmp_path / "huge.msext"
    chunk = b"\x00" * (1024 * 1024)
    with open(big, "wb") as f:
        for _ in range(51):
            f.write(chunk)
    resp = upload_file(client, big)
    assert resp.status_code == 413
    assert resp.json()["error"] == "too_large"
    # and the default really is 50 MB
    assert cfg.max_upload_bytes == 50 * 1024 * 1024


def test_single_file_over_10mb_rejected(client, tmp_path, cfg):
    """An 11 MB file inside the package fails the per-file 10 MB limit."""
    assert cfg.max_file_bytes == 10 * 1024 * 1024
    pkg = make_msext(tmp_path / "big.msext",
                     files={"large.txt": os.urandom(11 * 1024 * 1024)})
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    payload = resp.json()
    assert payload["error"] == "package_rejected"
    assert any("file too large" in e for e in payload["errors"])


def test_corrupt_zip_rejected(client, tmp_path):
    pkg = tmp_path / "broken.msext"
    pkg.write_bytes(b"PK\x03\x04" + os.urandom(256))
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_package"


def test_not_a_zip_rejected(client, tmp_path):
    pkg = tmp_path / "text.msext"
    pkg.write_bytes(b"this is not a zip at all")
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_package"


def test_zip_slip_rejected(client, tmp_path):
    pkg = make_zip_slip(tmp_path / "slip.msext")
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    payload = resp.json()
    assert payload["error"] == "zip_slip"
    assert any("traversal" in e for e in payload["errors"])


def test_symlink_rejected(client, tmp_path):
    pkg = make_symlink_package(tmp_path / "link.msext")
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert resp.json()["error"] == "symlink"


def test_missing_extension_json_rejected(client, tmp_path):
    pkg = make_msext(tmp_path / "nomanifest.msext", include_manifest=False)
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    payload = resp.json()
    assert any("extension.json" in e for e in payload["errors"])


def test_missing_readme_rejected(client, tmp_path):
    pkg = make_msext(tmp_path / "noreadme.msext", include_readme=False)
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert any("README.md" in e for e in resp.json()["errors"])


def test_invalid_semver_rejected(client, tmp_path):
    pkg = make_msext(tmp_path / "badver.msext",
                     manifest=default_manifest(version="1.0"))
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_manifest"
    assert any("SemVer" in e for e in resp.json()["errors"])


def test_invalid_extension_id_rejected(client, tmp_path):
    pkg = make_msext(tmp_path / "badid.msext",
                     manifest=default_manifest(ext_id="Bad ID!"))
    resp = upload_file(client, pkg)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_manifest"
    assert any("invalid extension id" in e for e in resp.json()["errors"])


def test_extension_id_metadata_mismatch_rejected(client, tmp_path):
    pkg = make_msext(tmp_path / "mismatch.msext")
    resp = upload_file(client, pkg, extension_id="com.other.thing")
    assert resp.status_code == 400
    assert any("does not match" in e for e in resp.json()["errors"])


def test_duplicate_id_version_rejected_against_repo(client, tmp_path, cfg):
    """extensions/example/1.0.0 exists in the checkout -> 409."""
    pkg = make_msext(tmp_path / "dup.msext",
                     manifest=default_manifest(ext_id="example", version="1.0.0"))
    resp = upload_file(client, pkg, filename="example-v1.0.0.msext")
    assert resp.status_code == 409
    assert resp.json()["error"] == "duplicate_version"
