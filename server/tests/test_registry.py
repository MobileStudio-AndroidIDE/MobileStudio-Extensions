"""Registry endpoint: GitHub Releases as source of truth + ETag caching."""

from __future__ import annotations

import json

from app.main import create_app
from tests.helpers import FakeGitHub, make_asset, make_release

MSEXT = "com.test.demo-v1.0.0.msext"


def _body(ext_id="com.test.demo", version="1.0.0", **extra) -> str:
    meta = {
        "id": ext_id,
        "name": "Demo Extension",
        "version": version,
        "author": "tester",
        "description": "Demo",
        "minMobileStudioVersion": "1.0.0",
        "sha256": "a" * 64,
    }
    meta.update(extra)
    return json.dumps(meta)


def _app_with(cfg, releases):
    gh = FakeGitHub(cfg, releases=releases)
    return create_app(cfg=cfg, github=gh), gh


def test_only_msext_assets_are_extensions(client, cfg, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[MSEXT and make_asset(MSEXT, tag="com.test.demo-v1.0.0"),
                make_asset("notes.zip", tag="com.test.demo-v1.0.0"),
                make_asset("old.apk", tag="com.test.demo-v1.0.0"),
                make_asset("lib.jar", tag="com.test.demo-v1.0.0")]))
    resp = client.get("/api/v1/extensions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "github-releases"
    assert data["count"] == 1
    entry = data["extensions"][0]
    assert entry["id"] == "com.test.demo"
    assert entry["version"] == "1.0.0"
    assert entry["download"].endswith(f"/com.test.demo-v1.0.0/{MSEXT}")
    assert entry["sha256"] == "a" * 64
    assert entry["releaseUrl"]


def test_draft_releases_are_excluded(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v9.9.9", body=_body(version="9.9.9"), draft=True,
        assets=[make_asset("com.test.demo-v9.9.9.msext",
                           tag="com.test.demo-v9.9.9")]))
    resp = client.get("/api/v1/extensions")
    assert resp.json()["count"] == 0


def test_prerelease_flag_is_configurable(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v2.0.0", body=_body(version="2.0.0"), prerelease=True,
        assets=[make_asset("com.test.demo-v2.0.0.msext",
                           tag="com.test.demo-v2.0.0")]))
    default = client.get("/api/v1/extensions").json()
    assert default["count"] == 0
    with_pre = client.get("/api/v1/extensions?include_prerelease=true").json()
    assert with_pre["count"] == 1
    assert with_pre["extensions"][0]["prerelease"] is True


def test_release_without_msext_asset_is_excluded(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset("checksums.txt", tag="com.test.demo-v1.0.0")]))
    assert client.get("/api/v1/extensions").json()["count"] == 0


def test_plain_body_falls_back_to_tag_parsing(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.legacy-v1.2.3", body="Just a text release note",
        assets=[make_asset("com.test.legacy-v1.2.3.msext",
                           tag="com.test.legacy-v1.2.3")], login="legacy-dev"))
    entry = client.get("/api/v1/extensions").json()["extensions"][0]
    assert entry["id"] == "com.test.legacy"
    assert entry["version"] == "1.2.3"
    assert entry["author"] == "legacy-dev"


def test_invalid_id_in_tag_is_skipped(client, fake_gh):
    fake_gh.releases.append(make_release(
        "BAD-ID-v1.0.0", body="",
        assets=[make_asset("BAD-ID-v1.0.0.msext", tag="BAD-ID-v1.0.0")]))
    # tag fallback id "BAD-ID" fails ID_RE (uppercase)
    fake_gh.releases.append(make_release(
        "ok.ext-v1.0.0", body=_body(ext_id="ok.ext"),
        assets=[make_asset("ok.ext-v1.0.0.msext", tag="ok.ext-v1.0.0")]))
    data = client.get("/api/v1/extensions").json()
    ids = [e["id"] for e in data["extensions"]]
    assert ids == ["ok.ext"]


def test_duplicate_id_keeps_highest_version(client, fake_gh):
    for v in ("1.0.0", "1.2.0", "1.10.0"):
        fake_gh.releases.append(make_release(
            f"com.test.demo-v{v}", body=_body(version=v),
            assets=[make_asset(f"com.test.demo-v{v}.msext",
                               tag=f"com.test.demo-v{v}")]))
    data = client.get("/api/v1/extensions").json()
    assert data["count"] == 1
    assert data["extensions"][0]["version"] == "1.10.0"


def test_etag_and_304(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset(MSEXT, tag="com.test.demo-v1.0.0")]))
    first = client.get("/api/v1/extensions")
    assert first.status_code == 200
    etag = first.headers["ETag"]
    assert etag and etag.startswith('"')
    assert first.headers["Cache-Control"] == "no-cache"
    assert first.headers["X-Registry-Source"] == "github-releases"
    assert first.headers.get("Last-Modified")

    second = client.get("/api/v1/extensions", headers={"If-None-Match": etag})
    assert second.status_code == 304
    assert second.content == b""
    assert second.headers["ETag"] == etag


def test_last_modified_conditional_304(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset(MSEXT, tag="com.test.demo-v1.0.0")]))
    first = client.get("/api/v1/extensions")
    lm = first.headers["Last-Modified"]
    resp = client.get("/api/v1/extensions", headers={"If-Modified-Since": lm})
    assert resp.status_code == 304


def test_upstream_conditional_request_reduces_rate_limit(client, cfg):
    gh = FakeGitHub(cfg, releases=[make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset(MSEXT, tag="com.test.demo-v1.0.0")])])
    app = create_app(cfg=cfg, github=gh)
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        c.get("/api/v1/extensions")
        c.get("/api/v1/extensions")
    # second fetch must be conditional upstream (ttl=0 in tests)
    conditional_calls = [call for call in gh.calls
                         if call[0] == "list_releases" and call[1]]
    assert conditional_calls, gh.calls


def test_ttl_cache_skips_upstream_when_fresh(cfg):
    cfg.registry_cache_ttl = 3600
    gh = FakeGitHub(cfg, releases=[make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset(MSEXT, tag="com.test.demo-v1.0.0")])])
    app = create_app(cfg=cfg, github=gh)
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        c.get("/api/v1/extensions")
        c.get("/api/v1/extensions")
    upstream = [call for call in gh.calls if call[0] == "list_releases"]
    assert len(upstream) == 1, upstream


def test_registry_invalidated_after_publish(client, fake_gh, cfg, tmp_path):
    """Even with a warm TTL the published extension shows up immediately."""
    from tests.helpers import make_msext, upload_file
    cfg.registry_cache_ttl = 3600
    assert client.get("/api/v1/extensions").json()["count"] == 0
    pkg = make_msext(tmp_path / "demo.msext")
    resp = upload_file(client, pkg)
    assert resp.status_code == 200
    sub = client.get(f"/api/v1/extensions/submissions/{resp.json()['submissionId']}").json()
    assert sub["status"] == "published"
    data = client.get("/api/v1/extensions").json()
    assert [e["id"] for e in data["extensions"]] == ["com.test.demo"]


def test_single_extension_detail_and_404(client, fake_gh):
    fake_gh.releases.append(make_release(
        "com.test.demo-v1.0.0", body=_body(),
        assets=[make_asset(MSEXT, tag="com.test.demo-v1.0.0")]))
    ok = client.get("/api/v1/extensions/com.test.demo")
    assert ok.status_code == 200
    assert ok.json()["id"] == "com.test.demo"
    missing = client.get("/api/v1/extensions/does.not.exist")
    assert missing.status_code == 404
