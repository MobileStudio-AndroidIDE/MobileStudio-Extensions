"""Authorization Code + PKCE: the app never sees a client secret."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from app.auth import AuthManager
from app.config import Config
from app.main import create_app
from tests.helpers import FakeGitHub


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def oauth_cfg(repo_dir, tmp_path, **kw) -> Config:
    base = dict(
        repo_dir=repo_dir,
        data_dir=tmp_path / "data-auth",
        require_auth=True,
        oauth_client_id="Iv1.testclient",
        oauth_client_secret="server-side-only-secret",
        oauth_redirect_uri="http://localhost:8000/api/v1/auth/github/callback",
        oauth_allowed_redirects="mobilestudio://",
        ci_required=False,
        registry_cache_ttl=0,
    )
    base.update(kw)
    return Config(**base)


def _app(cfg, gh, exchange_fn=None, user_fn=None):
    am = AuthManager(cfg, exchange_fn=exchange_fn, user_fn=user_fn)
    return create_app(cfg=cfg, github=gh, auth=am), am


def test_login_returns_pkce_authorize_url(client):
    # default test app has no OAuth config -> 503 (explicit, no silent failure)
    resp = client.get("/api/v1/auth/github/login")
    assert resp.status_code == 503
    assert resp.json()["error"] == "oauth_not_configured"


def test_login_flow_issues_s256_challenge(repo_dir, tmp_path):
    from fastapi.testclient import TestClient
    cfg = oauth_cfg(repo_dir, tmp_path)
    app, _ = _app(cfg, FakeGitHub(cfg))
    with TestClient(app) as c:
        resp = c.get("/api/v1/auth/github/login?redirect_to=mobilestudio://auth")
        assert resp.status_code == 200
        data = resp.json()
        parsed = urlparse(data["authorizeUrl"])
        qs = parse_qs(parsed.query)
        assert parsed.scheme == "https" and parsed.netloc == "github.com"
        assert qs["client_id"] == ["Iv1.testclient"]
        assert qs["code_challenge_method"] == ["S256"]
        assert qs["state"] == [data["state"]]
        assert "client_secret" not in data["authorizeUrl"]

        # exchange receives the verifier; it must hash to the challenge
        seen = {}

        def exchange(code, verifier):
            seen["code"] = code
            seen["verifier"] = verifier
            return {"access_token": "gho_test", "scope": "read:user"}

        am2 = AuthManager(cfg, exchange_fn=exchange, user_fn=lambda tok: "devuser")
        # replay the start call on the same manager so state/verifier match
        app2 = create_app(cfg=cfg, github=FakeGitHub(cfg), auth=am2)
        with TestClient(app2) as c2:
            start = c2.get("/api/v1/auth/github/login").json()
            challenge = parse_qs(urlparse(start["authorizeUrl"]).query)["code_challenge"][0]
            cb = c2.get(f"/api/v1/auth/github/callback?code=abc123&state={start['state']}")
            assert cb.status_code == 200, cb.text
            token = cb.json()["sessionToken"]
            assert cb.json()["expiresIn"] > 0

            me = c2.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
            assert me.status_code == 200
            assert me.json()["login"] == "devuser"
            # client secret never leaves the server
            assert "server-side-only-secret" not in me.text

        # PKCE binding: sha256(verifier) == challenge
        expected = _b64url(hashlib.sha256(seen["verifier"].encode()).digest())
        assert expected == challenge
        assert seen["code"] == "abc123"


def test_invalid_state_rejected(repo_dir, tmp_path):
    from fastapi.testclient import TestClient
    cfg = oauth_cfg(repo_dir, tmp_path)
    app, _ = _app(cfg, FakeGitHub(cfg),
                  exchange_fn=lambda c, v: {"access_token": "x"})
    with TestClient(app) as c:
        resp = c.get("/api/v1/auth/github/callback?code=x&state=bogus")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_state"


def test_redirect_allowlist_blocks_open_redirect(repo_dir, tmp_path):
    from fastapi.testclient import TestClient
    cfg = oauth_cfg(repo_dir, tmp_path)
    app, _ = _app(cfg, FakeGitHub(cfg),
                  exchange_fn=lambda c, v: {"access_token": "x"},
                  user_fn=lambda t: "dev")
    with TestClient(app) as c:
        # allowed deep link -> 302 with session in the URL fragment (not the path)
        start = c.get("/api/v1/auth/github/login?redirect_to=mobilestudio://auth").json()
        cb = c.get(f"/api/v1/auth/github/callback?code=x&state={start['state']}",
                   follow_redirects=False)
        assert cb.status_code == 302
        loc = cb.headers["location"]
        assert loc.startswith("mobilestudio://auth#session=")
        assert "session=" in loc.split("#", 1)[1]

        # evil redirect -> ignored, JSON body instead of a redirect
        start2 = c.get("/api/v1/auth/github/login?redirect_to=https://evil.example/").json()
        cb2 = c.get(f"/api/v1/auth/github/callback?code=x&state={start2['state']}")
        assert cb2.status_code == 200
        assert "sessionToken" in cb2.json()
        assert "evil.example" not in cb2.text


def test_upload_requires_login_when_auth_enabled(repo_dir, tmp_path):
    import io
    from fastapi.testclient import TestClient
    from tests.helpers import make_msext, default_manifest

    cfg = oauth_cfg(repo_dir, tmp_path)
    gh = FakeGitHub(cfg)
    am = AuthManager(cfg, exchange_fn=lambda c, v: {"access_token": "x"},
                     user_fn=lambda t: "dev")
    app = create_app(cfg=cfg, github=gh, auth=am)
    pkg = make_msext(tmp_path / "auth.msext")

    with TestClient(app) as c:
        # no session -> 401
        with open(pkg, "rb") as fh:
            denied = c.post("/api/v1/extensions/upload",
                            files={"file": ("auth.msext", fh, "application/zip")})
        assert denied.status_code == 401
        assert denied.json()["error"] == "unauthorized"

        # login, then upload with the session token
        start = c.get("/api/v1/auth/github/login").json()
        token = c.get(f"/api/v1/auth/github/callback?code=x&state={start['state']}") \
            .json()["sessionToken"]
        with open(pkg, "rb") as fh:
            ok = c.post(
                "/api/v1/extensions/upload",
                files={"file": ("auth.msext", fh, "application/zip")},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"] == "processing"


def test_health_reports_config_without_secrets(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["registrySource"] == "github-releases"
    assert "secret" not in resp.text.lower()
