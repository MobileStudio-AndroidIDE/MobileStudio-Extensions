"""GitHub client auth modes: GitHub App (production) vs PAT quick start."""

from __future__ import annotations

from app.config import Config
from app.github_client import GitHubClient


def test_pat_mode_is_configured_and_never_signs_a_jwt(tmp_path):
    cfg = Config(github_token="ghp_test_token")
    assert cfg.github_configured is True
    assert cfg.github_auth_mode == "token"
    client = GitHubClient(cfg)
    # static token returned directly - no HTTP, no App JWT
    assert client.installation_token() == "ghp_test_token"


def test_app_mode_wins_when_fully_configured(tmp_path):
    key_file = tmp_path / "key.pem"
    key_file.write_text("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    cfg = Config(
        github_app_id="1",
        github_installation_id="2",
        github_private_key_file=str(key_file),
        github_token="ghp_fallback",
    )
    assert cfg.app_configured is True
    assert cfg.github_configured is True
    assert cfg.github_auth_mode == "app"


def test_partial_app_config_falls_back_to_token():
    cfg = Config(github_app_id="1", github_token="ghp_fallback")
    assert cfg.app_configured is False
    assert cfg.github_auth_mode == "token"
    assert GitHubClient(cfg).installation_token() == "ghp_fallback"


def test_unconfigured_mode():
    cfg = Config()
    assert cfg.github_configured is False
    assert cfg.github_auth_mode == "none"


# ---------------------------------------------------------------------------
# Release URL construction
#
# `Config.releases_api_url` already ends in `/releases`, so every per-release
# path must be appended WITHOUT repeating it. A duplicate silently produces
# `.../releases/releases/tags/x`, which GitHub answers with 404: the update
# call fails outright, and the "does this tag already exist?" check returns
# None so duplicate versions slip through to create_release.
# ---------------------------------------------------------------------------

class _CapturingClient(GitHubClient):
    """Records every URL GitHubClient tries to hit, never touching the network."""

    def __init__(self, cfg):
        super().__init__(cfg)
        self.urls = []

    def _request(self, method, url, **kwargs):
        import httpx

        self.urls.append((method, url))
        status = 200 if method != "GET" else 404
        return httpx.Response(status, json={} if status == 200 else None, request=httpx.Request(method, url))


def test_release_urls_never_repeat_the_releases_segment():
    client = _CapturingClient(Config(github_token="ghp_test"))

    client.get_release_by_tag("com.test.demo-v1.0.0")
    client.release_exists("com.test.demo-v1.0.0")
    client.update_release(411232903, draft=False)
    client.create_release(tag="t", name="n", body="b", draft=False)

    for method, url in client.urls:
        assert "/releases/releases" not in url, f"{method} {url} duplicates /releases"


def test_release_by_tag_hits_the_canonical_github_path():
    client = _CapturingClient(Config(github_token="ghp_test", owner="acme", repo="widgets"))
    client.get_release_by_tag("demo-v1.2.3")
    (method, url), = client.urls
    assert method == "GET"
    assert url == "https://api.github.com/repos/acme/widgets/releases/tags/demo-v1.2.3"


def test_update_release_patches_the_release_resource():
    client = _CapturingClient(Config(github_token="ghp_test", owner="acme", repo="widgets"))
    client.update_release(7, draft=False)
    (method, url), = client.urls
    assert method == "PATCH"
    assert url == "https://api.github.com/repos/acme/widgets/releases/7"


def test_get_release_by_tag_treats_404_as_missing():
    client = _CapturingClient(Config(github_token="ghp_test"))
    assert client.get_release_by_tag("nope-v1.0.0") is None
    assert client.release_exists("nope-v1.0.0") is False
