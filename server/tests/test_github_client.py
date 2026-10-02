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
