"""Shared fixtures: isolated repo checkout, config, app factory, fake GitHub."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
REAL_REPO = SERVER_DIR.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app.config import Config          # noqa: E402
from app.main import create_app        # noqa: E402

SKIP = ("__pycache__", ".git", "data")


@pytest.fixture
def repo_dir(tmp_path: Path) -> Path:
    """Isolated copy of the real repo (scripts/schema/extensions)."""
    ws = tmp_path / "repo"
    ws.mkdir()
    for name in ("scripts", "schema"):
        shutil.copytree(REAL_REPO / name, ws / name, ignore=shutil.ignore_patterns(*SKIP))
    (ws / "extensions").mkdir()
    example = REAL_REPO / "extensions" / "example"
    if example.is_dir():
        shutil.copytree(example, ws / "extensions" / "example",
                        ignore=shutil.ignore_patterns(*SKIP))
    return ws


@pytest.fixture
def cfg(repo_dir: Path, tmp_path: Path) -> Config:
    return Config(
        repo_dir=repo_dir,
        data_dir=tmp_path / "data",
        require_auth=False,
        ci_required=True,
        ci_wait_timeout=5,
        ci_poll_interval=0.05,
        scan_timeout=120,
        validate_timeout=60,
        registry_cache_ttl=0,      # refetch every call unless a test raises it
    )


@pytest.fixture
def fake_gh(cfg: Config):
    from tests.helpers import FakeGitHub
    return FakeGitHub(cfg)


@pytest.fixture
def app(cfg, fake_gh):
    return create_app(cfg=cfg, github=fake_gh)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c
