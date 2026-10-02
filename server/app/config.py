"""Server configuration.

All secrets are read from environment variables ONLY. Nothing in this module
writes a secret to a file, a log line, or an exception message.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_SERVER_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_REPO_DIR = _SERVER_DIR.parent

MAX_UPLOAD_BYTES_DEFAULT = 50 * 1024 * 1024   # whole .msext package
MAX_FILE_BYTES_DEFAULT = 10 * 1024 * 1024    # single file inside the package
MAX_ENTRIES_DEFAULT = 2000


def _env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return default if v is None else v.strip()


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    try:
        return float(v.strip())
    except ValueError:
        return default


@dataclass
class Config:
    # --- GitHub repository (registry source of truth = GitHub Releases) ---
    owner: str = "MobileStudio-AndroidIDE"
    repo: str = "MobileStudio-Extensions"

    # --- GitHub App (secrets come from env only, never from source) ---
    github_app_id: str = ""
    github_installation_id: str = ""
    github_private_key_pem: str = ""       # raw PEM (literal newlines or \n escapes)
    github_private_key_file: str = ""      # alternative: path to a PEM file outside the repo
    # Quick start: a Personal Access Token instead of a GitHub App (App wins when both set)
    github_token: str = ""

    # --- GitHub OAuth app for Authorization Code + PKCE (server-side secret) ---
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_redirect_uri: str = "http://localhost:8000/api/v1/auth/github/callback"
    oauth_scopes: str = "read:user"
    oauth_allowed_redirects: str = "mobilestudio://"

    # --- sessions ---
    require_auth: bool = False             # auto-enabled when oauth_client_id is set
    session_ttl_seconds: int = 7 * 24 * 3600

    # --- upload limits ---
    max_upload_bytes: int = MAX_UPLOAD_BYTES_DEFAULT
    max_file_bytes: int = MAX_FILE_BYTES_DEFAULT
    max_entries: int = MAX_ENTRIES_DEFAULT

    # --- filesystem ---
    repo_dir: Path = field(default_factory=lambda: _DEFAULT_REPO_DIR)
    data_dir: Path = field(default_factory=lambda: _SERVER_DIR / "data")

    # --- pipeline ---
    scan_timeout: int = 300
    validate_timeout: int = 120
    ci_required: bool = True
    ci_wait_timeout: int = 600
    ci_poll_interval: float = 5.0

    # --- registry (GitHub Releases) cache ---
    registry_cache_ttl: int = 60           # seconds; invalidated immediately after publish
    include_prerelease_default: bool = False

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "Config":
        oauth_id = _env("GH_CLIENT_ID")
        cfg = cls(
            owner=_env("GH_OWNER", "MobileStudio-AndroidIDE"),
            repo=_env("GH_REPO", "MobileStudio-Extensions"),
            github_app_id=_env("GH_APP_ID"),
            github_installation_id=_env("GH_INSTALLATION_ID"),
            github_private_key_pem=_env("GH_PRIVATE_KEY_PEM"),
            github_private_key_file=_env("GH_PRIVATE_KEY_FILE"),
            github_token=_env("GH_TOKEN"),
            oauth_client_id=oauth_id,
            oauth_client_secret=_env("GH_CLIENT_SECRET"),
            oauth_redirect_uri=_env("OAUTH_REDIRECT_URI",
                                    "http://localhost:8000/api/v1/auth/github/callback"),
            oauth_allowed_redirects=_env("OAUTH_ALLOWED_REDIRECTS", "mobilestudio://"),
            require_auth=_env_bool("REQUIRE_AUTH", bool(oauth_id)),
            session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 7 * 24 * 3600),
            max_upload_bytes=_env_int("MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES_DEFAULT),
            max_file_bytes=_env_int("MAX_FILE_BYTES", MAX_FILE_BYTES_DEFAULT),
            max_entries=_env_int("MAX_ENTRIES", MAX_ENTRIES_DEFAULT),
            repo_dir=Path(_env("REPO_DIR", str(_DEFAULT_REPO_DIR))),
            data_dir=Path(_env("DATA_DIR", str(_SERVER_DIR / "data"))),
            scan_timeout=_env_int("SCAN_TIMEOUT", 300),
            validate_timeout=_env_int("VALIDATE_TIMEOUT", 120),
            ci_required=_env_bool("CI_REQUIRED", True),
            ci_wait_timeout=_env_int("CI_WAIT_TIMEOUT", 600),
            ci_poll_interval=_env_float("CI_POLL_INTERVAL", 5.0),
            registry_cache_ttl=_env_int("REGISTRY_CACHE_TTL", 60),
            include_prerelease_default=_env_bool("INCLUDE_PRERELEASE_DEFAULT", False),
        )
        return cfg

    # ------------------------------------------------------------------
    @property
    def app_configured(self) -> bool:
        return bool(self.github_app_id and self.github_installation_id and self.private_key_available)

    @property
    def github_configured(self) -> bool:
        return self.app_configured or bool(self.github_token)

    @property
    def github_auth_mode(self) -> str:
        if self.app_configured:
            return "app"
        if self.github_token:
            return "token"
        return "none"

    @property
    def private_key_available(self) -> bool:
        if self.github_private_key_file:
            return Path(self.github_private_key_file).is_file()
        pem = self.github_private_key_pem
        return bool(pem) and "PRIVATE KEY" in pem

    @property
    def private_key(self) -> str:
        """Returns the PEM text. Callers must never log or serialize the result."""
        if self.github_private_key_file:
            return Path(self.github_private_key_file).read_text(encoding="utf-8")
        pem = self.github_private_key_pem
        # env vars often carry literal \n sequences
        if "\n" not in pem and "\\n" in pem:
            pem = pem.replace("\\n", "\n")
        return pem

    @property
    def oauth_configured(self) -> bool:
        return bool(self.oauth_client_id and self.oauth_client_secret)

    @property
    def full_repo_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def releases_api_url(self) -> str:
        return f"https://api.github.com/repos/{self.owner}/{self.repo}/releases"

    @property
    def web_repo_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}"

    def release_tag(self, ext_id: str, version: str) -> str:
        return f"{ext_id}-v{version}"

    def release_asset_name(self, ext_id: str, version: str) -> str:
        return f"{ext_id}-v{version}.msext"

    def release_asset_url(self, ext_id: str, version: str) -> str:
        tag = self.release_tag(ext_id, version)
        name = self.release_asset_name(ext_id, version)
        return f"{self.web_repo_url}/releases/download/{tag}/{name}"
