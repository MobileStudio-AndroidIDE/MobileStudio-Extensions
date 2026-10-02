"""GitHub OAuth login for the MobileStudio app: Authorization Code + PKCE.

Design notes
------------
* The Android app NEVER holds a client secret. It only opens the authorize URL
  returned by /api/v1/auth/github/login and finishes at the callback below.
* The client secret and the code_verifier stay on the server.
* The GitHub access token is stored server-side, keyed by an opaque session
  token; only the session token is handed to the app (as a JSON body, or in a
  URL *fragment* so it never appears in server logs).
* Sessions and states are in-memory with TTLs (restart => re-login).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Callable, Dict, List, Optional

import httpx

log = logging.getLogger("server.auth")

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
STATE_TTL = 600


class AuthError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400):
        super().__init__(code)
        self.code = code
        self.message = message or code
        self.status = status


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class AuthManager:
    def __init__(
        self,
        cfg,
        http: Optional[httpx.Client] = None,
        exchange_fn: Optional[Callable[[str, str], dict]] = None,
        user_fn: Optional[Callable[str, dict]] = None,
    ):
        self.cfg = cfg
        self._http = http
        self._states: Dict[str, dict] = {}
        self._sessions: Dict[str, dict] = {}
        self._exchange_fn = exchange_fn
        self._user_fn = user_fn

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=httpx.Timeout(15.0))
        return self._http

    # ------------------------------------------------------------------
    def start(self, redirect_to: str = "") -> dict:
        """Creates state + PKCE verifier and returns the authorize URL."""
        if not self.cfg.oauth_configured:
            raise AuthError("oauth_not_configured",
                            "server is missing GH_CLIENT_ID / GH_CLIENT_SECRET", 503)
        verifier = _b64url(secrets.token_bytes(64))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        state = secrets.token_urlsafe(32)
        self._states[state] = {
            "verifier": verifier,
            "redirect_to": redirect_to or "",
            "exp": time.time() + STATE_TTL,
        }
        self._gc()
        from urllib.parse import urlencode
        url = AUTHORIZE_URL + "?" + urlencode({
            "client_id": self.cfg.oauth_client_id,
            "redirect_uri": self.cfg.oauth_redirect_uri,
            "scope": self.cfg.oauth_scopes,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        return {"authorizeUrl": url, "state": state,
                "redirectUri": self.cfg.oauth_redirect_uri}

    def callback(self, code: str, state: str) -> dict:
        """Exchanges the code (PKCE) and creates a server-side session."""
        entry = self._states.pop(state, None)
        if entry is None or entry["exp"] < time.time():
            raise AuthError("invalid_state", "state is unknown or expired")
        if not code:
            raise AuthError("missing_code", "authorization code missing")
        if self._exchange_fn is not None:
            token_data = self._exchange_fn(code, entry["verifier"])
        else:
            token_data = self._exchange_code(code, entry["verifier"])
        access = str(token_data.get("access_token") or "")
        if not access:
            raise AuthError("exchange_failed", str(token_data.get("error_description")
                                                    or token_data.get("error")
                                                    or "no access token"))
        session = secrets.token_urlsafe(32)
        self._sessions[session] = {
            "github_token": access,          # never leaves the server
            "scopes": str(token_data.get("scope") or ""),
            "exp": time.time() + self.cfg.session_ttl_seconds,
        }
        self._gc()
        return {
            "sessionToken": session,
            "expiresIn": self.cfg.session_ttl_seconds,
            "redirect": self._allowed_redirect(entry.get("redirect_to", "")),
        }

    def resolve(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        sess = self._sessions.get(token)
        if sess is None:
            return None
        if sess["exp"] < time.time():
            self._sessions.pop(token, None)
            return None
        return sess

    def logout(self, token: Optional[str]) -> None:
        if token:
            self._sessions.pop(token, None)

    def me(self, token: str) -> dict:
        sess = self.resolve(token)
        if sess is None:
            raise AuthError("unauthorized", "invalid or expired session", 401)
        login = ""
        if self._user_fn is not None:
            try:
                login = str(self._user_fn(sess["github_token"]) or "")
            except Exception:
                login = ""
        else:
            try:
                r = self.http.get(USER_URL, headers={
                    "Authorization": f"Bearer {sess['github_token']}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "MobileStudio-Extensions-Server",
                })
                if r.status_code == 200:
                    login = str(r.json().get("login") or "")
            except Exception:
                login = ""
        return {"login": login, "scopes": sess.get("scopes", ""),
                "expiresAt": sess["exp"]}

    # ------------------------------------------------------------------
    def _exchange_code(self, code: str, verifier: str) -> dict:
        """Server-side code -> token exchange (client secret stays here)."""
        try:
            r = self.http.post(
                TOKEN_URL,
                data={
                    "client_id": self.cfg.oauth_client_id,
                    "client_secret": self.cfg.oauth_client_secret,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": self.cfg.oauth_redirect_uri,
                },
                headers={"Accept": "application/json",
                         "User-Agent": "MobileStudio-Extensions-Server"},
            )
        except httpx.HTTPError as e:
            raise AuthError("exchange_failed", f"token endpoint unreachable ({type(e).__name__})") from None
        if r.status_code != 200:
            raise AuthError("exchange_failed", f"token endpoint HTTP {r.status_code}")
        return r.json()

    def _allowed_redirect(self, redirect_to: str) -> str:
        """Open-redirect guard: only allow prefixes from OAUTH_ALLOWED_REDIRECTS."""
        if not redirect_to:
            return ""
        allowed: List[str] = [
            p.strip() for p in (self.cfg.oauth_allowed_redirects or "").split(",")
            if p.strip()
        ]
        for prefix in allowed:
            if redirect_to.startswith(prefix):
                return redirect_to
        return ""

    def _gc(self) -> None:
        now = time.time()
        for k in [k for k, v in self._states.items() if v["exp"] < now]:
            self._states.pop(k, None)
        for k in [k for k, v in self._sessions.items() if v["exp"] < now]:
            self._sessions.pop(k, None)
