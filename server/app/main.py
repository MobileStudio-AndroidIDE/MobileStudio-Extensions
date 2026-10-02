"""FastAPI application: upload API, submission status, Releases registry, OAuth.

Endpoints
---------
POST /api/v1/extensions/upload            multipart .msext upload -> processing
GET  /api/v1/extensions/submissions/{id}  realtime submission status
GET  /api/v1/extensions/submissions       recent submissions
GET  /api/v1/extensions                   registry built from GitHub Releases
GET  /api/v1/extensions/{id}              single extension entry
GET  /api/v1/auth/github/login            Authorization Code + PKCE start
GET  /api/v1/auth/github/callback         code exchange (server-side secret)
GET  /api/v1/auth/me                      current session
GET  /api/v1/health                       liveness/config state (no secrets)
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, Header, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .auth import AuthError, AuthManager
from .config import Config
from .github_client import GitHubClient, GitHubError
from .msext import GateError, check_package, read_manifest, sanitize_filename, save_stream
from .pipeline import run_submission
from .registry import ReleasesRegistry, SEMVER, ID_RE
from .store import Store


def create_app(
    cfg: Optional[Config] = None,
    github=None,
    auth=None,
    store: Optional[Store] = None,
    registry=None,
) -> FastAPI:
    cfg = cfg or Config.from_env()
    gh = github if github is not None else (
        GitHubClient(cfg) if cfg.github_configured else None
    )
    st = store if store is not None else Store(cfg.data_dir)
    am = auth if auth is not None else AuthManager(cfg)
    reg = registry if registry is not None else (
        ReleasesRegistry(gh, cfg) if gh is not None else None
    )

    app = FastAPI(title="MobileStudio Extension Store API", version="1.0.0")
    app.state.cfg = cfg
    app.state.github = gh
    app.state.store = st
    app.state.auth = am
    app.state.registry = reg

    # ----------------------------------------------------------- helpers
    def _session(authorization: str = Header(default="")) -> Optional[dict]:
        token = ""
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        return am.resolve(token)

    def _auth_dependency(sess: Optional[dict] = Depends(_session)) -> Optional[dict]:
        if cfg.require_auth and sess is None:
            raise AuthError("unauthorized", "GitHub login required", 401)
        return sess

    @app.exception_handler(AuthError)
    async def _auth_error(_req: Request, exc: AuthError):
        return JSONResponse(status_code=exc.status,
                            content={"error": exc.code, "message": exc.message})

    @app.exception_handler(GitHubError)
    async def _gh_error(_req: Request, exc: GitHubError):
        return JSONResponse(status_code=502,
                            content={"error": "github_error", "message": str(exc)})

    # ----------------------------------------------------------- health
    @app.get("/api/v1/health")
    def health():
        return {
            "status": "ok",
            "githubAppConfigured": cfg.app_configured,
            "githubAuthMode": cfg.github_auth_mode,
            "oauthConfigured": cfg.oauth_configured,
            "requireAuth": cfg.require_auth,
            "registrySource": "github-releases",
        }

    # ----------------------------------------------------------- upload
    @app.post("/api/v1/extensions/upload")
    async def upload(
        background_tasks: BackgroundTasks,
        file: UploadFile = File(...),
        extensionId: str = Form(default=""),
        releaseNotes: str = Form(default=""),
        _sess: Optional[dict] = Depends(_auth_dependency),
    ):
        if gh is None:
            return JSONResponse(status_code=503, content={
                "error": "github_not_configured",
                "message": "GitHub App credentials are not configured on this server",
            })

        # 1) extension + filename checks BEFORE anything is written
        try:
            filename = sanitize_filename(file.filename)
        except GateError as e:
            return JSONResponse(status_code=e.status_code, content=e.payload())

        # 2) stream to a temp dir with a hard size cap (MIME is never trusted)
        tmpdir = Path(tempfile.mkdtemp(prefix="msext-upload-"))
        target = tmpdir / filename
        try:
            save_stream(file.file, target, cfg.max_upload_bytes)
        except GateError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return JSONResponse(status_code=e.status_code, content=e.payload())

        # 3) structural package checks (real ZIP inspection)
        try:
            check_package(target, cfg)
            manifest = read_manifest(target)
        except GateError as e:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return JSONResponse(status_code=e.status_code, content=e.payload())
        except Exception as e:  # unreadable manifest etc.
            shutil.rmtree(tmpdir, ignore_errors=True)
            msg = f"cannot read extension.json: {type(e).__name__}"
            return JSONResponse(status_code=400, content={
                "error": "invalid_manifest", "message": msg, "errors": [msg]})

        # 4) manifest sanity (fast fail before any GitHub work)
        ext_id = str(manifest.get("id") or "")
        version = str(manifest.get("version") or "")
        errors = []
        if not ID_RE.match(ext_id):
            errors.append(f"invalid extension id: {ext_id!r}")
        if not SEMVER.match(version):
            errors.append(f"version is not SemVer: {version!r}")
        if extensionId and extensionId != ext_id:
            errors.append(f"extensionId metadata ({extensionId!r}) does not match "
                          f"extension.json id ({ext_id!r})")
        if errors:
            shutil.rmtree(tmpdir, ignore_errors=True)
            return JSONResponse(status_code=400, content={
                "error": "invalid_manifest", "message": errors[0], "errors": errors})

        # 5) duplicate id+version against the committed extensions/ tree
        existing = Path(cfg.repo_dir) / "extensions" / ext_id / "extension.json"
        if existing.is_file():
            try:
                cur = str(json_loads(existing.read_text(encoding="utf-8-sig")).get("version"))
            except Exception:
                cur = ""
            if cur == version:
                shutil.rmtree(tmpdir, ignore_errors=True)
                return JSONResponse(status_code=409, content={
                    "error": "duplicate_version",
                    "message": f"{ext_id} v{version} is already registered",
                    "errors": [f"duplicate version: extensions/{ext_id}/ already has v{cur}"],
                })

        size = target.stat().st_size
        sub = st.create(ext_id, version, str(target), size)
        background_tasks.add_task(
            run_submission, sub.submissionId, cfg, st, gh,
            (reg.invalidate if reg is not None else None),
        )
        return {"status": "processing", "submissionId": sub.submissionId,
                "extensionId": ext_id, "version": version}

    # ------------------------------------------------------ submissions
    @app.get("/api/v1/extensions/submissions/{submission_id}")
    def submission_detail(submission_id: str):
        sub = st.get(submission_id)
        if sub is None:
            return JSONResponse(status_code=404, content={
                "error": "not_found",
                "message": f"unknown submission: {submission_id}"})
        return sub.to_public()

    @app.get("/api/v1/extensions/submissions")
    def submission_list(limit: int = 50):
        return {"submissions": [s.to_public() for s in st.list(limit)]}

    # --------------------------------------------------------- registry
    @app.get("/api/v1/extensions")
    def list_extensions(request: Request, include_prerelease: bool = False):
        if reg is None:
            return JSONResponse(status_code=503, content={
                "error": "github_not_configured",
                "message": "registry requires GitHub App credentials"})
        status, body, headers = reg.get(
            include_prerelease=include_prerelease,
            if_none_match=request.headers.get("if-none-match"),
            if_modified_since=request.headers.get("if-modified-since"),
        )
        if status == 304:
            return Response(status_code=304, headers=headers)
        return Response(content=body, status_code=status, headers=headers,
                        media_type="application/json")

    @app.get("/api/v1/extensions/{ext_id}")
    def extension_detail(ext_id: str, include_prerelease: bool = False):
        if reg is None:
            return JSONResponse(status_code=503, content={
                "error": "github_not_configured",
                "message": "registry requires GitHub App credentials"})
        entry = reg.find(ext_id, include_prerelease=include_prerelease)
        if entry is None:
            return JSONResponse(status_code=404, content={
                "error": "not_found", "message": f"extension not found: {ext_id}"})
        return entry

    # ------------------------------------------------------------- auth
    @app.get("/api/v1/auth/github/login")
    def auth_login(redirect_to: str = ""):
        return am.start(redirect_to=redirect_to)

    @app.get("/api/v1/auth/github/callback")
    def auth_callback(code: str = "", state: str = "", error: str = ""):
        if error:
            return JSONResponse(status_code=400, content={
                "error": "oauth_denied", "message": error})
        result = am.callback(code, state)   # raises AuthError -> handler
        redirect = result.get("redirect") or ""
        if redirect:
            sep = "#" if "#" not in redirect else "&"
            target = (f"{redirect}{sep}session={result['sessionToken']}"
                      f"&expiresIn={result['expiresIn']}")
            return RedirectResponse(target, status_code=302)
        return {"sessionToken": result["sessionToken"],
                "expiresIn": result["expiresIn"]}

    @app.get("/api/v1/auth/me")
    def auth_me(authorization: str = Header(default="")):
        token = _bearer(authorization)
        return am.me(token)

    @app.post("/api/v1/auth/logout")
    def auth_logout(authorization: str = Header(default="")):
        am.logout(_bearer(authorization))
        return {"status": "ok"}

    return app


def _bearer(header: str) -> str:
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def json_loads(text: str) -> dict:
    import json
    return json.loads(text)


app = create_app()
