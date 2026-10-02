# Extension Store Server

Upload/publish API for `.msext` packages. One submission runs the whole chain:

```
upload -> security_scan.py -> validate.py -> PR -> GitHub Actions -> merge
       -> draft Release -> .msext asset -> published Release
```

GitHub Releases is the registry source of truth; the server only derives the
registry from Releases (no committed index file).

## Run

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

`main.py` re-exports the FastAPI `app` built in `app/main.py`
(`uvicorn app.main:app` is equivalent).

### Render

- **Root Directory:** `server`
- **Start Command:**

```bash
uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
```

## Test

```bash
pip install -r requirements.txt
pytest            # 51 tests: upload gate, pipeline, registry, auth, github_client
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/extensions/upload` | multipart `.msext` upload -> submission |
| GET | `/api/v1/extensions/submissions/{id}` | submission status (queued/scanning/publishing/published/failed) |
| GET | `/api/v1/extensions/submissions` | recent submissions |
| GET | `/api/v1/extensions` | registry built from Releases (ETag/Last-Modified, 304 supported) |
| GET | `/api/v1/extensions/{id}` | one entry |
| GET | `/api/v1/auth/github/login` | Authorization Code + PKCE start |
| GET | `/api/v1/auth/github/callback` | code exchange (server-side secret) |
| GET | `/api/v1/auth/me` | current session |
| POST | `/api/v1/auth/logout` | end session |
| GET | `/api/v1/health` | liveness/config state (no secrets) |

## Environment variables

Secrets are read from the environment only, never from source.

| Variable | Required | Meaning |
|---|---|---|
| `GH_TOKEN` | *quick start* | Personal Access Token (repo scope) used **instead of** a GitHub App; see below |
| `GH_APP_ID` | for GitHub calls | GitHub App id |
| `GH_INSTALLATION_ID` | for GitHub calls | installation id of the App on the extensions repo |
| `GH_PRIVATE_KEY_PEM` / `GH_PRIVATE_KEY_FILE` | for GitHub calls | App private key (literal PEM, or path outside the repo) |
| `GH_CLIENT_ID` / `GH_CLIENT_SECRET` | for OAuth login | GitHub OAuth App (secret stays server-side) |
| `OAUTH_REDIRECT_URI` | no | default `http://localhost:8000/api/v1/auth/github/callback` |
| `OAUTH_ALLOWED_REDIRECTS` | no | comma-separated deep-link prefixes (default `mobilestudio://`) |
| `REQUIRE_AUTH` | no | default `true` when `GH_CLIENT_ID` is set |
| `REPO_DIR` | no | checkout of this repository (default: parent of `server/`) |
| `DATA_DIR` | no | submission state (default `server/data/`) |
| `MAX_UPLOAD_BYTES` / `MAX_FILE_BYTES` / `MAX_ENTRIES` | no | 50 MB / 10 MB / 2000 |
| `CI_REQUIRED` / `CI_WAIT_TIMEOUT` / `CI_POLL_INTERVAL` | no | Actions gate (default on / 600 s / 5 s) |
| `SCAN_TIMEOUT` / `VALIDATE_TIMEOUT` | no | script limits (300 s / 120 s) |
| `REGISTRY_CACHE_TTL` | no | registry TTL seconds (default 60; invalidated on publish) |
| `INCLUDE_PRERELEASE_DEFAULT` | no | list prereleases by default (default off) |

## GitHub auth: App (production) vs PAT (quick start)

- **GitHub App** (`GH_APP_ID` + `GH_INSTALLATION_ID` + `GH_PRIVATE_KEY_*`) —
  preferred, short-lived installation tokens, org-friendly. Wins when fully set.
- **`GH_TOKEN` (PAT quick start)** — a classic PAT with `repo` scope (or a
  fine-grained token with Contents/PRs/Checks/Metadata write) used when the App
  is not fully configured. Env only, never logged. Enough to run the whole
  pipeline today; migrate to the App later without code changes.

`GET /api/v1/health` reports the active mode as `githubAuthMode`.

## GitHub App permissions

On `MobileStudio-AndroidIDE/MobileStudio-Extensions`:

- **Contents**: read/write (branch, blobs, tree, commit)
- **Pull requests**: read/write (create, comment, merge)
- **Metadata**: read (releases, checks)
- **Checks**: read (wait for Actions validation before merge)

Releases are created through the REST API by the same App.

## Release conventions

- tag: `<extension-id>-v<version>` (e.g. `com.test.demo-v1.0.0`)
- asset: `<extension-id>-v<version>.msext` (only `.msext` assets are extensions)
- body: the `extension.json` metadata as JSON, plus `sha256`, `size`, `download`
- flow: draft Release -> upload asset -> undraft (users never see a partial Release)

## Security model

- `.msext` only; MIME is never trusted (ZIP magic + central directory checked)
- ZIP slip, symlink, entry/size limits, required members checked before disk use
- `security_scan.py` + `validate.py` gate every submission; nothing touches
  GitHub until both pass
- private key / client secret: env only, never logged, never committed, never
  sent to the app
- OAuth: Authorization Code + PKCE, verifier and token exchange stay on the
  server; the app receives only an opaque session token (JSON body or URL
  fragment `#session=...`)
