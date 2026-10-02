"""Publish pipeline.

    upload -> queued -> scanning (security_scan.py + validate.py + duplicate
    checks) -> publishing (branch -> commit -> PR -> wait GitHub Actions ->
    merge -> draft Release -> .msext asset -> publish Release) -> published

Nothing touches GitHub until every local check has passed, and the extension
only becomes visible in the registry (GitHub Releases) after the Release asset
upload succeeded, so a failed submission can never reach users.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional

from . import msext
from .store import Submission, Store

SKIP_DIRS = {"__pycache__", ".git", "build", ".gradle"}


def _run(cmd: List[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _build_workspace(cfg, ws: Path) -> None:
    """Copy the pieces validate.py needs (scripts, schema, extensions/)."""
    repo_dir = Path(cfg.repo_dir)
    for name in ("scripts", "schema"):
        src = repo_dir / name
        if not src.is_dir():
            raise RuntimeError(f"repo checkout is missing {name}/ (set REPO_DIR)")
        shutil.copytree(src, ws / name, ignore=shutil.ignore_patterns(*SKIP_DIRS),
                        dirs_exist_ok=True)
    ext_src = repo_dir / "extensions"
    (ws / "extensions").mkdir(parents=True, exist_ok=True)
    if ext_src.is_dir():
        shutil.copytree(ext_src, ws / "extensions", ignore=shutil.ignore_patterns(*SKIP_DIRS),
                        dirs_exist_ok=True)


def _scan_errors(scan: dict, proc: subprocess.CompletedProcess) -> List[str]:
    errs: List[str] = []
    for stage in scan.get("stages", []) or []:
        if stage.get("status") == "Failed":
            for finding in stage.get("findings", []) or []:
                errs.append(f"{stage.get('stage', 'scan')}: {finding}")
    if not errs:
        for line in (proc.stdout or "").splitlines():
            if line.startswith("ERROR"):
                errs.append(line)
    if not errs:
        errs = [f"security scan failed (exit {proc.returncode})"]
    return errs[:50]


def _validate_errors(stdout: str, returncode: int) -> List[str]:
    errs = [line[len("ERROR: "):] if line.startswith("ERROR: ") else line
            for line in (stdout or "").splitlines() if line.startswith("ERROR")]
    if not errs:
        errs = [f"validate.py failed (exit {returncode})"]
    return errs[:50]


def run_submission(
    submission_id: str,
    cfg,
    store: Store,
    gh,
    on_published: Optional[Callable[[], None]] = None,
) -> None:
    """Worker entry point (runs in a threadpool). Never raises."""
    sub = store.get(submission_id)
    if sub is None:
        return
    tmp = Path(tempfile.mkdtemp(prefix="msext-"))
    try:
        _process(sub, cfg, store, gh, tmp, on_published)
    except msext.GateError as e:
        sub.fail(*e.errors)
    except subprocess.TimeoutExpired:
        sub.fail("internal error: validation timed out")
    except Exception as e:  # noqa: BLE001 - surface, never crash the worker
        sub.fail(f"internal error: {type(e).__name__}: {e}")
    finally:
        if sub.packagePath:
            Path(sub.packagePath).unlink(missing_ok=True)
            sub.packagePath = ""
        shutil.rmtree(tmp, ignore_errors=True)
        store.save(sub)


def _process(sub, cfg, store, gh, tmp: Path, on_published) -> None:
    pkg = Path(sub.packagePath)

    # ---------------------------------------------------------- 1. scanning
    sub.status = "scanning"
    sub.event("scanning: running scripts/security_scan.py")
    store.save(sub)

    scan_out = tmp / "scan.json"
    cmd = [
        sys.executable, str(Path(cfg.repo_dir) / "scripts" / "security_scan.py"),
        str(pkg),
        "--ext-id", sub.extensionId,
        "--version", sub.version,
        "--out", str(scan_out),
        "--summary", str(tmp / "scan-summary.md"),
    ]
    proc = _run(cmd, Path(cfg.repo_dir), cfg.scan_timeout)
    scan = {}
    if scan_out.is_file():
        try:
            scan = json.loads(scan_out.read_text(encoding="utf-8"))
        except Exception:
            scan = {}
    sub.scan = {
        "status": scan.get("status", "Failed"),
        "sha256": scan.get("sha256", ""),
        "stages": scan.get("stages", []),
        "note": scan.get("note", ""),
    }
    sub.sha256 = scan.get("sha256", "") or sub.sha256
    if proc.returncode != 0 or not scan.get("passed"):
        sub.fail(*_scan_errors(scan, proc))
        store.save(sub)
        return
    sub.event("security scan passed")
    store.save(sub)

    # -------------------------------------------- 2. stage + validate.py
    if not msext.ID_RE.match(sub.extensionId):
        sub.fail(f"invalid extension id: {sub.extensionId!r}")
        store.save(sub)
        return

    ws = tmp / "workspace"
    _build_workspace(cfg, ws)

    folder = ws / "extensions" / sub.extensionId
    existing_version = None
    manifest_path = folder / "extension.json"
    if manifest_path.is_file():
        try:
            existing_version = str(
                json.loads(manifest_path.read_text(encoding="utf-8-sig")).get("version")
            )
        except Exception:
            existing_version = None
    if existing_version == sub.version:
        sub.fail(f"duplicate version: {sub.extensionId} v{sub.version} "
                 f"already registered in extensions/{sub.extensionId}/")
        store.save(sub)
        return

    sub.event("staging workspace + running scripts/validate.py")
    store.save(sub)
    if folder.exists():
        shutil.rmtree(folder)
    msext.safe_extract(pkg, folder)

    # rewrite distribution fields so the manifest points at the Release asset
    manifest = json.loads((folder / "extension.json").read_text(encoding="utf-8-sig"))
    if manifest.get("id") != sub.extensionId or str(manifest.get("version")) != sub.version:
        sub.fail("extension.json id/version does not match the uploaded package")
        store.save(sub)
        return
    manifest["download"] = cfg.release_asset_url(sub.extensionId, sub.version)
    manifest["size"] = int(pkg.stat().st_size)
    manifest["sha256"] = sub.sha256
    (folder / "extension.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    vproc = _run([sys.executable, str(ws / "scripts" / "validate.py")], ws, cfg.validate_timeout)
    if vproc.returncode != 0:
        sub.fail(*_validate_errors(vproc.stdout, vproc.returncode))
        store.save(sub)
        return
    sub.event("validate.py passed")
    store.save(sub)

    # ------------------------------------------------------- 3. publishing
    if gh is None:
        sub.fail("GitHub App is not configured on the server "
                 "(GH_APP_ID / GH_INSTALLATION_ID / GH_PRIVATE_KEY_*)")
        store.save(sub)
        return

    sub.status = "publishing"
    sub.event("publishing: branch -> PR -> Actions -> merge -> Release")
    store.save(sub)

    if not _publish(sub, cfg, gh, ws, manifest, pkg, store):
        store.save(sub)
        return

    sub.status = "published"
    sub.event(f"published: {sub.downloadUrl}")
    store.save(sub)
    if on_published is not None:
        try:
            on_published()
        except Exception:
            pass


def _publish(sub, cfg, gh, ws: Path, manifest: dict, pkg: Path, store: Store) -> None:
    tag = cfg.release_tag(sub.extensionId, sub.version)
    if gh.release_exists(tag):
        sub.fail(f"duplicate version: Release tag {tag} already exists")
        store.save(sub)
        return False

    main_sha = gh.get_branch_sha("main")
    branch = f"ext/{tag}"
    try:
        gh.get_branch_sha(branch)
    except Exception:
        pass  # 404 = branch does not exist yet (the normal case)
    else:
        sub.fail(f"branch already exists: {branch} (delete it and re-upload)")
        store.save(sub)
        return False

    # commit extensions/<id>/**
    entries = []
    ext_root = ws / "extensions" / sub.extensionId
    for rel, abs_path in msext.iter_package_files(ext_root):
        blob_sha = gh.create_blob(abs_path.read_bytes())
        entries.append({
            "path": f"extensions/{sub.extensionId}/{rel}",
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
        })
    base_tree = gh.get_commit_tree(main_sha)
    tree_sha = gh.create_tree(base_tree, entries)
    commit_sha = gh.create_commit(
        f"Add extension {sub.extensionId} v{sub.version}", tree_sha, [main_sha]
    )
    gh.create_branch(branch, commit_sha)

    pr = gh.create_pr(
        head=branch,
        base="main",
        title=f"Add extension: {sub.extensionId} v{sub.version}",
        body=(f"Automated submission from the MobileStudio upload API.\n\n"
              f"- extension: `{sub.extensionId}` v{sub.version}\n"
              f"- sha256: `{sub.sha256}`\n"
              f"- submission: `{sub.submissionId}`\n\n"
              f"Security scan + validate.py already passed server-side; "
              f"GitHub Actions re-validates before merge."),
    )
    sub.prUrl = pr.get("html_url", "")
    sub.branch = branch
    sub.event(f"pull request created: {sub.prUrl}")
    store.save(sub)

    if cfg.ci_required:
        state = gh.wait_for_checks(commit_sha, cfg.ci_wait_timeout, cfg.ci_poll_interval)
        if state == "failure":
            try:
                gh.pr_comment(pr["number"],
                              "❌ GitHub Actions validation failed — this submission was "
                              "rejected and will not be published.")
            except Exception:
                pass
            sub.fail("GitHub Actions checks failed (see PR checks)")
            return False
        if state == "timeout":
            sub.fail(f"GitHub Actions checks did not finish within {cfg.ci_wait_timeout}s")
            return False
    sub.event("GitHub Actions checks passed; merging PR")
    store.save(sub)

    if not gh.merge_pr(pr["number"], commit_sha):
        sub.fail("pull request merge failed")
        store.save(sub)
        return False
    try:
        gh.delete_branch(branch)
    except Exception:
        pass  # branch cleanup is best effort

    # Release: draft -> asset -> published (users only see complete releases)
    release = gh.create_release(
        tag=tag,
        name=f"{manifest.get('name', sub.extensionId)} v{sub.version}",
        body=json.dumps(manifest, indent=2, ensure_ascii=False),
        target_commitish="main",
        draft=True,
        prerelease=bool(manifest.get("prerelease")),
    )
    gh.upload_asset(
        release["upload_url"],
        cfg.release_asset_name(sub.extensionId, sub.version),
        pkg.read_bytes(),
        "application/zip",
    )
    gh.update_release(release["id"], draft=False)

    sub.releaseUrl = release.get("html_url", "") or \
        f"{cfg.web_repo_url}/releases/tag/{tag}"
    sub.downloadUrl = cfg.release_asset_url(sub.extensionId, sub.version)
    sub.event("release published with .msext asset")
    return True
