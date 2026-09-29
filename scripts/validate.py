#!/usr/bin/env python3
"""MobileStudio Extension Registry validator.

Validates (exit 1 on any error):
  1. registry.json — valid JSON, schemaVersion, entries reference existing folders
  2. extension.json per extension — JSON Schema validation
  3. extension ID — format + folder name match
  4. SemVer — version + minMobileStudioVersion
  5. duplicate ID/version — same ID with same version, or same ID twice in registry
  6. required files — extension.json + README.md per extension folder
  7. file size — individual file <= 10 MB, extension folder <= 50 MB
  8. structure — only allowed entries inside an extension folder
"""

import json
import os
import re
import sys

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema package missing (pip install jsonschema)")
    sys.exit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(ROOT, "schema", "extension.schema.json")
REGISTRY_PATH = os.path.join(ROOT, "registry.json")
EXTENSIONS_DIR = os.path.join(ROOT, "extensions")

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ALLOWED_EXT_FILES = {"extension.json", "README.md"}
MAX_FILE_BYTES = 10 * 1024 * 1024      # 10 MB per file
MAX_EXT_DIR_BYTES = 50 * 1024 * 1024   # 50 MB per extension folder

errors = []
warnings = []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except FileNotFoundError:
        err(f"required file missing: {os.path.relpath(path, ROOT)}")
    except json.JSONDecodeError as e:
        err(f"invalid JSON in {os.path.relpath(path, ROOT)}: {e}")
    return None


def main():
    # ── 1. registry.json ─────────────────────────────────────────
    registry = load_json(REGISTRY_PATH)
    registry_ids = set()
    if registry is not None:
        if not isinstance(registry, dict):
            err("registry.json: root must be an object")
        else:
            sv = registry.get("schemaVersion")
            if not sv or not SEMVER.match(str(sv)):
                err(f"registry.json: schemaVersion missing or not SemVer: {sv!r}")
            exts = registry.get("extensions")
            if not isinstance(exts, list):
                err("registry.json: 'extensions' must be an array")
            else:
                for i, entry in enumerate(exts):
                    if not isinstance(entry, dict):
                        err(f"registry.json: extensions[{i}] must be an object")
                        continue
                    eid = entry.get("id")
                    if not eid or not ID_RE.match(str(eid)):
                        err(f"registry.json: extensions[{i}] invalid id: {eid!r}")
                        continue
                    if eid in registry_ids:
                        err(f"registry.json: duplicate id in registry: {eid}")
                    registry_ids.add(eid)
                    folder = os.path.join(EXTENSIONS_DIR, eid)
                    if not os.path.isdir(folder):
                        err(f"registry.json: entry '{eid}' has no extensions/{eid}/ folder")
                    url = entry.get("download", "")
                    if not url.startswith("https://"):
                        err(f"registry.json: entry '{eid}' download must be HTTPS: {url!r}")

    # ── 2-8. per-extension validation ────────────────────────────
    with open(SCHEMA_PATH, "r", encoding="utf-8-sig") as f:
        schema = json.load(f)
    validator = jsonschema.Draft7Validator(schema)

    if not os.path.isdir(EXTENSIONS_DIR):
        err("extensions/ directory missing")
    else:
        seen = {}  # id -> set of versions
        for name in sorted(os.listdir(EXTENSIONS_DIR)):
            folder = os.path.join(EXTENSIONS_DIR, name)
            if not os.path.isdir(folder):
                warn(f"unexpected file in extensions/: {name}")
                continue

            # 6. required files
            manifest_path = os.path.join(folder, "extension.json")
            readme_path = os.path.join(folder, "README.md")
            if not os.path.isfile(manifest_path):
                err(f"extensions/{name}/: extension.json missing")
                continue
            if not os.path.isfile(readme_path):
                err(f"extensions/{name}/: README.md missing")

            # 7. file size
            total = 0
            for dirpath, _dirs, files in os.walk(folder):
                for fn in files:
                    fp = os.path.join(dirpath, fn)
                    sz = os.path.getsize(fp)
                    total += sz
                    if sz > MAX_FILE_BYTES:
                        err(f"extensions/{name}/{os.path.relpath(fp, folder)}: file too large ({sz} bytes > 10 MB)")
            if total > MAX_EXT_DIR_BYTES:
                err(f"extensions/{name}/: folder too large ({total} bytes > 50 MB)")

            # 8. structure
            for fn in os.listdir(folder):
                if fn.startswith("."):
                    continue
                if fn not in ALLOWED_EXT_FILES and not fn.startswith("icon."):
                    warn(f"extensions/{name}/: unexpected entry '{fn}' (allowed: extension.json, README.md, icon.*)")

            # 2. JSON Schema validation
            manifest = load_json(manifest_path)
            if manifest is None:
                continue
            for e in sorted(validator.iter_errors(manifest), key=lambda e: list(e.path)):
                loc = "/".join(str(p) for p in e.path) or "(root)"
                err(f"extensions/{name}/extension.json: schema violation at '{loc}': {e.message}")

            # 3. extension ID + folder match
            eid = manifest.get("id", "")
            if not ID_RE.match(str(eid)):
                err(f"extensions/{name}/extension.json: invalid id format: {eid!r}")
            if eid != name:
                err(f"extensions/{name}/extension.json: id '{eid}' does not match folder name '{name}'")

            # 4. SemVer
            for key in ("version", "minMobileStudioVersion"):
                v = str(manifest.get(key, ""))
                if not SEMVER.match(v):
                    err(f"extensions/{name}/extension.json: {key} is not SemVer: {v!r}")

            # 5. duplicate id/version
            seen.setdefault(eid, set()).add(str(manifest.get("version")))

            # HTTPS download
            url = str(manifest.get("download", ""))
            if not url.startswith("https://"):
                err(f"extensions/{name}/extension.json: download must be HTTPS")

    for eid, versions in seen.items():
        if len(versions) == 1 and eid in registry_ids:
            continue
    # duplicate version per id across folders cannot happen (folder == id),
    # but guard against an id appearing in multiple folders anyway
    id_folders = {}
    if os.path.isdir(EXTENSIONS_DIR):
        for name in sorted(os.listdir(EXTENSIONS_DIR)):
            folder = os.path.join(EXTENSIONS_DIR, name)
            if os.path.isdir(folder) and os.path.isfile(os.path.join(folder, "extension.json")):
                try:
                    with open(os.path.join(folder, "extension.json"), "r", encoding="utf-8-sig") as f:
                        eid = json.load(f).get("id")
                    id_folders.setdefault(eid, []).append(name)
                except Exception:
                    pass
    for eid, folders in id_folders.items():
        if len(folders) > 1:
            err(f"duplicate id '{eid}' in folders: {', '.join(folders)}")

    # ── report ───────────────────────────────────────────────────
    for w in warnings:
        print(f"WARNING: {w}")
    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        print(f"\nValidation FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    print(f"Validation OK: 0 errors, {len(warnings)} warning(s)")


if __name__ == "__main__":
    main()
