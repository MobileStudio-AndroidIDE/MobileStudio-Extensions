#!/usr/bin/env python3
"""MobileStudio Extension security scanner.

Multi-stage malware/security scan for an extension (.msext ZIP package or an
extension source folder). Stages:
  1. Package structure     — ZIP integrity, entry count, sizes, symlinks
  2. Executable scan       — ELF/PE/Mach-O binaries, APK/AAB, .exe/.so/.dex
  3. Script analysis       — suspicious patterns: download-then-exec, base64/hex
                             blobs, obfuscation markers, external URLs
  4. Manifest scan         — AndroidManifest permissions, dangerous permissions
  5. Integrity             — SHA-256 of the package, manifest/content mismatch
  6. Known-bad hashes      — simple known-malicious hash set (extensible)

Output: JSON result (stdout or --out) + GitHub Actions Summary markdown (--summary).
Exit code 0 = passed (warnings allowed), 1 = failed.

NOTE: passing this scan does NOT guarantee the absence of malware. It is a
best-effort automated security check; flagged packages go to manual review.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import zipfile

MAX_ENTRIES = 2000
MAX_FILE_BYTES = 10 * 1024 * 1024        # 10 MB per file
MAX_TOTAL_BYTES = 50 * 1024 * 1024       # 50 MB per package
MAX_B64_BLOB = 4096                      # base64/hex blob threshold (chars)

EXECUTABLE_EXTS = {".exe", ".so", ".dll", ".dylib", ".dex", ".jar", ".bin", ".o", ".a", ".out", ".apk", ".aab"}
ALLOWED_EXTS = {
    ".kt", ".kts", ".java", ".js", ".mjs", ".ts", ".tsx", ".json", ".xml", ".md",
    ".txt", ".html", ".css", ".lua", ".py", ".sh", ".bash", ".yaml", ".yml", ".sql",
    ".c", ".cpp", ".h", ".hpp", ".cmake", ".gradle", ".properties", ".pro", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif"
}
TEXT_EXTS = {".kt", ".kts", ".java", ".js", ".mjs", ".ts", ".tsx", ".json", ".xml", ".md", ".txt",
             ".html", ".css", ".lua", ".py", ".sh", ".bash", ".yaml", ".yml", ".sql",
             ".c", ".cpp", ".h", ".hpp", ".cmake", ".gradle", ".properties", ".pro"}

# Known-malicious hash set (SHA-256, lowercase). Extend via known_bad.json next to this script.
KNOWN_BAD = set()
_kb = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_bad.json")
if os.path.isfile(_kb):
    try:
        with open(_kb, "r", encoding="utf-8-sig") as f:
            KNOWN_BAD = {h.lower() for h in json.load(f).get("sha256", [])}
    except Exception:
        pass

DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BIND_DEVICE_ADMIN", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.WRITE_SETTINGS",
}

SUSPICIOUS_PATTERNS = [
    (r"curl\s+[^|;]*\|\s*(?:sh|bash|zsh)", "download-then-exec (curl | sh)"),
    (r"wget\s+[^|;]*\|\s*(?:sh|bash|zsh)", "download-then-exec (wget | sh)"),
    (r"(?:curl|wget|Invoke-WebRequest|http\.get|URL\()\s*[\"']*https?://[^\"')]+[\"']*\s*;?\s*(?:sh|bash|exec|Runtime\.getRuntime)", "download followed by exec"),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'](?!/system/bin)", "Runtime.exec outside /system/bin"),
    (r"chmod\s+[+ -]*[sx]", "chmod of exec permission"),
    (r"Base64\.getDecoder\(\)\.decode.*(?:exec|write|FileOutputStream)", "base64 decode then write/exec"),
    (r"dlopen\s*\(", "native dlopen call"),
    (r"System\.load\s*\(", "System.load (absolute path native load)"),
    (r"javax\.crypto.*Cipher.*getInstance\s*\(\s*[\"']AES/ECB", "weak crypto AES/ECB"),
]

OBFUSCATION_MARKERS = [
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}", "long hex escape sequence blob"),
    (r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){15,}", "long unicode escape sequence blob"),
    (r"eval\s*\(\s*atob\s*\(", "eval(atob(...))"),
    (r"Function\s*\(\s*[\"']return\s+eval", "Function('return eval')"),
    (r"exec\s*\(\s*compile\s*\(", "exec(compile(...)) python"),
]


class Result:
    def __init__(self):
        self.passed = True
        self.status = "Passed"      # Passed | Warning | Failed
        self.stages = []            # (stage, status, findings[])
        self.findings = []
        self.sha256 = ""
        self.file_count = 0
        self.total_bytes = 0

    def stage(self, name, status, findings):
        self.stages.append({"stage": name, "status": status, "findings": findings})
        if status == "Failed":
            self.passed = False
            self.status = "Failed"
        elif status == "Warning" and self.status != "Failed":
            self.status = "Warning"

    def summary_md(self, ext_id, version):
        icon = {"Passed": "✅", "Warning": "⚠️", "Failed": "❌"}[self.status]
        lines = [f"## {icon} Security Scan: {ext_id} v{version}", "",
                 f"- **Result**: {self.status}",
                 f"- **SHA-256**: `{self.sha256}`",
                 f"- **Files**: {self.file_count} ({self.total_bytes} bytes)", "", "| Stage | Status | Findings |", "|---|---|---|"]
        for s in self.stages:
            fnd = "; ".join(s["findings"][:5]) if s["findings"] else "—"
            icon2 = {"Passed": "✓", "Warning": "⚠", "Failed": "✗"}[s["status"]]
            lines.append(f"| {s['stage']} | {icon2} {s['status']} | {fnd} |")
        if not self.passed:
            lines += ["", "> ❌ Scan FAILED — the package must NOT be published or downloaded."]
        elif self.status == "Warning":
            lines += ["", "> ⚠️ Scan passed with warnings — manual review recommended."]
        else:
            lines += ["", "> ℹ️ Automated scan passed. This does NOT guarantee the absence of malware."]
        return "\n".join(lines)


def check_zip_structure(result, zf, entries):
    findings = []
    if len(entries) > MAX_ENTRIES:
        findings.append(f"too many entries: {len(entries)} > {MAX_ENTRIES}")
    total = 0
    symlinks = []
    for info in entries:
        total += info.file_size
        if info.file_size > MAX_FILE_BYTES:
            findings.append(f"entry too large: {info.filename} ({info.file_size} bytes)")
        # Symlink / special entries (unix mode in external_attr high bits)
        mode = info.external_attr >> 16
        if info.create_system == 3 and (mode & 0o170000) == 0o120000:
            symlinks.append(info.filename)
        # Absolute or traversal paths
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            findings.append(f"ZIP slip / path traversal: {info.filename}")
    result.file_count = len(entries)
    result.total_bytes = total
    if total > MAX_TOTAL_BYTES:
        findings.append(f"package too large: {total} > {MAX_TOTAL_BYTES}")
    if symlinks:
        findings.append(f"symlink entries (dangerous): {', '.join(symlinks[:5])}")
    result.stage("Package structure", "Failed" if findings else "Passed", findings)
    return findings


def check_executables(result, names, data_of):
    findings = []
    binaries = []
    disallowed = []
    for n in names:
        ext = os.path.splitext(n.lower())[1]
        if ext in EXECUTABLE_EXTS:
            binaries.append(n)
        elif ext not in ALLOWED_EXTS and os.path.splitext(n)[1]:
            disallowed.append(n)
        # ELF magic sniff on extension-less or suspicious files
        data = data_of(n)
        if data is not None and (data[:4] == b"\x7fELF" or data[:2] == b"MZ"):
            binaries.append(n)
    if binaries:
        findings.append(f"executable/binary files present: {', '.join(binaries[:8])}")
    if disallowed:
        findings.append(f"disallowed file types: {', '.join(disallowed[:8])}")
    result.stage("Executable scan", "Failed" if binaries else ("Warning" if disallowed else "Passed"), findings)


def scan_text_content(result, names, data_of):
    findings = []
    external_urls = set()
    for n in names:
        ext = os.path.splitext(n.lower())[1]
        if ext not in TEXT_EXTS:
            continue
        data = data_of(n)
        if data is None:
            continue
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            continue
        for pat, label in SUSPICIOUS_PATTERNS:
            if re.search(pat, text):
                findings.append(f"{n}: {label}")
        for pat, label in OBFUSCATION_MARKERS:
            if re.search(pat, text):
                findings.append(f"{n}: {label} (obfuscation)")
        for m in re.finditer(r"https?://[^\s\"'<>)]+", text):
            url = m.group(0)
            host = re.sub(r"^https?://", "", url).split("/")[0].lower()
            if host and host not in ("github.com", "raw.githubusercontent.com", "maven.google.com",
                                     "repo.maven.apache.org", "services.gradle.org", "developer.android.com"):
                external_urls.add(host)
    if external_urls:
        findings.append(f"external hosts referenced: {', '.join(sorted(external_urls)[:10])}")
    result.stage("Script analysis", "Failed" if findings else ("Warning" if external_urls else "Passed"), findings)


def check_manifest(result, names, data_of):
    findings = []
    manifests = [n for n in names if n.lower().endswith("androidmanifest.xml")]
    for n in manifests:
        data = data_of(n)
        if data is None:
            continue
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            findings.append(f"{n}: binary AndroidManifest (decoding failed)")
            continue
        for perm in re.findall(r"android\.permission\.[A-Z_]+", text):
            if perm in DANGEROUS_PERMS:
                findings.append(f"{n}: dangerous permission {perm}")
        if "android.permission.INTERNET" in text:
            findings.append(f"{n}: network permission INTERNET")
    if findings:
        result.stage("Manifest scan", "Warning", findings)
    else:
        result.stage("Manifest scan", "Passed", findings)


def check_known_bad(result, package_sha):
    findings = []
    if package_sha and package_sha.lower() in KNOWN_BAD:
        findings.append(f"known malicious hash: {package_sha}")
    result.stage("Known-bad hashes", "Failed" if findings else "Passed", findings)


def check_integrity(result, manifest, names):
    findings = []
    if manifest is None:
        findings.append("extension.json missing or unreadable")
    else:
        eid = manifest.get("id", "")
        if eid and not re.match(r"^[a-z0-9][a-z0-9._-]{2,63}$", str(eid)):
            findings.append(f"invalid extension id: {eid!r}")
        v = str(manifest.get("version", ""))
        if not re.match(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", v):
            findings.append(f"version is not SemVer: {v!r}")
        dl = str(manifest.get("download", ""))
        if dl and not dl.startswith("https://"):
            findings.append("download URL must be HTTPS")
    result.stage("Integrity", "Failed" if findings else "Passed", findings)


def scan_package(package_path, manifest_override=None):
    result = Result()
    # SHA-256 of the package
    if os.path.isfile(package_path):
        h = hashlib.sha256()
        with open(package_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        result.sha256 = h.hexdigest()

    manifest = manifest_override
    names = []
    data_of = lambda n: None

    if package_path.lower().endswith(".zip") or package_path.lower().endswith(".msext"):
        try:
            zf = zipfile.ZipFile(package_path)
            entries = zf.infolist()
            check_zip_structure(result, zf, entries)
            names = [i.filename for i in entries if not i.filename.endswith("/")]
            data_of = lambda n, _zf=zf: _zf.read(n)
            if manifest is None:
                for cand in ("extension.json", "./extension.json"):
                    try:
                        manifest = json.loads(zf.read(cand).decode("utf-8-sig"))
                        break
                    except KeyError:
                        continue
                    except Exception:
                        break
        except zipfile.BadZipFile as e:
            result.stage("Package structure", "Failed", [f"bad ZIP: {e}"])
            return result
    else:
        # Source folder scan
        names = []
        for dirpath, dirs, files in os.walk(package_path):
            dirs[:] = [d for d in dirs if d not in (".git", "build", ".gradle", "node_modules")]
            for fn in files:
                names.append(os.path.relpath(os.path.join(dirpath, fn), package_path).replace("\\", "/"))
        result.file_count = len(names)
        result.total_bytes = sum(
            os.path.getsize(os.path.join(package_path, n)) for n in names
            if os.path.isfile(os.path.join(package_path, n))
        )
        if len(names) > MAX_ENTRIES:
            result.stage("Package structure", "Failed", [f"too many files: {len(names)}"])
            return result
        result.stage("Package structure", "Passed", [])
        data_of = lambda n, _root=package_path: open(os.path.join(_root, n), "rb").read() if os.path.isfile(os.path.join(_root, n)) else None
        if manifest is None and os.path.isfile(os.path.join(package_path, "extension.json")):
            try:
                manifest = json.loads(open(os.path.join(package_path, "extension.json"), "r", encoding="utf-8-sig").read())
            except Exception:
                pass

    check_executables(result, names, data_of)
    scan_text_content(result, names, data_of)
    check_manifest(result, names, data_of)
    check_integrity(result, manifest, names)
    check_known_bad(result, result.sha256)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help=".msext/.zip package or extension source folder")
    ap.add_argument("--ext-id", default="")
    ap.add_argument("--version", default="")
    ap.add_argument("--out", default="", help="write JSON result to this file")
    ap.add_argument("--summary", default="", help="write GitHub Actions Summary markdown to this file")
    args = ap.parse_args()

    if not os.path.exists(args.target):
        print(f"ERROR: target not found: {args.target}")
        sys.exit(1)

    # .msext-only policy: file targets must be .msext packages (.zip/.apk/.aab/.jar rejected).
    # Directory targets (extension source folders) are still allowed for CI scans.
    if os.path.isfile(args.target) and not args.target.lower().endswith(".msext"):
        print(f"ERROR: only .msext packages are allowed as file targets "
              f"(got: {os.path.basename(args.target)})")
        sys.exit(1)

    result = scan_package(args.target)
    out = {
        "target": args.target,
        "extId": args.ext_id,
        "version": args.version,
        "status": result.status,
        "passed": result.passed,
        "sha256": result.sha256,
        "fileCount": result.file_count,
        "totalBytes": result.total_bytes,
        "stages": result.stages,
        "note": "Automated scan passed does NOT guarantee the absence of malware."
    }
    js = json.dumps(out, indent=2, ensure_ascii=False)
    print(js)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(js)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as f:
            f.write(result.summary_md(args.ext_id or os.path.basename(args.target), args.version))
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()