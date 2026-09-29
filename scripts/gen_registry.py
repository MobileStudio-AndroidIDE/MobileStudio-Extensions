#!/usr/bin/env python3
"""Regenerates repository.json: merges extensions/*/extension.json entries into
the registry, filling missing entries. Official entries without a source folder
are preserved as-is. Registry generation step of the security pipeline."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "repository.json")
EXTENSIONS = os.path.join(ROOT, "extensions")


def main():
    reg = {"schemaVersion": "1.1.0", "name": "MobileStudio-Extensions",
           "description": "Official MobileStudio extension registry", "extensions": []}
    if os.path.isfile(REGISTRY):
        try:
            with open(REGISTRY, "r", encoding="utf-8-sig") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                reg.update({k: v for k, v in loaded.items() if k != "extensions"})
                if isinstance(loaded.get("extensions"), list):
                    reg["extensions"] = loaded["extensions"]
        except Exception:
            pass

    entries = {e.get("id"): e for e in reg["extensions"] if isinstance(e, dict) and e.get("id")}
    added = 0
    if os.path.isdir(EXTENSIONS):
        for name in sorted(os.listdir(EXTENSIONS)):
            mf = os.path.join(EXTENSIONS, name, "extension.json")
            if not os.path.isfile(mf):
                continue
            try:
                with open(mf, "r", encoding="utf-8-sig") as f:
                    m = json.load(f)
            except Exception:
                continue
            eid = m.get("id")
            if not eid or eid in entries:
                continue
            entries[eid] = m
            reg["extensions"].append(m)
            added += 1

    with open(REGISTRY, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"repository.json regenerated: {len(reg['extensions'])} entries (+{added} from folders)")
    # Report changes so the workflow can decide to commit
    if added > 0:
        sys.exit(2)  # changed
    sys.exit(0)


if __name__ == "__main__":
    main()