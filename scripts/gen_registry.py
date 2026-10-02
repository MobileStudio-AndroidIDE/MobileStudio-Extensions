#!/usr/bin/env python3
"""DEPRECATED - repository.json registry generation is no longer used.

The extension registry source of truth is now GitHub Releases:

    GET /repos/MobileStudio-AndroidIDE/MobileStudio-Extensions/releases

Extensions are published as Releases (tag: <extension-id>-v<version>, asset:
<extension-id>-v<version>.msext, body: extension.json metadata as JSON). Only
.msext assets of non-draft releases are treated as extension packages.

This script is kept as a no-op stub so that stale invocations (old CI steps,
local scripts) do not recreate repository.json. It writes nothing and exits 0.
"""

import sys

MESSAGE = (
    "gen_registry.py: DEPRECATED - repository.json is no longer used. "
    "The registry is built from GitHub Releases "
    "(GET /repos/MobileStudio-AndroidIDE/MobileStudio-Extensions/releases). "
    "Nothing generated."
)


def main():
    print(MESSAGE)
    sys.exit(0)


if __name__ == "__main__":
    main()
