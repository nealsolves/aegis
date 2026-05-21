#!/usr/bin/env python3
"""Validate the v0.9.0 source beta / 0.3.3 package release boundary."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str]) -> int:
    print("$ " + " ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=REPO_ROOT, text=True)
    return result.returncode


def main() -> int:
    checks = [
        [sys.executable, "scripts/check_brand_and_version_parity.py"],
        [sys.executable, "scripts/check_public_docs_no_internal_imports.py"],
    ]
    failed = 0
    for cmd in checks:
        failed += int(_run(cmd) != 0)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
