#!/usr/bin/env python3
"""Check AEGIS brand, CLI command, and release-version parity."""
from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_VERSION = "0.3.3"
SOURCE_BETA = "v0.9.0"
CORE_DOCS = [
    "README.md",
    "PROJECT.md",
    "CHANGELOG.md",
    "implementation_status.md",
    "RELEASE_GATES.md",
]
CURRENT_PUBLIC_DOCS = [
    "README.md",
    "PROJECT.md",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
    "docs/reference/WORKFLOW_QUICKSTART.md",
    "docs/reference/WORKFLOW_CLI.md",
    "docs/reference/TROUBLESHOOTING.md",
    "docs/reference/STARTER_INDEX.md",
    "docs/reference/STARTER_RECIPES.md",
    "docs/reference/SUPPORTED_ENVIRONMENTS.md",
    "docs/reference/OPERATIONS_RUNBOOK.md",
]


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def _pyproject_version() -> str | None:
    match = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    errors: list[str] = []
    repo_root_str = str(REPO_ROOT)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    aegis = importlib.import_module("aegis")

    if _pyproject_version() != RUNTIME_VERSION:
        errors.append(f"pyproject.toml version must remain {RUNTIME_VERSION}")
    if getattr(aegis, "__version__", None) != RUNTIME_VERSION:
        errors.append(f"aegis.__version__ must remain {RUNTIME_VERSION}")

    for rel in CORE_DOCS:
        text = _read(rel)
        lower = text.lower()
        if RUNTIME_VERSION not in text:
            errors.append(f"{rel} does not mention shipped runtime {RUNTIME_VERSION}")
        if "0.9.0" in text and "beta" not in lower and "release/v0.9.0" not in lower:
            errors.append(f"{rel} mentions 0.9.0 without beta/release context")

    command_re = re.compile(r"\b(?:python\s+-m\s+)?aigc(?:\s|$)", re.IGNORECASE)
    for rel in CURRENT_PUBLIC_DOCS:
        if command_re.search(_read(rel)):
            errors.append(f"{rel} contains stale aigc CLI command")

    readme = _read("README.md")
    if f"source-only `{SOURCE_BETA}`" not in readme:
        errors.append("README.md must label v0.9.0 as source-only beta")
    if "shipped PyPI package remains `v0.3.3`" not in readme:
        errors.append("README.md must keep PyPI package release boundary explicit")

    if errors:
        print("Brand/version parity failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("PASS: AEGIS brand and version parity checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
