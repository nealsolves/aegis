#!/usr/bin/env python3
"""Check AEGIS brand, CLI command, and release-version parity."""
from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "doc_parity_manifest.yaml"
CANDIDATE_DISTRIBUTION = "aegis-ai-governance"
RUNTIME_VERSION = "0.9.0b1"
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


def _pyproject_name() -> str | None:
    match = re.search(r'^name\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    errors: list[str] = []
    manifest = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    repo_root_str = str(REPO_ROOT)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    aegis = importlib.import_module("aegis")

    if manifest.get("distribution_name") != CANDIDATE_DISTRIBUTION:
        errors.append(
            "doc_parity_manifest.yaml distribution_name must match the candidate"
        )
    if manifest.get("import_package") != "aegis":
        errors.append("doc_parity_manifest.yaml import_package must be aegis")
    if manifest.get("console_command") != "aegis":
        errors.append("doc_parity_manifest.yaml console_command must be aegis")
    if manifest.get("candidate_status") != "released-beta":
        errors.append(
            "doc_parity_manifest.yaml candidate_status must be released-beta"
        )
    if manifest.get("version") != RUNTIME_VERSION:
        errors.append("doc_parity_manifest.yaml version must match runtime candidate")
    if _pyproject_name() != CANDIDATE_DISTRIBUTION:
        errors.append(
            f"pyproject.toml distribution must be {CANDIDATE_DISTRIBUTION}"
        )
    if _pyproject_version() != RUNTIME_VERSION:
        errors.append(f"pyproject.toml version must be {RUNTIME_VERSION}")
    if getattr(aegis, "__version__", None) != RUNTIME_VERSION:
        errors.append(f"aegis.__version__ must be {RUNTIME_VERSION}")

    for rel in CORE_DOCS:
        text = _read(rel)
        lower = text.lower()
        if RUNTIME_VERSION not in text:
            errors.append(f"{rel} does not mention candidate runtime {RUNTIME_VERSION}")
        if "0.9.0" in text and "beta" not in lower and "release/v0.9.0" not in lower:
            errors.append(f"{rel} mentions 0.9.0 without beta/release context")

    command_re = re.compile(r"\b(?:python\s+-m\s+)?aigc(?:\s|$)", re.IGNORECASE)
    for rel in CURRENT_PUBLIC_DOCS:
        if command_re.search(_read(rel)):
            errors.append(f"{rel} contains stale aigc CLI command")

    readme = _read("README.md")
    if (
        f"Distribution release: `{CANDIDATE_DISTRIBUTION}=={RUNTIME_VERSION}`"
        not in readme
    ):
        errors.append("README.md must identify the exact distribution release")
    if "not yet published to PyPI" in readme:
        errors.append("README.md must not retain the pre-publication boundary")

    if errors:
        print("Brand/version parity failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("PASS: AEGIS brand and version parity checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
