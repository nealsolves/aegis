"""PR-11 release truth and AEGIS naming consistency tests."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import aegis


REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_TRUTH_DOCS = [
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


def _pyproject_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_runtime_metadata_remains_033_while_source_beta_is_090():
    assert _pyproject_version() == "0.3.3"
    assert aegis.__version__ == "0.3.3"

    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    assert "Current beta line: source-only `v0.9.0`" in readme
    assert "shipped PyPI package remains `v0.3.3`" in readme
    assert "source-only `v0.9.0` beta" in changelog
    assert "published package version remains `0.3.3`" in changelog


def test_canonical_release_docs_do_not_contradict_package_version():
    for rel in CORE_TRUTH_DOCS:
        text = _read(rel).lower()
        assert "0.3.3" in text, f"{rel} must mention the shipped package baseline"
        if "0.9.0" in text:
            assert "beta" in text or "release/v0.9.0" in text, (
                f"{rel} must frame 0.9.0 as beta/source/release-candidate context"
            )


def test_current_public_cli_docs_use_aegis_not_aigc_commands():
    command_re = re.compile(r"\b(?:python\s+-m\s+)?aigc(?:\s|$)")
    offenders = [
        rel for rel in CURRENT_PUBLIC_DOCS if command_re.search(_read(rel).lower())
    ]
    assert offenders == []


def test_brand_and_version_parity_script_passes():
    result = subprocess.run(
        ["python", "scripts/check_brand_and_version_parity.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
