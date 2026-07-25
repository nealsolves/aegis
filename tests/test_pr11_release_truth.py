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


def _pyproject_name() -> str:
    match = re.search(r'^name\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_runtime_metadata_matches_the_090_beta_distribution_candidate():
    assert _pyproject_name() == "aegis-ai-governance"
    assert _pyproject_version() == "0.9.0b1"
    assert aegis.__version__ == "0.9.0b1"

    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    assert "Distribution candidate: `aegis-ai-governance==0.9.0b1`" in readme
    assert "not yet published to PyPI" in readme
    assert "## [0.9.0b1] — Unreleased" in changelog
    assert "not yet published to PyPI" in changelog


def test_canonical_release_docs_identify_the_beta_candidate():
    for rel in CORE_TRUTH_DOCS:
        text = _read(rel).lower()
        assert "0.9.0b1" in text, f"{rel} must mention the package candidate"
        assert "beta" in text or "release/v0.9.0" in text, (
            f"{rel} must frame 0.9.0 as beta/release-candidate context"
        )


def test_current_public_cli_docs_use_aegis_not_aigc_commands():
    command_re = re.compile(r"\b(?:python\s+-m\s+)?aigc(?:\s|$)")
    offenders = [
        rel for rel in CURRENT_PUBLIC_DOCS if command_re.search(_read(rel).lower())
    ]
    assert offenders == []


def test_current_public_docs_use_the_new_distribution_install_name():
    legacy_install = re.compile(r"\bpip\s+install\s+[\"']?aegis(?:\[|\s|$)")
    offenders = [
        rel for rel in CURRENT_PUBLIC_DOCS if legacy_install.search(_read(rel))
    ]
    assert offenders == []

    for rel in [
        "README.md",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md",
        "docs/reference/WORKFLOW_QUICKSTART.md",
        "docs/reference/OPERATIONS_RUNBOOK.md",
    ]:
        assert "aegis-ai-governance" in _read(rel), (
            f"{rel} must identify the v0.9.0 beta distribution"
        )


def test_brand_and_version_parity_script_passes():
    result = subprocess.run(
        ["python", "scripts/check_brand_and_version_parity.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
