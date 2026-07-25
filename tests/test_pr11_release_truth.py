"""PR-11 release truth and AEGIS naming consistency tests."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import aegis
import yaml


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
    "RELEASE_GATES.md",
    "demo-app-react/public/portal.html",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
    "docs/reference/WORKFLOW_QUICKSTART.md",
    "docs/reference/WORKFLOW_CLI.md",
    "docs/reference/TROUBLESHOOTING.md",
    "docs/reference/STARTER_INDEX.md",
    "docs/reference/STARTER_RECIPES.md",
    "docs/reference/SUPPORTED_ENVIRONMENTS.md",
    "docs/reference/OPERATIONS_RUNBOOK.md",
    "docs/reference/external/OPENAI_AGENTS_ADAPTER.md",
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


def test_runtime_metadata_matches_the_090_beta_distribution_release():
    assert _pyproject_name() == "aegis-ai-governance"
    assert _pyproject_version() == "0.9.0b1"
    assert aegis.__version__ == "0.9.0b1"

    readme = _read("README.md")
    changelog = _read("CHANGELOG.md")
    assert "Distribution release: `aegis-ai-governance==0.9.0b1`" in readme
    assert "not yet published to PyPI" not in readme
    assert "## [0.9.0b1] — 2026-07-25" in changelog
    assert "not yet published to PyPI" not in changelog


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
        "demo-app-react/public/portal.html",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md",
        "docs/reference/WORKFLOW_QUICKSTART.md",
        "docs/reference/OPERATIONS_RUNBOOK.md",
    ]:
        assert "aegis-ai-governance" in _read(rel), (
            f"{rel} must identify the v0.9.0 beta distribution"
        )


def test_root_readme_identifies_main_beta_demo_and_eleven_lab_release():
    readme = _read("README.md")
    normalized = " ".join(readme.lower().split())

    assert "eleven hands-on labs" in normalized
    for lab in ("Lab 8", "Lab 9", "Lab 10", "Lab 11"):
        assert lab in readme
    assert ".github/workflows/deploy-demo-react.yml" in readme
    assert "demo-app-api/render.yaml" in readme
    assert "live from `main`" in readme
    assert "live from `develop`" not in readme


def test_prior_beta_evidence_is_archived_beneath_current_candidate_truth():
    evidence = _read("docs/releases/v0.9.0-beta-test-evidence.md")
    assert evidence.startswith("# AEGIS v0.9.0 Beta Test Evidence\n\n> Archived")
    assert "`aegis-ai-governance==0.9.0b1`" in evidence
    assert "not yet published to PyPI" in evidence


def test_current_optional_extra_guidance_uses_distribution_name():
    for rel in [
        "RELEASE_GATES.md",
        "demo-app-react/public/portal.html",
        "docs/dev/pr_context.md",
        "docs/reference/external/OPENAI_AGENTS_ADAPTER.md",
    ]:
        text = _read(rel)
        assert "aegis[openai-agents]" not in text
        assert "aegis-ai-governance[openai-agents]" in text


def test_brand_and_version_parity_script_passes():
    result = subprocess.run(
        [sys.executable, "scripts/check_brand_and_version_parity.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_doc_manifest_names_the_distribution_import_cli_and_release_status():
    manifest = yaml.safe_load(_read("doc_parity_manifest.yaml"))

    assert manifest["distribution_name"] == "aegis-ai-governance"
    assert manifest["import_package"] == "aegis"
    assert manifest["console_command"] == "aegis"
    assert manifest["version"] == "0.9.0b1"
    assert manifest["candidate_status"] == "released-beta"


def test_contribution_license_and_security_release_status_are_truthful():
    contributing = _read("CONTRIBUTING.md")
    security = _read("SECURITY.md")

    assert "Apache-2.0" in contributing
    assert "MIT License" not in contributing
    assert "0.9.0b1" in security
    assert "public beta" in security.lower()
    assert "| 0.9.0b1 | Yes (public beta)" in security
