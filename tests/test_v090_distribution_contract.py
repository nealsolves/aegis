"""Distribution contracts for the AEGIS v0.9.0 beta candidate."""
from __future__ import annotations

import re
from pathlib import Path

import aegis


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
PROJECT_SECTION = PYPROJECT.split("[project]", 1)[1].split(
    "[project.scripts]", 1
)[0]


def _project_scalar(name: str) -> str:
    match = re.search(rf'^{name}\s*=\s*"([^"]+)"$', PROJECT_SECTION, re.MULTILINE)
    assert match is not None, f"missing [project].{name}"
    return match.group(1)


def _runtime_dependencies() -> set[str]:
    match = re.search(
        r"^dependencies\s*=\s*\[(.*?)\]$",
        PROJECT_SECTION,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, "missing [project].dependencies"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def test_distribution_identity_is_distinct_from_import_and_cli_names():
    assert _project_scalar("name") == "aegis-ai-governance"
    assert (REPO_ROOT / "aegis" / "__init__.py").is_file()
    assert 'aegis = "aegis.cli:main"' in PYPROJECT


def test_candidate_version_is_consistent_in_metadata_and_runtime():
    assert _project_scalar("version") == "0.9.0b1"
    assert aegis.__version__ == "0.9.0b1"


def test_distribution_rename_does_not_change_runtime_dependencies():
    assert _runtime_dependencies() == {"PyYAML>=6.0", "jsonschema>=4.0"}


def test_development_extra_installs_the_declared_build_tool():
    dev_section = PYPROJECT.split("dev = [", 1)[1].split("]", 1)[0]
    assert '"build>=1.2"' in dev_section


def test_candidate_validator_covers_the_approved_end_to_end_gates():
    validator = (
        REPO_ROOT / "scripts" / "validate_v090_distribution_candidate.py"
    ).read_text(encoding="utf-8")
    for proof_marker in [
        '"pip", "check"',
        '"approval_checkpoints"',
        '"unresolved_checksums"',
        '"invocation_artifact_checksum"',
        '"session_id"',
    ]:
        assert proof_marker in validator


def test_optional_openai_agents_remediation_uses_distribution_name():
    source = (REPO_ROOT / "aegis" / "openai_agents_adapter.py").read_text(
        encoding="utf-8"
    )
    assert "aegis-ai-governance[openai-agents]" in source
    assert "aegis[openai-agents]" not in source
