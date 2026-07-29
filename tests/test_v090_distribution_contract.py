"""Distribution contracts for the AEGIS v0.9.0 beta candidate."""
from __future__ import annotations

from email.parser import BytesParser
from email.policy import default
import re
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile

import aegis
import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
PYPROJECT_DATA = tomllib.loads(PYPROJECT)
PROJECT_SECTION = PYPROJECT.split("[project]", 1)[1].split(
    "[project.scripts]", 1
)[0]
EXPECTED_OPTIONAL_DEPENDENCIES = {
    "aws-kms": ["boto3>=1.43.0"],
    "gcp-kms": [
        "google-cloud-kms>=3.15.0",
        "google-crc32c>=1.7.1",
        "cryptography>=45.0.1",
    ],
}
EXPECTED_INTEGRATION_MEMBERS = {
    "aegis/integrations/__init__.py",
    "aegis/integrations/kms.py",
    "aegis/integrations/_kms_common.py",
    "aegis/integrations/aws_kms.py",
    "aegis/integrations/google_cloud_kms.py",
}


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


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dist_dir = tmp_path_factory.mktemp("kms-distribution-contract")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(dist_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = list(dist_dir.glob("*.whl"))
    assert [wheel.name for wheel in wheels] == [
        "aegis_ai_governance-0.9.0b1-py3-none-any.whl"
    ]
    return wheels[0]


def _wheel_metadata(wheel: Path):
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        )
        return BytesParser(policy=default).parsebytes(
            archive.read(metadata_name)
        )


def test_distribution_identity_is_distinct_from_import_and_cli_names():
    assert _project_scalar("name") == "aegis-ai-governance"
    assert (REPO_ROOT / "aegis" / "__init__.py").is_file()
    assert 'aegis = "aegis.cli:main"' in PYPROJECT


def test_candidate_version_is_consistent_in_metadata_and_runtime():
    assert _project_scalar("version") == "0.9.0b1"
    assert aegis.__version__ == "0.9.0b1"


def test_distribution_rename_does_not_change_runtime_dependencies():
    assert PYPROJECT_DATA["project"]["dependencies"] == [
        "PyYAML>=6.0",
        "jsonschema>=4.0",
    ]
    assert _runtime_dependencies() == {"PyYAML>=6.0", "jsonschema>=4.0"}


def test_kms_optional_extras_have_exact_unbounded_lower_bounds():
    optional = PYPROJECT_DATA["project"]["optional-dependencies"]
    assert {
        name: optional[name] for name in EXPECTED_OPTIONAL_DEPENDENCIES
    } == EXPECTED_OPTIONAL_DEPENDENCIES
    assert all(
        "<" not in requirement
        for requirements in EXPECTED_OPTIONAL_DEPENDENCIES.values()
        for requirement in requirements
    )


def test_wheel_metadata_exposes_one_distribution_with_conditional_kms_extras(
    built_wheel: Path,
):
    metadata = _wheel_metadata(built_wheel)
    assert metadata["Name"] == "aegis-ai-governance"
    assert metadata["Version"] == "0.9.0b1"
    assert {"aws-kms", "gcp-kms"}.issubset(
        set(metadata.get_all("Provides-Extra", []))
    )
    assert {
        requirement
        for requirement in metadata.get_all("Requires-Dist", [])
        if 'extra == "aws-kms"' in requirement
        or 'extra == "gcp-kms"' in requirement
    } == {
        'boto3>=1.43.0; extra == "aws-kms"',
        'google-cloud-kms>=3.15.0; extra == "gcp-kms"',
        'google-crc32c>=1.7.1; extra == "gcp-kms"',
        'cryptography>=45.0.1; extra == "gcp-kms"',
    }


def test_wheel_contains_every_kms_integration_module(built_wheel: Path):
    with zipfile.ZipFile(built_wheel) as archive:
        assert EXPECTED_INTEGRATION_MEMBERS.issubset(archive.namelist())


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
