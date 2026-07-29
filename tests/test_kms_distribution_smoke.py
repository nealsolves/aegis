"""Behavioral contract for the installed-artifact KMS smoke validator."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "validate_kms_optional_extras.py"


def _load_smoke_validator():
    spec = importlib.util.spec_from_file_location(
        "task7_kms_smoke_validator",
        SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smoke_validator_exposes_the_release_lane_cli():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "--artifact" in result.stdout
    assert "--lane {base,aws,gcp,combined}" in result.stdout
    assert "--expected-versions" in result.stdout


def test_smoke_validator_rejects_non_object_version_contract(tmp_path: Path):
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"not used for invalid arguments")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--artifact",
            str(artifact),
            "--lane",
            "base",
            "--expected-versions",
            json.dumps(["boto3==1.43.0"]),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "expected versions must be a JSON object" in result.stderr


def test_smoke_metadata_accepts_semantically_equivalent_extra_markers():
    validator = _load_smoke_validator()

    validator._validate_kms_requirement_metadata(
        [
            "boto3 >= 1.43.0 ; 'aws-kms' == extra",
            "google-cloud-kms>=3.15.0;extra=='gcp-kms'",
            "google-crc32c >= 1.7.1 ; 'gcp-kms' == extra",
            "cryptography>=45.0.1; extra == 'gcp-kms'",
        ]
    )


@pytest.mark.parametrize(
    ("lane", "installed", "forbidden"),
    [
        (
            "base",
            {"aegis-ai-governance": "0.9.0b1", "botocore": "1.43.58"},
            "botocore",
        ),
        (
            "aws",
            {"boto3": "1.43.58", "google-auth": "2.56.2"},
            "google-auth",
        ),
        (
            "gcp",
            {"google-cloud-kms": "3.16.0", "s3transfer": "0.19.2"},
            "s3transfer",
        ),
    ],
)
def test_lane_isolation_rejects_opposite_provider_transitive_stacks(
    lane: str,
    installed: dict[str, str],
    forbidden: str,
):
    validator = _load_smoke_validator()

    with pytest.raises(
        validator.OptionalExtrasValidationError,
        match=rf"{lane} lane contains forbidden provider distributions: "
        rf"\['{forbidden}'\]",
    ):
        validator._validate_provider_family_isolation(lane, installed)
