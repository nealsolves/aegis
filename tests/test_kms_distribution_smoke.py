"""Behavioral contract for the installed-artifact KMS smoke validator."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "validate_kms_optional_extras.py"


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
