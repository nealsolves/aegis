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
APPROVED_KMS_REQUIREMENTS = [
    "boto3>=1.43.0; extra == 'aws-kms'",
    "google-cloud-kms>=3.15.0; extra == 'gcp-kms'",
    "google-crc32c>=1.7.1; extra == 'gcp-kms'",
    "cryptography>=45.0.1; extra == 'gcp-kms'",
]


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
            "PyYAML>=6.0",
            "jsonschema>=4.0",
            "build>=1.2; extra == 'dev'",
            "boto3 >= 1.43.0 ; 'aws-kms' == extra",
            "google-cloud-kms>=3.15.0;extra=='gcp-kms'",
            "google-crc32c >= 1.7.1 ; 'gcp-kms' == extra",
            "cryptography>=45.0.1; extra == 'gcp-kms'",
        ]
    )


@pytest.mark.parametrize(
    "unexpected",
    [
        "boto3>=1.43.0",
        "boto3>=1.43.0; extra == 'dev'",
        "google-cloud-kms>=3.15.0",
        "google-crc32c>=1.7.1; extra == 'aws-kms'",
        "cryptography>=46.0.0; extra == 'gcp-kms'",
    ],
)
def test_smoke_metadata_rejects_additional_provider_direct_requirements(
    unexpected: str,
):
    validator = _load_smoke_validator()

    with pytest.raises(
        validator.OptionalExtrasValidationError,
        match="installed KMS provider requirements are not exact",
    ):
        validator._validate_kms_requirement_metadata(
            [*APPROVED_KMS_REQUIREMENTS, unexpected]
        )


@pytest.mark.parametrize(
    "untrusted_requirement",
    [
        (
            "boto3 @ https://provider-token-123@example.invalid/pkg.whl; "
            "extra == 'aws-kms'"
        ),
        "boto3>=1.43.0; extra == 'provider-token-123'",
        "not a valid requirement provider-token-123",
    ],
)
def test_smoke_metadata_errors_redact_untrusted_requirement_values(
    untrusted_requirement: str,
):
    validator = _load_smoke_validator()

    with pytest.raises(validator.OptionalExtrasValidationError) as captured:
        validator._validate_kms_requirement_metadata(
            [*APPROVED_KMS_REQUIREMENTS, untrusted_requirement]
        )

    assert "provider-token-123" not in str(captured.value)


def test_smoke_report_uses_stable_artifact_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    validator = _load_smoke_validator()
    child_report = {
        "checks": ["installed-metadata"],
        "import_path": (
            "/private/tmp/aegis_kms_extra_random/venv/"
            "lib/python3.12/site-packages/aegis/__init__.py"
        ),
        "installed_versions": {},
        "provider_checks": {},
        "requires_dist": APPROVED_KMS_REQUIREMENTS,
    }

    monkeypatch.setattr(validator.venv, "create", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        validator,
        "_venv_python",
        lambda _venv_dir: Path("/isolated/venv/bin/python"),
    )
    monkeypatch.setattr(
        validator,
        "_clean_env",
        lambda _venv_dir: ({}, []),
    )
    monkeypatch.setattr(
        validator,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(child_report),
            stderr="",
        ),
    )

    artifacts = []
    for root_name in ("first-random-root", "second-random-root"):
        artifact = tmp_path / root_name / "candidate.whl"
        artifact.parent.mkdir()
        artifact.write_bytes(b"same candidate bytes")
        artifacts.append(artifact)

    reports = [
        validator._validate_artifact(artifact, "base", {})
        for artifact in artifacts
    ]

    assert reports[0] == reports[1]
    assert reports[0]["artifact_filename"] == "candidate.whl"
    assert reports[0]["import_location"] == "isolated-virtualenv"
    assert "artifact" not in reports[0]
    assert "import_path" not in reports[0]


def test_smoke_subprocess_failure_report_is_stable_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    validator = _load_smoke_validator()
    hostile_url = (
        "boto3 @ https://release-user:provider-token-123@example.invalid/"
        "boto3.whl"
    )
    reports = []
    exception_messages = []

    def fail_subprocess(command, **_kwargs):
        root = next(
            part.removesuffix("/venv/bin/python")
            for part in command
            if part.endswith("/venv/bin/python")
        )
        return subprocess.CompletedProcess(
            args=command,
            returncode=37,
            stdout=f"stdout secret={hostile_url} root={root}\n",
            stderr=f"stderr token=provider-token-123 path={root}/private\n",
        )

    monkeypatch.setattr(validator.subprocess, "run", fail_subprocess)

    for root_name in ("first-random-root", "second-random-root"):
        root = (tmp_path / root_name).resolve()
        artifact = root / "candidate.whl"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"candidate")

        def fail_validation(
            _artifact: Path,
            _lane: str,
            _expected_versions: dict[str, str],
            *,
            current_root=root,
        ):
            try:
                validator._run(
                    [
                        str(current_root / "venv/bin/python"),
                        "-m",
                        "pip",
                        "install",
                        hostile_url,
                    ],
                    cwd=current_root,
                    env={},
                    stage="install_artifact",
                )
            except validator.OptionalExtrasValidationError as error:
                exception_messages.append(str(error))
                raise

        monkeypatch.setattr(
            validator,
            "_validate_artifact",
            fail_validation,
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                str(SCRIPT),
                "--artifact",
                str(artifact),
                "--lane",
                "base",
                "--expected-versions",
                "{}",
            ],
        )

        assert validator.main() == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        reports.append(json.loads(captured.err))

    expected = {
        "category": "subprocess",
        "lane": "base",
        "return_code": 37,
        "schema_version": 1,
        "stage": "install_artifact",
        "status": "FAIL",
    }
    assert reports == [expected, expected]
    assert exception_messages == [
        "optional-extra subprocess failed",
        "optional-extra subprocess failed",
    ]
    rendered = json.dumps(reports) + " ".join(exception_messages)
    assert "provider-token-123" not in rendered
    assert "example.invalid" not in rendered
    assert str(tmp_path) not in rendered


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
