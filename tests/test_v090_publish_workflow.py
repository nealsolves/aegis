"""Static security contract for the PyPI Trusted Publishing workflow."""
from __future__ import annotations

import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
PINNED_ACTIONS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-python": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
    "actions/upload-artifact": "330a01c490aca151604b8cf639adc76d48f6c5d4",
    "actions/download-artifact": "018cc2cf5baa6db3ef3c5f8a56943fffe632ef53",
    "pypa/gh-action-pypi-publish": "cef221092ed1bacb1cc03d23a2d87d1d172e277b",
}
EXPECTED_LANES = {
    "base-wheel",
    "aws-min-wheel",
    "aws-current-wheel",
    "gcp-min-wheel",
    "gcp-current-wheel",
    "combined-current-wheel",
    "combined-current-sdist",
}


def _load_workflow() -> tuple[str, dict]:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)
    return text, workflow


def test_publish_workflow_matches_pending_trusted_publisher():
    _, workflow = _load_workflow()
    assert workflow["on"] == {"release": {"types": ["published"]}}

    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["build", "validate-optional-extras"]
    assert publish["environment"] == {
        "name": "pypi",
        "url": "https://pypi.org/p/aegis-ai-governance",
    }
    assert publish["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }


def test_publish_workflow_separates_unprivileged_build_from_oidc_publish():
    text, workflow = _load_workflow()
    build = workflow["jobs"]["build"]
    optional_validation = workflow["jobs"]["validate-optional-extras"]
    publish = workflow["jobs"]["publish"]

    assert build["permissions"] == {"contents": "read"}
    assert optional_validation["permissions"] == {"contents": "read"}
    assert "id-token" not in build["permissions"]
    assert "id-token" not in optional_validation["permissions"]
    assert all("run" not in step for step in publish["steps"])
    assert "secrets." not in text
    assert "password:" not in text


def test_build_job_proves_the_fresh_wheel_workflow_before_upload():
    _, workflow = _load_workflow()
    build_commands = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["build"]["steps"]
    )
    assert (
        "python scripts/validate_v090_distribution_candidate.py "
        "--dist-dir dist --no-build"
    ) in build_commands


def test_build_job_installs_backend_for_no_isolation_packaging_smoke():
    _, workflow = _load_workflow()
    install_step = next(
        step
        for step in workflow["jobs"]["build"]["steps"]
        if step["name"] == "Install validation and build dependencies"
    )

    assert '"setuptools"' in install_step["run"]
    assert ' -e ".[dev,aws-kms,gcp-kms]"' in install_step["run"]


def test_optional_extra_matrix_proves_exact_single_artifact_release_lanes():
    _, workflow = _load_workflow()
    validation = workflow["jobs"]["validate-optional-extras"]
    lanes = validation["strategy"]["matrix"]["include"]

    assert {entry["name"] for entry in lanes} == EXPECTED_LANES
    assert len(lanes) == len(EXPECTED_LANES)
    assert validation["needs"] == "build"

    expected_artifacts = {
        "base-wheel": "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl",
        "aws-min-wheel": "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl",
        "aws-current-wheel": "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl",
        "gcp-min-wheel": "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl",
        "gcp-current-wheel": "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl",
        "combined-current-wheel": (
            "dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl"
        ),
        "combined-current-sdist": (
            "dist/aegis_ai_governance-0.9.0b1.tar.gz"
        ),
    }
    assert {
        entry["name"]: entry["artifact"] for entry in lanes
    } == expected_artifacts
    assert {
        entry["name"]: entry["lane"] for entry in lanes
    } == {
        "base-wheel": "base",
        "aws-min-wheel": "aws",
        "aws-current-wheel": "aws",
        "gcp-min-wheel": "gcp",
        "gcp-current-wheel": "gcp",
        "combined-current-wheel": "combined",
        "combined-current-sdist": "combined",
    }
    assert next(
        entry for entry in lanes if entry["name"] == "aws-min-wheel"
    )["expected-versions"] == '{"boto3":"1.43.0"}'
    gcp_minimum = (
        '{"google-cloud-kms":"3.15.0","google-crc32c":"1.7.1",'
        '"cryptography":"45.0.1"}'
    )
    assert next(
        entry for entry in lanes if entry["name"] == "gcp-min-wheel"
    )["expected-versions"] == gcp_minimum
    assert all(
        entry["expected-versions"] == "{}"
        for entry in lanes
        if "current" in entry["name"]
    )


def test_every_optional_lane_downloads_the_build_once_and_never_rebuilds():
    _, workflow = _load_workflow()
    validation = workflow["jobs"]["validate-optional-extras"]
    download_steps = [
        step for step in validation["steps"]
        if step.get("uses", "").startswith("actions/download-artifact@")
    ]
    assert len(download_steps) == 1
    assert download_steps[0]["with"] == {
        "name": "python-package-distributions",
        "path": "dist/",
    }

    all_commands = "\n".join(
        step.get("run", "")
        for job in workflow["jobs"].values()
        for step in job["steps"]
    )
    assert all_commands.count("python -m build") == 1
    assert all_commands.count("validate_kms_optional_extras.py") == 1
    assert "aws-kms-" not in all_commands
    assert "gcp-kms-" not in all_commands


def test_build_and_optional_validation_check_out_the_exact_release_tag():
    _, workflow = _load_workflow()
    for job_name in ("build", "validate-optional-extras"):
        checkout = next(
            step for step in workflow["jobs"][job_name]["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        assert checkout["with"] == {
            "persist-credentials": "false",
            "ref": "${{ github.event.release.tag_name }}",
        }


def test_publish_workflow_pins_every_action_to_a_full_commit():
    text, _ = _load_workflow()
    uses = re.findall(r"^\s*uses:\s*([^@\s]+)@([0-9a-f]+)", text, re.MULTILINE)
    assert dict(uses) == PINNED_ACTIONS
    assert all(len(commit) == 40 for _, commit in uses)
