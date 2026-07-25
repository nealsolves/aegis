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


def _load_workflow() -> tuple[str, dict]:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)
    return text, workflow


def test_publish_workflow_matches_pending_trusted_publisher():
    _, workflow = _load_workflow()
    assert workflow["on"] == {"release": {"types": ["published"]}}

    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == "build"
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
    publish = workflow["jobs"]["publish"]

    assert build["permissions"] == {"contents": "read"}
    assert "id-token" not in build["permissions"]
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
    assert ' -e ".[dev]"' in install_step["run"]


def test_publish_workflow_pins_every_action_to_a_full_commit():
    text, _ = _load_workflow()
    uses = re.findall(r"^\s*uses:\s*([^@\s]+)@([0-9a-f]+)", text, re.MULTILINE)
    assert dict(uses) == PINNED_ACTIONS
    assert all(len(commit) == 40 for _, commit in uses)
