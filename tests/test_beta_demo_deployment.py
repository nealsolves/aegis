"""Deployment contract for the main-based public beta demo."""
from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PAGES_WORKFLOW = ROOT / ".github" / "workflows" / "deploy-demo-react.yml"
RENDER_BLUEPRINT = ROOT / "demo-app-api" / "render.yaml"

PINNED_PAGES_ACTIONS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/setup-python": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
    "actions/configure-pages": "983d7736d9b0ae728b81ab479565c72886d7745b",
    "actions/upload-pages-artifact": "7b1f4a764d45c48632c6b24a0339c27f5614fb0b",
    "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
}


def _load_pages_workflow() -> tuple[str, dict]:
    text = PAGES_WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.load(text, Loader=yaml.BaseLoader)
    assert isinstance(parsed, dict)
    return text, parsed


def test_pages_workflow_builds_and_deploys_only_the_main_beta():
    _, workflow = _load_pages_workflow()

    assert workflow["on"]["push"]["branches"] == ["main"]
    assert "develop" not in workflow["on"]["push"]["branches"]
    assert "workflow_dispatch" in workflow["on"]

    build = workflow["jobs"]["build"]
    deploy = workflow["jobs"]["deploy"]
    assert build["permissions"] == {
        "contents": "read",
        "pages": "read",
    }
    assert deploy["needs"] == "build"
    assert deploy["permissions"] == {
        "pages": "write",
        "id-token": "write",
    }
    assert deploy["environment"]["name"] == "github-pages"
    assert deploy["environment"]["url"] == "${{ steps.deployment.outputs.page_url }}"

    build_steps = {
        step["name"]: step
        for step in build["steps"]
        if isinstance(step, dict) and "name" in step
    }
    build_commands = "\n".join(
        step.get("run", "") for step in build["steps"] if isinstance(step, dict)
    )
    assert "npm ci" in build_commands
    assert "npm test" in build_commands
    assert "npm run lint" in build_commands
    assert "npm run build" in build_commands
    assert build_steps["Set up Python"]["with"] == {
        "python-version": "3.12",
    }
    assert build_steps["Check public copy"]["run"] == (
        "python scripts/check_demo_copy.py "
        "--frontend-root demo-app-react/src"
    )
    assert build_steps["Test production smoke contract"]["working-directory"] == (
        "demo-app-react"
    )
    assert build_steps["Test production smoke contract"]["run"] == (
        "npm run test:smoke"
    )
    step_names = [
        step["name"]
        for step in build["steps"]
        if isinstance(step, dict) and "name" in step
    ]
    assert step_names.index("Check public copy") < step_names.index(
        "Build frontend"
    )
    assert "env" not in build
    assert "env" not in build_steps["Test frontend"]
    assert build_steps["Require the public Render API URL"]["env"] == {
        "VITE_API_URL": "${{ vars.VITE_API_URL }}",
    }
    assert build_steps["Build frontend"]["env"] == {
        "VITE_API_URL": "${{ vars.VITE_API_URL }}",
    }


def test_pages_workflow_pins_actions_and_grants_no_secret_access():
    text, _ = _load_pages_workflow()
    uses = re.findall(r"^\s*uses:\s*([^@\s]+)@([0-9a-f]+)", text, re.MULTILINE)

    assert dict(uses) == PINNED_PAGES_ACTIONS
    assert all(len(commit) == 40 for _, commit in uses)
    assert "secrets." not in text
    assert "pull_request_target" not in text


def test_render_blueprint_deploys_the_stateless_backend_from_main():
    blueprint = yaml.safe_load(RENDER_BLUEPRINT.read_text(encoding="utf-8"))
    assert isinstance(blueprint, dict)
    assert len(blueprint["services"]) == 1

    service = blueprint["services"][0]
    assert service["type"] == "web"
    assert service["name"] == "aegis-demo-api"
    assert service["runtime"] == "python"
    assert "rootDir" not in service
    assert service["branch"] == "main"
    assert service["plan"] == "free"
    assert service["autoDeployTrigger"] == "commit"
    assert service["healthCheckPath"] == "/health"
    assert service["buildCommand"] == (
        "pip install -e . && pip install -r demo-app-api/requirements.txt"
    )
    assert service["startCommand"] == (
        "uvicorn main:app --app-dir demo-app-api --host 0.0.0.0 --port $PORT"
        " --workers 1 --no-proxy-headers"
    )
    assert service["envVars"] == [
        {"key": "PYTHON_VERSION", "value": "3.12"},
    ]
