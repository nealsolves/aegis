"""CI contracts for the maintained evidence-claims guard."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
GUARD_COMMAND = "python scripts/check_evidence_claims.py"
CHECKOUT_ACTION = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
NODE_ACTION = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
PYTHON_ACTION = "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"


def _workflow(relative_path: str) -> dict:
    """Load a workflow without YAML 1.1 coercing keys such as ``on``."""
    return yaml.load(
        (ROOT / relative_path).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def _step_index(steps: list[dict], predicate) -> int:
    for index, step in enumerate(steps):
        if predicate(step):
            return index
    raise AssertionError("Expected workflow step was not found")


def _run_step_index(steps: list[dict], command: str) -> int:
    return _step_index(steps, lambda step: command in step.get("run", ""))


def _setup_node_index(steps: list[dict]) -> int:
    return _step_index(steps, lambda step: step.get("uses") == NODE_ACTION)


def _setup_python_index(steps: list[dict]) -> int:
    return _step_index(steps, lambda step: step.get("uses") == PYTHON_ACTION)


def test_claims_guard_is_wired_into_all_required_workflows():
    security = _workflow(".github/workflows/security-boundaries.yml")
    publish = _workflow(".github/workflows/publish.yml")
    demo = _workflow(".github/workflows/deploy-demo-react.yml")

    evidence_claims = security["jobs"]["evidence-claims"]
    assert evidence_claims["runs-on"] == "ubuntu-latest"
    assert "strategy" not in evidence_claims
    security_steps = evidence_claims["steps"]
    assert security_steps[0]["uses"] == CHECKOUT_ACTION
    assert security_steps[0]["with"]["persist-credentials"] == "false"
    security_node = _setup_node_index(security_steps)
    assert security_steps[security_node]["with"]["node-version"] == "24"
    assert _setup_python_index(security_steps) < security_node
    assert _run_step_index(
        security_steps, 'python -m pip install -e ".[dev]"'
    ) < _run_step_index(security_steps, "npm ci") < _run_step_index(
        security_steps, GUARD_COMMAND
    )
    npm_step = security_steps[_run_step_index(security_steps, "npm ci")]
    assert npm_step["working-directory"] == "demo-app-react"

    release_steps = publish["jobs"]["build"]["steps"]
    release_node = _setup_node_index(release_steps)
    assert release_steps[release_node]["with"]["node-version"] == "24"
    assert _setup_python_index(release_steps) < release_node
    release_python_dependencies = _run_step_index(
        release_steps, '-e ".[dev,aws-kms,gcp-kms]"'
    )
    release_npm = _run_step_index(release_steps, "npm ci")
    release_validation = _run_step_index(release_steps, GUARD_COMMAND)
    assert release_python_dependencies < release_npm < release_validation
    assert release_steps[release_npm]["working-directory"] == "demo-app-react"
    assert release_steps[release_validation]["name"] == "Run release validation"

    demo_steps = demo["jobs"]["build"]["steps"]
    demo_node = _setup_node_index(demo_steps)
    assert demo_steps[demo_node]["with"]["node-version"] == "24"
    python_dependencies = _run_step_index(
        demo_steps, 'python -m pip install -e ".[dev]"'
    )
    demo_npm = _run_step_index(demo_steps, "npm ci")
    assert _setup_python_index(demo_steps) < python_dependencies < demo_npm
    assert demo_steps[demo_npm]["working-directory"] == "demo-app-react"
    demo_copy = _run_step_index(demo_steps, "python scripts/check_demo_copy.py")
    demo_guard = _run_step_index(demo_steps, GUARD_COMMAND)
    assert demo_guard == demo_copy + 1
