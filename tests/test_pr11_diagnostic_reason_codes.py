"""PR-11 workflow diagnostic reason-code coverage matrix."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegis import AEGIS
from aegis import (
    InvocationValidationError,
    SessionStateError,
    WorkflowApprovalRequiredError,
    WorkflowParticipantMismatchError,
    WorkflowProtocolViolationError,
    WorkflowToolBudgetExceededError,
)


BASE_POLICY = """\
policy_version: "1.0"
roles: [planner]
pre_conditions:
  required:
    role_declared:
      type: boolean
output_schema:
  type: object
  required: [result]
  properties:
    result: {type: string}
"""


def _write(tmp_path: Path, name: str, extra: str = "") -> Path:
    path = tmp_path / name
    path.write_text(BASE_POLICY + extra, encoding="utf-8")
    return path


def _doctor(path: Path) -> list[dict]:
    result = subprocess.run(
        [sys.executable, "-m", "aegis", "workflow", "doctor", str(path), "--json"],
        capture_output=True,
        text=True,
    )
    assert "Traceback" not in result.stderr
    return json.loads(result.stdout)


def _assert_doctor_shape(findings: list[dict]) -> None:
    assert findings
    for finding in findings:
        assert finding["code"]
        assert finding["message"]
        assert finding["next_action"]
        assert finding["severity"] in {"INFO", "WARNING", "ERROR"}


def test_static_reason_code_matrix_has_stable_shape(tmp_path):
    cases = {
        "WORKFLOW_INVALID_TRANSITION": "workflow:\n  required_sequence: [a, b]\n  allowed_transitions:\n    a: [c]\n",
        "WORKFLOW_STEP_BUDGET_EXCEEDED": "workflow:\n  max_steps: 1\n  required_sequence: [a, b]\n",
        "WORKFLOW_UNSUPPORTED_BINDING": "workflow:\n  participants:\n    - id: p1\n      protocols: [grpc]\n",
        "WORKFLOW_SESSION_TOKEN_INVALID": "pre_conditions:\n  required:\n    session_token:\n      type: string\n",
    }
    for code, extra in cases.items():
        path = _write(tmp_path, f"{code}.yaml", extra)
        findings = _doctor(path)
        _assert_doctor_shape(findings)
        assert code in [f["code"] for f in findings]


def test_starter_integrity_reason_code(tmp_path):
    starter = tmp_path / "starter"
    starter.mkdir()
    (starter / "policy.yaml").write_text(BASE_POLICY, encoding="utf-8")
    (starter / "workflow_example.py").write_text("from aegis._internal import errors\n", encoding="utf-8")
    (starter / "README.md").write_text("# Starter\n", encoding="utf-8")
    findings = _doctor(starter)
    _assert_doctor_shape(findings)
    assert "WORKFLOW_STARTER_INTEGRITY_ERROR" in [f["code"] for f in findings]


def test_runtime_reason_codes_are_typed_exceptions(tmp_path):
    policy = _write(tmp_path, "runtime.yaml", "workflow:\n  max_total_tool_calls: 1\n")
    protocol_policy = _write(
        tmp_path,
        "protocol.yaml",
        "workflow:\n  protocol_constraints:\n    a2a: {}\n",
    )
    inv = {
        "policy_file": str(policy),
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True},
    }
    with AEGIS().open_session(policy_file=str(policy)) as session:
        session._escalation = {"require_approval_after_steps": 1}
        token = session.enforce_step_pre_call(dict(inv))
        session.enforce_step_post_call(token, {"result": "ok"})
        with pytest.raises(WorkflowApprovalRequiredError) as approval:
            session.enforce_step_pre_call(dict(inv))
        assert approval.value.code == "WORKFLOW_APPROVAL_REQUIRED"
        session.cancel()

    with pytest.raises(WorkflowToolBudgetExceededError) as budget:
        with AEGIS().open_session(policy_file=str(policy)) as session:
            too_many = dict(inv)
            too_many["tool_calls"] = [{"name": "a"}, {"name": "b"}]
            session.enforce_step_pre_call(too_many)
    assert budget.value.code == "WORKFLOW_TOOL_BUDGET_EXCEEDED"

    with pytest.raises(WorkflowProtocolViolationError):
        with AEGIS().open_session(policy_file=str(protocol_policy)) as session:
            protocol_inv = dict(inv)
            protocol_inv["policy_file"] = str(protocol_policy)
            protocol_inv["protocol"] = "a2a"
            protocol_inv["context"] = {"role_declared": True, "protocol_evidence": {"a2a": {}}}
            session.enforce_step_pre_call(protocol_inv)

    with pytest.raises(InvocationValidationError):
        with AEGIS().open_session(policy_file=str(policy)) as session:
            fake = type("Fake", (), {"session_id": "other", "_token_id": "x"})()
            session.enforce_step_post_call(fake, {"result": "ok"})  # type: ignore[arg-type]

    with pytest.raises(SessionStateError):
        with AEGIS().open_session(policy_file=str(policy)) as session:
            session.pause(approval_id="x")
            session.complete()

    with pytest.raises(WorkflowParticipantMismatchError):
        with AEGIS().open_session(policy_file=str(policy)) as session:
            session._participants_by_id = {"p1": {"id": "p1", "roles": ["planner"]}}
            session.enforce_step_pre_call(dict(inv))
