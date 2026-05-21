"""PR-11 split-enforcement regression tests."""
from __future__ import annotations

import copy

import pytest

from aegis import AEGIS, CallbackAuditSink, InvocationValidationError, governed, set_audit_sink


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _pre_invocation() -> dict:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def test_split_pre_and_post_call_pass_with_gate_evidence():
    aegis = AEGIS()
    pre = aegis.enforce_pre_call(_pre_invocation())
    artifact = aegis.enforce_post_call(pre, GOOD_OUTPUT)

    assert artifact["enforcement_result"] == "PASS"
    metadata = artifact["metadata"]
    assert metadata["enforcement_mode"] == "split"
    assert "role_validation" in metadata["pre_call_gates_evaluated"]
    assert "schema_validation" in metadata["post_call_gates_evaluated"]


def test_split_phase_a_blocks_before_output_exists():
    inv = _pre_invocation()
    inv["role"] = "intruder"

    with pytest.raises(Exception) as exc_info:
        AEGIS().enforce_pre_call(inv)

    artifact = exc_info.value.audit_artifact
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["metadata"]["enforcement_mode"] == "split_pre_call_only"
    assert "post_call_gates_evaluated" not in artifact["metadata"]


def test_split_phase_b_fails_closed_on_invalid_output_and_consumes_token():
    aegis = AEGIS()
    pre = aegis.enforce_pre_call(_pre_invocation())

    with pytest.raises(Exception):
        aegis.enforce_post_call(pre, {"result": "missing confidence"})
    with pytest.raises(InvocationValidationError):
        aegis.enforce_post_call(pre, GOOD_OUTPUT)


def test_split_replay_deepcopy_token_rejected():
    aegis = AEGIS()
    pre = aegis.enforce_pre_call(_pre_invocation())
    cloned = copy.deepcopy(pre)

    aegis.enforce_post_call(pre, GOOD_OUTPUT)
    with pytest.raises(InvocationValidationError):
        aegis.enforce_post_call(cloned, GOOD_OUTPUT)


def test_split_tampered_policy_bytes_rejected():
    aegis = AEGIS()
    pre = aegis.enforce_pre_call(_pre_invocation())
    object.__setattr__(pre, "_frozen_evidence_bytes", b"{not-json")

    with pytest.raises(InvocationValidationError):
        aegis.enforce_post_call(pre, GOOD_OUTPUT)


def test_phase_b_uses_frozen_phase_a_policy_when_file_changes(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(PathLikePolicy.valid(), encoding="utf-8")
    inv = _pre_invocation()
    inv["policy_file"] = str(policy)
    aegis = AEGIS()

    pre = aegis.enforce_pre_call(inv)
    policy.write_text(PathLikePolicy.invalid_role_only(), encoding="utf-8")
    artifact = aegis.enforce_post_call(pre, GOOD_OUTPUT)

    assert artifact["enforcement_result"] == "PASS"


def test_governed_default_runs_split_before_wrapped_function():
    calls: list[str] = []
    artifacts: list[dict] = []
    set_audit_sink(CallbackAuditSink(artifacts.append))

    try:
        @governed(
            policy_file=POLICY,
            role="planner",
            model_provider="openai",
            model_identifier="gpt-4",
        )
        def model_call(input_data, context):
            calls.append("called")
            return GOOD_OUTPUT

        output = model_call(
            input_data={"query": "test"},
            context={"role_declared": True, "schema_exists": True},
        )
    finally:
        set_audit_sink(None)
    assert calls == ["called"]
    assert output == GOOD_OUTPUT
    assert artifacts[-1]["metadata"]["enforcement_mode"] == "split"


def test_governed_legacy_unified_opt_out_still_warns():
    artifacts: list[dict] = []
    set_audit_sink(CallbackAuditSink(artifacts.append))
    with pytest.warns(DeprecationWarning):

        try:
            @governed(
                policy_file=POLICY,
                role="planner",
                model_provider="openai",
                model_identifier="gpt-4",
                pre_call_enforcement=False,
            )
            def model_call(input_data, context):
                return GOOD_OUTPUT

            output = model_call(
                input_data={"query": "test"},
                context={"role_declared": True, "schema_exists": True},
            )
        finally:
            set_audit_sink(None)
    assert output == GOOD_OUTPUT
    assert artifacts[-1]["metadata"]["enforcement_mode"] == "unified"


class PathLikePolicy:
    @staticmethod
    def valid() -> str:
        return """\
policy_version: "1.0"
roles: [planner]
pre_conditions:
  required:
    role_declared:
      type: boolean
    schema_exists:
      type: boolean
post_conditions:
  required: [output_schema_valid]
output_schema:
  type: object
  required: [result, confidence]
  properties:
    result: {type: string}
    confidence: {type: number}
"""

    @staticmethod
    def invalid_role_only() -> str:
        return PathLikePolicy.valid().replace("roles: [planner]", "roles: [intruder]")
