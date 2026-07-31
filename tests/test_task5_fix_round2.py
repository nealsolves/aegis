"""Security regressions for the Task 5 independent-review second fix round."""

from __future__ import annotations

import pytest

from aegis._internal.enforcement import AEGIS
from aegis._internal.errors import (
    InvocationValidationError,
    PolicyValidationError,
)


_PINNED_POLICY = "tests/golden_replays/golden_policy_v1.yaml"
_NO_PRECONDITIONS_POLICY = "tests/fixtures/no_preconditions_policy.yaml"


def _step_invocation() -> dict:
    return {
        "policy_file": _PINNED_POLICY,
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def test_pinned_session_rejects_output_in_pre_call_with_failure_artifact() -> None:
    """Removing pre-call validation must not admit a completed invocation."""
    governance = AEGIS()
    invocation = _step_invocation()
    invocation["output"] = {"result": "must-not-enter-phase-a"}

    with governance.open_session(policy_file=_PINNED_POLICY) as session:
        pinned = session._compiled_policy
        with pytest.raises(InvocationValidationError) as raised:
            session.enforce_step_pre_call(invocation)

        assert raised.value.code == "INVOCATION_VALIDATION_ERROR"
        assert raised.value.details == {"field": "output"}
        assert raised.value.audit_artifact["enforcement_result"] == "FAIL"
        assert raised.value.audit_artifact["failure_gate"] == (
            "invocation_validation"
        )
        assert raised.value.audit_artifact["metadata"]["enforcement_mode"] == (
            "split_pre_call_only"
        )
        assert session._compiled_policy is pinned
        session.cancel()


def test_strict_pinned_session_rejects_policy_without_preconditions() -> None:
    """Bypassing strict validation must not weaken a pinned session policy."""
    governance = AEGIS(strict_mode=True)
    invocation = _step_invocation()
    invocation["policy_file"] = _NO_PRECONDITIONS_POLICY
    invocation["context"] = {}

    with governance.open_session(
        policy_file=_NO_PRECONDITIONS_POLICY,
    ) as session:
        pinned = session._compiled_policy
        with pytest.raises(PolicyValidationError) as raised:
            session.enforce_step_pre_call(invocation)

        assert raised.value.code == "POLICY_SCHEMA_VALIDATION_ERROR"
        assert raised.value.details == {
            "issues": ["Policy must define 'pre_conditions.required'"],
        }
        assert raised.value.audit_artifact["enforcement_result"] == "FAIL"
        assert raised.value.audit_artifact["failure_gate"] == (
            "invocation_validation"
        )
        assert raised.value.audit_artifact["metadata"]["enforcement_mode"] == (
            "split_pre_call_only"
        )
        assert session._compiled_policy is pinned
        session.cancel()
