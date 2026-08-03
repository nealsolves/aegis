"""Opaque public PreCallResult handle contract tests."""

from __future__ import annotations

import os
from dataclasses import FrozenInstanceError, fields

import pytest

from aegis._internal.enforcement import (
    PreCallResult,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import InvocationValidationError


def _pre_call_invocation() -> dict[str, object]:
    return {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _valid_output() -> dict[str, object]:
    return {"result": "test output", "confidence": 0.95}


def test_precall_result_contains_only_opaque_identity_and_binding_fields():
    handle = enforce_pre_call(_pre_call_invocation())

    assert {field.name for field in fields(handle)} == {
        "operation_id",
        "issuer_id",
        "process_id",
        "correlation_id",
        "policy_digest",
        "canonicalization_profile",
    }
    assert handle.operation_id
    assert handle.issuer_id
    assert handle.process_id == os.getpid()
    assert handle.correlation_id
    assert handle.policy_digest
    assert handle.canonicalization_profile == "aegis-json-v2"


def test_precall_result_contains_no_authorization_state():
    handle = enforce_pre_call(_pre_call_invocation())
    forbidden = {
        "effective_policy",
        "resolved_guards",
        "resolved_conditions",
        "phase_a_metadata",
        "invocation_snapshot",
        "policy_file",
        "model_provider",
        "model_identifier",
        "role",
        "_compiled_policy",
        "_consumed",
        "_phase_b_grouped_gates",
        "_frozen_evidence_bytes",
        "_token_hmac",
        "_origin",
    }

    assert forbidden.isdisjoint(handle.__slots__)
    for name in forbidden:
        assert not hasattr(handle, name)


def test_precall_result_is_frozen():
    handle = enforce_pre_call(_pre_call_invocation())

    with pytest.raises((FrozenInstanceError, AttributeError)):
        handle.operation_id = "replaced"


def test_directly_constructed_handle_is_not_authorization():
    forged = PreCallResult(
        operation_id="forged-operation",
        issuer_id="forged-issuer",
        process_id=os.getpid(),
        correlation_id="forged-correlation",
        policy_digest="forged-policy",
        canonicalization_profile="aegis-json-v2",
    )

    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_post_call(forged, _valid_output())

    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"


def test_failed_phase_b_attempt_burns_handle():
    handle = enforce_pre_call(_pre_call_invocation())

    with pytest.raises(InvocationValidationError):
        enforce_post_call(handle, "not a dict")

    with pytest.raises(InvocationValidationError) as replay_exc:
        enforce_post_call(handle, _valid_output())
    assert replay_exc.value.code == "OPERATION_NOT_ACTIVE"
