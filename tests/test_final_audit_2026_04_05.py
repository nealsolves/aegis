"""Regression tests for the split-enforcement authorization boundary.

The original audit covered portable sentinel/HMAC tokens. A3 replaces that
boundary with registry-backed, process- and issuer-affine operation handles.
"""
from __future__ import annotations

import dataclasses
import os

import pytest

from aegis._internal.enforcement import (
    AIGC,
    PreCallResult,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import InvocationValidationError

GOLDEN_POLICY = "tests/golden_replays/golden_policy_v1.yaml"


def _pre_call_inv():
    return {
        "policy_file": GOLDEN_POLICY,
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-5-20250929",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _valid_output():
    return {"result": "ok", "confidence": 0.9}


def _forged_handle() -> PreCallResult:
    return PreCallResult(
        operation_id="forged",
        issuer_id="0" * 32,
        process_id=os.getpid(),
        correlation_id="audit-forgery",
        policy_digest="0" * 64,
        canonicalization_profile="forged",
    )


@pytest.mark.parametrize("use_instance", [False, True])
def test_directly_forged_handle_fails_closed_with_artifact(use_instance):
    runtime = AIGC() if use_instance else None
    post_call = runtime.enforce_post_call if runtime else enforce_post_call

    with pytest.raises(InvocationValidationError) as exc_info:
        post_call(_forged_handle(), _valid_output())

    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"
    artifact = exc_info.value.audit_artifact
    assert artifact is not None
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failure_gate"] == "invocation_validation"


def test_policy_binding_tamper_burns_the_live_operation():
    issued = enforce_pre_call(_pre_call_inv())
    forged = dataclasses.replace(issued, policy_digest="0" * 64)

    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_post_call(forged, _valid_output())
    assert exc_info.value.code == "OPERATION_POLICY_MISMATCH"

    with pytest.raises(InvocationValidationError) as replay:
        enforce_post_call(issued, _valid_output())
    assert replay.value.code == "OPERATION_NOT_ACTIVE"


def test_profile_binding_tamper_fails_closed():
    issued = enforce_pre_call(_pre_call_inv())
    forged = dataclasses.replace(
        issued,
        canonicalization_profile="forged-profile",
    )

    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_post_call(forged, _valid_output())
    assert exc_info.value.code == "OPERATION_PROFILE_MISMATCH"
    assert exc_info.value.audit_artifact is not None


def test_invalid_output_is_typed_and_burns_the_handle():
    issued = enforce_pre_call(_pre_call_inv())

    with pytest.raises(InvocationValidationError) as exc_info:
        enforce_post_call(issued, object())
    assert exc_info.value.audit_artifact is not None
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"

    with pytest.raises(InvocationValidationError) as replay:
        enforce_post_call(issued, _valid_output())
    assert replay.value.code == "OPERATION_NOT_ACTIVE"


def test_genuine_handles_complete_normally():
    module_handle = enforce_pre_call(_pre_call_inv())
    assert enforce_post_call(
        module_handle,
        _valid_output(),
    )["enforcement_result"] == "PASS"

    runtime = AIGC()
    instance_handle = runtime.enforce_pre_call(_pre_call_inv())
    assert runtime.enforce_post_call(
        instance_handle,
        _valid_output(),
    )["enforcement_result"] == "PASS"
