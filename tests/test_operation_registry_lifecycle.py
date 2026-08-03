"""Lifecycle and ownership regressions for A3 operation registries."""
from __future__ import annotations

from dataclasses import replace

import pytest

from aegis import AEGIS, CallbackAuditSink, HMACSigner
from aegis._internal.errors import AuditSinkError, InvocationValidationError
from aegis._internal.operation_registry import OperationRegistry
from aegis._internal.signing import (
    FINALIZER_INVOCATION_DOMAIN,
    verify_finalized_artifact,
)

GOLDEN_POLICY = "tests/golden_replays/golden_policy_v1.yaml"


def _invocation():
    return {
        "policy_file": GOLDEN_POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _output():
    return {"result": "ok", "confidence": 0.9}


def test_instance_handle_rejected_by_other_instance():
    first = AEGIS()
    second = AEGIS()
    handle = first.enforce_pre_call(_invocation())

    with pytest.raises(InvocationValidationError) as exc_info:
        second.enforce_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_ISSUER_MISMATCH"

    assert first.enforce_post_call(
        handle,
        _output(),
    )["enforcement_result"] == "PASS"


def test_session_cancel_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.cancel()

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"


def test_session_finalize_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.finalize()

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"


def test_discarded_adapter_step_removes_pending_operation():
    runtime = AEGIS()
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    session.discard_adapter_step(handle)

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(handle, _output())
    assert exc_info.value.code == "OPERATION_NOT_ACTIVE"
    session.cancel()


def test_invalid_session_post_metadata_consumes_and_emits_fail_artifact():
    artifacts = []
    runtime = AEGIS(sink=CallbackAuditSink(artifacts.append))
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(
            handle,
            _output(),
            step_metadata=[],
        )

    assert exc_info.value.audit_artifact is not None
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"
    assert len(artifacts) == 1
    with pytest.raises(InvocationValidationError) as replay:
        session.enforce_step_post_call(handle, _output())
    assert replay.value.code == "OPERATION_NOT_ACTIVE"
    assert replay.value.audit_artifact is not None
    assert len(artifacts) == 2
    session.cancel()


def test_invalid_session_post_metadata_is_consumed_before_validation(monkeypatch):
    events = []
    original_consume = OperationRegistry.consume

    def traced_consume(registry, handle):
        events.append("consume")
        return original_consume(registry, handle)

    class InvalidMetadata:
        @property
        def __class__(self):
            events.append("validate")
            return list

    monkeypatch.setattr(OperationRegistry, "consume", traced_consume)
    session = AEGIS().open_session()
    handle = session.enforce_step_pre_call(_invocation())

    with pytest.raises(InvocationValidationError):
        session.enforce_step_post_call(
            handle,
            _output(),
            step_metadata=InvalidMetadata(),
        )

    assert events[:2] == ["consume", "validate"]
    session.cancel()


def test_session_wrapper_fields_are_consumed_before_validation(monkeypatch):
    events = []
    original_consume = OperationRegistry.consume

    def traced_consume(registry, handle):
        events.append("consume")
        return original_consume(registry, handle)

    class ForgedStepId:
        def __eq__(self, other):
            del other
            events.append("validate")
            return False

    monkeypatch.setattr(OperationRegistry, "consume", traced_consume)
    session = AEGIS().open_session()
    handle = session.enforce_step_pre_call(_invocation())
    forged = replace(handle, step_id=ForgedStepId())

    with pytest.raises(InvocationValidationError):
        session.enforce_step_post_call(forged, _output())

    assert events[:2] == ["consume", "validate"]
    session.cancel()


def test_invalid_session_post_metadata_uses_signed_instance_evidence_boundary():
    artifacts = []
    signer = HMACSigner(b"session-rejection-key")
    runtime = AEGIS(
        sink=CallbackAuditSink(artifacts.append),
        signer=signer,
    )
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    with pytest.raises(InvocationValidationError):
        session.enforce_step_post_call(handle, _output(), step_metadata=[])

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["signature_status"] == "signed"
    assert verify_finalized_artifact(
        artifact,
        signer,
        domain=FINALIZER_INVOCATION_DOMAIN,
    )
    session.cancel()


def test_invalid_session_post_metadata_fails_closed_on_delivery_loss():
    def fail_sink(_artifact):
        raise RuntimeError("provider secret must not escape")

    runtime = AEGIS(sink=CallbackAuditSink(fail_sink))
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())

    with pytest.raises(AuditSinkError) as exc_info:
        session.enforce_step_post_call(handle, _output(), step_metadata=[])

    assert exc_info.value.code == "AUDIT_DELIVERY_FAILED"
    assert "provider secret" not in str(exc_info.value)
    assert (
        runtime.evidence_diagnostics().evidence_delivery_failures_total
        == 1
    )
    session.cancel()


def test_malformed_session_handle_is_typed_audited_and_non_consuming():
    artifacts = []
    runtime = AEGIS(sink=CallbackAuditSink(artifacts.append))
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation())
    malformed = replace(handle, issuer_id=7)

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(malformed, _output())

    assert exc_info.value.code == "OPERATION_HANDLE_INVALID"
    assert exc_info.value.audit_artifact is not None
    assert len(artifacts) == 1
    assert session.enforce_step_post_call(
        handle,
        _output(),
    )["enforcement_result"] == "PASS"
    session.complete()


def test_forged_session_metadata_consumes_with_one_fail_artifact():
    artifacts = []
    runtime = AEGIS(sink=CallbackAuditSink(artifacts.append))
    session = runtime.open_session()
    handle = session.enforce_step_pre_call(_invocation(), step_id="real")
    forged = replace(handle, step_id="forged")

    with pytest.raises(InvocationValidationError) as exc_info:
        session.enforce_step_post_call(forged, _output())

    assert exc_info.value.code == "OPERATION_SESSION_METADATA_MISMATCH"
    assert exc_info.value.audit_artifact is not None
    assert len(artifacts) == 1
    with pytest.raises(InvocationValidationError) as replay:
        session.enforce_step_post_call(handle, _output())
    assert replay.value.code == "OPERATION_NOT_ACTIVE"
    session.cancel()
