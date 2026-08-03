from __future__ import annotations

import pytest

from aegis import AEGIS
from aegis._internal.errors import (
    AuditSinkError,
    EvidenceConfigurationError,
    EvidenceFinalizationError,
)
from aegis._internal.sinks import AuditSink, CallbackAuditSink
from aegis._internal.signing import ArtifactSigner


INVOCATION = {
    "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
    "model_provider": "openai",
    "model_identifier": "gpt-test",
    "role": "planner",
    "input": {"prompt": "test"},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


class BrokenSink(AuditSink):
    def emit(self, audit_artifact):
        raise RuntimeError("provider secret must not escape")


class IdentityFreeSigner(ArtifactSigner):
    def sign(self, payload):
        return "opaque-signature"

    def verify(self, payload, signature):
        return False


def test_v2_instance_requires_a_sink():
    with pytest.raises(EvidenceConfigurationError) as exc_info:
        AEGIS(sink=None)
    assert exc_info.value.code == "V2_SINK_REQUIRED"


def test_broken_sink_cannot_return_pass_and_records_once():
    governance = AEGIS(sink=BrokenSink())

    with pytest.raises(AuditSinkError) as exc_info:
        governance.enforce(INVOCATION)

    assert exc_info.value.code == "AUDIT_DELIVERY_FAILED"
    assert "provider secret" not in str(exc_info.value)
    snapshot = governance.evidence_diagnostics()
    assert snapshot.evidence_delivery_failures_total == 1


def test_broken_sink_replaces_deny_exception_when_fail_evidence_is_lost():
    governance = AEGIS(sink=BrokenSink())
    denied = {**INVOCATION, "role": "unauthorized"}

    with pytest.raises(AuditSinkError) as exc_info:
        governance.enforce(denied)

    assert exc_info.value.code == "AUDIT_DELIVERY_FAILED"
    assert governance.evidence_diagnostics().evidence_delivery_failures_total == 1


def test_v2_instance_rejects_best_effort_log_delivery():
    with pytest.raises(ValueError, match="only supports 'raise'"):
        AEGIS(sink=BrokenSink(), on_sink_failure="log")


def test_acknowledged_sink_returns_exact_finalized_value():
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    artifact = governance.enforce(INVOCATION)
    assert emitted == [artifact]


def test_broken_workflow_sink_records_once_and_cannot_finalize():
    governance = AEGIS(sink=BrokenSink())
    session = governance.open_session(session_id="broken-workflow")

    with pytest.raises(AuditSinkError):
        session.finalize()

    assert governance.evidence_diagnostics().evidence_delivery_failures_total == 1


def test_legacy_signer_without_v2_identity_fails_closed_and_records_once():
    governance = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        signer=IdentityFreeSigner(),
    )

    with pytest.raises(EvidenceFinalizationError):
        governance.enforce(INVOCATION)

    snapshot = governance.evidence_diagnostics()
    assert snapshot.evidence_finalization_failures_total == 1
