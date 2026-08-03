from __future__ import annotations

import pytest

from aegis import AEGIS, CallbackAuditSink, HMACSigner
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.signing import (
    FINALIZER_WORKFLOW_DOMAIN,
    verify_finalized_artifact,
)


@pytest.mark.parametrize(
    ("transition", "expected_status"),
    [
        ("complete", "COMPLETED"),
        ("cancel", "CANCELED"),
        ("finalize", "INCOMPLETE"),
    ],
)
def test_workflow_terminal_states_are_signed_and_emitted_exactly_once(
    transition,
    expected_status,
):
    emitted = []
    signer = HMACSigner(b"workflow-test-key")
    governance = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        signer=signer,
    )
    session = governance.open_session(session_id=f"session-{transition}")

    getattr(session, transition)()
    artifact = session.finalize() if transition != "finalize" else session.workflow_artifact

    assert artifact["status"] == expected_status
    assert artifact["signature_status"] == "signed"
    assert artifact["signature_metadata"]["payload_type"] == "workflow_artifact"
    assert artifact["signature_metadata"]["canonicalization_profile"] == (
        "aegis-json-v2"
    )
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert verify_finalized_artifact(
        artifact,
        signer,
        domain=FINALIZER_WORKFLOW_DOMAIN,
    )
    assert emitted == [artifact]


def test_failed_workflow_is_signed_before_original_exception_propagates():
    emitted = []
    signer = HMACSigner(b"workflow-test-key")
    governance = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        signer=signer,
    )

    with pytest.raises(RuntimeError, match="host failure"):
        with governance.open_session(session_id="session-failed"):
            raise RuntimeError("host failure")

    assert len(emitted) == 1
    artifact = emitted[0]
    assert artifact["status"] == "FAILED"
    assert artifact["signature_status"] == "signed"
    assert verify_finalized_artifact(
        artifact,
        signer,
        domain=FINALIZER_WORKFLOW_DOMAIN,
    )


def test_unsigned_workflow_status_is_explicit_and_integrity_valid():
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="session-unsigned")
    artifact = session.finalize()

    assert artifact["signature_status"] == "unsigned"
    assert artifact["signature"] is None
    assert "signature_metadata" not in artifact
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert emitted == [artifact]
