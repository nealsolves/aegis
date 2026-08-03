from dataclasses import FrozenInstanceError

import pytest

from aegis._internal.evidence_diagnostics import EvidenceDiagnostics
from aegis._internal.errors import AuditSinkError, EvidenceFinalizationError


def test_diagnostics_increment_and_snapshot_is_read_only(caplog):
    diagnostics = EvidenceDiagnostics()

    with caplog.at_level("ERROR", logger="aegis.evidence_diagnostics"):
        diagnostics.record_finalization_failure(
            7, "checksum", "CANONICALIZATION_FAILED"
        )
    snapshot = diagnostics.snapshot()

    assert snapshot.evidence_finalization_failures_total == 1
    assert snapshot.evidence_delivery_failures_total == 0
    assert "attempt_id=7" in caplog.text
    assert "stage=checksum" in caplog.text
    assert "reason_code=CANONICALIZATION_FAILED" in caplog.text
    with pytest.raises(FrozenInstanceError):
        snapshot.evidence_finalization_failures_total = 9


def test_delivery_failure_has_its_own_counter_and_single_log(caplog):
    diagnostics = EvidenceDiagnostics()

    with caplog.at_level("ERROR", logger="aegis.evidence_diagnostics"):
        diagnostics.record_delivery_failure(3, "sink", "AUDIT_DELIVERY_FAILED")

    snapshot = diagnostics.snapshot()
    assert snapshot.evidence_finalization_failures_total == 0
    assert snapshot.evidence_delivery_failures_total == 1
    matching = [
        record for record in caplog.records if "attempt_id=3" in record.message
    ]
    assert len(matching) == 1


def test_diagnostics_replace_unsafe_log_labels(caplog):
    diagnostics = EvidenceDiagnostics()

    with caplog.at_level("ERROR", logger="aegis.evidence_diagnostics"):
        diagnostics.record_finalization_failure(
            4,
            "checksum\nsecret-token",
            "raw provider response",
        )

    assert "secret-token" not in caplog.text
    assert "raw provider response" not in caplog.text
    assert "stage=unknown" in caplog.text
    assert "reason_code=UNKNOWN" in caplog.text


def test_evidence_finalization_error_has_stable_default_code():
    error = EvidenceFinalizationError("could not finalize")

    assert error.code == "EVIDENCE_FINALIZATION_FAILED"


def test_audit_sink_error_accepts_specific_stable_code():
    error = AuditSinkError("delivery failed", code="AUDIT_DELIVERY_FAILED")

    assert error.code == "AUDIT_DELIVERY_FAILED"
