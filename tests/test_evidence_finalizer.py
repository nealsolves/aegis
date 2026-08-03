import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis._internal.attempts import AttemptFactory
from aegis._internal.evidence_finalizer import (
    EvidenceDraft,
    EvidenceFinalizer,
    EvidenceFinalizerConfig,
)
from aegis._internal.errors import (
    AuditSinkError,
    EvidenceFinalizationError,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.outcomes import FailureRecord, TerminalClass
from aegis._internal.sinks import AuditSink


ROOT = Path(__file__).resolve().parents[1]


class RecordingSink(AuditSink):
    def __init__(self, events=None, *, mutate=False, error=None):
        self.events = events
        self.mutate = mutate
        self.error = error
        self.artifact = None

    def emit(self, audit_artifact):
        if self.events is not None:
            self.events.append("emit")
        if self.error is not None:
            raise self.error
        self.artifact = audit_artifact
        if self.mutate:
            audit_artifact["policy_file"] = "sink-mutated"


class RecordingValidator:
    def __init__(self, validator, events):
        self.validator = validator
        self.events = events

    def validate(self, artifact):
        self.events.append("schema")
        self.validator.validate(artifact)


class RecordingSigner:
    def __init__(self, events):
        self.events = events
        self.signed_checksum = None

    def sign(self, artifact, *, domain, signed_at):
        self.events.append("sign")
        self.signed_checksum = artifact["checksum"]
        signed = copy.deepcopy(artifact)
        signed.update(
            signature_status="signed",
            signature="ab" * 32,
            signature_metadata={
                "schema_version": "1",
                "signing_profile": "aegis-signature-v1",
                "canonicalization_version": "aegis-canonical-json-v1",
                "canonicalization_profile": "aegis-json-v2",
                "payload_type": "audit_artifact",
                "algorithm": "HMAC-SHA256",
                "signature_encoding": "hex",
                "key_reference": "local://test",
                "key_version": "1",
                "signed_at": signed_at,
            },
        )
        assert domain == "aegis.invocation.v2"
        return signed


def _attempt():
    return AttemptFactory(clock=lambda: 100).allocate(
        "enforce_invocation",
        "unified",
        {
            "policy_file": "policy.yaml",
            "model_provider": "openai",
            "model_identifier": "gpt-test",
            "role": "planner",
            "input": {"prompt": "hello"},
            "output": {"answer": "ok"},
            "context": {"tenant": "demo"},
        },
    )


def _body():
    return {
        "policy_schema_version": "http://json-schema.org/draft-07/schema#",
        "policy_version": "1.0",
        "input_checksum": "a" * 64,
        "output_checksum": "b" * 64,
        "failure_gate": None,
        "failure_reason": None,
        "risk_score": 0.2,
        "provenance": None,
    }


def _audit_validator():
    schema = json.loads((ROOT / "schemas/audit_artifact.schema.json").read_text())
    return Draft7Validator(schema)


def _draft(**overrides):
    values = {
        "attempt": _attempt(),
        "terminal": TerminalClass.ALLOW,
        "artifact_type": "invocation",
        "body": _body(),
    }
    values.update(overrides)
    return EvidenceDraft(**values)


def test_finalizer_orders_checksum_sign_schema_emit(monkeypatch):
    import aegis._internal.evidence_finalizer as finalizer_module

    events = []
    real_checksum = finalizer_module.build_content_checksum_v2

    def recording_checksum(artifact):
        events.append("checksum")
        return real_checksum(artifact)

    monkeypatch.setattr(
        finalizer_module,
        "build_content_checksum_v2",
        recording_checksum,
    )
    sink = RecordingSink(events)
    signer = RecordingSigner(events)
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=signer,
            schema_validator=RecordingValidator(_audit_validator(), events),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(_draft())

    assert events == ["checksum", "sign", "schema", "emit"]
    assert sink.artifact == artifact
    assert signer.signed_checksum == artifact["checksum"]


def test_unsigned_finalization_is_explicit_and_schema_valid():
    sink = RecordingSink()
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=None,
            schema_validator=_audit_validator(),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(_draft())

    assert artifact["signature_status"] == "unsigned"
    assert artifact["signature"] is None
    assert "signature_metadata" not in artifact
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert sink.artifact == artifact


def test_fail_draft_uses_closed_terminal_and_failure_records():
    sink = RecordingSink()
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=None,
            schema_validator=_audit_validator(),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(
        _draft(
            terminal=TerminalClass.DENY,
            failures=(FailureRecord("ROLE_DENIED", "Role denied", "role"),),
        )
    )

    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failures"] == [
        {"code": "ROLE_DENIED", "message": "Role denied", "field": "role"}
    ]


def test_early_failure_uses_minimum_attempt_identity():
    attempt = AttemptFactory(clock=lambda: 100).allocate(
        "enforce_invocation", "unified", object()
    )
    sink = RecordingSink()
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=None,
            schema_validator=_audit_validator(),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(
        _draft(
            attempt=attempt,
            terminal=TerminalClass.INVALID_RESULT,
            body={},
            failures=(
                FailureRecord(
                    "INVOCATION_VALIDATION_ERROR",
                    "Invocation is invalid",
                ),
            ),
        )
    )

    assert artifact["policy_file"] == "unknown"
    assert artifact["model_provider"] == "unknown"
    assert artifact["model_identifier"] == "unknown"
    assert artifact["role"] == "unknown"
    assert artifact["enforcement_result"] == "FAIL"


@pytest.mark.parametrize(
    "field",
    [
        "checksum",
        "signature",
        "signature_metadata",
        "signature_status",
        "canonicalization_profile",
        "audit_schema_version",
        "workflow_schema_version",
    ],
)
def test_draft_rejects_caller_supplied_finalization_fields(field):
    body = _body()
    body[field] = "forged"
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=RecordingSink(),
            signer=None,
            schema_validator=_audit_validator(),
        )
    )

    with pytest.raises(EvidenceFinalizationError):
        finalizer.finalize(_draft(body=body))


def test_same_draft_cannot_be_finalized_twice():
    draft = _draft()
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=RecordingSink(),
            signer=None,
            schema_validator=_audit_validator(),
        )
    )

    finalizer.finalize(draft)
    with pytest.raises(EvidenceFinalizationError, match="already finalized"):
        finalizer.finalize(draft)


def test_sink_mutation_cannot_change_returned_finalized_value():
    sink = RecordingSink(mutate=True)
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=None,
            schema_validator=_audit_validator(),
        )
    )

    artifact = finalizer.finalize(_draft())

    assert artifact["policy_file"] == "policy.yaml"
    assert sink.artifact["policy_file"] == "sink-mutated"


def test_sink_failure_is_bounded_and_typed():
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=RecordingSink(error=RuntimeError("provider secret")),
            signer=None,
            schema_validator=_audit_validator(),
        )
    )

    with pytest.raises(AuditSinkError) as captured:
        finalizer.finalize(_draft())

    assert captured.value.code == "AUDIT_DELIVERY_FAILED"
    assert "provider secret" not in str(captured.value)
