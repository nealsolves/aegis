"""Chain placement is covered before checksum, signature, and delivery."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis._internal.attempts import AttemptFactory
from aegis._internal.chain_linker import ChainCoordinates
from aegis._internal.evidence_finalizer import (
    EvidenceDraft,
    EvidenceFinalizer,
    EvidenceFinalizerConfig,
)
from aegis._internal.enforcement import (
    AEGIS,
    _reset_module_enforcement_for_test,
    configure_module_enforcement,
    enforce_invocation,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.errors import (
    AuditSinkError,
    ChainLinkError,
    EvidenceFinalizationError,
)
from aegis._internal.outcomes import TerminalClass
from aegis._internal.signature_models import SignatureEncoding, SignerIdentity
from aegis._internal.signing import (
    ArtifactSignerAdapter,
    FINALIZER_INVOCATION_DOMAIN,
    HMACSigner,
    verify_finalized_artifact,
)
from aegis._internal.sinks import AuditSink


ROOT = Path(__file__).resolve().parents[1]


class RecordingReservation:
    def __init__(
        self,
        coordinates,
        events,
        *,
        commit_error=None,
        abort_error=None,
    ):
        self.coordinates = coordinates
        self.events = events
        self.commit_error = commit_error
        self.abort_error = abort_error
        self.committed_checksum = None
        self.abort_calls = 0

    def commit(self, content_checksum):
        self.events.append("commit")
        if self.commit_error is not None:
            raise self.commit_error
        self.committed_checksum = content_checksum

    def abort(self):
        self.events.append("abort")
        self.abort_calls += 1
        if self.abort_error is not None:
            raise self.abort_error


class RecordingLinker:
    def __init__(self, reservation, events, *, reserve_error=None):
        self.reservation = reservation
        self.events = events
        self.reserve_error = reserve_error
        self.requests = []

    def reserve(self, request, *, timeout):
        self.events.append("link")
        self.requests.append((request, timeout))
        if self.reserve_error is not None:
            raise self.reserve_error
        return self.reservation

    def reconcile(self, reservation_id, observed_artifact):
        raise AssertionError("reconciliation is host-driven, not automatic")


class RecordingSink(AuditSink):
    def __init__(self, events, *, error=None):
        self.events = events
        self.error = error
        self.artifacts = []

    def emit(self, audit_artifact):
        self.events.append("emit")
        if self.error is not None:
            raise self.error
        self.artifacts.append(audit_artifact)


class RecordingValidator:
    def __init__(self, events, *, error=None):
        self.events = events
        self.error = error
        schema = json.loads(
            (ROOT / "schemas/audit_artifact.schema.json").read_text()
        )
        self.validator = Draft7Validator(schema)

    def validate(self, artifact):
        self.events.append("schema")
        if self.error is not None:
            raise self.error
        self.validator.validate(artifact)


class RecordingSigner:
    def __init__(self, signer, events, *, error=None):
        self.signer = signer
        self.events = events
        self.error = error

    def sign(self, artifact, *, domain, signed_at):
        self.events.append("sign")
        if self.error is not None:
            raise self.error
        return self.signer.sign(artifact, domain=domain, signed_at=signed_at)


def _coordinates():
    return ChainCoordinates(
        chain_id="tenant-audit",
        chain_index=4,
        previous_audit_checksum="a" * 64,
        reservation_id="4d73bf845f9c4dbe96f218e9b47038d2",
    )


def _attempt():
    return AttemptFactory(clock=lambda: 100).allocate(
        "enforce_invocation",
        "unified",
        {
            "policy_file": "policy.yaml",
            "model_provider": "openai",
            "model_identifier": "gpt-test",
            "role": "planner",
        },
    )


def _invocation_draft(**overrides):
    values = {
        "attempt": _attempt(),
        "terminal": TerminalClass.ALLOW,
        "artifact_type": "invocation",
        "body": {
            "policy_schema_version": "http://json-schema.org/draft-07/schema#",
            "policy_version": "1.0",
            "input_checksum": "b" * 64,
            "output_checksum": "c" * 64,
        },
        "metadata": {"correlation_id": "correlation-4"},
    }
    values.update(overrides)
    return EvidenceDraft(**values)


def _governed_invocation():
    return {
        "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
        "model_provider": "openai",
        "model_identifier": "gpt-test-model",
        "role": "planner",
        "input": {"task": "describe system"},
        "output": {"result": "description", "confidence": 0.99},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _workflow_draft(**overrides):
    values = {
        "attempt": _attempt(),
        "terminal": TerminalClass.ALLOW,
        "artifact_type": "workflow",
        "body": {"session_id": "session-1", "status": "COMPLETED"},
        "chain_eligible": False,
    }
    values.update(overrides)
    return EvidenceDraft(**values)


def _identity():
    return SignerIdentity(
        algorithm="HMAC-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="local://chain-test",
        key_version="1",
    )


def _configured_finalizer(
    linker,
    events,
    *,
    signer_error=None,
    schema_error=None,
    sink_error=None,
):
    raw_signer = HMACSigner(b"chain-before-sign-key")
    signer = RecordingSigner(
        ArtifactSignerAdapter(raw_signer, _identity()),
        events,
        error=signer_error,
    )
    sink = RecordingSink(events, error=sink_error)
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=sink,
            signer=signer,
            schema_validator=RecordingValidator(events, error=schema_error),
            chain_linker=linker,
            clock=lambda: 101,
        )
    )
    return finalizer, raw_signer, sink


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("chain_id", "other-chain"),
        ("chain_index", 5),
        ("previous_audit_checksum", "d" * 64),
        ("reservation_id", "other-reservation"),
    ],
)
def test_chain_coordinates_are_checksum_and_signature_covered(
    monkeypatch,
    field,
    replacement,
):
    import aegis._internal.evidence_finalizer as finalizer_module

    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    finalizer, raw_signer, sink = _configured_finalizer(linker, events)
    real_checksum = finalizer_module.build_content_checksum_v2

    def recording_checksum(artifact):
        events.append("checksum")
        return real_checksum(artifact)

    monkeypatch.setattr(
        finalizer_module,
        "build_content_checksum_v2",
        recording_checksum,
    )

    artifact = finalizer.finalize(_invocation_draft())

    assert events == ["link", "checksum", "sign", "schema", "emit", "commit"]
    assert sink.artifacts == [artifact]
    assert reservation.committed_checksum == artifact["checksum"]
    request, timeout = linker.requests[0]
    assert request.attempt_id == 0
    assert request.artifact_type == "invocation"
    assert request.correlation_id == "correlation-4"
    assert 0 < timeout <= 5

    tampered = copy.deepcopy(artifact)
    tampered[field] = replacement
    assert verify_content_checksum_v2(tampered) is ContentIntegrity.INVALID
    assert not verify_finalized_artifact(
        tampered,
        raw_signer,
        domain=FINALIZER_INVOCATION_DOMAIN,
    )


def test_schema_copies_require_complete_chain_coordinates():
    root_schema = (ROOT / "schemas/audit_artifact.schema.json").read_bytes()
    packaged_schema = (
        ROOT / "aegis/schemas/audit_artifact.schema.json"
    ).read_bytes()
    assert root_schema == packaged_schema
    schema = json.loads(root_schema)
    validator = Draft7Validator(schema)
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    finalizer, _, _ = _configured_finalizer(
        RecordingLinker(reservation, events),
        events,
    )
    artifact = finalizer.finalize(_invocation_draft())

    for field in (
        "chain_id",
        "chain_index",
        "previous_audit_checksum",
        "reservation_id",
    ):
        partial = copy.deepcopy(artifact)
        partial.pop(field)
        assert list(validator.iter_errors(partial)), field


@pytest.mark.parametrize(
    ("stage", "expected_exception"),
    [
        ("checksum", EvidenceFinalizationError),
        ("sign", EvidenceFinalizationError),
        ("schema", EvidenceFinalizationError),
        ("emit", AuditSinkError),
    ],
)
def test_pre_acknowledgement_failures_abort_once(
    monkeypatch,
    stage,
    expected_exception,
):
    import aegis._internal.evidence_finalizer as finalizer_module

    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    options = {}
    if stage == "checksum":
        monkeypatch.setattr(
            finalizer_module,
            "build_content_checksum_v2",
            lambda artifact: (_ for _ in ()).throw(RuntimeError("checksum secret")),
        )
    elif stage == "sign":
        options["signer_error"] = RuntimeError("signer secret")
    elif stage == "schema":
        options["schema_error"] = RuntimeError("schema secret")
    else:
        options["sink_error"] = RuntimeError("sink secret")
    finalizer, _, sink = _configured_finalizer(linker, events, **options)

    with pytest.raises(expected_exception):
        finalizer.finalize(_invocation_draft())

    assert reservation.abort_calls == 1
    assert reservation.committed_checksum is None
    assert not sink.artifacts
    assert events[-1] == "abort"


def test_invalid_reserved_coordinates_abort_and_fail_closed():
    events = []
    reservation = RecordingReservation(
        {
            "chain_id": "tenant-audit",
            "chain_index": 2,
            "previous_audit_checksum": "signature-value",
            "reservation_id": "reservation",
        },
        events,
    )
    linker = RecordingLinker(reservation, events)
    finalizer, _, sink = _configured_finalizer(linker, events)

    with pytest.raises(ChainLinkError) as exc_info:
        finalizer.finalize(_invocation_draft())

    assert exc_info.value.code == "CHAIN_PREVIOUS_INVALID"
    assert reservation.abort_calls == 1
    assert not sink.artifacts


def test_abort_failure_does_not_mask_original_finalization_error():
    events = []
    reservation = RecordingReservation(
        _coordinates(),
        events,
        abort_error=RuntimeError("abort secret"),
    )
    linker = RecordingLinker(reservation, events)
    finalizer, _, _ = _configured_finalizer(
        linker,
        events,
        signer_error=RuntimeError("signer secret"),
    )

    with pytest.raises(EvidenceFinalizationError) as exc_info:
        finalizer.finalize(_invocation_draft())

    assert "abort secret" not in str(exc_info.value)
    assert reservation.abort_calls == 1


def test_reserve_failure_is_normalized_without_emitting_unchained_evidence():
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(
        reservation,
        events,
        reserve_error=RuntimeError("host storage secret"),
    )
    finalizer, _, sink = _configured_finalizer(linker, events)

    with pytest.raises(ChainLinkError) as exc_info:
        finalizer.finalize(_invocation_draft())

    assert exc_info.value.code == "CHAIN_LINK_UNAVAILABLE"
    assert "host storage secret" not in str(exc_info.value)
    assert events == ["link"]
    assert not sink.artifacts


def test_commit_failure_after_acknowledgement_never_aborts_or_reuses_coordinate():
    events = []
    reservation = RecordingReservation(
        _coordinates(),
        events,
        commit_error=RuntimeError("commit secret"),
    )
    linker = RecordingLinker(reservation, events)
    finalizer, _, sink = _configured_finalizer(linker, events)

    with pytest.raises(ChainLinkError) as exc_info:
        finalizer.finalize(_invocation_draft())

    assert exc_info.value.code == "CHAIN_LINK_COMMIT_FAILED"
    assert "commit secret" not in str(exc_info.value)
    assert len(sink.artifacts) == 1
    assert sink.artifacts[0]["reservation_id"] == (
        reservation.coordinates.reservation_id
    )
    assert reservation.abort_calls == 0
    assert events[-2:] == ["emit", "commit"]


def test_workflow_evidence_never_calls_linker_and_rejects_chain_claims():
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    finalizer, _, sink = _configured_finalizer(linker, events)

    with pytest.raises(EvidenceFinalizationError):
        finalizer.finalize(_workflow_draft(chain_eligible=True))
    with pytest.raises(EvidenceFinalizationError):
        finalizer.finalize(
            _workflow_draft(body={"chain_id": "forged-chain"})
        )

    assert not linker.requests
    assert not sink.artifacts


def test_configured_linker_cannot_be_bypassed_by_invocation_draft():
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    finalizer, _, sink = _configured_finalizer(linker, events)

    with pytest.raises(ChainLinkError) as exc_info:
        finalizer.finalize(_invocation_draft(chain_eligible=False))

    assert exc_info.value.code == "CHAIN_ARTIFACT_INELIGIBLE"
    assert not linker.requests
    assert not sink.artifacts


def test_instance_enforcement_threads_host_linker_to_finalization():
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    sink = RecordingSink(events)
    governance = AEGIS(sink=sink, chain_linker=linker)

    artifact = governance.enforce(_governed_invocation())

    assert artifact["reservation_id"] == reservation.coordinates.reservation_id
    assert reservation.committed_checksum == artifact["checksum"]
    assert sink.artifacts == [artifact]


def test_module_enforcement_threads_sealed_host_linker_to_finalization():
    events = []
    reservation = RecordingReservation(_coordinates(), events)
    linker = RecordingLinker(reservation, events)
    sink = RecordingSink(events)
    _reset_module_enforcement_for_test()
    configure_module_enforcement(sink=sink, chain_linker=linker)

    artifact = enforce_invocation(_governed_invocation())

    assert artifact["reservation_id"] == reservation.coordinates.reservation_id
    assert reservation.committed_checksum == artifact["checksum"]
    assert sink.artifacts == [artifact]


def test_enforcement_rejects_malformed_linker_before_governed_traffic():
    with pytest.raises(TypeError, match="chain_linker"):
        AEGIS(sink=RecordingSink([]), chain_linker=object())
    _reset_module_enforcement_for_test()
    with pytest.raises(TypeError, match="chain_linker"):
        configure_module_enforcement(
            sink=RecordingSink([]),
            chain_linker=object(),
        )
