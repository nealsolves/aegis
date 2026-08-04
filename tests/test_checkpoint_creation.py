"""Explicit trusted-checkpoint creation and frozen signing-byte vectors."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from typing import Callable

import pytest

from aegis._internal.attempts import AttemptFactory
from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.chain_linker import ChainCoordinates
from aegis._internal.evidence_finalizer import (
    EvidenceDraft,
    EvidenceFinalizer,
    EvidenceFinalizerConfig,
    _audit_validator,
    _workflow_validator,
)
from aegis._internal.outcomes import TerminalClass
from aegis._internal.errors import CheckpointError
from aegis._internal.signature_models import SignatureMetadata
from aegis._internal.sinks import CallbackAuditSink
from aegis.checkpoints import (
    create_chain_checkpoint,
    create_workflow_checkpoint,
)
from tests.support.external_signing import (
    SENSITIVE_CORPUS,
    DeterministicExternalSigner,
)


CHAIN_CHECKPOINT_VECTOR = (
    b"AEGIS-SIGNATURE\x00aegis-chain-checkpoint-v1\x00chain_checkpoint\x00"
    b'{"artifact_checksum":"0950a94123e6fdd87f5ed62291f857b6895acce493b75a099bb0fbb055d1025a",'
    b'"artifact_schema_version":"2.0","canonicalization_profile":"aegis-json-v2",'
    b'"chain_id":"checkpoint-chain","chain_index":2,"chain_length":3,'
    b'"checkpoint_profile":"aegis-chain-checkpoint-v1",'
    b'"checkpoint_schema_version":"1","checkpointed_at":1725000000,'
    b'"signature_metadata":{"algorithm":"HMAC-SHA256",'
    b'"canonicalization_version":"aegis-json-v2",'
    b'"key_reference":"deterministic-audit-key","key_version":"version/current",'
    b'"payload_type":"chain_checkpoint","schema_version":"1",'
    b'"signature_encoding":"hex","signed_at":1725000000,'
    b'"signing_profile":"aegis-chain-checkpoint-v1"}}'
)

WORKFLOW_CHECKPOINT_VECTOR = (
    b"AEGIS-SIGNATURE\x00aegis-workflow-checkpoint-v1\x00workflow_checkpoint\x00"
    b'{"canonicalization_profile":"aegis-json-v2",'
    b'"checkpoint_profile":"aegis-workflow-checkpoint-v1",'
    b'"checkpoint_schema_version":"1","checkpointed_at":1725000001,'
    b'"final_status":"COMPLETED","invocations":['
    b'{"checksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    b'"step_index":0},'
    b'{"checksum":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
    b'"step_index":1}],"session_id":"checkpoint-session",'
    b'"signature_metadata":{"algorithm":"HMAC-SHA256",'
    b'"canonicalization_version":"aegis-json-v2",'
    b'"key_reference":"deterministic-audit-key","key_version":"version/current",'
    b'"payload_type":"workflow_checkpoint","schema_version":"1",'
    b'"signature_encoding":"hex","signed_at":1725000001,'
    b'"signing_profile":"aegis-workflow-checkpoint-v1"},"step_count":2,'
    b'"workflow_checksum":"d132782647b8739f21a350c2c851a53fbc35ba2107972eecf1300e3d4ee7df3e",'
    b'"workflow_schema_version":"2.0"}'
)

EXPECTED_CHAIN_RECORD = {
    "checkpoint_schema_version": "1",
    "checkpoint_profile": "aegis-chain-checkpoint-v1",
    "canonicalization_profile": "aegis-json-v2",
    "chain_id": "checkpoint-chain",
    "chain_index": 2,
    "chain_length": 3,
    "artifact_schema_version": "2.0",
    "artifact_checksum": (
        "0950a94123e6fdd87f5ed62291f857b6895acce493b75a099bb0fbb055d1025a"
    ),
    "checkpointed_at": 1_725_000_000,
    "signature_metadata": {
        "schema_version": "1",
        "signing_profile": "aegis-chain-checkpoint-v1",
        "canonicalization_version": "aegis-json-v2",
        "payload_type": "chain_checkpoint",
        "algorithm": "HMAC-SHA256",
        "signature_encoding": "hex",
        "key_reference": "deterministic-audit-key",
        "key_version": "version/current",
        "signed_at": 1_725_000_000,
    },
    "signature": "f64f21e1e9c518ac65b1efc7491b378b0e48f5ec25adb13b317bc676b44c6740",
}

EXPECTED_WORKFLOW_RECORD = {
    "checkpoint_schema_version": "1",
    "checkpoint_profile": "aegis-workflow-checkpoint-v1",
    "canonicalization_profile": "aegis-json-v2",
    "workflow_schema_version": "2.0",
    "session_id": "checkpoint-session",
    "final_status": "COMPLETED",
    "step_count": 2,
    "invocations": [
        {"step_index": 0, "checksum": "b" * 64},
        {"step_index": 1, "checksum": "c" * 64},
    ],
    "workflow_checksum": (
        "d132782647b8739f21a350c2c851a53fbc35ba2107972eecf1300e3d4ee7df3e"
    ),
    "checkpointed_at": 1_725_000_001,
    "signature_metadata": {
        "schema_version": "1",
        "signing_profile": "aegis-workflow-checkpoint-v1",
        "canonicalization_version": "aegis-json-v2",
        "payload_type": "workflow_checkpoint",
        "algorithm": "HMAC-SHA256",
        "signature_encoding": "hex",
        "key_reference": "deterministic-audit-key",
        "key_version": "version/current",
        "signed_at": 1_725_000_001,
    },
    "signature": "0bc0b2a0a82f5f184178c5624b413abc36f80107a0aaf35a39f693fd70c8254d",
}


class _Reservation:
    def __init__(self, chain_index: int = 2) -> None:
        self.coordinates = ChainCoordinates(
            "checkpoint-chain",
            chain_index,
            "a" * 64,
            "reservation-2",
        )

    def commit(self, content_checksum: str) -> None:
        del content_checksum

    def abort(self) -> None:
        pass


class _Linker:
    def __init__(self, chain_index: int = 2) -> None:
        self.chain_index = chain_index

    def reserve(self, request: object, *, timeout: float) -> _Reservation:
        del request, timeout
        return _Reservation(self.chain_index)

    def reconcile(self, reservation_id: str, observed_artifact: object) -> None:
        del reservation_id, observed_artifact


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


def _chained_artifact(*, chain_index: int = 2) -> dict[str, object]:
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=CallbackAuditSink(lambda artifact: None),
            signer=None,
            schema_validator=_audit_validator(),
            chain_linker=_Linker(chain_index),
            clock=lambda: 101,
        )
    )
    return finalizer.finalize(
        EvidenceDraft(
            attempt=_attempt(),
            terminal=TerminalClass.ALLOW,
            artifact_type="invocation",
            body={
                "policy_schema_version": (
                    "http://json-schema.org/draft-07/schema#"
                ),
                "policy_version": "1.0",
                "input_checksum": "b" * 64,
                "output_checksum": "c" * 64,
            },
        )
    )


@pytest.fixture
def chained_artifact() -> dict[str, object]:
    return _chained_artifact()


def _finalized_workflow(
    *,
    session_id: str = "checkpoint-session",
    step_count: int = 2,
    invocations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=CallbackAuditSink(lambda artifact: None),
            signer=None,
            schema_validator=_workflow_validator(),
            clock=lambda: 101,
        )
    )
    return finalizer.finalize(
        EvidenceDraft(
            attempt=_attempt(),
            terminal=TerminalClass.ALLOW,
            artifact_type="workflow",
            chain_eligible=False,
            body={
                "artifact_type": "workflow",
                "session_id": session_id,
                "status": "COMPLETED",
                "started_at": 100,
                "finalized_at": 101,
                "steps": [],
                "invocation_audit_checksums": ["b" * 64, "c" * 64],
                "step_count": step_count,
                "invocations": invocations
                if invocations is not None
                else [
                    {"step_index": 0, "checksum": "b" * 64},
                    {"step_index": 1, "checksum": "c" * 64},
                ],
            },
        )
    )


@pytest.fixture
def finalized_workflow() -> dict[str, object]:
    return _finalized_workflow()


def test_chain_checkpoint_payload_matches_frozen_vector(chained_artifact):
    before = deepcopy(chained_artifact)
    signer = DeterministicExternalSigner()

    checkpoint = create_chain_checkpoint(
        chained_artifact,
        signer,
        checkpointed_at=1_725_000_000,
    )

    assert chained_artifact == before
    assert len(signer.payloads) == 1
    assert signer.payloads[0] == CHAIN_CHECKPOINT_VECTOR
    assert checkpoint.to_dict() == EXPECTED_CHAIN_RECORD
    with pytest.raises(FrozenInstanceError):
        checkpoint.chain_id = "mutated"


def test_workflow_checkpoint_payload_matches_frozen_vector(finalized_workflow):
    before = deepcopy(finalized_workflow)
    signer = DeterministicExternalSigner()

    checkpoint = create_workflow_checkpoint(
        finalized_workflow,
        signer,
        checkpointed_at=1_725_000_001,
    )

    assert finalized_workflow == before
    assert len(signer.payloads) == 1
    assert signer.payloads[0] == WORKFLOW_CHECKPOINT_VECTOR
    assert checkpoint.to_dict() == EXPECTED_WORKFLOW_RECORD
    with pytest.raises(FrozenInstanceError):
        checkpoint.session_id = "mutated"


@pytest.mark.parametrize(
    ("record", "vector"),
    [
        (EXPECTED_CHAIN_RECORD, CHAIN_CHECKPOINT_VECTOR),
        (EXPECTED_WORKFLOW_RECORD, WORKFLOW_CHECKPOINT_VECTOR),
    ],
)
def test_signed_record_reconstructs_the_same_frozen_payload(record, vector):
    from aegis._internal.checkpoint_signing import _checkpoint_payload

    signed_record = deepcopy(record)
    metadata = SignatureMetadata.from_dict(
        deepcopy(signed_record["signature_metadata"])
    )

    assert _checkpoint_payload(signed_record, metadata) == vector


class _ForbiddenSigner:
    def __init__(self) -> None:
        self.identity_calls = 0
        self.storage_calls = 0

    def signer_identity(self):
        self.identity_calls += 1
        raise AssertionError("source preflight must precede identity lookup")

    def sign(self, payload, identity):
        del payload, identity
        raise AssertionError("source preflight must precede signing")

    def store(self, record) -> None:
        del record
        self.storage_calls += 1


class _StorageAwareSigner(DeterministicExternalSigner):
    def __init__(self, *, mode: str) -> None:
        super().__init__(mode=mode)
        self.storage_calls = 0

    def store(self, record) -> None:
        del record
        self.storage_calls += 1


def _assert_sanitized_failure(
    operation: Callable[[], object],
    source: object,
    *,
    expected_code: str,
    signer: object,
    caplog: pytest.LogCaptureFixture,
) -> CheckpointError:
    before = deepcopy(source)
    returned: list[object] = []
    with pytest.raises(CheckpointError) as raised:
        returned.append(operation())
    assert returned == []
    assert source == before
    assert getattr(signer, "storage_calls", 0) == 0
    public_text = (
        str(raised.value)
        + repr(raised.value.details)
        + caplog.text
    )
    assert raised.value.code == expected_code
    assert raised.value.details == {}
    for sensitive in SENSITIVE_CORPUS:
        assert sensitive not in public_text
    return raised.value


@pytest.mark.parametrize(
    "mutation",
    [
        lambda artifact: [],
        lambda artifact: {
            key: value
            for key, value in artifact.items()
            if key
            not in {
                "chain_id",
                "chain_index",
                "previous_audit_checksum",
                "reservation_id",
            }
        },
        lambda artifact: {**artifact, "checksum": "f" * 64},
        lambda artifact: {**artifact, "audit_schema_version": "1.4"},
        lambda artifact: {**artifact, "chain_index": True},
    ],
    ids=["wrong-type", "unchained", "checksum", "schema", "boolean-index"],
)
def test_chain_source_failures_precede_identity_lookup(
    chained_artifact,
    mutation,
    caplog,
):
    source = mutation(deepcopy(chained_artifact))
    signer = _ForbiddenSigner()

    _assert_sanitized_failure(
        lambda: create_chain_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_000,
        ),
        source,
        expected_code="CHECKPOINT_SOURCE_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert signer.identity_calls == 0


def test_chain_length_overflow_is_source_invalid_before_identity(caplog):
    source = _chained_artifact(chain_index=SAFE_INTEGER_MAX)
    signer = _ForbiddenSigner()

    _assert_sanitized_failure(
        lambda: create_chain_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_000,
        ),
        source,
        expected_code="CHECKPOINT_SOURCE_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert signer.identity_calls == 0


@pytest.mark.parametrize(
    "source_factory",
    [
        lambda workflow: [],
        lambda workflow: {**workflow, "checksum": "f" * 64},
        lambda workflow: {**workflow, "workflow_schema_version": "1.4"},
        lambda workflow: {
            key: value
            for key, value in workflow.items()
            if key != "session_id"
        },
        lambda workflow: _finalized_workflow(
            step_count=2,
            invocations=[
                {"step_index": 0, "checksum": "b" * 64},
                {"step_index": 2, "checksum": "c" * 64},
            ],
        ),
        lambda workflow: _finalized_workflow(session_id="   "),
        lambda workflow: _finalized_workflow(session_id="x" * 513),
    ],
    ids=[
        "wrong-type",
        "checksum",
        "schema",
        "incomplete",
        "gapped-claim",
        "blank-session",
        "oversized-session",
    ],
)
def test_workflow_source_failures_precede_identity_lookup(
    finalized_workflow,
    source_factory,
    caplog,
):
    source = source_factory(deepcopy(finalized_workflow))
    signer = _ForbiddenSigner()

    _assert_sanitized_failure(
        lambda: create_workflow_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_001,
        ),
        source,
        expected_code="CHECKPOINT_SOURCE_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert signer.identity_calls == 0


@pytest.mark.parametrize(
    ("creator_name", "checkpointed_at"),
    [("chain", True), ("workflow", False)],
)
def test_boolean_checkpoint_time_is_rejected_before_identity_lookup(
    chained_artifact,
    finalized_workflow,
    creator_name,
    checkpointed_at,
    caplog,
):
    source = (
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    signer = _ForbiddenSigner()
    creator = (
        create_chain_checkpoint
        if creator_name == "chain"
        else create_workflow_checkpoint
    )

    _assert_sanitized_failure(
        lambda: creator(source, signer, checkpointed_at=checkpointed_at),
        source,
        expected_code="CHECKPOINT_INPUT_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert signer.identity_calls == 0


def test_source_limit_failure_stops_before_schema_checksum_and_identity(
    chained_artifact,
    monkeypatch,
    caplog,
):
    import aegis._internal.checkpoint_signing as checkpoint_signing

    source = deepcopy(chained_artifact)
    source["context"] = {"oversized": "x" * (4 * 1024 * 1024)}
    signer = _ForbiddenSigner()
    later_calls: list[str] = []

    def forbidden_validator():
        later_calls.append("schema")
        raise AssertionError

    def forbidden_checksum(value):
        del value
        later_calls.append("checksum")
        raise AssertionError

    monkeypatch.setattr(
        checkpoint_signing,
        "_audit_validator",
        forbidden_validator,
    )
    monkeypatch.setattr(
        checkpoint_signing,
        "verify_content_checksum_v2",
        forbidden_checksum,
    )

    _assert_sanitized_failure(
        lambda: create_chain_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_000,
        ),
        source,
        expected_code="CHECKPOINT_INPUT_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert later_calls == []
    assert signer.identity_calls == 0


@pytest.mark.parametrize(
    "mode",
    [
        "identity_error",
        "identity_unexpected",
        "malformed_identity",
        "signing_error",
        "signing_unexpected",
        "malformed_receipt",
        "rotate_receipt",
        "malformed_signature",
        "mutate_identity",
    ],
)
@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_signing_failures_are_atomic_and_sanitized(
    chained_artifact,
    finalized_workflow,
    creator_name,
    mode,
    caplog,
):
    source = (
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    checkpointed_at = (
        1_725_000_000 if creator_name == "chain" else 1_725_000_001
    )
    creator = (
        create_chain_checkpoint
        if creator_name == "chain"
        else create_workflow_checkpoint
    )
    signer = _StorageAwareSigner(mode=mode)

    error = _assert_sanitized_failure(
        lambda: creator(
            source,
            signer,
            checkpointed_at=checkpointed_at,
        ),
        source,
        expected_code="CHECKPOINT_SIGNING_ERROR",
        signer=signer,
        caplog=caplog,
    )

    assert error.__cause__ is not None


@pytest.mark.parametrize(
    "field",
    [
        "checkpoint_profile",
        "canonicalization_profile",
        "checkpointed_at",
        "signature_metadata",
    ],
)
def test_checkpoint_payload_rejects_cross_field_disagreement(field):
    from aegis._internal.checkpoint_signing import _checkpoint_payload

    record = deepcopy(EXPECTED_CHAIN_RECORD)
    metadata = SignatureMetadata.from_dict(record["signature_metadata"])
    if field == "checkpoint_profile":
        record[field] = "aegis-workflow-checkpoint-v1"
    elif field == "canonicalization_profile":
        record[field] = "aegis-canonical-json-v1"
    elif field == "checkpointed_at":
        record[field] = 1_725_000_001
    else:
        record[field] = {
            **record[field],
            "payload_type": "workflow_checkpoint",
        }

    with pytest.raises(CheckpointError) as raised:
        _checkpoint_payload(record, metadata)

    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
