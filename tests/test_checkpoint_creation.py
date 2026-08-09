"""Explicit trusted-checkpoint creation and frozen signing-byte vectors."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from decimal import Decimal
from fractions import Fraction
from importlib import import_module
import json
from pathlib import Path
import subprocess
import sys
import traceback
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
from aegis._internal.errors import CheckpointError, SignatureMetadataError
from aegis._internal.signature_models import EvidenceType, SignatureMetadata
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


@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_cold_creation_performs_no_schema_io_or_validator_cache_mutation(
    chained_artifact,
    finalized_workflow,
    creator_name,
):
    source = (
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    program = """
import json
from pathlib import Path
import sys

from tests.support.external_signing import DeterministicExternalSigner
import aegis._internal.checkpoint_signing as checkpoint_signing
import aegis._internal.evidence_finalizer as evidence_finalizer

evidence_finalizer._AUDIT_VALIDATOR = None
evidence_finalizer._WORKFLOW_VALIDATOR = None
reads = []
original_read_text = Path.read_text

def recording_read_text(path, *args, **kwargs):
    reads.append(str(path))
    return original_read_text(path, *args, **kwargs)

Path.read_text = recording_read_text
request = json.loads(sys.stdin.read())
creator = (
    checkpoint_signing.create_chain_checkpoint
    if request["creator"] == "chain"
    else checkpoint_signing.create_workflow_checkpoint
)
result = creator(
    request["source"],
    DeterministicExternalSigner(),
    checkpointed_at=1725000000,
)
print(json.dumps({
    "reads": reads,
    "audit_cache": evidence_finalizer._AUDIT_VALIDATOR is not None,
    "workflow_cache": evidence_finalizer._WORKFLOW_VALIDATOR is not None,
    "profile": result.checkpoint_profile,
    "imports_finalizer_validator": (
        "_audit_validator" in vars(checkpoint_signing)
        or "_workflow_validator" in vars(checkpoint_signing)
    ),
}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        input=json.dumps({"creator": creator_name, "source": source}),
        text=True,
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
        check=True,
    )
    observed = json.loads(completed.stdout.strip().splitlines()[-1])

    assert observed["reads"] == []
    assert observed["audit_cache"] is False
    assert observed["workflow_cache"] is False
    assert observed["imports_finalizer_validator"] is False
    assert observed["profile"] == (
        "aegis-chain-checkpoint-v1"
        if creator_name == "chain"
        else "aegis-workflow-checkpoint-v1"
    )


def test_pure_checkpoint_source_validation_matches_audit_schema_corpus(
    chained_artifact,
):
    try:
        module = import_module("aegis._internal.checkpoint_source_validation")
    except ModuleNotFoundError:
        module = None
    validate = (
        None if module is None else getattr(module, "is_valid_audit_artifact_v2", None)
    )
    assert callable(validate)

    valid = deepcopy(chained_artifact)
    cases: tuple[tuple[dict[str, object], bool], ...] = (
        (valid, True),
        ({key: value for key, value in valid.items() if key != "role"}, False),
        ({**valid, "unexpected": None}, False),
        ({**valid, "enforcement_result": "UNKNOWN"}, False),
        ({**valid, "failure_gate": []}, False),
        ({**valid, "failures": [{"code": "x", "message": "x"}]}, False),
        ({**valid, "context": {"step_index": 0}}, False),
        (
            {
                key: value
                for key, value in valid.items()
                if key != "reservation_id"
            },
            False,
        ),
        ({**valid, "checksum": "not-a-checksum"}, False),
    )
    schema = _audit_validator()
    for source, expected in cases:
        assert schema.is_valid(source) is expected
        assert validate(source) is expected


def test_pure_checkpoint_source_validation_matches_workflow_schema_corpus(
    finalized_workflow,
):
    try:
        module = import_module("aegis._internal.checkpoint_source_validation")
    except ModuleNotFoundError:
        module = None
    validate = (
        None
        if module is None
        else getattr(module, "is_valid_workflow_artifact_v2", None)
    )
    assert callable(validate)

    valid = deepcopy(finalized_workflow)
    cases: tuple[tuple[dict[str, object], bool], ...] = (
        (valid, True),
        (
            {
                key: value
                for key, value in valid.items()
                if key != "artifact_type"
            },
            False,
        ),
        ({**valid, "unexpected": None}, False),
        ({**valid, "status": "UNKNOWN"}, False),
        ({**valid, "status": []}, False),
        (
            {
                **valid,
                "invocations": [
                    {"step_index": 0, "checksum": "b" * 64, "extra": True}
                ],
            },
            False,
        ),
        ({**valid, "approval_checkpoints": [{"paused_at": "invalid"}]}, False),
        ({**valid, "step_count": 1_025}, False),
        ({**valid, "checksum": "not-a-checksum"}, False),
    )
    schema = _workflow_validator()
    for source, expected in cases:
        assert schema.is_valid(source) is expected
        assert validate(source) is expected


class _IntSubclass(int):
    pass


class _FloatSubclass(float):
    pass


class _StringSubclass(str):
    pass


class _ListSubclass(list):
    pass


class _DictSubclass(dict):
    pass


class _HostileJsonValue:
    def __iter__(self):
        raise AssertionError("hostile value was invoked")


@pytest.mark.parametrize(
    "exotic",
    (
        _IntSubclass(1),
        _FloatSubclass(1.0),
        _StringSubclass("value"),
        _ListSubclass(),
        _DictSubclass(),
        Decimal("1"),
        Fraction(1, 2),
        1 + 2j,
        _HostileJsonValue(),
    ),
    ids=(
        "int-subclass",
        "float-subclass",
        "str-subclass",
        "list-subclass",
        "dict-subclass",
        "decimal",
        "fraction",
        "complex",
        "hostile",
    ),
)
@pytest.mark.parametrize("source_kind", ("audit", "workflow"))
def test_pure_checkpoint_source_validation_rejects_non_exact_json_values(
    chained_artifact,
    finalized_workflow,
    exotic,
    source_kind,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_audit_artifact_v2,
        is_valid_workflow_artifact_v2,
    )

    if source_kind == "audit":
        source = deepcopy(chained_artifact)
        source["context"]["opaque"] = exotic
        validate = is_valid_audit_artifact_v2
    else:
        source = deepcopy(finalized_workflow)
        source["metadata"] = {"opaque": exotic}
        validate = is_valid_workflow_artifact_v2

    assert validate(source) is False


def _replace_path(source, path, value):
    changed = deepcopy(source)
    target = changed
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    return changed


def _audit_parity_source(chained_artifact):
    source = deepcopy(chained_artifact)
    source["context"] = {
        **source["context"],
        "session_id": "session",
        "step_id": "step",
        "step_index": 2,
        "workflow_policy_digest": "d" * 64,
    }
    source["metadata"] = {
        **source["metadata"],
        "pre_call_timestamp": 1,
        "post_call_timestamp": 2,
    }
    source["signature_metadata"] = {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "canonicalization_profile": "aegis-json-v2",
        "payload_type": "audit_artifact",
        "algorithm": "HMAC-SHA256",
        "signature_encoding": "hex",
        "key_reference": "key/reference",
        "key_version": "version/1",
        "signed_at": 1,
    }
    source["provenance"] = {
        "derived_from_audit_checksums": ["e" * 64],
        "compilation_source_hash": "f" * 64,
    }
    return source


@pytest.mark.parametrize(
    ("path", "below_minimum"),
    (
        (("timestamp",), -1),
        (("context", "step_index"), -1),
        (("metadata", "pre_call_timestamp"), -1),
        (("metadata", "post_call_timestamp"), -1),
        (("signature_metadata", "signed_at"), -1),
        (("chain_index",), -1),
    ),
)
def test_pure_audit_validator_matches_draft7_for_every_integer_field(
    chained_artifact,
    path,
    below_minimum,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_audit_artifact_v2,
    )

    source = _audit_parity_source(chained_artifact)
    schema = _audit_validator()
    for value, expected in (
        (3.0, True),
        (3.5, False),
        (True, False),
        (below_minimum, False),
    ):
        candidate = _replace_path(source, path, value)
        assert schema.is_valid(candidate) is expected
        assert is_valid_audit_artifact_v2(candidate) is expected


@pytest.mark.parametrize(
    ("path", "below_minimum", "negative_is_valid"),
    (
        (("started_at",), -1, True),
        (("finalized_at",), -1, True),
        (("step_count",), -1, False),
        (("invocations", 0, "step_index"), -1, False),
        (("approval_checkpoints", 0, "paused_at"), -1, True),
        (("approval_checkpoints", 0, "resumed_at"), -1, True),
    ),
)
def test_pure_workflow_validator_matches_draft7_for_every_integer_field(
    finalized_workflow,
    path,
    below_minimum,
    negative_is_valid,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_workflow_artifact_v2,
    )

    source = deepcopy(finalized_workflow)
    source["approval_checkpoints"] = [{"paused_at": 1, "resumed_at": 2}]
    schema = _workflow_validator()
    for value, expected in (
        (3.0, True),
        (3.5, False),
        (True, False),
        (below_minimum, negative_is_valid),
    ):
        candidate = _replace_path(source, path, value)
        assert schema.is_valid(candidate) is expected
        assert is_valid_workflow_artifact_v2(candidate) is expected


@pytest.mark.parametrize(
    "path",
    (
        ("input_checksum",),
        ("output_checksum",),
        ("context", "workflow_policy_digest"),
        ("checksum",),
        ("previous_audit_checksum",),
        ("provenance", "derived_from_audit_checksums", 0),
        ("provenance", "compilation_source_hash"),
    ),
)
def test_pure_audit_validator_uses_draft7_terminal_newline_pattern_semantics(
    chained_artifact,
    path,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_audit_artifact_v2,
    )

    source = _audit_parity_source(chained_artifact)
    candidate = _replace_path(source, path, "a" * 64 + "\n")

    assert _audit_validator().is_valid(candidate) is True
    assert is_valid_audit_artifact_v2(candidate) is True


@pytest.mark.parametrize(
    "path",
    (("checksum",), ("invocations", 0, "checksum")),
)
def test_pure_workflow_validator_uses_draft7_terminal_newline_pattern_semantics(
    finalized_workflow,
    path,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_workflow_artifact_v2,
    )

    candidate = _replace_path(finalized_workflow, path, "a" * 64 + "\n")

    assert _workflow_validator().is_valid(candidate) is True
    assert is_valid_workflow_artifact_v2(candidate) is True


@pytest.mark.parametrize(
    ("path", "invalid_values"),
    (
        (("signature_metadata", "algorithm"), ("ok\n", "sigé", "x" * 129)),
        (("signature_metadata", "key_reference"), ("ok\n", "keyé", "x" * 513)),
        (("signature_metadata", "key_version"), ("ok\n", "veré", "x" * 129)),
    ),
)
def test_pure_audit_validator_matches_all_bounded_identity_regex_fields(
    chained_artifact,
    path,
    invalid_values,
):
    from aegis._internal.checkpoint_source_validation import (
        is_valid_audit_artifact_v2,
    )

    source = _audit_parity_source(chained_artifact)
    for value in invalid_values:
        candidate = _replace_path(source, path, value)
        assert _audit_validator().is_valid(candidate) is False
        assert is_valid_audit_artifact_v2(candidate) is False


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


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("checkpoint_schema_version", _StringSubclass("1")),
        ("checkpoint_profile", _StringSubclass("aegis-chain-checkpoint-v1")),
        ("canonicalization_profile", _StringSubclass("aegis-json-v2")),
        ("chain_id", ""),
        ("chain_id", "   "),
        ("chain_id", _StringSubclass("checkpoint-chain")),
        ("chain_index", True),
        ("chain_index", 2.0),
        ("chain_index", -1),
        ("chain_index", SAFE_INTEGER_MAX + 1),
        ("chain_length", True),
        ("chain_length", 3.0),
        ("chain_length", 2),
        ("artifact_schema_version", _StringSubclass("2.0")),
        ("artifact_checksum", "A" * 64),
        ("artifact_checksum", "a" * 64 + "\n"),
        ("artifact_checksum", _StringSubclass("a" * 64)),
        ("checkpointed_at", True),
        ("checkpointed_at", 1_725_000_000.0),
        ("checkpointed_at", -1),
        ("checkpointed_at", SAFE_INTEGER_MAX + 1),
    ),
)
def test_chain_unsigned_record_preflight_exact_field_matrix(field, value):
    from aegis._internal.checkpoint_signing import _preflight_unsigned_checkpoint

    unsigned = {
        key: deepcopy(item)
        for key, item in EXPECTED_CHAIN_RECORD.items()
        if key not in {"signature_metadata", "signature"}
    }
    unsigned[field] = value

    with pytest.raises((CheckpointError, SignatureMetadataError)):
        _preflight_unsigned_checkpoint(
            unsigned,
            profile="aegis-chain-checkpoint-v1",
            payload_type=EvidenceType.CHAIN_CHECKPOINT,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("checkpoint_schema_version", _StringSubclass("1")),
        ("checkpoint_profile", _StringSubclass("aegis-workflow-checkpoint-v1")),
        ("canonicalization_profile", _StringSubclass("aegis-json-v2")),
        ("workflow_schema_version", _StringSubclass("2.0")),
        ("session_id", ""),
        ("session_id", "   "),
        ("session_id", _StringSubclass("checkpoint-session")),
        ("final_status", _StringSubclass("COMPLETED")),
        ("final_status", "RUNNING"),
        ("step_count", True),
        ("step_count", 2.0),
        ("step_count", -1),
        ("step_count", 1),
        ("step_count", SAFE_INTEGER_MAX + 1),
        ("workflow_checksum", "A" * 64),
        ("workflow_checksum", "a" * 64 + "\n"),
        ("workflow_checksum", _StringSubclass("a" * 64)),
        ("checkpointed_at", True),
        ("checkpointed_at", 1_725_000_001.0),
        ("checkpointed_at", -1),
        ("checkpointed_at", SAFE_INTEGER_MAX + 1),
    ),
)
def test_workflow_unsigned_record_preflight_exact_field_matrix(field, value):
    from aegis._internal.checkpoint_signing import _preflight_unsigned_checkpoint

    unsigned = {
        key: deepcopy(item)
        for key, item in EXPECTED_WORKFLOW_RECORD.items()
        if key not in {"signature_metadata", "signature"}
    }
    unsigned[field] = value

    with pytest.raises((CheckpointError, SignatureMetadataError)):
        _preflight_unsigned_checkpoint(
            unsigned,
            profile="aegis-workflow-checkpoint-v1",
            payload_type=EvidenceType.WORKFLOW_CHECKPOINT,
        )


@pytest.mark.parametrize(
    "invocations",
    (
        ({"step_index": True, "checksum": "b" * 64},),
        ({"step_index": 0.0, "checksum": "b" * 64},),
        ({"step_index": -0.0, "checksum": "b" * 64},),
        ({"step_index": -1, "checksum": "b" * 64},),
        ({"step_index": SAFE_INTEGER_MAX + 1, "checksum": "b" * 64},),
        ({"step_index": 1, "checksum": "b" * 64},),
        ({"step_index": 0, "checksum": "B" * 64},),
        ({"step_index": 0, "checksum": "b" * 64 + "\n"},),
        ({"step_index": 0, "checksum": _StringSubclass("b" * 64)},),
    ),
)
def test_workflow_unsigned_record_preflight_invocation_matrix(invocations):
    from aegis._internal.checkpoint_signing import _preflight_unsigned_checkpoint

    unsigned = {
        key: deepcopy(item)
        for key, item in EXPECTED_WORKFLOW_RECORD.items()
        if key not in {"signature_metadata", "signature"}
    }
    unsigned["step_count"] = len(invocations)
    unsigned["invocations"] = [dict(entry) for entry in invocations]

    with pytest.raises((CheckpointError, SignatureMetadataError)):
        _preflight_unsigned_checkpoint(
            unsigned,
            profile="aegis-workflow-checkpoint-v1",
            payload_type=EvidenceType.WORKFLOW_CHECKPOINT,
        )


class _ForbiddenSigner:
    def __init__(self) -> None:
        self.identity_calls = 0
        self.sign_calls = 0
        self.storage_calls = 0
        self.publish_calls = 0
        self.request_calls = 0

    def signer_identity(self):
        self.identity_calls += 1
        raise AssertionError("source preflight must precede identity lookup")

    def sign(self, payload, identity):
        del payload, identity
        self.sign_calls += 1
        raise AssertionError("source preflight must precede signing")

    def store(self, record) -> None:
        del record
        self.storage_calls += 1

    def publish(self, record) -> None:
        del record
        self.publish_calls += 1

    def request(self, payload) -> None:
        del payload
        self.request_calls += 1


class _StorageAwareSigner(DeterministicExternalSigner):
    def __init__(self, *, mode: str) -> None:
        super().__init__(mode=mode)
        self.storage_calls = 0

    def store(self, record) -> None:
        del record
        self.storage_calls += 1


class _OrderedCapabilitySigner(DeterministicExternalSigner):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []
        self.side_effect_calls: list[str] = []

    def signer_identity(self):
        self.events.append("signer_identity")
        return super().signer_identity()

    def sign(self, payload, identity):
        self.events.append("sign")
        return super().sign(payload, identity)

    def store(self, record) -> None:
        del record
        self.side_effect_calls.append("store")

    def publish(self, record) -> None:
        del record
        self.side_effect_calls.append("publish")

    def request(self, payload) -> None:
        del payload
        self.side_effect_calls.append("request")


@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_successful_creation_uses_only_ordered_signer_capabilities(
    chained_artifact,
    finalized_workflow,
    creator_name,
):
    source = (
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    source_before = deepcopy(source)
    creator = (
        create_chain_checkpoint
        if creator_name == "chain"
        else create_workflow_checkpoint
    )
    checkpointed_at = (
        1_725_000_000 if creator_name == "chain" else 1_725_000_001
    )
    signer = _OrderedCapabilitySigner()

    result = creator(source, signer, checkpointed_at=checkpointed_at)

    assert result is not None
    assert signer.events == ["signer_identity", "sign"]
    assert len(signer.payloads) == 1
    assert signer.side_effect_calls == []
    assert source == source_before


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
    assert getattr(signer, "identity_calls", 0) == 0
    assert getattr(signer, "storage_calls", 0) == 0
    assert getattr(signer, "publish_calls", 0) == 0
    assert getattr(signer, "request_calls", 0) == 0
    assert getattr(signer, "sign_calls", 0) == 0
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


@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_schema_valid_integral_float_is_rejected_by_checkpoint_exact_gates(
    chained_artifact,
    finalized_workflow,
    creator_name,
    caplog,
):
    from aegis._internal.evidence_profiles import build_content_checksum_v2

    source = deepcopy(
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    if creator_name == "chain":
        source["chain_index"] = 2.0
        creator = create_chain_checkpoint
    else:
        source["step_count"] = 2.0
        creator = create_workflow_checkpoint
    unsigned = {
        key: value
        for key, value in source.items()
        if key not in {
            "checksum",
            "signature",
            "signature_metadata",
            "signature_status",
        }
    }
    source["checksum"] = build_content_checksum_v2(unsigned)["checksum"]
    signer = _ForbiddenSigner()

    _assert_sanitized_failure(
        lambda: creator(source, signer, checkpointed_at=1_725_000_000),
        source,
        expected_code="CHECKPOINT_SOURCE_INVALID",
        signer=signer,
        caplog=caplog,
    )


@pytest.mark.parametrize(
    ("mutation", "case"),
    (
        (lambda source: source["invocations"][0].update(step_index=0.0), "float"),
        (lambda source: source["invocations"][0].update(step_index=-0.0), "negative-zero"),
        (
            lambda source: source["invocations"][0].update(
                checksum=source["invocations"][0]["checksum"] + "\n"
            ),
            "terminal-newline-checksum",
        ),
    ),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_workflow_copied_record_fields_fail_before_every_signer_capability(
    finalized_workflow,
    mutation,
    case,
    caplog,
):
    del case
    from aegis._internal.evidence_profiles import build_content_checksum_v2

    source = deepcopy(finalized_workflow)
    mutation(source)
    unsigned = {
        key: value
        for key, value in source.items()
        if key not in {
            "checksum",
            "signature",
            "signature_metadata",
            "signature_status",
        }
    }
    source["checksum"] = build_content_checksum_v2(unsigned)["checksum"]
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


@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_schema_valid_terminal_newline_checksum_fails_before_signer(
    chained_artifact,
    finalized_workflow,
    creator_name,
    caplog,
):
    source = deepcopy(
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    source["checksum"] += "\n"
    signer = _ForbiddenSigner()
    creator = (
        create_chain_checkpoint
        if creator_name == "chain"
        else create_workflow_checkpoint
    )

    _assert_sanitized_failure(
        lambda: creator(source, signer, checkpointed_at=1_725_000_000),
        source,
        expected_code="CHECKPOINT_SOURCE_INVALID",
        signer=signer,
        caplog=caplog,
    )


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

    def forbidden_validator(value):
        del value
        later_calls.append("schema")
        raise AssertionError

    def forbidden_checksum(value):
        del value
        later_calls.append("checksum")
        raise AssertionError

    monkeypatch.setattr(
        checkpoint_signing,
        "is_valid_audit_artifact_v2",
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


def test_workflow_source_limit_failure_stops_every_signer_capability(
    finalized_workflow,
    caplog,
):
    source = deepcopy(finalized_workflow)
    source["metadata"] = {"oversized": "x" * (4 * 1024 * 1024)}
    signer = _ForbiddenSigner()

    _assert_sanitized_failure(
        lambda: create_workflow_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_001,
        ),
        source,
        expected_code="CHECKPOINT_INPUT_INVALID",
        signer=signer,
        caplog=caplog,
    )

    assert signer.identity_calls == 0
    assert signer.sign_calls == 0


def test_escaped_source_over_canonical_byte_limit_stops_before_signer(
    chained_artifact,
):
    from aegis._internal.evidence_profiles import build_content_checksum_v2

    source = deepcopy(chained_artifact)
    source["context"]["padding"] = "\x00" * 700_000
    unsigned = {
        key: value
        for key, value in source.items()
        if key
        not in {
            "checksum",
            "signature",
            "signature_metadata",
            "signature_status",
        }
    }
    source["checksum"] = build_content_checksum_v2(unsigned)["checksum"]
    signer = _ForbiddenSigner()

    with pytest.raises(CheckpointError) as raised:
        create_chain_checkpoint(
            source,
            signer,
            checkpointed_at=1_725_000_000,
        )

    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert signer.identity_calls == 0
    assert signer.sign_calls == 0


@pytest.mark.parametrize("creator_name", ["chain", "workflow"])
def test_cyclic_source_stops_before_every_signer_capability(
    chained_artifact,
    finalized_workflow,
    creator_name,
    caplog,
):
    source = deepcopy(
        chained_artifact if creator_name == "chain" else finalized_workflow
    )
    cycle: list[object] = []
    cycle.append(cycle)
    source["cycle"] = cycle
    signer = _ForbiddenSigner()
    creator = (
        create_chain_checkpoint
        if creator_name == "chain"
        else create_workflow_checkpoint
    )

    with pytest.raises(CheckpointError) as raised:
        creator(source, signer, checkpointed_at=1_725_000_000)

    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}
    assert source["cycle"] is cycle
    assert cycle[0] is cycle
    assert signer.identity_calls == 0
    assert signer.sign_calls == 0
    assert signer.storage_calls == 0
    assert signer.publish_calls == 0
    assert signer.request_calls == 0
    public_text = str(raised.value) + repr(raised.value.details) + caplog.text
    for sensitive in SENSITIVE_CORPUS:
        assert sensitive not in public_text


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

    formatted = "".join(traceback.format_exception(error))
    assert error.__cause__ is None
    assert error.__context__ is None
    for sensitive in SENSITIVE_CORPUS:
        assert sensitive not in formatted
    expected_sign_calls = (
        0
        if mode.startswith("identity") or mode == "malformed_identity"
        else 1
    )
    assert len(signer.payloads) == expected_sign_calls


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
