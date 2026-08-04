"""Trusted chain-checkpoint verification and completeness binding."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from itertools import product

import pytest

import aegis._internal.chain_checkpoint_verification as checkpoint_verification_module
import aegis._internal.verification as verification_module
from aegis._internal.checkpoint_signing import _checkpoint_payload
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.signature_models import (
    AnchorStatus,
    SignatureMetadata,
    SignatureStatus,
)
from aegis.audit_chain import (
    ChainContinuity,
    ChainVerificationReport,
    Completeness,
    ContentIntegrity,
    verify_chain_detailed,
)
from aegis.checkpoints import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    TrustedChainCheckpoint,
    create_chain_checkpoint,
)
from tests.support.external_signing import (
    DeterministicExternalSigner,
    DeterministicExternalVerifier,
    SENSITIVE_CORPUS,
    default_key_records,
)


def _artifact(
    index: int,
    previous_checksum: str | None,
    *,
    chain_id: str = "checkpoint-chain",
    output_checksum: str = "c" * 64,
) -> dict[str, object]:
    artifact = build_content_checksum_v2(
        {
            "audit_schema_version": "2.0",
            "canonicalization_profile": "aegis-json-v2",
            "chain_id": chain_id,
            "chain_index": index,
            "context": {"tenant": "demo"},
            "enforcement_result": "PASS",
            "failure_gate": None,
            "failure_reason": None,
            "failures": [],
            "input_checksum": "b" * 64,
            "metadata": {},
            "model_identifier": "gpt-test",
            "model_provider": "openai",
            "output_checksum": output_checksum,
            "policy_file": "policy.yaml",
            "policy_schema_version": "http://json-schema.org/draft-07/schema#",
            "policy_version": "1.0",
            "previous_audit_checksum": previous_checksum,
            "provenance": None,
            "reservation_id": f"reservation-{index}",
            "risk_score": None,
            "role": "planner",
            "timestamp": 100 + index,
        }
    )
    artifact.update(signature=None, signature_status="unsigned")
    return artifact


@pytest.fixture
def valid_chain() -> list[dict[str, object]]:
    first = _artifact(0, None)
    second = _artifact(1, first["checksum"])
    third = _artifact(2, second["checksum"])
    return [first, second, third]


def _replacement_chain(
    length: int = 3,
    *,
    chain_id: str = "checkpoint-chain",
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    previous: str | None = None
    for index in range(length):
        artifact = _artifact(
            index,
            previous,
            chain_id=chain_id,
            output_checksum="d" * 64,
        )
        artifacts.append(artifact)
        previous = artifact["checksum"]  # type: ignore[assignment]
    return artifacts


def _resign_chain_checkpoint(
    checkpoint: TrustedChainCheckpoint,
    **updates: object,
) -> TrustedChainCheckpoint:
    unsigned = checkpoint.to_dict()
    unsigned.update(updates)
    unsigned.pop("signature_metadata")
    unsigned.pop("signature")
    metadata = SignatureMetadata.from_dict(
        checkpoint.signature_metadata.to_dict()
    )
    if "checkpointed_at" in updates:
        metadata = replace(metadata, signed_at=unsigned["checkpointed_at"])
    signer = DeterministicExternalSigner()
    receipt = signer.sign(
        _checkpoint_payload(unsigned, metadata),
        signer.signer_identity(),
    )
    return TrustedChainCheckpoint.from_dict(
        {
            **unsigned,
            "signature_metadata": metadata.to_dict(),
            "signature": receipt.signature,
        }
    )


@pytest.fixture
def chain_checkpoint(valid_chain):
    return create_chain_checkpoint(
        valid_chain[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )


@pytest.fixture
def verifier():
    return DeterministicExternalVerifier()


class _CountingVerifier:
    def __init__(self, delegate=None, events=None):
        self.delegate = delegate or DeterministicExternalVerifier()
        self.events = events
        self.calls = 0

    def verify(self, payload, signature, metadata):
        self.calls += 1
        if self.events is not None:
            self.events.append("checkpoint")
        return self.delegate.verify(payload, signature, metadata)


class _HostileCheckpointIterator:
    def __init__(self, values, *, infinite=False):
        self._values = values
        self._infinite = infinite
        self.next_calls = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.next_calls += 1
        index = self.next_calls - 1
        if self._infinite:
            return self._values[index % len(self._values)]
        if index >= len(self._values):
            raise StopIteration
        return self._values[index]

    def __bool__(self):
        raise AssertionError("caller truthiness must not be used")

    def __len__(self):
        raise AssertionError("caller len must not be used")

    def __length_hint__(self):
        raise AssertionError("caller length hint must not be used")

    def __repr__(self):
        raise AssertionError("caller repr must not be used")


def _distinct_checkpoint_dicts(checkpoint, count):
    source = checkpoint.to_dict()
    return [
        {**deepcopy(source), "signature": f"{index + 1:064x}"}
        for index in range(count)
    ]


def test_no_checkpoint_preserves_current_report(valid_chain):
    before = verify_chain_detailed(valid_chain)
    after = verify_chain_detailed(valid_chain, checkpoints=())

    assert after == before
    assert (
        after.checkpoint_signature_status
        is CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert after.checkpoint_results == ()


def test_absent_checkpoint_input_does_not_consume_chain_budget():
    artifact = {"nodes": [None] * 65_533}

    report = verify_chain_detailed([artifact])

    assert report.content_integrity is ContentIntegrity.INVALID
    assert report.chain_continuity is ChainContinuity.UNCHAINED
    assert not any(
        error.code == "CHAIN_VERIFICATION_LIMIT_EXCEEDED"
        for error in report.errors
    )


def test_anchored_terminal_checkpoint_proves_complete_chain(
    valid_chain, chain_checkpoint, verifier
):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=verifier,
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.MATCHED
    )


def test_checkpoint_does_not_change_existing_verification_axes(
    valid_chain, chain_checkpoint, verifier
):
    baseline = verify_chain_detailed(valid_chain)
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=verifier,
    )

    assert (
        report.content_integrity,
        report.chain_continuity,
        report.signature_status,
        report.anchor_status,
        report.internal_valid,
    ) == (
        baseline.content_integrity,
        baseline.chain_continuity,
        baseline.signature_status,
        baseline.anchor_status,
        baseline.internal_valid,
    )


def test_report_constructor_retains_positional_and_keyword_compatibility():
    positional = ChainVerificationReport(
        ContentIntegrity.VALID,
        ChainContinuity.VALID,
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        Completeness.UNPROVEN,
        (),
    )
    keyword = ChainVerificationReport(
        content_integrity=ContentIntegrity.VALID,
        chain_continuity=ChainContinuity.VALID,
        signature_status=SignatureStatus.UNSIGNED,
        anchor_status=AnchorStatus.NOT_EVALUATED,
        completeness=Completeness.UNPROVEN,
        errors=(),
    )

    assert positional == keyword
    assert positional.checkpoint_results == ()
    assert (
        positional.checkpoint_signature_status
        is CheckpointSignatureStatus.NOT_EVALUATED
    )


def test_checkpoint_input_preflight_precedes_all_verification_axes_and_callbacks(
    valid_chain, chain_checkpoint, monkeypatch
):
    events: list[str] = []
    original_content = verification_module._verify_content
    original_continuity = verification_module._verify_continuity
    original_signatures = verification_module._verify_signatures

    def checkpoints():
        events.append("checkpoint-input")
        yield chain_checkpoint

    def content(*args, **kwargs):
        events.append("content")
        return original_content(*args, **kwargs)

    def continuity(*args, **kwargs):
        events.append("continuity")
        return original_continuity(*args, **kwargs)

    def signatures(*args, **kwargs):
        events.append("signature")
        return original_signatures(*args, **kwargs)

    def anchor(_artifacts):
        events.append("anchor")
        return AnchorStatus.NOT_EVALUATED

    monkeypatch.setattr(verification_module, "_verify_content", content)
    monkeypatch.setattr(verification_module, "_verify_continuity", continuity)
    monkeypatch.setattr(verification_module, "_verify_signatures", signatures)
    checkpoint_verifier = _CountingVerifier(events=events)

    verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints(),
        checkpoint_verifier=checkpoint_verifier,
        anchor_verifier=anchor,
    )

    assert events == [
        "checkpoint-input",
        "content",
        "continuity",
        "signature",
        "anchor",
        "checkpoint",
    ]


def test_checkpoint_iterator_cannot_replace_measured_artifacts_before_axes(
    valid_chain, chain_checkpoint
):
    replacement = _replacement_chain()

    def checkpoints():
        replacement[:] = deepcopy(valid_chain)
        yield chain_checkpoint

    report = verify_chain_detailed(
        replacement,
        checkpoints=checkpoints(),
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.CONFLICT
    assert report.completeness is Completeness.CONTRADICTED


def test_checkpoint_iterator_cannot_bypass_measured_resource_limit(
    valid_chain, chain_checkpoint
):
    replacement = _replacement_chain()

    def checkpoints():
        replacement[:] = deepcopy(valid_chain)
        replacement[-1]["late_mutation"] = [None] * 70_000
        yield chain_checkpoint

    report = verify_chain_detailed(
        replacement,
        checkpoints=checkpoints(),
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.CONFLICT
    assert report.completeness is Completeness.CONTRADICTED


def test_compatibility_anchor_callback_cannot_mutate_checkpoint_binding(
    valid_chain, chain_checkpoint
):
    replacement = _replacement_chain()

    def mutating_anchor(artifacts):
        artifacts[-1]["checksum"] = chain_checkpoint.artifact_checksum
        return AnchorStatus.NOT_EVALUATED

    report = verify_chain_detailed(
        replacement,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
        anchor_verifier=mutating_anchor,
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.CONFLICT
    assert report.completeness is Completeness.CONTRADICTED


@pytest.mark.parametrize(
    "artifacts",
    [pytest.param({}, id="non-list"), pytest.param([None] * 1_025, id="too-many")],
)
def test_invalid_chain_input_does_not_consume_checkpoint_input(artifacts):
    class NeverConsumed:
        def __iter__(self):
            raise AssertionError("checkpoint input was consumed")

    report = verify_chain_detailed(artifacts, checkpoints=NeverConsumed())

    assert report.checkpoint_results == ()
    assert (
        report.checkpoint_signature_status
        is CheckpointSignatureStatus.NOT_EVALUATED
    )


def test_invalid_explicit_scope_precedes_checkpoint_consumption(valid_chain):
    class NeverConsumed:
        def __iter__(self):
            raise AssertionError("checkpoint input was consumed")

    report = verify_chain_detailed(
        valid_chain,
        expected_chain_id="   ",
        checkpoints=NeverConsumed(),
    )

    assert report.content_integrity is ContentIntegrity.NOT_EVALUATED
    assert report.chain_continuity is ChainContinuity.NOT_EVALUATED
    assert [error.code for error in report.errors] == ["CHECKPOINT_SCOPE_INVALID"]


@pytest.mark.parametrize(
    "artifacts",
    [
        pytest.param([], id="empty"),
        pytest.param(
            [_artifact(0, None) | {"chain_id": None}],
            id="invalid",
        ),
    ],
)
def test_checkpoint_input_cannot_select_scope_from_invalid_chain(
    artifacts, chain_checkpoint
):
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        artifacts,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert checkpoint_verifier.calls == 0
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.NOT_EVALUATED
    )
    assert report.checkpoint_results[0].signature_result is None
    assert report.completeness is Completeness.UNPROVEN


@pytest.mark.parametrize("malformed", [{}, object()])
def test_malformed_checkpoint_never_reaches_provider(valid_chain, malformed):
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[malformed],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert checkpoint_verifier.calls == 0
    assert report.checkpoint_results == ()
    assert (
        report.checkpoint_signature_status
        is CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_RECORD_INVALID", 0)
    ]


@pytest.mark.parametrize("checkpoints", [None, [object()] * 65])
def test_invalid_or_over_limit_checkpoint_input_precedes_all_callbacks(
    valid_chain, checkpoints
):
    calls: list[str] = []

    def callback(*_args):
        calls.append("callback")
        return AnchorStatus.ANCHORED

    report = verify_chain_detailed(
        valid_chain,
        signature_verifier=_CountingVerifier(events=calls),
        anchor_verifier=callback,
        checkpoints=checkpoints,
        checkpoint_verifier=_CountingVerifier(events=calls),
    )

    assert calls == []
    assert report.content_integrity is ContentIntegrity.NOT_EVALUATED
    assert report.chain_continuity is ChainContinuity.NOT_EVALUATED
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_INPUT_INVALID"
        if checkpoints is None
        else "CHECKPOINT_LIMIT_EXCEEDED"
    ]


def test_checkpoint_subclass_never_reaches_provider(valid_chain, chain_checkpoint):
    class CheckpointSubclass(TrustedChainCheckpoint):
        pass

    subclass = CheckpointSubclass(
        *(
            getattr(chain_checkpoint, field)
            for field in TrustedChainCheckpoint.__dataclass_fields__
        )
    )
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[subclass],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert checkpoint_verifier.calls == 0
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_RECORD_INVALID"
    ]


def test_forged_exact_checkpoint_is_reparsed_before_provider(
    valid_chain, chain_checkpoint
):
    forged = object.__new__(TrustedChainCheckpoint)
    for field in TrustedChainCheckpoint.__dataclass_fields__:
        object.__setattr__(forged, field, getattr(chain_checkpoint, field))
    object.__setattr__(forged, "chain_length", 999)
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[forged],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert checkpoint_verifier.calls == 0
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_RECORD_INVALID"
    ]


def test_exact_dictionary_checkpoint_is_snapshotted_and_not_mutated(
    valid_chain, chain_checkpoint
):
    supplied = chain_checkpoint.to_dict()
    before = deepcopy(supplied)

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[supplied],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert supplied == before
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_results[0].checkpoint is not chain_checkpoint


def test_exact_duplicate_checkpoint_records_verify_once(valid_chain, chain_checkpoint):
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint, chain_checkpoint.to_dict()],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert checkpoint_verifier.calls == 1
    assert report.checkpoint_results[0].input_indexes == (0, 1)
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_same_checkpoint_dictionary_object_is_snapshotted_per_occurrence(
    valid_chain, chain_checkpoint, verifier
):
    supplied = chain_checkpoint.to_dict()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[supplied, supplied],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 1
    assert len(report.checkpoint_results) == 1
    assert report.checkpoint_results[0].input_indexes == (0, 1)
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_reused_mutating_checkpoint_dictionary_is_snapshotted_at_each_yield(
    valid_chain, chain_checkpoint
):
    historical = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )
    reused = chain_checkpoint.to_dict()

    def checkpoints():
        yield reused
        reused.clear()
        reused.update(historical.to_dict())
        yield reused

    verifier = DeterministicExternalVerifier()
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints(),
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 2
    assert [result.input_indexes for result in report.checkpoint_results] == [
        (0,),
        (1,),
    ]
    assert [result.binding_status for result in report.checkpoint_results] == [
        CheckpointBindingStatus.MATCHED,
        CheckpointBindingStatus.HISTORICAL,
    ]
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


@pytest.mark.parametrize("reverse", [False, True])
def test_consistent_anchored_checkpoints_at_multiple_coordinates_prove_terminal_head(
    valid_chain,
    reverse,
):
    historical = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )
    terminal = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_002,
    )

    checkpoints = [historical, terminal] if reverse else [terminal, historical]
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints,
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert [result.binding_status for result in report.checkpoint_results] == [
        (
            CheckpointBindingStatus.HISTORICAL
            if reverse
            else CheckpointBindingStatus.MATCHED
        ),
        (
            CheckpointBindingStatus.MATCHED
            if reverse
            else CheckpointBindingStatus.HISTORICAL
        ),
    ]
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_out_of_scope_checkpoint_is_diagnostic_and_never_calls_provider(
    valid_chain,
):
    other_chain = _replacement_chain(chain_id="other-chain")
    checkpoint = create_chain_checkpoint(
        other_chain[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    verifier = DeterministicExternalVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[checkpoint],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 0
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.NOT_EVALUATED
    assert report.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.OUT_OF_SCOPE
    )
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_SCOPE_MISMATCH", 0)
    ]


def test_out_of_scope_record_does_not_degrade_in_scope_terminal_proof(
    valid_chain, chain_checkpoint
):
    other_chain = _replacement_chain(chain_id="other-chain")
    other_checkpoint = create_chain_checkpoint(
        other_chain[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )
    verifier = DeterministicExternalVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[other_checkpoint, chain_checkpoint],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 1
    assert [result.binding_status for result in report.checkpoint_results] == [
        CheckpointBindingStatus.OUT_OF_SCOPE,
        CheckpointBindingStatus.MATCHED,
    ]
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_SCOPE_MISMATCH", 0)
    ]


def test_binding_conflict_error_uses_conflicting_record_caller_index(
    valid_chain, chain_checkpoint
):
    other_chain = _replacement_chain(chain_id="other-chain")
    out_of_scope = create_chain_checkpoint(
        other_chain[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )
    conflicting = _resign_chain_checkpoint(
        chain_checkpoint,
        artifact_checksum="d" * 64,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[out_of_scope, chain_checkpoint, conflicting],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.completeness is Completeness.CONTRADICTED
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_SCOPE_MISMATCH", 0),
        ("CHECKPOINT_BINDING_CONFLICT", 2),
    ]


def test_same_coordinate_anchored_checksum_disagreement_is_authoritative_conflict(
    valid_chain, chain_checkpoint
):
    conflicting = _resign_chain_checkpoint(
        chain_checkpoint,
        artifact_checksum="d" * 64,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint, conflicting],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_BINDING_CONFLICT", 1)
    ]


def test_same_coordinate_authority_conflict_does_not_require_supplied_link(
    valid_chain,
):
    checkpoint = create_chain_checkpoint(
        valid_chain[0],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    conflicting = _resign_chain_checkpoint(
        checkpoint,
        artifact_checksum="d" * 64,
    )

    report = verify_chain_detailed(
        valid_chain[2:],
        expected_chain_id="checkpoint-chain",
        checkpoints=[checkpoint, conflicting],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert [result.binding_status for result in report.checkpoint_results] == [
        CheckpointBindingStatus.OUTSIDE,
        CheckpointBindingStatus.OUTSIDE,
    ]
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_BINDING_CONFLICT", 0)
    ]


@pytest.mark.parametrize(
    "order",
    [
        ("first-checksum", "second-claim-1", "second-claim-2"),
        ("second-claim-1", "second-claim-2", "first-checksum"),
    ],
)
def test_same_coordinate_conflict_marks_every_authority_regardless_of_order(
    valid_chain,
    order,
):
    first_checksum = create_chain_checkpoint(
        valid_chain[0],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    second_claim_1 = _resign_chain_checkpoint(
        first_checksum,
        artifact_checksum="d" * 64,
    )
    second_claim_2 = _resign_chain_checkpoint(
        second_claim_1,
        checkpointed_at=1_725_000_001,
    )
    by_name = {
        "first-checksum": first_checksum,
        "second-claim-1": second_claim_1,
        "second-claim-2": second_claim_2,
    }

    report = verify_chain_detailed(
        valid_chain[2:],
        expected_chain_id="checkpoint-chain",
        checkpoints=[by_name[name] for name in order],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert [result.binding_status for result in report.checkpoint_results] == [
        CheckpointBindingStatus.OUTSIDE,
        CheckpointBindingStatus.OUTSIDE,
        CheckpointBindingStatus.OUTSIDE,
    ]
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_BINDING_CONFLICT", 0),
    ]


def test_explicit_scope_mismatch_requires_anchored_in_scope_authority(valid_chain):
    evidence = _replacement_chain(chain_id="evidence-chain")
    evidence_checkpoint = create_chain_checkpoint(
        evidence[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    untrusted_in_scope = _resign_chain_checkpoint(
        evidence_checkpoint,
        chain_id="expected-chain",
    ).to_dict()
    untrusted_in_scope["signature"] = "00" * 32

    report = verify_chain_detailed(
        evidence,
        expected_chain_id="expected-chain",
        checkpoints=[untrusted_in_scope],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.MATCHED
    )
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.INVALID
    assert report.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN
    assert not any(
        error.code == "CHECKPOINT_BINDING_CONFLICT" for error in report.errors
    )


def test_identifier_replacement_without_explicit_scope_is_out_of_scope(
    valid_chain, chain_checkpoint
):
    replacement = _replacement_chain(chain_id="replacement-chain")
    verifier = DeterministicExternalVerifier()

    report = verify_chain_detailed(
        replacement,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 0
    assert report.completeness is Completeness.UNPROVEN
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.OUT_OF_SCOPE
    )


def test_current_and_host_accepted_historical_keys_can_jointly_prove_head(
    valid_chain,
):
    historical = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(key_version="version/historical"),
        checkpointed_at=9_999_999_999,
    )
    current = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(key_version="version/current"),
        checkpointed_at=1,
    )
    records = dict(default_key_records())
    records["version/historical"] = replace(
        records["version/historical"],
        anchor_status=AnchorStatus.ANCHORED,
    )
    verifier = DeterministicExternalVerifier(
        key_records={
            (record.key_reference, record.key_version): record
            for record in records.values()
        }
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[current, historical],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 2
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_unanchored_historical_key_cannot_be_hidden_by_current_anchored_key(
    valid_chain,
):
    historical = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(key_version="version/historical"),
        checkpointed_at=1_725_000_001,
    )
    current = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(key_version="version/current"),
        checkpointed_at=1_725_000_002,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[current, historical],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.UNANCHORED
    assert report.completeness is Completeness.UNPROVEN


def test_revoked_key_cannot_be_hidden_by_current_anchored_key(valid_chain):
    revoked = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(key_version="version/revoked"),
        checkpointed_at=1,
    )
    current = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(key_version="version/current"),
        checkpointed_at=9_999_999_999,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[current, revoked],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.REVOKED
    assert report.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN


def test_boolean_noninitial_chain_index_cannot_participate_in_checkpoint_proof():
    first = _artifact(0, None)
    boolean_coordinate = _artifact(True, first["checksum"])
    terminal = _artifact(2, boolean_coordinate["checksum"])
    artifacts = [first, boolean_coordinate, terminal]
    checkpoint = create_chain_checkpoint(
        terminal,
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )

    report = verify_chain_detailed(
        artifacts,
        expected_chain_id="checkpoint-chain",
        checkpoints=[checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.INVALID
    assert report.completeness is not Completeness.CHECKPOINT_PROVEN
    assert any(error.code == "CHAIN_INDEX_INVALID" for error in report.errors)


_CHECKPOINT_SIGNATURE_PRECEDENCE = (
    CheckpointSignatureStatus.NOT_EVALUATED,
    CheckpointSignatureStatus.VALID,
    CheckpointSignatureStatus.UNKNOWN_KEY,
    CheckpointSignatureStatus.REVOKED,
    CheckpointSignatureStatus.INVALID,
    CheckpointSignatureStatus.INDETERMINATE,
)


@pytest.mark.parametrize(
    ("left", "right"),
    tuple(product(_CHECKPOINT_SIGNATURE_PRECEDENCE, repeat=2)),
)
def test_every_checkpoint_signature_status_pair_uses_explicit_precedence(
    left,
    right,
):
    aggregate = getattr(
        checkpoint_verification_module,
        "_aggregate_checkpoint_signature_status",
        None,
    )
    expected = _CHECKPOINT_SIGNATURE_PRECEDENCE[
        max(
            _CHECKPOINT_SIGNATURE_PRECEDENCE.index(left),
            _CHECKPOINT_SIGNATURE_PRECEDENCE.index(right),
        )
    ]

    assert callable(aggregate)
    assert aggregate((left, right)) is expected


_CHECKPOINT_ANCHOR_PRECEDENCE = (
    AnchorStatus.ANCHORED,
    AnchorStatus.UNANCHORED,
    AnchorStatus.NOT_EVALUATED,
    AnchorStatus.INVALID,
)


@pytest.mark.parametrize(
    ("left", "right"),
    tuple(product(_CHECKPOINT_ANCHOR_PRECEDENCE, repeat=2)),
)
def test_every_checkpoint_anchor_status_pair_uses_explicit_precedence(
    left,
    right,
):
    aggregate = getattr(
        checkpoint_verification_module,
        "_aggregate_checkpoint_anchor_status",
        None,
    )
    expected = _CHECKPOINT_ANCHOR_PRECEDENCE[
        max(
            _CHECKPOINT_ANCHOR_PRECEDENCE.index(left),
            _CHECKPOINT_ANCHOR_PRECEDENCE.index(right),
        )
    ]

    assert callable(aggregate)
    assert aggregate((left, right)) is expected


def test_empty_checkpoint_status_aggregation_uses_unevaluated_defaults():
    aggregate_signature = getattr(
        checkpoint_verification_module,
        "_aggregate_checkpoint_signature_status",
        None,
    )
    aggregate_anchor = getattr(
        checkpoint_verification_module,
        "_aggregate_checkpoint_anchor_status",
        None,
    )

    assert callable(aggregate_signature)
    assert callable(aggregate_anchor)
    assert (
        aggregate_signature(())
        is CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert aggregate_anchor(()) is AnchorStatus.NOT_EVALUATED


@pytest.mark.parametrize(
    ("checkpoint_position", "window", "binding", "completeness"),
    [
        (1, slice(None), CheckpointBindingStatus.HISTORICAL, Completeness.UNPROVEN),
        (3, slice(0, 3), CheckpointBindingStatus.AHEAD, Completeness.CONTRADICTED),
        (1, slice(1, 3), CheckpointBindingStatus.PARTIAL, Completeness.UNPROVEN),
        (0, slice(1, 3), CheckpointBindingStatus.OUTSIDE, Completeness.UNPROVEN),
        (3, slice(1, 3), CheckpointBindingStatus.AHEAD, Completeness.UNPROVEN),
    ],
)
def test_checkpoint_binding_preserves_historical_partial_and_ahead_semantics(
    valid_chain, checkpoint_position, window, binding, completeness
):
    fourth = _artifact(3, valid_chain[-1]["checksum"])
    extended_chain = [*valid_chain, fourth]
    checkpoint = create_chain_checkpoint(
        extended_chain[checkpoint_position],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000 + checkpoint_position,
    )

    report = verify_chain_detailed(
        extended_chain[window],
        checkpoints=[checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_results[0].binding_status is binding
    assert report.completeness is completeness


def test_unanchored_terminal_checkpoint_does_not_promote_completeness(valid_chain):
    checkpoint = create_chain_checkpoint(
        valid_chain[-1],
        DeterministicExternalSigner(key_version="version/historical"),
        checkpointed_at=1_725_000_000,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.UNANCHORED
    assert report.completeness is Completeness.UNPROVEN


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_anchor", "expects_error"),
    [
        (
            "unavailable",
            CheckpointSignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            False,
        ),
        (
            "unexpected",
            CheckpointSignatureStatus.INDETERMINATE,
            AnchorStatus.INVALID,
            True,
        ),
        (
            "malformed",
            CheckpointSignatureStatus.INDETERMINATE,
            AnchorStatus.INVALID,
            True,
        ),
    ],
)
def test_provider_failure_keeps_structural_binding_and_never_promotes(
    valid_chain,
    chain_checkpoint,
    mode,
    expected_status,
    expected_anchor,
    expects_error,
):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(mode=mode),
    )

    assert report.checkpoint_signature_status is expected_status
    assert report.checkpoint_anchor_status is expected_anchor
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.MATCHED
    )
    assert report.completeness is Completeness.UNPROVEN
    assert (
        "CHECKPOINT_VERIFICATION_ERROR" in [error.code for error in report.errors]
    ) is expects_error
    assert "provider-token" not in repr(report.errors)


def test_checkpoint_errors_are_emitted_in_caller_input_order(
    valid_chain, chain_checkpoint
):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint, {}],
        checkpoint_verifier=DeterministicExternalVerifier(mode="unexpected"),
    )

    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_VERIFICATION_ERROR", 0),
        ("CHECKPOINT_RECORD_INVALID", 1),
    ]


def test_invalid_signature_keeps_matched_binding_without_trust_promotion(
    valid_chain, chain_checkpoint
):
    forged = chain_checkpoint.to_dict()
    forged["signature"] = "00" * 32

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[forged],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.INVALID
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.MATCHED
    )
    assert report.completeness is Completeness.UNPROVEN


def test_checksum_valid_whole_chain_replacement_is_contradicted(
    valid_chain, chain_checkpoint
):
    replacement = _replacement_chain()

    report = verify_chain_detailed(
        replacement,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.CONFLICT
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_BINDING_CONFLICT"
    ]


@pytest.mark.parametrize("relationship", ["conflict", "ahead"])
@pytest.mark.parametrize("malformed_first", [False, True])
def test_malformed_checkpoint_cannot_mask_singular_trusted_contradiction(
    valid_chain,
    chain_checkpoint,
    relationship,
    malformed_first,
):
    artifacts = (
        _replacement_chain()
        if relationship == "conflict"
        else valid_chain[:-1]
    )
    checkpoints = (
        [{}, chain_checkpoint]
        if malformed_first
        else [chain_checkpoint, {}]
    )

    report = verify_chain_detailed(
        artifacts,
        checkpoints=checkpoints,
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    expected_binding = (
        CheckpointBindingStatus.CONFLICT
        if relationship == "conflict"
        else CheckpointBindingStatus.AHEAD
    )
    assert report.checkpoint_results[0].binding_status is expected_binding
    assert (
        report.checkpoint_signature_status
        is CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    trusted_index = 1 if malformed_first else 0
    malformed_index = 0 if malformed_first else 1
    assert [(error.code, error.index) for error in report.errors] == sorted(
        [
            ("CHECKPOINT_BINDING_CONFLICT", trusted_index),
            ("CHECKPOINT_RECORD_INVALID", malformed_index),
        ],
        key=lambda error: error[1],
    )


def test_explicit_scope_mismatch_conflicts_even_when_checkpoint_checksum_matches(
    valid_chain,
):
    evidence = _replacement_chain(chain_id="evidence-chain")
    evidence_checkpoint = create_chain_checkpoint(
        evidence[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    in_scope_checkpoint = _resign_chain_checkpoint(
        evidence_checkpoint,
        chain_id="expected-chain",
    )

    report = verify_chain_detailed(
        evidence,
        expected_chain_id="expected-chain",
        checkpoints=[in_scope_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.CONFLICT
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_BINDING_CONFLICT", 0)
    ]


def test_full_chain_tail_deletion_is_contradicted(valid_chain, chain_checkpoint):
    report = verify_chain_detailed(
        valid_chain[:-1],
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.chain_continuity is ChainContinuity.VALID
    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.AHEAD
    assert report.completeness is Completeness.CONTRADICTED


def test_unchained_input_cannot_derive_checkpoint_scope(valid_chain, chain_checkpoint):
    unsigned = {
        key: value
        for key, value in valid_chain[0].items()
        if key
        not in {
            "chain_id",
            "chain_index",
            "previous_audit_checksum",
            "reservation_id",
            "checksum",
            "signature",
            "signature_status",
        }
    }
    unchained = build_content_checksum_v2(unsigned)
    unchained.update(signature=None, signature_status="unsigned")
    checkpoint_verifier = _CountingVerifier()

    report = verify_chain_detailed(
        [unchained],
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=checkpoint_verifier,
    )

    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.UNCHAINED
    assert checkpoint_verifier.calls == 0
    assert (
        report.checkpoint_results[0].binding_status
        is CheckpointBindingStatus.NOT_EVALUATED
    )


@pytest.mark.parametrize("mutation", ["body", "checksum", "link"])
def test_mutation_never_promotes_checkpoint_completeness(
    valid_chain, chain_checkpoint, mutation
):
    mutated = deepcopy(valid_chain)
    if mutation == "body":
        mutated[-1]["context"]["tenant"] = "tampered"  # type: ignore[index]
    elif mutation == "checksum":
        mutated[-1]["checksum"] = "f" * 64
    else:
        mutated[-1]["previous_audit_checksum"] = "f" * 64

    report = verify_chain_detailed(
        mutated,
        expected_chain_id="checkpoint-chain",
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.completeness is not Completeness.CHECKPOINT_PROVEN


@pytest.mark.parametrize("change", ["insert", "delete", "reorder"])
def test_structural_chain_changes_never_promote_checkpoint_completeness(
    valid_chain, chain_checkpoint, change
):
    changed = list(valid_chain)
    if change == "insert":
        changed.insert(1, _artifact(99, "e" * 64))
    elif change == "delete":
        del changed[1]
    else:
        changed[0], changed[1] = changed[1], changed[0]

    report = verify_chain_detailed(
        changed,
        expected_chain_id="checkpoint-chain",
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.completeness is not Completeness.CHECKPOINT_PROVEN


@pytest.mark.parametrize(
    "stream_kind",
    ["distinct", "duplicate", "malformed", "infinite"],
)
def test_raw_checkpoint_limit_reads_only_the_sixty_fifth_element_and_stops(
    valid_chain,
    chain_checkpoint,
    stream_kind,
):
    source = chain_checkpoint.to_dict()
    if stream_kind == "distinct":
        values = _distinct_checkpoint_dicts(chain_checkpoint, 65)
    elif stream_kind == "malformed":
        values = [{} for _ in range(65)]
    else:
        values = [source] * 65
    checkpoints = _HostileCheckpointIterator(
        [source] if stream_kind == "infinite" else values,
        infinite=stream_kind == "infinite",
    )
    checkpoint_verifier = DeterministicExternalVerifier()
    callbacks: list[str] = []

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints,
        checkpoint_verifier=checkpoint_verifier,
        anchor_verifier=lambda _artifacts: callbacks.append("anchor")
        or AnchorStatus.ANCHORED,
    )

    assert checkpoints.next_calls == 65
    assert checkpoint_verifier.call_count == 0
    assert callbacks == []
    assert report.content_integrity is ContentIntegrity.NOT_EVALUATED
    assert report.chain_continuity is ChainContinuity.NOT_EVALUATED
    assert report.checkpoint_results == ()
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_LIMIT_EXCEEDED"
    ]


def test_sixty_four_raw_duplicate_occurrences_verify_once(valid_chain, chain_checkpoint):
    source = chain_checkpoint.to_dict()
    checkpoints = _HostileCheckpointIterator([source] * 64)
    verifier = DeterministicExternalVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints,
        checkpoint_verifier=verifier,
    )

    assert checkpoints.next_calls == 65
    assert verifier.call_count == 1
    assert len(report.checkpoint_results) == 1
    assert report.checkpoint_results[0].input_indexes == tuple(range(64))
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_checkpoint_provider_call_count_is_capped_at_sixty_four_unique_records(
    valid_chain,
    chain_checkpoint,
):
    checkpoints = _HostileCheckpointIterator(
        _distinct_checkpoint_dicts(chain_checkpoint, 64)
    )
    verifier = DeterministicExternalVerifier()

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints,
        checkpoint_verifier=verifier,
    )

    assert checkpoints.next_calls == 65
    assert verifier.call_count == 64
    assert len(report.checkpoint_results) == 64
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN


def test_checkpoint_iterator_exception_is_sanitized_before_callbacks(
    valid_chain,
    chain_checkpoint,
):
    class ExplodingIterator:
        def __init__(self):
            self.calls = 0

        def __iter__(self):
            return self

        def __next__(self):
            self.calls += 1
            if self.calls == 1:
                return chain_checkpoint
            raise RuntimeError(" | ".join(SENSITIVE_CORPUS))

    checkpoints = ExplodingIterator()
    verifier = DeterministicExternalVerifier()
    callbacks: list[str] = []

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=checkpoints,
        checkpoint_verifier=verifier,
        anchor_verifier=lambda _artifacts: callbacks.append("anchor")
        or AnchorStatus.ANCHORED,
    )

    assert checkpoints.calls == 2
    assert verifier.call_count == 0
    assert callbacks == []
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_INPUT_INVALID"
    ]
    assert not any(secret in repr(report.errors) for secret in SENSITIVE_CORPUS)


def _hostile_checkpoint_graph(kind):
    if kind == "bytes":
        return {"oversized": "x" * (4 * 1024 * 1024 + 1)}
    if kind == "nodes":
        return {"nodes": [None] * 65_537}
    if kind == "depth":
        nested = None
        for _ in range(33):
            nested = [nested]
        return {"nested": nested}
    if kind == "cycle":
        cyclic = {}
        cyclic["cycle"] = cyclic
        return cyclic
    if kind == "custom-container":
        class CustomList(list):
            pass

        return {"custom": CustomList()}
    if kind == "non-string-key":
        return {1: "value"}
    raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind",
    ["bytes", "nodes", "depth", "cycle", "custom-container", "non-string-key"],
)
def test_checkpoint_resource_preflight_rejects_hostile_graphs_before_all_callbacks(
    valid_chain,
    kind,
):
    verifier = DeterministicExternalVerifier()
    callbacks: list[str] = []

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[_hostile_checkpoint_graph(kind)],
        checkpoint_verifier=verifier,
        anchor_verifier=lambda _artifacts: callbacks.append("anchor")
        or AnchorStatus.ANCHORED,
    )

    assert verifier.call_count == 0
    assert callbacks == []
    assert report.content_integrity is ContentIntegrity.NOT_EVALUATED
    assert report.chain_continuity is ChainContinuity.NOT_EVALUATED
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_LIMIT_EXCEEDED"
    ]


@pytest.mark.parametrize("resource", ["bytes", "nodes"])
def test_chain_and_checkpoints_share_one_aggregate_resource_budget(resource):
    if resource == "bytes":
        artifacts = [{"left": "a" * 2_100_000}]
        checkpoint = {"right": "b" * 2_100_000}
    else:
        artifacts = [{"left": [None] * 40_000}]
        checkpoint = {"right": [None] * 40_000}
    verifier = DeterministicExternalVerifier()
    callbacks: list[str] = []

    report = verify_chain_detailed(
        artifacts,
        checkpoints=[checkpoint],
        checkpoint_verifier=verifier,
        anchor_verifier=lambda _artifacts: callbacks.append("anchor")
        or AnchorStatus.ANCHORED,
    )

    assert verifier.call_count == 0
    assert callbacks == []
    assert [error.code for error in report.errors] == [
        "CHECKPOINT_LIMIT_EXCEEDED"
    ]


@pytest.mark.parametrize(
    "mode",
    ["unexpected", "malformed", "malformed_combination"],
)
def test_hostile_provider_failure_is_bounded_typed_and_redacted(
    valid_chain,
    chain_checkpoint,
    mode,
    caplog,
):
    verifier = DeterministicExternalVerifier(mode=mode)

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 1
    assert (
        report.checkpoint_signature_status
        is CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN
    assert [(error.code, error.index) for error in report.errors] == [
        ("CHECKPOINT_VERIFICATION_ERROR", 0)
    ]
    rendered = repr(report.errors) + caplog.text
    assert not any(secret in rendered for secret in SENSITIVE_CORPUS)


def test_unknown_key_cannot_be_hidden_by_an_anchored_terminal_record(
    valid_chain,
    chain_checkpoint,
):
    unknown = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    ).to_dict()
    unknown["signature_metadata"]["key_version"] = "version/unknown"

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint, unknown],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.UNKNOWN_KEY
    assert report.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN


def test_invalid_anchor_cannot_be_hidden_by_an_anchored_terminal_record(valid_chain):
    invalid_anchor = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(key_version="version/invalid-anchor"),
        checkpointed_at=1_725_000_001,
    )
    terminal = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_002,
    )

    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[terminal, invalid_anchor],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN


@pytest.mark.parametrize(
    ("mode", "expected_anchor", "expects_error"),
    [
        ("unavailable", AnchorStatus.NOT_EVALUATED, False),
        ("unexpected", AnchorStatus.INVALID, True),
        ("malformed", AnchorStatus.INVALID, True),
    ],
)
def test_unavailable_or_failed_record_cannot_be_hidden_by_anchored_record(
    valid_chain,
    mode,
    expected_anchor,
    expects_error,
):
    historical = create_chain_checkpoint(
        valid_chain[1],
        DeterministicExternalSigner(key_version="version/historical"),
        checkpointed_at=1_725_000_001,
    )
    terminal = create_chain_checkpoint(
        valid_chain[2],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_002,
    )

    class RoutingVerifier:
        def __init__(self):
            self.normal = DeterministicExternalVerifier()
            self.selected = DeterministicExternalVerifier(mode=mode)

        def verify(self, payload, signature, metadata):
            verifier = (
                self.selected
                if metadata.key_version == "version/historical"
                else self.normal
            )
            return verifier.verify(payload, signature, metadata)

    verifier = RoutingVerifier()
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[terminal, historical],
        checkpoint_verifier=verifier,
    )

    assert verifier.normal.call_count == 1
    assert verifier.selected.call_count == 1
    assert (
        report.checkpoint_signature_status
        is CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is expected_anchor
    assert report.completeness is Completeness.UNPROVEN
    assert (
        "CHECKPOINT_VERIFICATION_ERROR"
        in [error.code for error in report.errors]
    ) is expects_error


def test_checkpoint_and_artifact_errors_share_the_hundred_error_report_cap():
    artifacts = []
    previous = None
    for index in range(64):
        artifact = _artifact(index, previous)
        artifacts.append(artifact)
        previous = artifact["checksum"]
    checkpoint = create_chain_checkpoint(
        artifacts[-1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    for artifact in artifacts:
        artifact.update(
            signature="ab" * 32,
            signature_metadata={},
            signature_status="signed",
        )
    verifier = DeterministicExternalVerifier(mode="unexpected")

    report = verify_chain_detailed(
        artifacts,
        checkpoints=_distinct_checkpoint_dicts(checkpoint, 64),
        checkpoint_verifier=verifier,
    )

    assert verifier.call_count == 64
    assert len(report.errors) == 100
    assert not any(secret in repr(report.errors) for secret in SENSITIVE_CORPUS)


def test_different_checkpoint_coordinates_are_not_compared_without_chain_links(
    valid_chain,
):
    first_history = create_chain_checkpoint(
        valid_chain[0],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_000,
    )
    alternate = _replacement_chain(length=2)
    second_history = create_chain_checkpoint(
        alternate[1],
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )

    report = verify_chain_detailed(
        valid_chain[2:],
        expected_chain_id="checkpoint-chain",
        checkpoints=[first_history, second_history],
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert [result.binding_status for result in report.checkpoint_results] == [
        CheckpointBindingStatus.OUTSIDE,
        CheckpointBindingStatus.OUTSIDE,
    ]
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.UNPROVEN
    assert not any(
        error.code == "CHECKPOINT_BINDING_CONFLICT" for error in report.errors
    )
