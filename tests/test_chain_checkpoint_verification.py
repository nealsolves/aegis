"""Trusted chain-checkpoint verification and completeness binding."""

from __future__ import annotations

from copy import deepcopy

import pytest

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
    [pytest.param([], id="empty"), pytest.param([_artifact(0, None) | {"chain_id": None}], id="invalid")],
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
    ("mode", "expected_status", "expects_error"),
    [
        ("unavailable", CheckpointSignatureStatus.INDETERMINATE, False),
        ("unexpected", CheckpointSignatureStatus.INDETERMINATE, True),
        ("malformed", CheckpointSignatureStatus.INDETERMINATE, True),
    ],
)
def test_provider_failure_keeps_structural_binding_and_never_promotes(
    valid_chain, chain_checkpoint, mode, expected_status, expects_error
):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=DeterministicExternalVerifier(mode=mode),
    )

    assert report.checkpoint_signature_status is expected_status
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
