"""Trusted workflow-checkpoint verification and exact claim binding."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import inspect

import pytest

import aegis._internal.workflow_verification as workflow_verification_module
from aegis import (
    AEGIS,
    CallbackAuditSink,
    Completeness,
    HMACSigner,
    SignatureStatus,
)
from aegis._internal.checkpoint_signing import _checkpoint_payload
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.signature_models import (
    AnchorStatus,
    ExternalVerificationOutcome,
    SignatureMetadata,
    VerificationReasonCode,
)
from aegis.checkpoints import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    TrustedWorkflowCheckpoint,
    create_chain_checkpoint,
    create_workflow_checkpoint,
)
from aegis.workflow_verification import (
    WorkflowClaimStatus,
    WorkflowVerificationReport,
    verify_workflow_claim,
)
from tests.support.external_signing import (
    DeterministicExternalSigner,
    DeterministicExternalVerifier,
    DeterministicKeyRecord,
    SENSITIVE_CORPUS,
    default_key_records,
)


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _invocation(query: str) -> dict[str, object]:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": query},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _evidence_set(*, session_id: str = "verified-session", signer=None):
    emitted: list[dict[str, object]] = []
    governance = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        signer=signer,
    )
    session = governance.open_session(session_id=session_id)
    for index in range(2):
        handle = session.enforce_step_pre_call(
            _invocation(f"query-{index}"),
            step_id=f"step-{index}",
        )
        session.enforce_step_post_call(handle, GOOD_OUTPUT)
    workflow = session.finalize(status="COMPLETED")
    invocations = [
        artifact
        for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]
    return workflow, invocations


def _refinalize_unsigned(artifact: dict[str, object]) -> dict[str, object]:
    body = {
        key: deepcopy(value)
        for key, value in artifact.items()
        if key
        not in {
            "checksum",
            "signature",
            "signature_metadata",
            "signature_status",
        }
    }
    finalized = build_content_checksum_v2(body)
    return {**finalized, "signature_status": "unsigned", "signature": None}


@pytest.fixture
def evidence_set():
    return _evidence_set()


@pytest.fixture
def workflow_checkpoint(evidence_set):
    workflow, _ = evidence_set
    return create_workflow_checkpoint(
        workflow,
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )


@pytest.fixture
def verifier():
    return DeterministicExternalVerifier()


def _mutate_supplied_set(evidence_set, mutation: str):
    workflow, invocations = evidence_set
    if mutation == "missing":
        return workflow, invocations[:-1]
    if mutation == "duplicate":
        return workflow, [invocations[0], invocations[0]]
    if mutation == "extra":
        return workflow, [*invocations, invocations[0]]
    if mutation == "reordered":
        return workflow, list(reversed(invocations))
    raise AssertionError(f"unknown test mutation: {mutation}")


def _forge_workflow_checkpoint(
    checkpoint: TrustedWorkflowCheckpoint,
    **updates: object,
) -> TrustedWorkflowCheckpoint:
    forged = object.__new__(TrustedWorkflowCheckpoint)
    for field in TrustedWorkflowCheckpoint.__dataclass_fields__:
        value = updates.get(field, getattr(checkpoint, field))
        vars(TrustedWorkflowCheckpoint)[field].__set__(forged, value)
    return forged


def _checkpoint_for_key(
    workflow: dict[str, object],
    key_version: str,
    *,
    records=None,
) -> TrustedWorkflowCheckpoint:
    return create_workflow_checkpoint(
        workflow,
        DeterministicExternalSigner(
            key_records=records,
            key_version=key_version,
        ),
        checkpointed_at=1_725_000_001,
    )


def _tamper_signature(
    checkpoint: TrustedWorkflowCheckpoint,
) -> TrustedWorkflowCheckpoint:
    snapshot = checkpoint.to_dict()
    snapshot["signature"] = "00" * 32
    return TrustedWorkflowCheckpoint.from_dict(snapshot)


def _resign_workflow_checkpoint(
    checkpoint: TrustedWorkflowCheckpoint,
    **updates: object,
) -> TrustedWorkflowCheckpoint:
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
    return TrustedWorkflowCheckpoint.from_dict(
        {
            **unsigned,
            "signature_metadata": metadata.to_dict(),
            "signature": receipt.signature,
        }
    )


def _mutate_bound_workflow(
    workflow: dict[str, object],
    mutation: str,
) -> dict[str, object]:
    changed = deepcopy(workflow)
    if mutation == "workflow_schema_version":
        changed["workflow_schema_version"] = "2.1"
        return changed
    elif mutation == "session_id":
        changed["session_id"] = "replacement-session"
    elif mutation == "final_status":
        changed["status"] = "FAILED"
    elif mutation == "step_count":
        changed["step_count"] = 3
    elif mutation == "step_index":
        changed["invocations"][0]["step_index"] = 1  # type: ignore[index]
    elif mutation == "invocation_checksum":
        changed["invocations"][0]["checksum"] = "f" * 64  # type: ignore[index]
    elif mutation == "claim_order":
        changed["invocations"].reverse()  # type: ignore[union-attr]
    elif mutation == "workflow_checksum":
        changed["checksum"] = "f" * 64
        return changed
    else:
        raise AssertionError(f"unknown test mutation: {mutation}")
    return _refinalize_unsigned(changed)


def test_matching_anchored_workflow_checkpoint_proves_exact_claim(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_signature_status is CheckpointSignatureStatus.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert len(report.checkpoint_results) == 1
    result = report.checkpoint_results[0]
    assert result.input_indexes == (0,)
    assert result.binding_status is CheckpointBindingStatus.MATCHED
    assert result.signature_result is not None
    assert verifier.call_count == 1


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "reordered"])
def test_anchored_claim_contradicts_incomplete_supplied_evidence(
    evidence_set,
    workflow_checkpoint,
    verifier,
    mutation,
):
    workflow, invocations = _mutate_supplied_set(evidence_set, mutation)

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED


def test_host_selected_checkpoint_conflict_contradicts_without_repairing_b4(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    changed = deepcopy(workflow)
    changed["status"] = "FAILED"
    changed = _refinalize_unsigned(changed)

    report = verify_workflow_claim(
        changed,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CONTRADICTED
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.CONFLICT
    )


def test_nonbinding_content_tamper_matches_claim_but_is_contradicted(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    changed = deepcopy(workflow)
    changed["metadata"]["attacker"] = "tampered"  # type: ignore[index]

    report = verify_workflow_claim(
        changed,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )
    assert "CHECKPOINT_BINDING_CONFLICT" not in {
        error.code for error in report.errors
    }


def test_unanchored_matching_checkpoint_cannot_contradict_invalid_b4(
    evidence_set,
):
    workflow, invocations = evidence_set
    checkpoint = _checkpoint_for_key(workflow, "version/historical")

    report = verify_workflow_claim(
        workflow,
        invocations[:-1],
        expected_checkpoint=checkpoint,
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN
    assert report.checkpoint_anchor_status is AnchorStatus.UNANCHORED
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )


def test_unanchored_host_selected_mismatch_is_structural_not_authoritative():
    original, _ = _evidence_set()
    replacement, invocations = _evidence_set(session_id="replacement-session")
    historical_checkpoint = create_workflow_checkpoint(
        original,
        DeterministicExternalSigner(key_version="version/historical"),
        checkpointed_at=1_725_000_001,
    )

    report = verify_workflow_claim(
        replacement,
        invocations,
        expected_checkpoint=historical_checkpoint,
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.UNPROVEN
    assert report.checkpoint_anchor_status is AnchorStatus.UNANCHORED
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.CONFLICT
    )
    assert "CHECKPOINT_BINDING_CONFLICT" not in {
        error.code for error in report.errors
    }


def test_omitted_and_explicit_none_checkpoint_reports_are_equal(evidence_set):
    workflow, invocations = evidence_set
    verifier = DeterministicExternalVerifier()

    omitted = verify_workflow_claim(workflow, invocations)
    explicit = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=None,
        checkpoint_verifier=verifier,
    )

    assert explicit == omitted
    assert verifier.call_count == 0
    assert explicit.checkpoint_signature_status is (
        CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert explicit.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert explicit.checkpoint_results == ()


def test_workflow_verifier_public_signature_is_singular():
    signature = inspect.signature(verify_workflow_claim)

    assert tuple(signature.parameters) == (
        "workflow",
        "invocations",
        "expected_checkpoint",
        "checkpoint_verifier",
    )
    assert signature.parameters["expected_checkpoint"].kind is (
        inspect.Parameter.KEYWORD_ONLY
    )
    assert signature.parameters["checkpoint_verifier"].kind is (
        inspect.Parameter.KEYWORD_ONLY
    )


def test_legacy_four_field_report_construction_keeps_checkpoint_defaults():
    positional = WorkflowVerificationReport(
        WorkflowClaimStatus.VALID,
        SignatureStatus.UNSIGNED,
        Completeness.UNPROVEN,
        (),
    )
    keyword = WorkflowVerificationReport(
        claim_status=WorkflowClaimStatus.VALID,
        signature_status=SignatureStatus.UNSIGNED,
        completeness=Completeness.UNPROVEN,
        errors=(),
    )

    assert positional == keyword
    assert positional.checkpoint_signature_status is (
        CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert positional.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED
    assert positional.checkpoint_results == ()


@pytest.mark.parametrize(
    "mutation",
    [
        "workflow_schema_version",
        "session_id",
        "final_status",
        "step_count",
        "step_index",
        "invocation_checksum",
        "claim_order",
        "workflow_checksum",
    ],
)
def test_anchored_checkpoint_contradicts_every_bound_workflow_mutation(
    evidence_set,
    workflow_checkpoint,
    verifier,
    mutation,
):
    workflow, invocations = evidence_set
    changed = _mutate_bound_workflow(workflow, mutation)

    report = verify_workflow_claim(
        changed,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.completeness is Completeness.CONTRADICTED
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.CONFLICT
    )
    assert "CHECKPOINT_BINDING_CONFLICT" in {
        error.code for error in report.errors
    }


def test_whole_workflow_replacement_is_an_anchored_conflict(
    workflow_checkpoint,
    verifier,
):
    replacement, invocations = _evidence_set(session_id="replacement-session")

    report = verify_workflow_claim(
        replacement,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CONTRADICTED
    result = report.checkpoint_results[0]
    assert result.binding_status is CheckpointBindingStatus.CONFLICT
    assert result.scope_id == "verified-session"
    assert result.signature_result is not None


def test_unrelated_other_session_evidence_remains_filtered_under_checkpoint(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    _, unrelated = _evidence_set(session_id="unrelated-session")

    report = verify_workflow_claim(
        workflow,
        [unrelated[0], *invocations],
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


def test_artifact_signature_axis_is_unchanged_by_checkpoint_proof():
    workflow, invocations = _evidence_set(
        signer=HMACSigner(b"workflow-checkpoint-artifact-key")
    )
    checkpoint = create_workflow_checkpoint(
        workflow,
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=checkpoint,
        checkpoint_verifier=DeterministicExternalVerifier(),
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


@pytest.mark.parametrize(
    (
        "case",
        "expected_signature",
        "expected_anchor",
        "expected_completeness",
    ),
    [
        (
            "current",
            CheckpointSignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            Completeness.CHECKPOINT_PROVEN,
        ),
        (
            "historical-anchored",
            CheckpointSignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            Completeness.CHECKPOINT_PROVEN,
        ),
        (
            "historical-unanchored",
            CheckpointSignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            Completeness.UNPROVEN,
        ),
        (
            "unknown",
            CheckpointSignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            Completeness.UNPROVEN,
        ),
        (
            "revoked",
            CheckpointSignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            Completeness.UNPROVEN,
        ),
        (
            "unavailable",
            CheckpointSignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            Completeness.UNPROVEN,
        ),
        (
            "invalid-anchor",
            CheckpointSignatureStatus.VALID,
            AnchorStatus.INVALID,
            Completeness.UNPROVEN,
        ),
        (
            "invalid-signature",
            CheckpointSignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            Completeness.UNPROVEN,
        ),
        (
            "no-verifier",
            CheckpointSignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            Completeness.UNPROVEN,
        ),
    ],
)
def test_checkpoint_key_and_anchor_outcomes_remain_typed_and_metadata_bound(
    evidence_set,
    case,
    expected_signature,
    expected_anchor,
    expected_completeness,
):
    workflow, invocations = evidence_set
    records = dict(default_key_records())
    if case == "historical-anchored":
        records["version/historical"] = replace(
            records["version/historical"],
            anchor_status=AnchorStatus.ANCHORED,
        )
        checkpoint = _checkpoint_for_key(
            workflow,
            "version/historical",
            records=records,
        )
        verifier_records = {
            (record.key_reference, record.key_version): record
            for record in records.values()
        }
        checkpoint_verifier = DeterministicExternalVerifier(
            key_records=verifier_records
        )
    elif case == "unknown":
        unknown = DeterministicKeyRecord(
            "deterministic-audit-key",
            "version/unknown",
            b"unknown deterministic key material",
            AnchorStatus.ANCHORED,
        )
        records[unknown.key_version] = unknown
        checkpoint = _checkpoint_for_key(
            workflow,
            unknown.key_version,
            records=records,
        )
        checkpoint_verifier = DeterministicExternalVerifier()
    elif case in {"historical-unanchored", "revoked", "invalid-anchor"}:
        key_version = {
            "historical-unanchored": "version/historical",
            "revoked": "version/revoked",
            "invalid-anchor": "version/invalid-anchor",
        }[case]
        checkpoint = _checkpoint_for_key(workflow, key_version)
        checkpoint_verifier = DeterministicExternalVerifier()
    else:
        checkpoint = _checkpoint_for_key(workflow, "version/current")
        checkpoint_verifier = DeterministicExternalVerifier()
        if case == "unavailable":
            checkpoint_verifier = DeterministicExternalVerifier(
                mode="unavailable"
            )
        elif case == "invalid-signature":
            checkpoint = _tamper_signature(checkpoint)
        elif case == "no-verifier":
            checkpoint_verifier = None

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=checkpoint,
        checkpoint_verifier=checkpoint_verifier,
    )

    assert report.checkpoint_signature_status is expected_signature
    assert report.checkpoint_anchor_status is expected_anchor
    assert report.completeness is expected_completeness
    result = report.checkpoint_results[0]
    assert result.binding_status is CheckpointBindingStatus.MATCHED
    assert result.signature_result is not None
    assert result.signature_result.signature_metadata == (
        result.checkpoint.signature_metadata
    )
    assert result.signature_result.signature_metadata is not (
        checkpoint.signature_metadata
    )
    assert result.signature_result.signature_status is not SignatureStatus.UNSIGNED
    assert result.signature_result.reason_code not in {
        VerificationReasonCode.UNSIGNED,
        VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
        VerificationReasonCode.SIGNATURE_METADATA_MISSING,
    }


@pytest.mark.parametrize(
    "mode",
    ["unexpected", "malformed", "malformed_combination"],
)
def test_provider_contract_failures_are_sanitized_and_retain_typed_result(
    evidence_set,
    workflow_checkpoint,
    mode,
):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=DeterministicExternalVerifier(mode=mode),
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.UNPROVEN
    assert report.checkpoint_signature_status is (
        CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results[0].signature_result is not None
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_VERIFICATION_ERROR"
    }
    rendered = repr(report)
    assert all(secret not in rendered for secret in SENSITIVE_CORPUS)


@pytest.mark.parametrize(
    ("signature_status", "anchor_status", "reason_code"),
    [
        (
            SignatureStatus.UNSIGNED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.UNSIGNED,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        ),
        (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
        ),
    ],
)
def test_context_only_provider_outcomes_are_rejected(
    evidence_set,
    workflow_checkpoint,
    signature_status,
    anchor_status,
    reason_code,
):
    workflow, invocations = evidence_set

    class ContextOnlyVerifier:
        def verify(self, payload, signature, metadata):
            del payload, signature, metadata
            return ExternalVerificationOutcome(
                signature_status,
                anchor_status,
                reason_code,
                "caller-controlled-message",
            )

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=ContextOnlyVerifier(),
    )

    assert report.checkpoint_signature_status is (
        CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results[0].signature_result is not None
    assert report.checkpoint_results[0].signature_result.reason_code is (
        VerificationReasonCode.VERIFIER_UNAVAILABLE
    )
    assert "caller-controlled-message" not in repr(report)


def test_workflow_checkpoint_source_and_all_evidence_remain_unmodified(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    workflow_before = deepcopy(workflow)
    invocations_before = deepcopy(invocations)
    checkpoint_before = workflow_checkpoint.to_dict()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert workflow == workflow_before
    assert invocations == invocations_before
    assert workflow_checkpoint.to_dict() == checkpoint_before
    assert report.checkpoint_results[0].checkpoint == workflow_checkpoint
    assert report.checkpoint_results[0].checkpoint is not workflow_checkpoint


def test_invocation_iterator_cannot_replace_measured_workflow(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set

    def mutating_invocations():
        yield invocations[0]
        workflow.clear()
        workflow.update({"attacker": "replacement"})
        yield invocations[1]

    report = verify_workflow_claim(
        workflow,
        mutating_invocations(),
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert workflow == {"attacker": "replacement"}
    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )


def test_artifact_signature_verifier_cannot_mutate_b4_or_binding_snapshot(
    evidence_set,
    workflow_checkpoint,
    verifier,
    monkeypatch,
):
    workflow, invocations = evidence_set

    def mutating_signature_verifier(artifacts, *_args, **_kwargs):
        artifacts[0].clear()
        artifacts[0]["attacker"] = "replacement"
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        mutating_signature_verifier,
    )

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )


def test_checkpoint_provider_receives_disposable_metadata(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set
    delegate = DeterministicExternalVerifier()

    class MutatingVerifier:
        def verify(self, payload, signature, metadata):
            outcome = delegate.verify(payload, signature, metadata)
            object.__setattr__(metadata, "key_version", "attacker-version")
            return outcome

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=MutatingVerifier(),
    )

    assert workflow_checkpoint.signature_metadata.key_version == "version/current"
    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert (
        report.checkpoint_results[0]
        .signature_result.signature_metadata.key_version
        == "version/current"
    )


def test_checkpoint_provider_cannot_replace_sources_used_for_decision(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set
    delegate = DeterministicExternalVerifier()

    class ReplacingVerifier:
        def verify(self, payload, signature, metadata):
            outcome = delegate.verify(payload, signature, metadata)
            workflow.clear()
            workflow["attacker"] = "replacement"
            invocations.clear()
            vars(TrustedWorkflowCheckpoint)["session_id"].__set__(
                workflow_checkpoint,
                "attacker-session",
            )
            return outcome

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=ReplacingVerifier(),
    )

    assert workflow == {"attacker": "replacement"}
    assert invocations == []
    assert workflow_checkpoint.session_id == "attacker-session"
    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    result = report.checkpoint_results[0]
    assert result.scope_id == "verified-session"
    assert result.checkpoint.session_id == "verified-session"
    assert result.binding_status is CheckpointBindingStatus.MATCHED


def test_preflight_finishes_before_artifact_and_checkpoint_provider_calls(
    evidence_set,
    workflow_checkpoint,
    monkeypatch,
):
    workflow, invocations = evidence_set
    events: list[str] = []

    def invocation_stream():
        yield from invocations
        events.append("invocations-preflight")

    def artifact_verifier(*_args, **_kwargs):
        events.append("artifact-verifier")
        return SignatureStatus.UNSIGNED, None

    class CheckpointVerifier:
        def verify(self, payload, signature, metadata):
            events.append("checkpoint-verifier")
            return DeterministicExternalVerifier().verify(
                payload,
                signature,
                metadata,
            )

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    report = verify_workflow_claim(
        workflow,
        invocation_stream(),
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=CheckpointVerifier(),
    )

    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert events == [
        "invocations-preflight",
        "artifact-verifier",
        "checkpoint-verifier",
    ]


def test_supplied_count_overflow_stops_both_provider_axes(
    evidence_set,
    workflow_checkpoint,
    monkeypatch,
):
    workflow, _ = evidence_set
    artifact_calls = 0
    checkpoint_verifier = DeterministicExternalVerifier()

    def artifact_verifier(*_args, **_kwargs):
        nonlocal artifact_calls
        artifact_calls += 1
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    report = verify_workflow_claim(
        workflow,
        ({} for _ in range(1_025)),
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=checkpoint_verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert artifact_calls == 0
    assert checkpoint_verifier.call_count == 0
    assert report.checkpoint_results == ()


@pytest.mark.parametrize(
    "invalid_claim",
    [
        [(0, "a" * 64)],
        ((0,),),
        ((False, "a" * 64),),
        ((0, object()),),
        tuple((index, "a" * 64) for index in range(1_025)),
    ],
    ids=["list", "tuple-shape", "boolean-index", "object-checksum", "count"],
)
def test_forged_typed_claim_is_rejected_before_to_dict_allocation(
    evidence_set,
    workflow_checkpoint,
    invalid_claim,
    monkeypatch,
):
    workflow, invocations = evidence_set
    forged = _forge_workflow_checkpoint(
        workflow_checkpoint,
        invocations=invalid_claim,
    )
    to_dict_calls = 0

    def forbidden_to_dict(_value):
        nonlocal to_dict_calls
        to_dict_calls += 1
        raise AssertionError("to_dict must follow tuple count/shape guards")

    monkeypatch.setattr(
        TrustedWorkflowCheckpoint,
        "to_dict",
        forbidden_to_dict,
    )
    verifier = DeterministicExternalVerifier()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=forged,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_signature_status is (
        CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert to_dict_calls == 0
    assert verifier.call_count == 0


def test_workflow_checkpoint_subclass_is_rejected_without_dispatch(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set

    class WorkflowCheckpointSubclass(TrustedWorkflowCheckpoint):
        pass

    subclass = object.__new__(WorkflowCheckpointSubclass)
    for field in TrustedWorkflowCheckpoint.__dataclass_fields__:
        vars(TrustedWorkflowCheckpoint)[field].__set__(
            subclass,
            getattr(workflow_checkpoint, field),
        )
    verifier = DeterministicExternalVerifier()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=subclass,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert verifier.call_count == 0


def test_forged_exact_record_is_reparsed_before_provider(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set
    forged = _forge_workflow_checkpoint(
        workflow_checkpoint,
        session_id="",
    )
    verifier = DeterministicExternalVerifier()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=forged,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_signature_status is (
        CheckpointSignatureStatus.INDETERMINATE
    )
    assert report.checkpoint_anchor_status is AnchorStatus.INVALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert verifier.call_count == 0


def test_workflow_and_invocation_documents_cannot_replay_as_checkpoint(
    evidence_set,
):
    workflow, invocations = evidence_set
    verifier = DeterministicExternalVerifier()

    for replay in (workflow, invocations[0]):
        report = verify_workflow_claim(
            workflow,
            invocations,
            expected_checkpoint=replay,
            checkpoint_verifier=verifier,
        )
        assert report.claim_status is WorkflowClaimStatus.VALID
        assert report.checkpoint_results == ()
        assert {error.code for error in report.errors} == {
            "CHECKPOINT_RECORD_INVALID"
        }
    assert verifier.call_count == 0


def test_serialized_checkpoint_is_not_an_alternate_input_policy(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set
    verifier = DeterministicExternalVerifier()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint.to_dict(),
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert verifier.call_count == 0


@pytest.mark.parametrize("container", [list, tuple])
def test_checkpoint_container_does_not_create_multi_workflow_policy(
    evidence_set,
    workflow_checkpoint,
    container,
):
    workflow, invocations = evidence_set
    verifier = DeterministicExternalVerifier()
    alternate = container([workflow_checkpoint.to_dict()])

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=alternate,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert verifier.call_count == 0


def test_chain_checkpoint_cannot_replay_as_workflow_checkpoint(evidence_set):
    workflow, invocations = evidence_set
    chained = deepcopy(invocations[0])
    chained.update(
        chain_id="checkpoint-chain",
        chain_index=0,
        previous_audit_checksum=None,
        reservation_id="reservation-0",
    )
    chained = _refinalize_unsigned(chained)
    chain_checkpoint = create_chain_checkpoint(
        chained,
        DeterministicExternalSigner(),
        checkpointed_at=1_725_000_001,
    )
    verifier = DeterministicExternalVerifier()

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=chain_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.checkpoint_results == ()
    assert {error.code for error in report.errors} == {
        "CHECKPOINT_RECORD_INVALID"
    }
    assert verifier.call_count == 0


@pytest.mark.parametrize("shape", ["cycle", "depth", "nodes", "bytes"])
def test_malformed_checkpoint_resource_graph_stops_both_provider_axes(
    evidence_set,
    shape,
    monkeypatch,
):
    workflow, invocations = evidence_set
    if shape == "cycle":
        checkpoint_input: object = {}
        checkpoint_input["cycle"] = checkpoint_input  # type: ignore[index]
    elif shape == "depth":
        checkpoint_input = None
        for _ in range(33):
            checkpoint_input = [checkpoint_input]
    elif shape == "nodes":
        checkpoint_input = [None] * 65_536
    else:
        checkpoint_input = {"oversized": "x" * (4 * 1024 * 1024 + 1)}
    artifact_calls = 0
    verifier = DeterministicExternalVerifier()

    def artifact_verifier(*_args, **_kwargs):
        nonlocal artifact_calls
        artifact_calls += 1
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=checkpoint_input,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert {error.code for error in report.errors} == {
        "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED"
    }
    assert artifact_calls == 0
    assert verifier.call_count == 0


def test_aggregate_workflow_invocation_checkpoint_budget_is_shared(
    evidence_set,
    workflow_checkpoint,
    monkeypatch,
):
    workflow, invocations = evidence_set
    padded = deepcopy(workflow)
    padded["metadata"]["padding"] = "x" * (4 * 1024 * 1024 - 5_020)  # type: ignore[index]
    artifact_calls = 0
    verifier = DeterministicExternalVerifier()

    def artifact_verifier(*_args, **_kwargs):
        nonlocal artifact_calls
        artifact_calls += 1
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    without_checkpoint = verify_workflow_claim(
        padded,
        invocations,
    )
    assert without_checkpoint.claim_status is WorkflowClaimStatus.INVALID
    assert artifact_calls == 1

    artifact_calls = 0
    report = verify_workflow_claim(
        padded,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert {error.code for error in report.errors} == {
        "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED"
    }
    assert artifact_calls == 0
    assert verifier.call_count == 0


def test_supplied_collection_byte_overhead_is_charged_before_providers(
    evidence_set,
    workflow_checkpoint,
    monkeypatch,
):
    workflow, _ = evidence_set
    padded = deepcopy(workflow)
    padded["metadata"]["padding"] = "x" * 4_189_334  # type: ignore[index]
    supplied = [{} for _ in range(1_024)]
    artifact_calls = 0
    verifier = DeterministicExternalVerifier()

    def artifact_verifier(*_args, **_kwargs):
        nonlocal artifact_calls
        artifact_calls += 1
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    without_checkpoint = verify_workflow_claim(padded, supplied)
    assert without_checkpoint.claim_status is WorkflowClaimStatus.INVALID
    assert artifact_calls == 1

    artifact_calls = 0
    report = verify_workflow_claim(
        padded,
        supplied,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert {error.code for error in report.errors} == {
        "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED"
    }
    assert artifact_calls == 0
    assert verifier.call_count == 0


def test_supplied_collection_node_overhead_is_charged_before_providers(
    evidence_set,
    workflow_checkpoint,
    monkeypatch,
):
    workflow, _ = evidence_set
    supplied = [{"nodes": [None] * 62} for _ in range(1_023)]
    artifact_calls = 0
    verifier = DeterministicExternalVerifier()

    def artifact_verifier(*_args, **_kwargs):
        nonlocal artifact_calls
        artifact_calls += 1
        return SignatureStatus.UNSIGNED, None

    monkeypatch.setattr(
        workflow_verification_module,
        "_verify_signatures",
        artifact_verifier,
    )

    without_checkpoint = verify_workflow_claim(workflow, supplied)
    assert without_checkpoint.claim_status is WorkflowClaimStatus.INVALID
    assert artifact_calls == 1

    artifact_calls = 0
    report = verify_workflow_claim(
        workflow,
        supplied,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert {error.code for error in report.errors} == {
        "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED"
    }
    assert artifact_calls == 0
    assert verifier.call_count == 0


def test_claim_entry_overflow_remains_b4_authoritative_with_checkpoint(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, _ = evidence_set
    changed = deepcopy(workflow)
    changed["step_count"] = 1_025
    changed["invocations"] = [
        {"step_index": index, "checksum": "a" * 64}
        for index in range(1_025)
    ]
    changed = _refinalize_unsigned(changed)

    report = verify_workflow_claim(
        changed,
        (),
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.CONFLICT
    )
    assert verifier.call_count == 1
    assert "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED" in {
        error.code for error in report.errors
    }


def test_error_cap_does_not_skip_singular_checkpoint_evaluation(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    hostile = []
    for index in range(150):
        artifact = deepcopy(invocations[0])
        artifact["context"]["step_index"] = index + 1
        hostile.append(_refinalize_unsigned(artifact))

    report = verify_workflow_claim(
        workflow,
        hostile,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
    assert len(report.errors) == 100
    assert len(report.checkpoint_results) == 1
    assert verifier.call_count == 1


def test_b4_errors_precede_checkpoint_provider_error(
    evidence_set,
    workflow_checkpoint,
):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(
        workflow,
        invocations[:-1],
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=DeterministicExternalVerifier(mode="unexpected"),
    )

    codes = [error.code for error in report.errors]
    assert codes.index("WORKFLOW_CLAIM_COUNT_MISMATCH") < codes.index(
        "CHECKPOINT_VERIFICATION_ERROR"
    )
    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN


def test_resigned_checkpoint_timestamp_does_not_change_exact_binding(
    evidence_set,
    workflow_checkpoint,
    verifier,
):
    workflow, invocations = evidence_set
    resigned = _resign_workflow_checkpoint(
        workflow_checkpoint,
        checkpointed_at=1_725_000_999,
    )

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=resigned,
        checkpoint_verifier=verifier,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_results[0].binding_status is (
        CheckpointBindingStatus.MATCHED
    )
