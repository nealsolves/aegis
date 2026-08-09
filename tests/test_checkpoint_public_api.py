"""Frozen public contracts for trusted checkpoint creation and verification."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, is_dataclass
import gc
from importlib import import_module
import inspect
import json
from typing import get_type_hints

import pytest

import aegis
import aegis._internal.checkpoint_models as checkpoint_models
import aegis._internal.checkpoint_signing as checkpoint_signing
import aegis._internal.external_signing as external_signing
import aegis._internal.signature_models as signature_models
import aegis.audit_chain as audit_chain
import aegis.checkpoints as checkpoints
import aegis.errors as errors
import aegis.workflow_verification as workflow_verification
from aegis.signing import (
    AnchorStatus,
    ArtifactVerificationResult,
    EvidenceType,
    ExternalArtifactSigner,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    VerificationReasonCode,
)


EXPECTED_CHECKPOINT_EXPORTS = frozenset(
    {
        "CheckpointBindingStatus",
        "CheckpointError",
        "CheckpointSignatureStatus",
        "CheckpointVerificationResult",
        "TrustedChainCheckpoint",
        "TrustedWorkflowCheckpoint",
        "create_chain_checkpoint",
        "create_workflow_checkpoint",
    }
)

EXPECTED_AUDIT_CHAIN_EXPORTS = frozenset(
    {
        "AuditChain",
        "ChainCoordinates",
        "ChainContinuity",
        "ChainLinkError",
        "ChainLinker",
        "ChainLinkRequest",
        "ChainReservation",
        "ChainVerificationReport",
        "Completeness",
        "ContentIntegrity",
        "VerificationError",
        "verify_chain",
        "verify_chain_detailed",
    }
)

EXPECTED_WORKFLOW_VERIFICATION_EXPORTS = frozenset(
    {
        "WorkflowClaimStatus",
        "WorkflowVerificationReport",
        "verify_workflow_claim",
    }
)


@pytest.fixture
def chain_checkpoint() -> checkpoints.TrustedChainCheckpoint:
    return checkpoints.TrustedChainCheckpoint.from_dict(
        {
            "checkpoint_schema_version": "1",
            "checkpoint_profile": "aegis-chain-checkpoint-v1",
            "canonicalization_profile": "aegis-json-v2",
            "chain_id": "chain-public-api",
            "chain_index": 0,
            "chain_length": 1,
            "artifact_schema_version": "2.0",
            "artifact_checksum": "a" * 64,
            "checkpointed_at": 1_725_000_000,
            "signature_metadata": {
                "schema_version": "1",
                "signing_profile": "aegis-chain-checkpoint-v1",
                "canonicalization_version": "aegis-json-v2",
                "payload_type": "chain_checkpoint",
                "algorithm": "ed25519",
                "signature_encoding": "hex",
                "key_reference": "kms://checkpoint-key",
                "key_version": "7",
                "signed_at": 1_725_000_000,
            },
            "signature": "ab" * 32,
        }
    )


@pytest.fixture
def workflow_checkpoint() -> checkpoints.TrustedWorkflowCheckpoint:
    return checkpoints.TrustedWorkflowCheckpoint.from_dict(
        {
            "checkpoint_schema_version": "1",
            "checkpoint_profile": "aegis-workflow-checkpoint-v1",
            "canonicalization_profile": "aegis-json-v2",
            "workflow_schema_version": "2.0",
            "session_id": "session-public-api",
            "final_status": "COMPLETED",
            "step_count": 1,
            "invocations": [{"step_index": 0, "checksum": "b" * 64}],
            "workflow_checksum": "c" * 64,
            "checkpointed_at": 1_725_000_001,
            "signature_metadata": {
                "schema_version": "1",
                "signing_profile": "aegis-workflow-checkpoint-v1",
                "canonicalization_version": "aegis-json-v2",
                "payload_type": "workflow_checkpoint",
                "algorithm": "ed25519",
                "signature_encoding": "base64",
                "key_reference": "kms://workflow-key",
                "key_version": "8",
                "signed_at": 1_725_000_001,
            },
            "signature": "Zm9v",
        }
    )


@pytest.mark.parametrize("name", sorted(EXPECTED_CHECKPOINT_EXPORTS))
def test_checkpoint_public_exports_are_identical(name: str) -> None:
    assert getattr(aegis, name) is getattr(checkpoints, name)


def test_checkpoint_error_is_one_identical_public_contract() -> None:
    assert aegis.CheckpointError is checkpoints.CheckpointError
    assert aegis.CheckpointError is errors.CheckpointError
    assert aegis.CheckpointError("safe").code == "CHECKPOINT_INPUT_INVALID"


def test_checkpoint_facade_has_one_exact_complete_public_surface() -> None:
    assert frozenset(checkpoints.__all__) == EXPECTED_CHECKPOINT_EXPORTS
    assert len(checkpoints.__all__) == len(EXPECTED_CHECKPOINT_EXPORTS)
    assert {
        name for name in vars(checkpoints) if not name.startswith("_")
    } == EXPECTED_CHECKPOINT_EXPORTS
    assert EXPECTED_CHECKPOINT_EXPORTS <= frozenset(aegis.__all__)


def test_checkpoint_facade_leaks_no_aliases_constants_or_private_helpers() -> None:
    forbidden = {
        "CheckpointRecord",
        "CHECKPOINT_CANONICALIZATION_VERSION",
        "CHAIN_CHECKPOINT_SIGNING_PROFILE",
        "WORKFLOW_CHECKPOINT_SIGNING_PROFILE",
        "_checkpoint_payload",
        "_sign_checkpoint",
        "verify_prepared_checkpoint",
    }
    assert all(not hasattr(checkpoints, name) for name in forbidden)
    assert all(not hasattr(aegis, name) for name in forbidden)
    assert forbidden.isdisjoint(aegis.__all__)


def test_existing_verification_facades_keep_their_source_compatible_exports() -> None:
    assert frozenset(audit_chain.__all__) == EXPECTED_AUDIT_CHAIN_EXPORTS
    assert (
        frozenset(workflow_verification.__all__)
        == EXPECTED_WORKFLOW_VERIFICATION_EXPORTS
    )
    assert aegis.verify_chain_detailed is audit_chain.verify_chain_detailed
    assert (
        aegis.verify_workflow_claim
        is workflow_verification.verify_workflow_claim
    )
    assert (
        aegis.ChainVerificationReport
        is audit_chain.ChainVerificationReport
    )
    assert (
        aegis.WorkflowVerificationReport
        is workflow_verification.WorkflowVerificationReport
    )
    forbidden_aliases = EXPECTED_CHECKPOINT_EXPORTS - {"CheckpointError"}
    assert all(not hasattr(audit_chain, name) for name in forbidden_aliases)
    assert all(
        not hasattr(workflow_verification, name)
        for name in forbidden_aliases
    )


def test_existing_report_construction_remains_source_compatible() -> None:
    chain = audit_chain.ChainVerificationReport(
        audit_chain.ContentIntegrity.VALID,
        audit_chain.ChainContinuity.VALID,
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        audit_chain.Completeness.UNPROVEN,
        (),
    )
    assert chain.checkpoint_results == ()
    assert (
        chain.checkpoint_signature_status
        is checkpoints.CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert chain.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED

    workflow = workflow_verification.WorkflowVerificationReport(
        workflow_verification.WorkflowClaimStatus.VALID,
        SignatureStatus.UNSIGNED,
        audit_chain.Completeness.UNPROVEN,
        (),
    )
    assert workflow.checkpoint_results == ()
    assert (
        workflow.checkpoint_signature_status
        is checkpoints.CheckpointSignatureStatus.NOT_EVALUATED
    )
    assert workflow.checkpoint_anchor_status is AnchorStatus.NOT_EVALUATED


@pytest.mark.parametrize(
    ("function", "expected"),
    [
        (
            checkpoints.create_chain_checkpoint,
            "(artifact: 'object', signer: 'ExternalArtifactSigner', *, "
            "checkpointed_at: 'int') -> 'TrustedChainCheckpoint'",
        ),
        (
            checkpoints.create_workflow_checkpoint,
            "(workflow: 'object', signer: 'ExternalArtifactSigner', *, "
            "checkpointed_at: 'int') -> 'TrustedWorkflowCheckpoint'",
        ),
        (
            audit_chain.verify_chain_detailed,
            "(artifacts: 'object', *, signature_verifier: 'object | None' = "
            "None, anchor_verifier: 'object | None' = None, "
            "legacy_authorization: 'object | None' = None, checkpoints: "
            "'object' = (), checkpoint_verifier: 'object | None' = None, "
            "expected_chain_id: 'object | None' = None) -> "
            "'ChainVerificationReport'",
        ),
        (
            workflow_verification.verify_workflow_claim,
            "(workflow: 'object', invocations: 'object', *, "
            "expected_checkpoint: 'object | None' = None, checkpoint_verifier: "
            "'object | None' = None) -> 'WorkflowVerificationReport'",
        ),
    ],
)
def test_public_checkpoint_function_signatures_are_exact(
    function: object,
    expected: str,
) -> None:
    assert str(inspect.signature(function)) == expected  # type: ignore[arg-type]


def test_creator_type_hints_resolve_to_public_contracts() -> None:
    assert get_type_hints(checkpoints.create_chain_checkpoint) == {
        "artifact": object,
        "signer": ExternalArtifactSigner,
        "checkpointed_at": int,
        "return": checkpoints.TrustedChainCheckpoint,
    }
    assert get_type_hints(checkpoints.create_workflow_checkpoint) == {
        "workflow": object,
        "signer": ExternalArtifactSigner,
        "checkpointed_at": int,
        "return": checkpoints.TrustedWorkflowCheckpoint,
    }


def test_checkpoint_enums_have_exact_public_values() -> None:
    assert tuple(status.value for status in checkpoints.CheckpointSignatureStatus) == (
        "not_evaluated",
        "valid",
        "invalid",
        "unknown_key",
        "revoked",
        "indeterminate",
    )
    assert tuple(status.value for status in checkpoints.CheckpointBindingStatus) == (
        "not_evaluated",
        "matched",
        "historical",
        "partial",
        "outside",
        "ahead",
        "conflict",
        "out_of_scope",
    )


@pytest.mark.parametrize(
    "record_type",
    [
        checkpoints.TrustedChainCheckpoint,
        checkpoints.TrustedWorkflowCheckpoint,
        checkpoints.CheckpointVerificationResult,
    ],
)
def test_public_checkpoint_dataclasses_are_frozen_and_slotted(
    record_type: type[object],
) -> None:
    assert is_dataclass(record_type)
    assert record_type.__dataclass_params__.frozen is True  # type: ignore[attr-defined]
    assert tuple(record_type.__slots__) == tuple(  # type: ignore[attr-defined]
        field.name for field in fields(record_type)
    )


def test_public_checkpoint_records_are_json_native_and_slotted(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
    workflow_checkpoint: checkpoints.TrustedWorkflowCheckpoint,
) -> None:
    for record in (chain_checkpoint, workflow_checkpoint):
        assert json.loads(json.dumps(record.to_dict(), allow_nan=False)) == record.to_dict()
        assert not hasattr(record, "__dict__")
        with pytest.raises(FrozenInstanceError):
            record.checkpointed_at = 0  # type: ignore[misc]


def test_public_exports_are_the_internal_contract_objects() -> None:
    assert (
        checkpoints.TrustedChainCheckpoint
        is checkpoint_models.TrustedChainCheckpoint
    )
    assert (
        checkpoints.TrustedWorkflowCheckpoint
        is checkpoint_models.TrustedWorkflowCheckpoint
    )
    assert (
        checkpoints.CheckpointSignatureStatus
        is checkpoint_models.CheckpointSignatureStatus
    )
    assert (
        checkpoints.CheckpointBindingStatus
        is checkpoint_models.CheckpointBindingStatus
    )
    assert (
        checkpoints.CheckpointVerificationResult
        is checkpoint_models.CheckpointVerificationResult
    )
    assert (
        checkpoints.create_chain_checkpoint
        is checkpoint_signing.create_chain_checkpoint
    )
    assert (
        checkpoints.create_workflow_checkpoint
        is checkpoint_signing.create_workflow_checkpoint
    )


def _valid_signature_result(
    checkpoint: checkpoints.TrustedChainCheckpoint,
) -> ArtifactVerificationResult:
    return ArtifactVerificationResult(
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        "Signature is valid and externally anchored",
        checkpoint.signature_metadata,
    )


@pytest.mark.parametrize(
    "binding_status",
    [
        checkpoints.CheckpointBindingStatus.NOT_EVALUATED,
        checkpoints.CheckpointBindingStatus.OUT_OF_SCOPE,
    ],
)
def test_public_result_none_iff_binding_was_not_evaluated(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
    binding_status: checkpoints.CheckpointBindingStatus,
) -> None:
    result = checkpoints.CheckpointVerificationResult(
        (0,),
        chain_checkpoint,
        chain_checkpoint.chain_id,
        chain_checkpoint.chain_index,
        None,
        binding_status,
    )
    assert result.signature_result is None
    with pytest.raises(checkpoints.CheckpointError):
        checkpoints.CheckpointVerificationResult(
            (0,),
            chain_checkpoint,
            chain_checkpoint.chain_id,
            chain_checkpoint.chain_index,
            _valid_signature_result(chain_checkpoint),
            binding_status,
        )


def test_public_result_requires_contextual_matching_checkpoint_metadata(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
) -> None:
    mismatched = SignatureMetadata(
        schema_version="1",
        signing_profile="aegis-chain-checkpoint-v1",
        canonicalization_version="aegis-json-v2",
        payload_type=EvidenceType.CHAIN_CHECKPOINT,
        algorithm="ed25519",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="kms://checkpoint-key",
        key_version="different-version",
        signed_at=1_725_000_000,
    )
    invalid_results = (
        None,
        ArtifactVerificationResult(
            SignatureStatus.UNSIGNED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.UNSIGNED,
            "safe",
            None,
        ),
        ArtifactVerificationResult(
            SignatureStatus.VALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
            "safe",
            chain_checkpoint.signature_metadata,
        ),
        ArtifactVerificationResult(
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
            "safe",
            chain_checkpoint.signature_metadata,
        ),
        ArtifactVerificationResult(
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
            "safe",
            mismatched,
        ),
    )
    for signature_result in invalid_results:
        with pytest.raises(checkpoints.CheckpointError):
            checkpoints.CheckpointVerificationResult(
                (0,),
                chain_checkpoint,
                chain_checkpoint.chain_id,
                chain_checkpoint.chain_index,
                signature_result,
                checkpoints.CheckpointBindingStatus.MATCHED,
            )


def _anchored_outcome() -> aegis.ExternalVerificationOutcome:
    return aegis.ExternalVerificationOutcome(
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        "provider-controlled-message",
    )


def test_impossible_external_reason_policy_cannot_be_relaxed(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
) -> None:
    impossible = external_signing._CONTEXTUALLY_IMPOSSIBLE_EXTERNAL_REASONS
    reason = VerificationReasonCode.LEGACY_SIGNATURE_VALID
    removed = False
    try:
        impossible.remove(reason)
        removed = True
        outcome = aegis.ExternalVerificationOutcome(
            SignatureStatus.VALID,
            AnchorStatus.NOT_EVALUATED,
            reason,
            "provider-controlled-message",
        )
        external_signing._normalize_external_outcome(
            outcome,
            chain_checkpoint.signature_metadata,
        )
    except AttributeError:
        pass
    finally:
        if type(impossible) is set:
            impossible.add(reason)
    assert removed is False


@pytest.mark.parametrize(
    ("module_name", "policy_name"),
    [
        ("aegis._internal.signature_models", "ALLOWED_VERIFICATION_OUTCOMES"),
        ("aegis._internal.external_signing", "_SAFE_REASON_MESSAGES"),
        ("aegis._internal.chain_checkpoint_verification", "_SIGNATURE_PRECEDENCE"),
        ("aegis._internal.chain_checkpoint_verification", "_ANCHOR_PRECEDENCE"),
        ("aegis._internal.verification", "_SIGNATURE_PRIORITY"),
        ("aegis._internal.verification", "_ANCHOR_PRIORITY"),
    ],
)
def test_security_policy_objects_have_no_mutable_referent(
    module_name: str,
    policy_name: str,
) -> None:
    policy = getattr(import_module(module_name), policy_name, None)
    assert policy is None or not any(
        isinstance(referent, (dict, list, set))
        for referent in gc.get_referents(policy)
    )


def test_referent_inspection_cannot_admit_unsigned_matched_result(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
) -> None:
    policy = getattr(
        signature_models,
        "ALLOWED_VERIFICATION_OUTCOMES",
        None,
    )
    referents = [] if policy is None else gc.get_referents(policy)
    backing = next(
        (referent for referent in referents if type(referent) is dict),
        None,
    )
    key = (SignatureStatus.UNSIGNED, AnchorStatus.NOT_EVALUATED)
    original = None if backing is None else backing[key]
    try:
        if backing is not None:
            backing[key] = frozenset(
                {VerificationReasonCode.SIGNATURE_VALID_ANCHORED}
            )
        with pytest.raises(errors.VerificationContractError):
            provider_result = ArtifactVerificationResult(
                SignatureStatus.UNSIGNED,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
                "safe",
                chain_checkpoint.signature_metadata,
            )
            checkpoints.CheckpointVerificationResult(
                (0,),
                chain_checkpoint,
                chain_checkpoint.chain_id,
                chain_checkpoint.chain_index,
                provider_result,
                checkpoints.CheckpointBindingStatus.MATCHED,
            )
    finally:
        if backing is not None:
            backing[key] = original


def test_referent_inspection_cannot_replace_core_owned_reason_message(
    chain_checkpoint: checkpoints.TrustedChainCheckpoint,
) -> None:
    messages = getattr(external_signing, "_SAFE_REASON_MESSAGES", None)
    referents = [] if messages is None else gc.get_referents(messages)
    backing = next(
        (referent for referent in referents if type(referent) is dict),
        None,
    )
    reason = VerificationReasonCode.SIGNATURE_VALID_ANCHORED
    original = None if backing is None else backing[reason]
    try:
        if backing is not None:
            backing[reason] = "attacker-controlled-message"
        result = external_signing._normalize_external_outcome(
            _anchored_outcome(),
            chain_checkpoint.signature_metadata,
        )
    finally:
        if backing is not None:
            backing[reason] = original
    assert result.message == "Signature is valid and externally anchored"


@pytest.mark.parametrize(
    (
        "module_name",
        "policy_name",
        "aggregate_name",
        "better",
        "worse",
        "default",
    ),
    [
        (
            "aegis._internal.chain_checkpoint_verification",
            "_SIGNATURE_PRECEDENCE",
            "_aggregate_checkpoint_signature_status",
            checkpoints.CheckpointSignatureStatus.VALID,
            checkpoints.CheckpointSignatureStatus.INVALID,
            None,
        ),
        (
            "aegis._internal.chain_checkpoint_verification",
            "_ANCHOR_PRECEDENCE",
            "_aggregate_checkpoint_anchor_status",
            AnchorStatus.ANCHORED,
            AnchorStatus.INVALID,
            None,
        ),
        (
            "aegis._internal.verification",
            "_SIGNATURE_PRIORITY",
            "_worst",
            SignatureStatus.VALID,
            SignatureStatus.INVALID,
            SignatureStatus.UNSIGNED,
        ),
        (
            "aegis._internal.verification",
            "_ANCHOR_PRIORITY",
            "_worst",
            AnchorStatus.ANCHORED,
            AnchorStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
        ),
    ],
)
def test_referent_inspection_cannot_relax_worst_status_aggregation(
    module_name: str,
    policy_name: str,
    aggregate_name: str,
    better: object,
    worse: object,
    default: object,
) -> None:
    module = import_module(module_name)
    policy = getattr(module, policy_name, None)
    referents = [] if policy is None else gc.get_referents(policy)
    backing = next(
        (referent for referent in referents if type(referent) is dict),
        None,
    )
    original = None if backing is None else (backing[better], backing[worse])
    try:
        if backing is not None:
            backing[better] = 10_000
            backing[worse] = -10_000
        aggregate = getattr(module, aggregate_name)
        priority = policy
        if priority is None and module_name.endswith(".verification"):
            priority = getattr(
                module,
                "_signature_priority"
                if policy_name == "_SIGNATURE_PRIORITY"
                else "_anchor_priority",
            )
        result = (
            aggregate((better, worse))
            if default is None
            else aggregate((better, worse), priority, default)
        )
    finally:
        if backing is not None:
            backing[better], backing[worse] = original
    assert result is worse


@pytest.mark.parametrize(
    ("module_name", "priority_name"),
    [
        (
            "aegis._internal.chain_checkpoint_verification",
            "_checkpoint_signature_priority",
        ),
        (
            "aegis._internal.chain_checkpoint_verification",
            "_checkpoint_anchor_priority",
        ),
        ("aegis._internal.verification", "_signature_priority"),
        ("aegis._internal.verification", "_anchor_priority"),
    ],
)
def test_status_priority_functions_reject_values_outside_closed_enums(
    module_name: str,
    priority_name: str,
) -> None:
    priority = getattr(import_module(module_name), priority_name)
    with pytest.raises(TypeError):
        priority(object())
