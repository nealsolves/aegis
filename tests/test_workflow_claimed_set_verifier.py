"""Typed verification of workflow-signed invocation claimed sets."""

from __future__ import annotations

import copy

import pytest

from aegis import (
    AEGIS,
    CallbackAuditSink,
    Completeness,
    HMACSigner,
    SignatureStatus,
    WorkflowClaimStatus,
    WorkflowVerificationReport,
    verify_workflow_claim,
)
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis.workflow_verification import (
    WorkflowClaimStatus as ModuleWorkflowClaimStatus,
)
from aegis.workflow_verification import (
    WorkflowVerificationReport as ModuleWorkflowVerificationReport,
)
from aegis.workflow_verification import (
    verify_workflow_claim as module_verify_workflow_claim,
)


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _invocation(query: str) -> dict:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "input": {"query": query},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _evidence_set(*, signer=None, session_id="verified-session"):
    emitted = []
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


def _refinalize_unsigned(artifact: dict) -> dict:
    body = {
        key: copy.deepcopy(value)
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


def _error_codes(report: WorkflowVerificationReport) -> set[str]:
    return {error.code for error in report.errors}


def test_valid_supplied_set_matches_the_workflow_claim(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(workflow, invocations)

    assert report == WorkflowVerificationReport(
        claim_status=WorkflowClaimStatus.VALID,
        signature_status=SignatureStatus.UNSIGNED,
        completeness=Completeness.UNPROVEN,
        errors=(),
    )


def test_missing_index_invalidates_the_claim(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(workflow, invocations[:-1])

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_COUNT_MISMATCH" in _error_codes(report)


def test_duplicate_index_invalidates_the_claim(evidence_set):
    workflow, invocations = evidence_set
    duplicated = [invocations[0], invocations[0]]

    report = verify_workflow_claim(workflow, duplicated)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_INDEX_MISMATCH" in _error_codes(report)


def test_wrong_session_artifact_is_not_selected(evidence_set):
    workflow, invocations = evidence_set
    wrong_session = copy.deepcopy(invocations[1])
    wrong_session["context"]["session_id"] = "another-session"

    report = verify_workflow_claim(workflow, [invocations[0], wrong_session])

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_COUNT_MISMATCH" in _error_codes(report)


def test_wrong_supplied_checksum_invalidates_the_claim(evidence_set):
    workflow, invocations = evidence_set
    changed = copy.deepcopy(invocations)
    changed[1]["checksum"] = "f" * 64

    report = verify_workflow_claim(workflow, changed)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_CHECKSUM_MISMATCH" in _error_codes(report)
    assert "INVOCATION_CONTENT_INVALID" in _error_codes(report)


def test_reordered_supplied_artifacts_invalidate_the_ordered_claim(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(workflow, list(reversed(invocations)))

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_INDEX_MISMATCH" in _error_codes(report)


def test_extra_same_session_artifact_invalidates_exact_count(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(workflow, [*invocations, invocations[0]])

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_COUNT_MISMATCH" in _error_codes(report)


def test_extra_other_session_artifact_is_ignored(evidence_set):
    workflow, invocations = evidence_set
    _, unrelated = _evidence_set(session_id="unrelated-session")

    report = verify_workflow_claim(workflow, [unrelated[0], *invocations])

    assert report.claim_status is WorkflowClaimStatus.VALID


def test_workflow_artifact_cannot_substitute_for_an_invocation(evidence_set):
    workflow, invocations = evidence_set
    substitute = _refinalize_unsigned(
        {
            "workflow_schema_version": "2.0",
            "canonicalization_profile": "aegis-json-v2",
            "context": copy.deepcopy(invocations[0]["context"]),
        }
    )

    report = verify_workflow_claim(workflow, [substitute, invocations[1]])

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "INVOCATION_PROFILE_INVALID" in _error_codes(report)


def test_boolean_step_index_cannot_alias_integer_zero(evidence_set):
    workflow, invocations = evidence_set
    changed = copy.deepcopy(invocations)
    changed[0]["context"]["step_index"] = False
    changed[0] = _refinalize_unsigned(changed[0])

    report = verify_workflow_claim(workflow, changed)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_CLAIM_INDEX_MISMATCH" in _error_codes(report)


def test_legacy_workflow_is_classified_without_claim_promotion():
    legacy = {
        "workflow_schema_version": "1.4",
        "artifact_type": "workflow",
        "session_id": "legacy-session",
        "signature": None,
    }

    report = verify_workflow_claim(legacy, [])

    assert report.claim_status is WorkflowClaimStatus.LEGACY
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert report.completeness is Completeness.UNPROVEN


def test_valid_claim_without_checkpoint_never_proves_completeness(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(
        workflow,
        (artifact for artifact in invocations),
        expected_checkpoint=None,
    )

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.UNPROVEN


def test_non_none_checkpoint_fails_closed_until_issue_46(evidence_set):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=object(),
    )

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN
    assert "WORKFLOW_CHECKPOINT_UNSUPPORTED" in _error_codes(report)


def test_invalid_workflow_content_cannot_produce_a_valid_claim(evidence_set):
    workflow, invocations = evidence_set
    changed = copy.deepcopy(workflow)
    changed["status"] = "FAILED"

    report = verify_workflow_claim(changed, invocations)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert "WORKFLOW_CONTENT_INVALID" in _error_codes(report)


def test_signed_workflow_without_a_verifier_has_indeterminate_signature():
    workflow, invocations = _evidence_set(
        signer=HMACSigner(b"workflow-verification-test-key")
    )

    report = verify_workflow_claim(workflow, invocations)

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert report.completeness is Completeness.UNPROVEN
    assert report.errors == ()


def test_malformed_workflow_signature_is_indeterminate_not_valid():
    workflow, invocations = _evidence_set(
        signer=HMACSigner(b"workflow-verification-test-key")
    )
    malformed = copy.deepcopy(workflow)
    malformed["signature"] = "not-a-valid-hex-signature"

    report = verify_workflow_claim(malformed, invocations)

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert "SIGNATURE_METADATA_INVALID" in _error_codes(report)


def test_signed_status_without_signature_is_indeterminate_not_unsigned(
    evidence_set,
):
    workflow, invocations = evidence_set
    malformed = copy.deepcopy(workflow)
    malformed["signature_status"] = "signed"

    report = verify_workflow_claim(malformed, invocations)

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert "SIGNATURE_METADATA_INVALID" in _error_codes(report)


@pytest.mark.parametrize(
    "factory",
    [tuple, lambda values: (value for value in values)],
    ids=["tuple", "one-shot-generator"],
)
def test_ordered_iterables_are_consumed_once_and_preserve_order(
    evidence_set,
    factory,
):
    workflow, invocations = evidence_set

    report = verify_workflow_claim(workflow, factory(invocations))

    assert report.claim_status is WorkflowClaimStatus.VALID


@pytest.mark.parametrize("invalid", [None, "not-artifacts", {"zero": "artifact"}])
def test_non_iterable_or_mapping_invocation_input_returns_typed_error(
    evidence_set,
    invalid,
):
    workflow, _ = evidence_set

    report = verify_workflow_claim(workflow, invalid)

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_INVOCATIONS_INPUT_INVALID" in _error_codes(report)


def test_public_imports_are_stable_and_identical():
    assert WorkflowClaimStatus is ModuleWorkflowClaimStatus
    assert WorkflowVerificationReport is ModuleWorkflowVerificationReport
    assert verify_workflow_claim is module_verify_workflow_claim
