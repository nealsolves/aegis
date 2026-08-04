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
from aegis._internal import workflow_verification as workflow_verification_module
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


def test_generic_session_artifact_without_workflow_triggers_is_ignored(
    evidence_set,
):
    """Generic session context must not be mistaken for partial B4 correlation."""
    workflow, invocations = evidence_set
    generic = copy.deepcopy(invocations[0])
    generic["context"].pop("step_id")
    generic["context"].pop("step_index")
    generic["context"].pop("workflow_policy_digest")
    generic = _refinalize_unsigned(generic)

    report = verify_workflow_claim(workflow, [generic, *invocations])

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert "INVOCATION_CORRELATION_INVALID" not in _error_codes(report)


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


def test_huge_step_count_returns_typed_mismatch_without_count_sized_allocation(
    evidence_set,
    monkeypatch,
):
    workflow, _ = evidence_set
    changed = copy.deepcopy(workflow)
    changed["step_count"] = 10**12
    changed["invocations"] = []
    changed = _refinalize_unsigned(changed)
    real_range = range

    def reject_huge_range(*args):
        value = real_range(*args)
        if len(value) > 1000:
            raise AssertionError("count-sized range allocation attempted")
        return value

    monkeypatch.setattr(
        workflow_verification_module,
        "range",
        reject_huge_range,
        raising=False,
    )

    report = verify_workflow_claim(changed, ())

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.UNPROVEN
    assert "WORKFLOW_CLAIM_COUNT_MISMATCH" in _error_codes(report)


def test_checksum_valid_schema_incomplete_workflow_is_invalid(evidence_set):
    workflow, invocations = evidence_set
    incomplete = copy.deepcopy(workflow)
    incomplete.pop("status")
    incomplete = _refinalize_unsigned(incomplete)

    report = verify_workflow_claim(incomplete, invocations)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "WORKFLOW_SCHEMA_INVALID" in _error_codes(report)


def test_contradictory_workflow_role_marker_cannot_pass_as_invocation(
    evidence_set,
):
    workflow, invocations = evidence_set
    contradictory = copy.deepcopy(invocations[0])
    contradictory["artifact_type"] = "workflow"
    contradictory = _refinalize_unsigned(contradictory)
    changed_workflow = copy.deepcopy(workflow)
    changed_workflow["invocations"][0]["checksum"] = contradictory["checksum"]
    changed_workflow = _refinalize_unsigned(changed_workflow)

    report = verify_workflow_claim(
        changed_workflow,
        [contradictory, invocations[1]],
    )

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "INVOCATION_SCHEMA_INVALID" in _error_codes(report)


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


@pytest.mark.parametrize(
    "field",
    ["session_id", "step_id", "step_index", "workflow_policy_digest"],
)
def test_partial_workflow_correlation_is_rejected_by_verifier(
    evidence_set,
    field,
):
    """Removing any quartet member must invalidate an otherwise matching claim."""
    workflow, invocations = evidence_set
    changed_invocations = copy.deepcopy(invocations)
    changed_invocations[0]["context"].pop(field)
    changed_invocations[0] = _refinalize_unsigned(changed_invocations[0])
    changed_workflow = copy.deepcopy(workflow)
    changed_workflow["invocations"][0]["checksum"] = (
        changed_invocations[0]["checksum"]
    )
    changed_workflow = _refinalize_unsigned(changed_workflow)

    report = verify_workflow_claim(changed_workflow, changed_invocations)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert "INVOCATION_CORRELATION_INVALID" in _error_codes(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda artifact: artifact.update(
            canonicalization_profile="aegis-json-v2"
        ),
        lambda artifact: artifact.update(checksum="0" * 64),
        lambda artifact: artifact.update(audit_schema_version="2.0"),
        lambda artifact: artifact.update(step_count=0, invocations=[]),
    ],
    ids=["v2-profile", "v2-checksum", "audit-discriminator", "v2-claim"],
)
def test_legacy_hybrid_cannot_select_legacy_workflow_rules(mutation):
    """A 1.x marker cannot authorize contradictory v2 workflow features."""
    hybrid = {
        "workflow_schema_version": "1.4",
        "artifact_type": "workflow",
        "session_id": "legacy-session",
        "signature": None,
    }
    mutation(hybrid)

    report = verify_workflow_claim(hybrid, [])

    assert report.claim_status is not WorkflowClaimStatus.LEGACY
    assert report.completeness is Completeness.UNPROVEN


def test_infinite_invocation_iterable_stops_at_hard_document_limit(evidence_set):
    """Replacing bounded iteration with list() would never return."""
    workflow, _ = evidence_set

    def infinite():
        while True:
            yield {"context": {}}

    report = verify_workflow_claim(workflow, infinite())

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED" in _error_codes(report)


def test_verifier_never_calls_untrusted_length_hint(evidence_set):
    """Manual incremental consumption must ignore hostile sizing hooks."""
    workflow, invocations = evidence_set

    class HostileLengthHint:
        def __iter__(self):
            return iter(invocations)

        def __length_hint__(self):
            raise AssertionError("length hint must not be called")

    report = verify_workflow_claim(workflow, HostileLengthHint())

    assert report.claim_status is WorkflowClaimStatus.VALID


@pytest.mark.parametrize("failure", [MemoryError, RecursionError, RuntimeError])
def test_exceptional_invocation_iterable_returns_typed_report(
    evidence_set,
    failure,
):
    """Iterator failures, including resource failures, must not escape."""
    workflow, _ = evidence_set

    class BrokenIterable:
        def __iter__(self):
            raise failure("iterator failed")

    report = verify_workflow_claim(workflow, BrokenIterable())

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_INVOCATIONS_INPUT_INVALID" in _error_codes(report)


def test_cyclic_workflow_returns_typed_budget_report(evidence_set):
    """Recursive input must be rejected before checksum/signature traversal."""
    workflow, invocations = evidence_set
    cyclic = copy.deepcopy(workflow)
    cyclic["metadata"]["cycle"] = cyclic

    report = verify_workflow_claim(cyclic, invocations)

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED" in _error_codes(report)


def test_deep_workflow_returns_typed_budget_report(evidence_set):
    """Nesting deeper than the verifier budget must not reach recursion."""
    workflow, invocations = evidence_set
    changed = copy.deepcopy(workflow)
    nested = changed["metadata"]
    for _ in range(40):
        nested["next"] = {}
        nested = nested["next"]

    report = verify_workflow_claim(changed, invocations)

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED" in _error_codes(report)


def test_oversized_workflow_returns_typed_budget_report(evidence_set):
    """Verification bytes must be bounded before canonical serialization."""
    workflow, invocations = evidence_set
    changed = copy.deepcopy(workflow)
    changed["metadata"]["oversized"] = "x" * (4 * 1024 * 1024 + 1)

    report = verify_workflow_claim(changed, invocations)

    assert report.claim_status is WorkflowClaimStatus.NOT_EVALUATED
    assert "WORKFLOW_VERIFICATION_LIMIT_EXCEEDED" in _error_codes(report)


def test_verification_error_collection_has_hard_ceiling(evidence_set):
    """A hostile supplied set cannot force an unbounded error tuple."""
    workflow, invocations = evidence_set
    hostile = []
    for index in range(150):
        artifact = copy.deepcopy(invocations[0])
        artifact["context"]["step_index"] = index + 1
        hostile.append(_refinalize_unsigned(artifact))

    report = verify_workflow_claim(workflow, hostile)

    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert 1 <= len(report.errors) <= 100
