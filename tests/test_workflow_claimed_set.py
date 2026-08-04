"""Signed workflow claimed-set construction and schema coverage."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis import AEGIS, CallbackAuditSink, HMACSigner, SessionStateError
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
)
from aegis._internal.errors import GovernanceViolationError
from aegis._internal.outcomes import TerminalClass
from aegis._internal.session import SessionAttempt
from aegis._internal.workflow_limits import MAX_WORKFLOW_ATTEMPTS
from aegis._internal.workflow_verification import (
    MAX_WORKFLOW_CLAIM_ENTRIES,
    MAX_WORKFLOW_SUPPLIED_ARTIFACTS,
)
from aegis._internal.signing import (
    FINALIZER_WORKFLOW_DOMAIN,
    verify_finalized_artifact,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY = "tests/golden_replays/golden_policy_v1.yaml"
GOOD_OUTPUT = {"result": "answer", "confidence": 0.95}


def _invocation(*, role: str = "planner") -> dict:
    return {
        "policy_file": POLICY,
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": role,
        "input": {"query": "test"},
        "context": {"role_declared": True, "schema_exists": True},
    }


def _terminal_record(index: int, checksum: str) -> SessionAttempt:
    return SessionAttempt(
        step_index=index,
        step_id=f"step-{index}",
        attempt_id=index + 1,
        invocation_checksum=checksum,
        terminal=TerminalClass.DENY,
    )


@pytest.fixture
def signer() -> HMACSigner:
    return HMACSigner(b"workflow-claimed-set-test-key")


@pytest.fixture
def session(signer: HMACSigner):
    return AEGIS(signer=signer).open_session(session_id="claimed-set-session")


@pytest.fixture
def attempted_session(session):
    with pytest.raises(GovernanceViolationError) as denial:
        session.enforce_step_pre_call(
            _invocation(role="attacker"),
            step_id="rejected",
        )

    handle = session.enforce_step_pre_call(_invocation(), step_id="accepted")
    allowed = session.enforce_step_post_call(handle, GOOD_OUTPUT)
    return session, denial.value.audit_artifact["checksum"], allowed["checksum"]


def test_workflow_claims_every_attempt_in_index_order(attempted_session, signer):
    """Building the claim from successful steps would omit the denied attempt."""
    session, denied_checksum, allowed_checksum = attempted_session

    artifact = session.finalize(status="FAILED")

    assert artifact["step_count"] == 2
    assert artifact["invocations"] == [
        {"step_index": 0, "checksum": denied_checksum},
        {"step_index": 1, "checksum": allowed_checksum},
    ]
    assert artifact["step_count"] == len(artifact["invocations"])
    assert [item["step_index"] for item in artifact["invocations"]] == [0, 1]
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert verify_finalized_artifact(
        artifact,
        signer,
        domain=FINALIZER_WORKFLOW_DOMAIN,
    )


def test_failure_attempt_is_claimed_even_when_legacy_steps_omit_it(
    attempted_session,
):
    """Reusing the legacy successful-step summary would hide a denial."""
    session, denied_checksum, _ = attempted_session

    artifact = session.finalize(status="FAILED")

    assert len(artifact["steps"]) == 1
    assert artifact["invocations"][0] == {
        "step_index": 0,
        "checksum": denied_checksum,
    }
    assert len(artifact["invocations"]) == 2


def test_zero_attempt_workflow_has_an_empty_signed_claim(session, signer):
    """Special-casing an empty workflow must not omit its count or claimed set."""
    artifact = session.finalize()

    assert artifact["step_count"] == 0
    assert artifact["invocations"] == []
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert verify_finalized_artifact(
        artifact,
        signer,
        domain=FINALIZER_WORKFLOW_DOMAIN,
    )


def test_allocated_index_one_cannot_be_relabelled_as_single_step(session):
    """Counting surviving records would relabel allocated index one as zero."""
    session._next_step_index = 2
    session._attempts = {1: _terminal_record(1, "1" * 64)}

    with pytest.raises(SessionStateError) as exc_info:
        session.finalize(status="INCOMPLETE")

    assert exc_info.value.code == "SESSION_ATTEMPT_INCOMPLETE"


@pytest.mark.parametrize(
    ("records", "expected_indices"),
    [
        (
            {
                0: _terminal_record(0, "0" * 64),
                1: _terminal_record(2, "2" * 64),
            },
            [0, 2],
        ),
        (
            {
                0: _terminal_record(0, "0" * 64),
                1: _terminal_record(0, "1" * 64),
            },
            [0, 0],
        ),
    ],
    ids=["gap", "duplicate"],
)
def test_workflow_refuses_non_gapless_attempt_records(
    session,
    records,
    expected_indices,
):
    """A complete-length registry still must contain exactly indices zero and one."""
    session._next_step_index = 2
    session._attempts = records

    with pytest.raises(SessionStateError) as exc_info:
        session.finalize(status="INCOMPLETE")

    assert [record.step_index for record in records.values()] == expected_indices
    assert exc_info.value.code == "SESSION_ATTEMPT_GAP"


def _mutate_count(artifact: dict) -> None:
    artifact["step_count"] = 3


def _reorder_pairs(artifact: dict) -> None:
    artifact["invocations"].reverse()


def _remove_failure_attempt(artifact: dict) -> None:
    artifact["invocations"].pop(0)


def _duplicate_index(artifact: dict) -> None:
    artifact["invocations"][1]["step_index"] = 0


@pytest.mark.parametrize(
    "mutate",
    [_mutate_count, _reorder_pairs, _remove_failure_attempt, _duplicate_index],
    ids=["count", "reorder", "remove-failure", "duplicate-index"],
)
def test_workflow_checksum_and_signature_cover_the_entire_claim(
    attempted_session,
    signer,
    mutate,
):
    """Excluding any count or ordered-pair content would admit claim tampering."""
    session, _, _ = attempted_session
    artifact = session.finalize(status="FAILED")
    tampered = copy.deepcopy(artifact)

    mutate(tampered)

    assert verify_content_checksum_v2(tampered) is ContentIntegrity.INVALID
    assert not verify_finalized_artifact(
        tampered,
        signer,
        domain=FINALIZER_WORKFLOW_DOMAIN,
    )


def test_both_workflow_schemas_require_the_gap_representable_claim(session):
    """Omitting either structural claim field must fail both distributed schemas."""
    artifact = session.finalize()
    schema_paths = (
        ROOT / "schemas/workflow_artifact.schema.json",
        ROOT / "aegis/schemas/workflow_artifact.schema.json",
    )

    assert schema_paths[0].read_bytes() == schema_paths[1].read_bytes()
    for schema_path in schema_paths:
        validator = Draft7Validator(
            json.loads(schema_path.read_text(encoding="utf-8"))
        )
        assert list(validator.iter_errors(artifact)) == []
        for field in ("step_count", "invocations"):
            missing = {key: value for key, value in artifact.items() if key != field}
            assert any(
                error.validator == "required" and field in error.message
                for error in validator.iter_errors(missing)
            )

        gap_representable = copy.deepcopy(artifact)
        gap_representable["step_count"] = 2
        gap_representable["invocations"] = [
            {"step_index": 1, "checksum": "a" * 64}
        ]
        assert list(validator.iter_errors(gap_representable)) == []


def test_both_workflow_schemas_bound_claim_size(session):
    """Removing schema maxima would let callers hand verifiers unbounded claims."""
    artifact = session.finalize()
    schema_paths = (
        ROOT / "schemas/workflow_artifact.schema.json",
        ROOT / "aegis/schemas/workflow_artifact.schema.json",
    )

    for schema_path in schema_paths:
        validator = Draft7Validator(
            json.loads(schema_path.read_text(encoding="utf-8"))
        )
        oversized_count = copy.deepcopy(artifact)
        oversized_count["step_count"] = 1_025
        assert any(
            error.validator == "maximum"
            for error in validator.iter_errors(oversized_count)
        )

        oversized_claim = copy.deepcopy(artifact)
        oversized_claim["invocations"] = [
            {"step_index": 0, "checksum": "0" * 64}
        ] * 1_025
        assert any(
            error.validator == "maxItems"
            for error in validator.iter_errors(oversized_claim)
        )


def test_policy_and_workflow_schema_limits_are_exactly_1024():
    """Policy, producer, artifacts, and verifier must share one hard ceiling."""
    policy_paths = (
        ROOT / "schemas/policy_dsl.schema.json",
        ROOT / "aegis/schemas/policy_dsl.schema.json",
    )
    workflow_paths = (
        ROOT / "schemas/workflow_artifact.schema.json",
        ROOT / "aegis/schemas/workflow_artifact.schema.json",
    )

    assert policy_paths[0].read_bytes() == policy_paths[1].read_bytes()
    assert workflow_paths[0].read_bytes() == workflow_paths[1].read_bytes()
    assert MAX_WORKFLOW_ATTEMPTS == 1_024
    assert MAX_WORKFLOW_CLAIM_ENTRIES == MAX_WORKFLOW_ATTEMPTS
    assert MAX_WORKFLOW_SUPPLIED_ARTIFACTS == MAX_WORKFLOW_ATTEMPTS
    for path in policy_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert (
            schema["properties"]["workflow"]["properties"]["max_steps"]
            ["maximum"]
            == 1_024
        )
    for path in workflow_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["properties"]["step_count"]["maximum"] == 1_024
        assert schema["properties"]["invocations"]["maxItems"] == 1_024


def test_both_audit_schemas_require_complete_workflow_correlation():
    """Any workflow marker must activate the full bounded quartet contract."""
    emitted = []
    governance = AEGIS(sink=CallbackAuditSink(emitted.append))
    session = governance.open_session(session_id="audit-correlation-schema")
    handle = session.enforce_step_pre_call(_invocation(), step_id="s1")
    artifact = session.enforce_step_post_call(handle, GOOD_OUTPUT)
    session.finalize(status="COMPLETED")
    schema_paths = (
        ROOT / "schemas/audit_artifact.schema.json",
        ROOT / "aegis/schemas/audit_artifact.schema.json",
    )

    for schema_path in schema_paths:
        validator = Draft7Validator(
            json.loads(schema_path.read_text(encoding="utf-8"))
        )
        assert list(validator.iter_errors(artifact)) == []
        for field in (
            "session_id",
            "step_id",
            "step_index",
            "workflow_policy_digest",
        ):
            partial = copy.deepcopy(artifact)
            partial["context"].pop(field)
            assert list(validator.iter_errors(partial))
