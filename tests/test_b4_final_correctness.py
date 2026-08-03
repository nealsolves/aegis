"""Integrated B4 terminal-evidence and public-contract acceptance tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

import aegis
import aegis.workflow_verification as workflow_verification
from aegis import (
    AEGIS,
    AIGCError,
    CallbackAuditSink,
    Completeness,
    HMACSigner,
    SignatureStatus,
    WorkflowClaimStatus,
    verify_workflow_claim,
)
from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    verify_content_checksum_v2,
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


def _signed_evidence(*, session_id: str) -> tuple[dict, list[dict]]:
    emitted: list[dict] = []
    governance = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        signer=HMACSigner(b"b4-final-correctness-key"),
    )
    with governance.open_session(session_id=session_id) as session:
        handle = session.enforce_step_pre_call(_invocation(), step_id="step-0")
        session.enforce_step_post_call(handle, GOOD_OUTPUT)
        session.complete()
    workflow = session.workflow_artifact
    invocations = [
        artifact
        for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]
    return workflow, invocations


@pytest.mark.parametrize(
    ("scenario", "expected_status"),
    [
        ("phase-a-deny", "FAILED"),
        ("phase-b-deny", "FAILED"),
        ("unexpected-phase-a", "FAILED"),
        ("unexpected-phase-b", "FAILED"),
        ("cancellation", "CANCELED"),
    ],
)
def test_every_noncompleted_path_emits_one_signed_verifiable_claim(
    scenario,
    expected_status,
    monkeypatch,
):
    """Every allocated path must converge on one invocation and one workflow."""
    emitted: list[dict] = []
    governance = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        signer=HMACSigner(b"b4-e2e-terminal-key"),
    )
    session = governance.open_session(session_id=f"e2e-{scenario}")

    if scenario == "cancellation":
        with session:
            session.enforce_step_pre_call(_invocation(), step_id="step-0")
            session.cancel()
    else:
        expected_exception: type[BaseException] = (
            RuntimeError if scenario.startswith("unexpected-") else AIGCError
        )
        if scenario == "unexpected-phase-a":
            def fail_phase_a(*_args, **_kwargs):
                raise RuntimeError("unexpected phase A")

            monkeypatch.setattr(
                session,
                "_enforce_step_pre_call_attempt",
                fail_phase_a,
            )
        with pytest.raises(expected_exception):
            with session:
                if scenario == "phase-a-deny":
                    session.enforce_step_pre_call(
                        _invocation(role="attacker"),
                        step_id="step-0",
                    )
                else:
                    handle = session.enforce_step_pre_call(
                        _invocation(),
                        step_id="step-0",
                    )
                    if scenario == "unexpected-phase-b":
                        def fail_phase_b(_record, _output):
                            raise RuntimeError("unexpected phase B")

                        monkeypatch.setattr(
                            governance,
                            "_enforce_consumed_post_call",
                            fail_phase_b,
                        )
                    session.enforce_step_post_call(
                        handle,
                        {} if scenario == "phase-b-deny" else GOOD_OUTPUT,
                    )

    invocations = [
        artifact
        for artifact in emitted
        if artifact.get("audit_schema_version") == "2.0"
    ]
    workflows = [
        artifact
        for artifact in emitted
        if artifact.get("workflow_schema_version") == "2.0"
    ]
    assert len(invocations) == 1
    assert len(workflows) == 1
    workflow = workflows[0]
    assert workflow == session.workflow_artifact
    assert workflow["status"] == expected_status
    assert workflow["status"] != "COMPLETED"
    assert workflow["signature_status"] == "signed"
    assert workflow["step_count"] == 1
    assert workflow["invocations"] == [
        {"step_index": 0, "checksum": invocations[0]["checksum"]}
    ]

    schema = json.loads(
        (ROOT / "schemas/workflow_artifact.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert list(Draft7Validator(schema).iter_errors(workflow)) == []
    report = verify_workflow_claim(workflow, invocations)
    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert report.completeness is Completeness.UNPROVEN


def _change(field: str, value: object):
    def mutate(metadata: dict) -> None:
        metadata[field] = value

    return mutate


def _add_extra(metadata: dict) -> None:
    metadata["unexpected"] = "field"


def _remove_required(metadata: dict) -> None:
    metadata.pop("algorithm")


@pytest.mark.parametrize(
    "mutate",
    [
        _change("payload_type", "audit_artifact"),
        _change("canonicalization_profile", "aegis-canonical-json-v1"),
        _change("schema_version", "2"),
        _change("algorithm", "not-an-algorithm"),
        _change("signature_encoding", "base64"),
        _change("key_reference", ""),
        _change("signed_at", False),
        _add_extra,
        _remove_required,
    ],
    ids=[
        "payload",
        "profile",
        "version",
        "algorithm",
        "encoding",
        "key-identity",
        "signed-at",
        "extra",
        "missing",
    ],
)
def test_signature_metadata_mutation_never_changes_claim_axis(mutate):
    """Untrusted signature metadata cannot demote or promote claim matching."""
    workflow, invocations = _signed_evidence(session_id="metadata-matrix")
    changed = copy.deepcopy(workflow)
    mutate(changed["signature_metadata"])

    assert verify_content_checksum_v2(changed) is ContentIntegrity.VALID
    report = verify_workflow_claim(changed, invocations)

    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.signature_status is SignatureStatus.INDETERMINATE
    assert report.completeness is Completeness.UNPROVEN
    assert "SIGNATURE_METADATA_INVALID" in {
        error.code for error in report.errors
    }


def test_workflow_verifier_public_exports_are_exact_and_identical():
    expected = [
        "WorkflowClaimStatus",
        "WorkflowVerificationReport",
        "verify_workflow_claim",
    ]

    assert workflow_verification.__all__ == expected
    assert [name for name in aegis.__all__ if name in expected] == expected
    for name in expected:
        assert getattr(aegis, name) is getattr(workflow_verification, name)
