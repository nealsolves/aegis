from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis import (
    AEGIS,
    AuditLineage,
    HMACSigner,
    PreconditionError,
    ProvenanceGate,
    verify_artifact,
)
from aegis.audit import checksum
from demo_contract import DemoGateResult
from demo_fixtures import get_fixture
from main import app


client = TestClient(app)

CASES = [
    ("atlas", "first_attempt", "FAIL", "PROVENANCE_MISSING"),
    ("atlas", "corrected", "PASS", None),
    ("northstar", "first_attempt", "FAIL", "ROLE_NOT_ALLOWED"),
    (
        "northstar",
        "authorized_retry",
        "PAUSED",
        "PHYSICIAN_APPROVAL_REQUIRED",
    ),
    ("northstar", "corrected", "PASS", None),
    (
        "meridian",
        "first_attempt",
        "PAUSED",
        "WORKFLOW_SEQUENCE_VIOLATION",
    ),
    ("meridian", "corrected", "PASS", None),
]

# Fixed non-production test material. Production deployments must supply a
# managed secret instead of reusing this demo fixture key.
ATLAS_DEMO_ONLY_TEST_KEY = b"aegis-atlas-demo-only-hmac-key-v1"


def _invocation_artifacts(body: dict) -> list[dict]:
    artifact = body["artifact"]
    if artifact is None:
        return []
    if "invocation_artifacts" in artifact:
        return artifact["invocation_artifacts"]
    return [artifact]


def _expected_outputs(scenario_id: str, variant: str) -> list[dict]:
    fixture = get_fixture(scenario_id, variant)
    if scenario_id == "northstar" and variant == "first_attempt":
        return [{}]
    if scenario_id == "meridian" and variant == "first_attempt":
        return [fixture.output["invoice_intake"]]
    if scenario_id == "meridian":
        return [
            fixture.output[step_id]
            for step_id in (
                "invoice_intake",
                "vendor_verification",
                "risk_review",
                "payment_preparation",
                "approval",
            )
        ]
    return [fixture.output]


@pytest.mark.parametrize(
    ("scenario_id", "variant", "decision", "reason_code"),
    CASES,
)
def test_scenario_outcome_matrix(
    scenario_id: str,
    variant: str,
    decision: str,
    reason_code: str | None,
):
    """Catches any server outcome that drifts from the governed roleplay matrix."""
    response = client.post(
        f"/api/demo/scenarios/{scenario_id}/runs",
        json={"variant": variant},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scenario_id"] == scenario_id
    assert body["variant"] == variant
    assert body["fixture_version"] == "2026-07-25.1"
    assert body["decision"] == decision
    assert body["transcript"]
    assert all(set(entry) == {"speaker", "text"} for entry in body["transcript"])

    if reason_code is None:
        assert body["error"] is None
    else:
        assert body["error"]["code"] == reason_code

    artifacts = _invocation_artifacts(body)
    expected_outputs = _expected_outputs(scenario_id, variant)
    assert len(artifacts) == len(expected_outputs)
    fixture = get_fixture(scenario_id, variant)
    for artifact, expected_output in zip(artifacts, expected_outputs, strict=True):
        assert artifact["enforcement_result"] in {"PASS", "FAIL"}
        assert re.fullmatch(r"[0-9a-f]{64}", artifact["input_checksum"])
        assert re.fullmatch(r"[0-9a-f]{64}", artifact["output_checksum"])
        assert artifact["input_checksum"] == checksum({"prompt": fixture.prompt})
        assert artifact["output_checksum"] == checksum(expected_output)


def test_demo_gate_result_requires_outcome_exactly_when_evaluated():
    """Catches an unevaluated gate being presented as an AEGIS decision."""
    DemoGateResult(
        name="risk_scoring",
        phase="post_call",
        evaluated=False,
        outcome=None,
        reason_code=None,
    )

    with pytest.raises(ValueError):
        DemoGateResult(
            name="risk_scoring",
            phase="post_call",
            evaluated=True,
            outcome=None,
            reason_code=None,
        )
    with pytest.raises(ValueError):
        DemoGateResult(
            name="risk_scoring",
            phase="post_call",
            evaluated=False,
            outcome="PASS",
            reason_code=None,
        )


def test_atlas_corrected_artifact_is_signed_and_checksums_fixture_output():
    """Catches unsigned or checksum-divergent Atlas correction evidence."""
    response = client.post(
        "/api/demo/scenarios/atlas/runs",
        json={"variant": "corrected"},
    )
    artifact = response.json()["artifact"]

    assert verify_artifact(artifact, HMACSigner(ATLAS_DEMO_ONLY_TEST_KEY))
    assert artifact["output_checksum"] == checksum(
        {
            "policy_citation": "BRV-04",
            "refund_commitment": (
                "Approved review may proceed under fictional policy BRV-04."
            ),
            "reply": "The fictional refund request is ready for approved review.",
        }
    )
    assert artifact["provenance"]["source_ids"] == ["atlas-policy-BRV-04"]


def test_northstar_first_attempt_fails_during_pre_call():
    """Catches accidental model-output governance after an unauthorized role."""
    response = client.post(
        "/api/demo/scenarios/northstar/runs",
        json={"variant": "first_attempt"},
    )
    body = response.json()
    artifact = body["artifact"]
    gates = {gate["name"]: gate for gate in body["gates"]}

    assert body["error"]["code"] == "ROLE_NOT_ALLOWED"
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["metadata"]["enforcement_mode"] == "split_pre_call_only"
    assert artifact["output_checksum"] == checksum({})
    assert gates["privacy_scope"]["outcome"] == "PASS"
    assert gates["role_validation"]["evaluated"] is True
    assert gates["role_validation"]["outcome"] == "FAIL"
    assert gates["role_validation"]["reason_code"] == "ROLE_NOT_ALLOWED"


def test_northstar_authorized_retry_preserves_stopped_pipeline_evidence():
    """Catches invented risk evidence or loss of the pending physician checkpoint."""
    response = client.post(
        "/api/demo/scenarios/northstar/runs",
        json={"variant": "authorized_retry"},
    )
    body = response.json()
    gates = {gate["name"]: gate for gate in body["gates"]}

    assert body["decision"] == "PAUSED"
    assert gates["clinical_scope"]["evaluated"] is True
    assert gates["clinical_scope"]["outcome"] == "FAIL"
    assert gates["clinical_scope"]["reason_code"] == (
        "PHYSICIAN_APPROVAL_REQUIRED"
    )
    assert gates["risk_scoring"] == {
        "name": "risk_scoring",
        "phase": "post_call",
        "evaluated": False,
        "outcome": None,
        "reason_code": None,
    }

    artifact = body["artifact"]
    assert artifact["enforcement_result"] == "FAIL"
    assert artifact["failures"][0]["code"] == "PHYSICIAN_APPROVAL_REQUIRED"
    assert artifact["risk_score"] is None

    workflow = body["workflow_artifact"]
    assert workflow["artifact_type"] == "workflow"
    assert workflow["status"] == "INCOMPLETE"
    assert workflow["approval_checkpoints"] == [
        {
            "checkpoint_id": "northstar-physician-approval",
            "paused_at": workflow["approval_checkpoints"][0]["paused_at"],
            "approver_id": "fictional-physician-reviewer",
            "reason": "Physician approval is required for clinical scope.",
            "status": "pending",
            "resumed_at": None,
            "approval_note": None,
            "denial_reason": None,
        }
    ]


def test_northstar_corrected_records_physician_approval_and_risk_score():
    """Catches a corrected clinical workflow that bypasses approval or strict risk."""
    response = client.post(
        "/api/demo/scenarios/northstar/runs",
        json={"variant": "corrected"},
    )
    body = response.json()
    gates = {gate["name"]: gate for gate in body["gates"]}

    assert gates["clinical_scope"]["outcome"] == "PASS"
    assert gates["risk_scoring"]["evaluated"] is True
    assert gates["risk_scoring"]["outcome"] == "PASS"
    assert body["artifact"]["risk_score"] == 0.0
    assert body["artifact"]["metadata"]["risk_scoring"]["mode"] == "strict"
    assert body["workflow_artifact"]["status"] == "COMPLETED"
    assert body["workflow_artifact"]["approval_checkpoints"][0]["status"] == (
        "approved"
    )


def test_meridian_first_attempt_pauses_after_real_sequence_failure():
    """Catches a synthetic pause that is not backed by the SDK sequence error."""
    response = client.post(
        "/api/demo/scenarios/meridian/runs",
        json={"variant": "first_attempt"},
    )
    body = response.json()

    assert body["error"]["code"] == "WORKFLOW_SEQUENCE_VIOLATION"
    assert body["workflow_artifact"]["status"] == "INCOMPLETE"
    assert [step["step_id"] for step in body["workflow_artifact"]["steps"]] == [
        "invoice_intake"
    ]

    invocation = body["artifact"]
    workflow_checksum = body["workflow_artifact"]["steps"][0][
        "invocation_artifact_checksum"
    ]
    assert AuditLineage().checksum_of(invocation) == workflow_checksum


def test_meridian_corrected_returns_correlated_trace_and_audit_export():
    """Catches missing or unresolved workflow projections for the five-step run."""
    response = client.post(
        "/api/demo/scenarios/meridian/runs",
        json={"variant": "corrected"},
    )
    body = response.json()
    evidence = body["artifact"]
    invocation_artifacts = evidence["invocation_artifacts"]

    assert len(invocation_artifacts) == 5
    assert body["workflow_artifact"]["artifact_type"] == "workflow"
    assert body["workflow_artifact"]["status"] == "COMPLETED"
    assert body["workflow_artifact"]["approval_checkpoints"][0]["status"] == (
        "approved"
    )

    trace = evidence["trace"]
    assert trace["status"] == "COMPLETED"
    assert trace["step_count"] == 5
    assert trace["unresolved_checksums"] == []
    assert all(step["resolved"] for step in trace["steps"])

    exported = evidence["export"]
    assert exported["export_mode"] == "audit"
    assert exported["compliance_summary"]["COMPLETED"] == 1
    assert exported["integrity"]["unresolved_count"] == 0


def test_atlas_false_refund_approval_blocks_before_refund_commitment():
    """Catches false satisfying the approval precondition before a commitment."""
    fixture = get_fixture("atlas", "corrected")
    context = dict(fixture.context)
    context["refund_approved"] = False
    invocation = {
        "policy_file": str(
            Path(__file__).resolve().parents[1] / "demo_policies" / "atlas.yaml"
        ),
        "model_provider": "internal",
        "model_identifier": "deterministic-fixture-v1",
        "role": fixture.role,
        "input": {"prompt": fixture.prompt},
        "context": context,
        "tool_calls": [
            {"name": "fictional_account_lookup", "call_id": "atlas-negative-01"},
            {"name": "fictional_refund_review", "call_id": "atlas-negative-02"},
        ],
    }
    governance = AEGIS(custom_gates=[ProvenanceGate()])

    with pytest.raises(PreconditionError) as exc_info:
        governance.enforce_pre_call(invocation)

    assert exc_info.value.code == "PRECONDITION_FAILED"
    assert exc_info.value.audit_artifact["enforcement_result"] == "FAIL"
