"""PR-11 workflow trace/export integrity tests."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aegis import AEGIS, JsonFileAuditSink
from aegis.workflow_export import export_workflow
from aegis.workflow_trace import reconstruct_trace


POLICY = "tests/golden_replays/golden_policy_v1.yaml"


def _run_success_jsonl(path: Path) -> dict:
    with AEGIS(sink=JsonFileAuditSink(path)).open_session() as session:
        for step_id in ["s1", "s2"]:
            pre = session.enforce_step_pre_call({
                "policy_file": POLICY,
                "model_provider": "openai",
                "model_identifier": "gpt-4",
                "role": "planner",
                "input": {"query": step_id},
                "context": {
                    "role_declared": True,
                    "schema_exists": True,
                    "authorization": "Bearer should-not-appear-in-audit-export",
                },
            }, step_id=step_id)
            session.enforce_step_post_call(
                pre,
                {"result": f"answer {step_id}", "confidence": 0.95},
                step_metadata={
                    "governance": {
                        "rationale": "approval_required_before_external_handoff",
                        "decision_basis": ["allowed_transitions"],
                        "operator_action": "approval_granted",
                        "source_ids": ["doc-001"],
                        "provider_payload": {
                            "api_key": "must-not-project",
                            "raw": "operator-only-debug",
                        },
                    }
                },
            )
        session.complete()
    return session.workflow_artifact


def _load_jsonl(path: Path) -> tuple[list[dict], list[dict]]:
    workflow: list[dict] = []
    invocation: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        artifact = json.loads(line)
        if artifact.get("artifact_type") == "workflow":
            workflow.append(artifact)
        else:
            invocation.append(artifact)
    return workflow, invocation


def test_trace_and_export_resolve_successful_workflow(tmp_path):
    jsonl = tmp_path / "audit.jsonl"
    workflow_artifact = _run_success_jsonl(jsonl)
    workflow, invocation = _load_jsonl(jsonl)

    trace = reconstruct_trace(workflow_artifact, invocation)
    audit_export = export_workflow(workflow, invocation, mode="audit")
    operator_export = export_workflow(workflow, invocation, mode="operator")

    assert trace["status"] == "COMPLETED"
    assert trace["unresolved_checksums"] == []
    assert audit_export["integrity"]["unresolved_count"] == 0
    assert operator_export["integrity"]["total_invocation_artifacts"] == 2
    assert "invocation_artifact" not in audit_export["sessions"][0]["steps"][0]


def test_trace_and_export_mark_missing_artifacts_without_inventing_evidence(tmp_path):
    jsonl = tmp_path / "audit.jsonl"
    workflow_artifact = _run_success_jsonl(jsonl)

    trace = reconstruct_trace(workflow_artifact, [])
    audit_export = export_workflow([workflow_artifact], [], mode="audit")
    operator_export = export_workflow([workflow_artifact], [], mode="operator")

    assert len(trace["unresolved_checksums"]) == 2
    assert audit_export["integrity"]["unresolved_count"] == 2
    assert operator_export["sessions"][0]["steps"][0]["invocation_artifact"] is None
    assert operator_export["integrity"]["verification_guidance"]


def test_audit_export_projects_rationale_but_not_raw_provider_payload_or_secrets(tmp_path):
    jsonl = tmp_path / "audit.jsonl"
    _run_success_jsonl(jsonl)
    workflow, invocation = _load_jsonl(jsonl)

    audit_export = export_workflow(workflow, invocation, mode="audit")
    serialized = json.dumps(audit_export)
    step = audit_export["sessions"][0]["steps"][0]

    assert step["governance"]["rationale"] == "approval_required_before_external_handoff"
    assert "provider_payload" not in step["governance"]
    projected = json.dumps(step["governance"])
    for sensitive in ["api_key", "authorization", "Bearer", "must-not-project"]:
        assert sensitive not in projected


def test_trace_and_export_cli_handle_failed_workflow_evidence(tmp_path):
    jsonl = tmp_path / "audit.jsonl"
    try:
        with AEGIS(sink=JsonFileAuditSink(jsonl)).open_session() as session:
            raise RuntimeError("intentional workflow failure")
    except RuntimeError:
        pass

    trace = subprocess.run(
        [sys.executable, "-m", "aegis", "workflow", "trace", "--input", str(jsonl)],
        capture_output=True,
        text=True,
    )
    export = subprocess.run(
        [sys.executable, "-m", "aegis", "workflow", "export", "--input", str(jsonl), "--mode", "audit"],
        capture_output=True,
        text=True,
    )
    assert trace.returncode == 0, trace.stderr
    assert export.returncode == 0, export.stderr
    assert json.loads(trace.stdout)[0]["status"] == "FAILED"
    assert json.loads(export.stdout)["compliance_summary"]["FAILED"] == 1
