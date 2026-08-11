"""Synthetic regulated workflow fixture for evidence-locator demonstrations.

This example produces technical evidence only. It does not determine legal
applicability, control satisfaction, or operating effectiveness.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Mapping

import jsonschema
import yaml

from aegis import (
    AEGIS,
    build_content_checksum_v2,
    CallbackAuditSink,
    ContentIntegrity,
    ProvenanceGate,
    verify_content_checksum_v2,
)


SCENARIO_ID = "regulated-source-bound-workflow-v1"
SESSION_ID = "compliance-regulated-fixture"
FIXED_EPOCH = 1_725_000_000
_FINALIZATION_FIELDS = {
    "checksum",
    "signature",
    "signature_metadata",
    "signature_status",
}
ROOT = Path(__file__).resolve().parents[2]


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _policy() -> dict[str, object]:
    return {
        "policy_version": "1.0",
        "roles": ["compliance-analyst"],
        "pre_conditions": {"required": {"caller_id": {"type": "string"}}},
        "tools": {
            "allowed_tools": [{"name": "document_reader", "max_calls": 3}]
        },
    }


def _invocation(policy_path: Path, *, prompt: str, source_ids: list[str], tool: bool) -> dict:
    invocation = {
        "policy_file": str(policy_path),
        "input": {"prompt": prompt},
        "context": {
            "caller_id": "synthetic-compliance-fixture",
            "provenance": {"source_ids": source_ids},
        },
        "model_provider": "synthetic-local",
        "model_identifier": "no-network-model",
        "role": "compliance-analyst",
    }
    if tool:
        invocation["tool_calls"] = [{"name": "document_reader", "call_id": "fixture-read-1"}]
    return invocation


def _finalize_unsigned(value: dict) -> dict:
    unsigned = {
        key: item for key, item in value.items() if key not in _FINALIZATION_FIELDS
    }
    finalized = build_content_checksum_v2(unsigned)
    finalized.update(signature_status="unsigned", signature=None)
    return finalized


def _normalize_invocations(values: list[dict]) -> list[dict]:
    normalized = []
    for index, value in enumerate(values):
        artifact = dict(value)
        artifact["policy_file"] = "policy.yaml"
        artifact["timestamp"] = FIXED_EPOCH + index
        metadata = dict(artifact.get("metadata", {}))
        metadata["pre_call_timestamp"] = FIXED_EPOCH + index
        metadata["post_call_timestamp"] = FIXED_EPOCH + index
        artifact["metadata"] = metadata
        normalized.append(_finalize_unsigned(artifact))
    return normalized


def _normalize_workflow(value: dict, invocations: list[dict]) -> dict:
    artifact = dict(value)
    checksums = [item["checksum"] for item in invocations]
    artifact["policy_file"] = "policy.yaml"
    artifact["started_at"] = FIXED_EPOCH
    artifact["finalized_at"] = FIXED_EPOCH + len(invocations)
    artifact["invocation_audit_checksums"] = checksums
    artifact["invocations"] = [
        {"step_index": index, "checksum": checksum}
        for index, checksum in enumerate(checksums)
    ]
    steps = [dict(item) for item in artifact["steps"]]
    for index, step in enumerate(steps):
        step["invocation_artifact_checksum"] = checksums[index]
    artifact["steps"] = steps
    return _finalize_unsigned(artifact)


def run(output_dir: Path) -> dict[str, Path]:
    """Execute the fixed synthetic scenario and write evidence to output_dir."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ValueError("output directory must be empty")
    policy_path = output_dir / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(_policy(), sort_keys=True), encoding="utf-8", newline="\n"
    )

    emitted: list[dict] = []
    governance = AEGIS(
        sink=CallbackAuditSink(lambda artifact: emitted.append(dict(artifact))),
        custom_gates=[ProvenanceGate(require_source_ids=True)],
    )
    session = None
    with governance.open_session(
        policy_file=str(policy_path),
        session_id=SESSION_ID,
        metadata={"scenario_id": SCENARIO_ID, "synthetic": True},
    ) as session:
        first = session.enforce_step_pre_call(
            _invocation(
                policy_path,
                prompt="Analyze the fixed synthetic source records.",
                source_ids=["fixture-source-001", "fixture-source-002"],
                tool=True,
            ),
            step_id="source_analysis",
        )
        session.enforce_step_post_call(
            first,
            {"result": "Synthetic source analysis completed."},
            step_metadata={
                "governance": {
                    "rationale": "source_bound_analysis",
                    "decision_basis": ["provenance.source_ids"],
                    "source_ids": ["fixture-source-001", "fixture-source-002"],
                    "operator_action": "not_required",
                    "waiver_id": None,
                }
            },
        )
        second = session.enforce_step_pre_call(
            _invocation(
                policy_path,
                prompt="Summarize the fixed synthetic analysis.",
                source_ids=["source_analysis"],
                tool=False,
            ),
            step_id="summary",
        )
        session.enforce_step_post_call(
            second,
            {"result": "Synthetic summary completed."},
            step_metadata={
                "governance": {
                    "rationale": "source_bound_summary",
                    "decision_basis": ["provenance.source_ids"],
                    "source_ids": ["source_analysis"],
                    "operator_action": "not_required",
                    "waiver_id": None,
                }
            },
        )
        session.complete()
    if session is None or session.workflow_artifact is None:
        raise RuntimeError("workflow artifact was not emitted")

    invocations = _normalize_invocations(
        [item for item in emitted if item.get("audit_schema_version") == "2.0"]
    )
    workflow = _normalize_workflow(session.workflow_artifact, invocations)
    paths = {
        "policy": policy_path,
        "invocations": output_dir / "invocations.json",
        "workflow": output_dir / "workflow.json",
        "summary": output_dir / "summary.json",
    }
    _write_json(paths["invocations"], invocations)
    _write_json(paths["workflow"], workflow)
    _write_json(
        paths["summary"],
        {
            "scenario_id": SCENARIO_ID,
            "synthetic": True,
            "demonstrates_operating_effectiveness": False,
            "invocation_count": len(invocations),
            "workflow_status": workflow["status"],
        },
    )
    verify_outputs(paths)
    return paths


def verify_outputs(outputs: Mapping[str, Path], *, root: Path = ROOT) -> None:
    """Verify the fixed fixture outputs without consulting catalog YAML."""
    invocations = json.loads(Path(outputs["invocations"]).read_text(encoding="utf-8"))
    workflow = json.loads(Path(outputs["workflow"]).read_text(encoding="utf-8"))
    summary = json.loads(Path(outputs["summary"]).read_text(encoding="utf-8"))
    policy = yaml.safe_load(Path(outputs["policy"]).read_text(encoding="utf-8"))
    if not isinstance(invocations, list) or len(invocations) != 2:
        raise ValueError("fixture must contain exactly two invocation artifacts")
    audit_schema = json.loads(
        (root / "schemas" / "audit_artifact.schema.json").read_text(encoding="utf-8")
    )
    workflow_schema = json.loads(
        (root / "schemas" / "workflow_artifact.schema.json").read_text(
            encoding="utf-8"
        )
    )
    if policy != _policy():
        raise ValueError("fixture policy contract mismatch")
    for artifact in invocations:
        try:
            jsonschema.validate(artifact, audit_schema)
        except jsonschema.ValidationError as exc:
            raise ValueError("invocation schema validation failed") from exc
        if verify_content_checksum_v2(artifact) is not ContentIntegrity.VALID:
            raise ValueError("invocation checksum verification failed")
        if artifact.get("signature_status") != "unsigned" or artifact.get("signature") is not None:
            raise ValueError("fixture signature state is not the expected unsigned state")
    expected_sources = [
        ["fixture-source-001", "fixture-source-002"],
        ["source_analysis"],
    ]
    actual_sources = [
        item.get("context", {}).get("provenance", {}).get("source_ids")
        for item in invocations
    ]
    if actual_sources != expected_sources:
        raise ValueError("fixture provenance contract mismatch")
    try:
        jsonschema.validate(workflow, workflow_schema)
    except jsonschema.ValidationError as exc:
        raise ValueError("workflow schema validation failed") from exc
    if verify_content_checksum_v2(workflow) is not ContentIntegrity.VALID:
        raise ValueError("workflow checksum verification failed")
    if workflow.get("session_id") != SESSION_ID or workflow.get("status") != "COMPLETED":
        raise ValueError("workflow contract mismatch")
    if workflow.get("step_count") != 2 or len(workflow.get("invocations", [])) != 2:
        raise ValueError("workflow claimed-set contract mismatch")
    if summary != {
        "scenario_id": SCENARIO_ID,
        "synthetic": True,
        "demonstrates_operating_effectiveness": False,
        "invocation_count": 2,
        "workflow_status": "COMPLETED",
    }:
        raise ValueError("fixture summary contract mismatch")


def verify_fixture_contract(root: Path = ROOT) -> None:
    """Run the fixed harness in a temporary directory for publication CI."""
    with TemporaryDirectory(prefix="aegis-compliance-") as directory:
        outputs = run(Path(directory))
        verify_outputs(outputs, root=root)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    outputs = run(args.output_dir)
    print(f"Scenario: {SCENARIO_ID}")
    print(f"Workflow: {outputs['workflow']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
