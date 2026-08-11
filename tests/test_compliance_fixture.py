from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from aegis import verify_content_checksum_v2
from aegis.audit_chain import ContentIntegrity
from examples.compliance.regulated_workflow import (
    SCENARIO_ID,
    run,
    verify_outputs,
)


ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_regulated_fixture_emits_schema_valid_traceable_evidence(tmp_path: Path):
    outputs = run(tmp_path)

    assert set(outputs) == {"policy", "invocations", "workflow", "summary"}
    invocations = _load(outputs["invocations"])
    workflow = _load(outputs["workflow"])
    summary = _load(outputs["summary"])
    audit_schema = _load(ROOT / "schemas" / "audit_artifact.schema.json")
    workflow_schema = _load(ROOT / "schemas" / "workflow_artifact.schema.json")

    assert len(invocations) == 2
    for artifact in invocations:
        jsonschema.validate(artifact, audit_schema)
        assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
        assert artifact["signature_status"] == "unsigned"
        assert artifact["signature"] is None
    jsonschema.validate(workflow, workflow_schema)
    assert verify_content_checksum_v2(workflow) is ContentIntegrity.VALID
    assert workflow["status"] == "COMPLETED"
    assert workflow["session_id"] == "compliance-regulated-fixture"
    assert workflow["step_count"] == 2
    assert summary == {
        "scenario_id": SCENARIO_ID,
        "synthetic": True,
        "demonstrates_operating_effectiveness": False,
        "invocation_count": 2,
        "workflow_status": "COMPLETED",
    }
    verify_outputs(outputs)


def test_regulated_fixture_rejects_altered_evidence(tmp_path: Path):
    outputs = run(tmp_path)
    invocations = _load(outputs["invocations"])
    invocations[0]["enforcement_result"] = "DENY"
    outputs["invocations"].write_text(json.dumps(invocations), encoding="utf-8")

    try:
        verify_outputs(outputs)
    except ValueError as exc:
        assert any(
            reason in str(exc).lower()
            for reason in ("schema", "checksum", "signature")
        )
    else:
        raise AssertionError("altered evidence was accepted")


def test_regulated_fixture_is_byte_stable_across_output_directories(tmp_path: Path):
    first = run(tmp_path / "first")
    second = run(tmp_path / "second")

    for name in ("policy", "invocations", "workflow", "summary"):
        assert first[name].read_bytes() == second[name].read_bytes()
