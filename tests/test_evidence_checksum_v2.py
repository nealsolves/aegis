import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis._internal.evidence_profiles import (
    ContentIntegrity,
    EvidenceProfileError,
    build_content_checksum_v2,
    verify_content_checksum_v2,
)


ROOT = Path(__file__).resolve().parents[1]


def v2_artifact(**overrides):
    artifact = {
        "audit_schema_version": "2.0",
        "canonicalization_profile": "aegis-json-v2",
        "chain_id": "chain-1",
        "chain_index": 2,
        "previous_audit_checksum": "a" * 64,
        "step_index": 2,
        "body": {"value": 1.0},
    }
    artifact.update(overrides)
    return artifact


def test_content_checksum_covers_chain_and_workflow_metadata():
    artifact = v2_artifact()
    finalized = build_content_checksum_v2(artifact)
    original_checksum = finalized["checksum"]
    candidate = {k: v for k, v in finalized.items() if k != "checksum"}
    candidate["step_index"] = 3
    assert build_content_checksum_v2(candidate)["checksum"] != original_checksum


def test_v2_audit_schema_rejects_missing_checksum():
    schema = json.loads((ROOT / "schemas/audit_artifact.schema.json").read_text())
    artifact = {
        "audit_schema_version": "2.0",
        "canonicalization_profile": "aegis-json-v2",
    }
    errors = list(Draft7Validator(schema).iter_errors(artifact))
    assert any(error.validator == "required" and "checksum" in error.message for error in errors)


def test_v2_workflow_schema_rejects_missing_checksum():
    schema = json.loads((ROOT / "schemas/workflow_artifact.schema.json").read_text())
    artifact = {
        "workflow_schema_version": "2.0",
        "canonicalization_profile": "aegis-json-v2",
    }
    errors = list(Draft7Validator(schema).iter_errors(artifact))
    assert any(error.validator == "required" and "checksum" in error.message for error in errors)


def test_checksum_builder_rejects_legacy_profile_instead_of_overwriting_it():
    with pytest.raises(EvidenceProfileError) as exc:
        build_content_checksum_v2({"audit_schema_version": "1.4"})
    assert exc.value.code == "EVIDENCE_PROFILE_MISMATCH"


@pytest.mark.parametrize("field", ["checksum", "signature", "signature_metadata"])
def test_checksum_builder_rejects_caller_supplied_finalization_fields(field):
    artifact = v2_artifact()
    artifact[field] = None
    with pytest.raises(EvidenceProfileError) as exc:
        build_content_checksum_v2(artifact)
    assert exc.value.code == "EVIDENCE_FINALIZATION_FIELDS_PRESENT"


@pytest.mark.parametrize(
    "declarations",
    [
        {},
        {"audit_schema_version": "1.4"},
        {"audit_schema_version": "3.0"},
        {"workflow_schema_version": "1.0"},
        {"audit_schema_version": "2.0", "workflow_schema_version": "2.0"},
        {"audit_schema_version": "2.0", "canonicalization_profile": "legacy"},
    ],
)
def test_checksum_builder_requires_one_exact_v2_declaration(declarations):
    with pytest.raises(EvidenceProfileError) as exc:
        build_content_checksum_v2(declarations)
    assert exc.value.code == "EVIDENCE_PROFILE_MISMATCH"


def test_checksum_verifier_does_not_mutate_a_signed_artifact():
    artifact = build_content_checksum_v2(v2_artifact())
    artifact["signature"] = "signed"
    artifact["signature_metadata"] = {"key": "rotated"}
    before = copy.deepcopy(artifact)
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert artifact == before


def test_checksum_is_stable_across_resigning_and_key_rotation():
    artifact = build_content_checksum_v2(v2_artifact())
    rotated = copy.deepcopy(artifact)
    artifact.update(signature="one", signature_metadata={"key": "one"})
    rotated.update(signature="two", signature_metadata={"key": "two"})
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.VALID
    assert verify_content_checksum_v2(rotated) is ContentIntegrity.VALID
    assert artifact["checksum"] == rotated["checksum"]


@pytest.mark.parametrize("checksum", [None, "", "A" * 64, "a" * 63])
def test_missing_or_malformed_checksum_is_invalid(checksum):
    artifact = build_content_checksum_v2(v2_artifact())
    artifact["checksum"] = checksum
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.INVALID


def test_body_mutation_invalidates_checksum():
    artifact = build_content_checksum_v2(v2_artifact())
    artifact["body"]["value"] = 2
    assert verify_content_checksum_v2(artifact) is ContentIntegrity.INVALID


def test_root_and_packaged_schema_pairs_are_byte_identical():
    assert (ROOT / "schemas/audit_artifact.schema.json").read_bytes() == (
        ROOT / "aegis/schemas/audit_artifact.schema.json"
    ).read_bytes()
    assert (ROOT / "schemas/workflow_artifact.schema.json").read_bytes() == (
        ROOT / "aegis/schemas/workflow_artifact.schema.json"
    ).read_bytes()
