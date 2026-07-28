"""Strict-schema contracts for metadata-aware artifact signatures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, ValidationError


SOURCE_SCHEMA_PATH = Path("schemas/audit_artifact.schema.json")
PACKAGE_SCHEMA_PATH = Path("aegis/schemas/audit_artifact.schema.json")


def _schema() -> dict:
    return json.loads(SOURCE_SCHEMA_PATH.read_text(encoding="utf-8"))


def _artifact() -> dict:
    return {
        "audit_schema_version": "1.4",
        "policy_file": "test.yaml",
        "policy_schema_version": "http://json-schema.org/draft-07/schema#",
        "policy_version": "1.0",
        "model_provider": "openai",
        "model_identifier": "gpt-4",
        "role": "planner",
        "enforcement_result": "PASS",
        "failures": [],
        "failure_gate": None,
        "failure_reason": None,
        "input_checksum": "a" * 64,
        "output_checksum": "b" * 64,
        "timestamp": 1_700_000_000,
        "context": {},
        "metadata": {},
        "risk_score": None,
        "signature": None,
    }


def _signature_metadata() -> dict:
    return {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": "audit_artifact",
        "algorithm": "HSM-SHA256",
        "signature_encoding": "hex",
        "key_reference": "kms://audit/key",
        "key_version": "version/7",
        "signed_at": 1_721_600_000,
    }


def _metadata_aware_artifact() -> dict:
    artifact = _artifact()
    artifact["signature"] = "aabb"
    artifact["signature_metadata"] = _signature_metadata()
    return artifact


def _validate(artifact: dict) -> None:
    Draft7Validator(_schema()).validate(artifact)


def test_historical_signed_artifact_without_metadata_remains_valid():
    artifact = _artifact()
    artifact["signature"] = "legacy-signature"

    _validate(artifact)


def test_fully_signed_metadata_aware_artifact_is_valid():
    artifact = _metadata_aware_artifact()

    _validate(artifact)

    assert artifact["audit_schema_version"] == "1.4"


def test_signature_metadata_null_is_rejected():
    artifact = _artifact()
    artifact["signature_metadata"] = None

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize("missing_field", tuple(_signature_metadata()))
def test_signature_metadata_requires_every_field(missing_field: str):
    artifact = _metadata_aware_artifact()
    artifact["signature_metadata"].pop(missing_field)

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize("additional_field", ["provider_hint", "certificate_chain"])
def test_signature_metadata_rejects_every_additional_field(additional_field: str):
    artifact = _metadata_aware_artifact()
    artifact["signature_metadata"][additional_field] = "unexpected"

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize(
    ("field", "unsupported_value"),
    [
        ("schema_version", "2"),
        ("signing_profile", "aegis-signature-v2"),
        ("canonicalization_version", "aegis-canonical-json-v2"),
        ("payload_type", "policy"),
    ],
)
def test_signature_metadata_rejects_unsupported_fixed_values(
    field: str, unsupported_value: str
):
    artifact = _metadata_aware_artifact()
    artifact["signature_metadata"][field] = unsupported_value

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("algorithm", ""),
        ("algorithm", "a" * 129),
        ("algorithm", "HSM SHA256"),
        ("key_reference", ""),
        ("key_reference", "k" * 513),
        ("key_reference", "kms://audit/\x00key"),
        ("key_reference", "kms://audit/\x1fkey"),
        ("key_reference", "kms://audit/\x7fkey"),
        ("key_reference", "kms://audit/\x85key"),
        ("key_version", ""),
        ("key_version", "v" * 129),
        ("key_version", "version 7"),
    ],
)
def test_signature_metadata_rejects_invalid_identity_fields(
    field: str, invalid_value: str
):
    artifact = _metadata_aware_artifact()
    artifact["signature_metadata"][field] = invalid_value

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize("invalid_signed_at", [-1, 1.5, "1", True, None])
def test_signature_metadata_rejects_negative_or_non_integer_signed_at(
    invalid_signed_at: object,
):
    artifact = _metadata_aware_artifact()
    artifact["signature_metadata"]["signed_at"] = invalid_signed_at

    with pytest.raises(ValidationError):
        _validate(artifact)


@pytest.mark.parametrize("signature", [None, "", "aabb"])
def test_signature_accepts_only_string_or_null_values(signature: str | None):
    artifact = _artifact()
    artifact["signature"] = signature

    _validate(artifact)


@pytest.mark.parametrize("signature", [False, 1, [], {}])
def test_signature_rejects_non_string_non_null_values(signature: object):
    artifact = _artifact()
    artifact["signature"] = signature

    with pytest.raises(ValidationError):
        _validate(artifact)


def test_source_and_packaged_audit_schemas_are_byte_identical():
    assert SOURCE_SCHEMA_PATH.read_bytes() == PACKAGE_SCHEMA_PATH.read_bytes()
