"""Tests for non-retrieving, reusable Draft 7 output validators."""

from types import MappingProxyType

import pytest

from aegis._internal.errors import PolicyValidationError, SchemaValidationError
from aegis._internal.schema_compiler import compile_output_schema
from aegis._internal.validator import validate_schema


DRAFT_7 = "http://json-schema.org/draft-07/schema#"


@pytest.mark.parametrize(
    "reference",
    [
        "https://example.invalid/schema.json",
        "http://example.invalid/schema.json#/definitions/value",
        "file:///etc/passwd",
        "//example.invalid/schema.json",
        "urn:example:schema",
        "other-schema.json#/definitions/value",
    ],
)
def test_external_or_document_relative_ref_is_compile_error(reference):
    schema = {"$schema": DRAFT_7, "$ref": reference}
    with pytest.raises(PolicyValidationError) as exc:
        compile_output_schema(schema)
    assert exc.value.code == "OUTPUT_SCHEMA_EXTERNAL_REF"


def test_nested_external_ref_is_compile_error():
    schema = {
        "$schema": DRAFT_7,
        "type": "object",
        "properties": {
            "result": {"$ref": "https://example.invalid/result.json"},
        },
    }
    with pytest.raises(PolicyValidationError) as exc:
        compile_output_schema(schema)
    assert exc.value.code == "OUTPUT_SCHEMA_EXTERNAL_REF"
    assert exc.value.details["path"] == "$.properties.result.$ref"


@pytest.mark.parametrize(
    "schema_id",
    [
        "https://example.invalid/base",
        "file:///tmp/base.json",
        "relative/base.json",
        "//example.invalid/base",
    ],
)
def test_base_uri_trick_is_compile_error(schema_id):
    schema = {"$schema": DRAFT_7, "$id": schema_id, "type": "string"}
    with pytest.raises(PolicyValidationError) as exc:
        compile_output_schema(schema)
    assert exc.value.code == "OUTPUT_SCHEMA_EXTERNAL_REF"


def test_incompatible_schema_dialect_is_compile_error():
    with pytest.raises(PolicyValidationError) as exc:
        compile_output_schema(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
            }
        )
    assert exc.value.code == "OUTPUT_SCHEMA_DIALECT_UNSUPPORTED"


def test_same_document_fragment_ref_is_allowed_and_functional():
    validator = compile_output_schema(
        {
            "$schema": DRAFT_7,
            "definitions": {"result": {"type": "string"}},
            "type": "object",
            "properties": {"result": {"$ref": "#/definitions/result"}},
            "required": ["result"],
        }
    )
    validator.validate({"result": "ok"})
    with pytest.raises(SchemaValidationError):
        validator.validate({"result": 42})


def test_unresolvable_same_document_ref_is_bounded_schema_error():
    validator = compile_output_schema(
        {
            "$schema": DRAFT_7,
            "$ref": "#/definitions/missing",
            "definitions": {},
        }
    )
    with pytest.raises(SchemaValidationError) as exc:
        validator.validate("value")
    assert exc.value.code == "OUTPUT_SCHEMA_REFERENCE_ERROR"


def test_compiled_validator_is_detached_and_reusable():
    source = {
        "$schema": DRAFT_7,
        "type": "object",
        "properties": {"result": {"type": "string"}},
        "required": ["result"],
    }
    validator = compile_output_schema(source)
    source["properties"]["result"]["type"] = "integer"

    validator.validate({"result": "first"})
    validator.validate({"result": "second"})
    with pytest.raises(SchemaValidationError):
        validator.validate({"result": 42})
    assert isinstance(validator.schema, MappingProxyType)


def test_first_validation_error_is_deterministic():
    validator = compile_output_schema(
        {
            "type": "object",
            "properties": {
                "zeta": {"type": "string"},
                "alpha": {"type": "integer"},
            },
        }
    )
    with pytest.raises(SchemaValidationError) as exc:
        validator.validate({"zeta": 1, "alpha": "wrong"})
    assert exc.value.details["path"] == "$.alpha"


def test_output_pattern_uses_re2_and_json_schema_search_semantics():
    validator = compile_output_schema(
        {"type": "string", "pattern": "(APPROVED|REJECTED)-[0-9]{2,4}"}
    )
    validator.validate("prefix APPROVED-123 suffix")
    with pytest.raises(SchemaValidationError):
        validator.validate("PENDING-123")


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "string", "pattern": "(?=APPROVED)APPROVED"},
        {
            "type": "object",
            "patternProperties": {r"(field)\1": {"type": "string"}},
        },
    ],
)
def test_every_output_schema_pattern_is_precompiled_by_re2(schema):
    with pytest.raises(PolicyValidationError) as exc:
        compile_output_schema(schema)
    assert exc.value.code == "PATTERN_UNSUPPORTED"


def test_pattern_properties_use_compiled_re2():
    validator = compile_output_schema(
        {
            "type": "object",
            "patternProperties": {
                "^(primary|secondary)_[0-9]{2}$": {"type": "integer"},
            },
        }
    )
    validator.validate({"primary_42": 7})
    with pytest.raises(SchemaValidationError):
        validator.validate({"secondary_12": "wrong"})


def test_additional_properties_does_not_reexecute_pattern_with_python_re(
    monkeypatch,
):
    validator = compile_output_schema(
        {
            "type": "object",
            "patternProperties": {"^field_[0-9]+$": {"type": "integer"}},
            "additionalProperties": False,
        }
    )

    def python_re_must_not_run(*args, **kwargs):
        raise AssertionError("policy pattern reached Python re")

    monkeypatch.setattr("jsonschema._utils.re.search", python_re_must_not_run)
    validator.validate({"field_42": 7})
    with pytest.raises(SchemaValidationError):
        validator.validate({"other": 7})


def test_oversized_output_pattern_candidate_maps_to_schema_error():
    validator = compile_output_schema({"type": "string", "pattern": "^x+$"})
    with pytest.raises(SchemaValidationError) as exc:
        validator.validate("x" * 16_385)
    assert exc.value.code == "PATTERN_INPUT_TOO_LARGE"


def test_validate_schema_consumes_precompiled_validator():
    validator = compile_output_schema(
        {
            "type": "object",
            "properties": {"result": {"type": "string"}},
            "required": ["result"],
        }
    )
    validate_schema({"result": "ok"}, validator)
    with pytest.raises(SchemaValidationError):
        validate_schema({"result": 42}, validator)
