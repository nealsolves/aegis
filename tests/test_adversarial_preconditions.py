"""Adversarial tests for compiled typed preconditions."""

import pytest

from aegis._internal.errors import PolicyValidationError, PreconditionError
from aegis._internal.policy_compiler import compile_policy


def policy_with_precondition(spec):
    return {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "pre_conditions": {"required": {"approval": spec}},
    }


@pytest.mark.parametrize(
    "spec",
    [
        {"pattern": "^APPROVED-[0-9]{6}$"},
        {"minLength": 2},
        {"maxLength": 12},
        {"minimum": 100},
        {"maximum": 999},
    ],
)
def test_type_specific_keyword_without_type_is_compile_error(spec):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy_with_precondition(spec), source="test")
    assert exc.value.code == "PRECONDITION_TYPE_REQUIRED"


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "integer", "pattern": "^[0-9]+$"},
        {"type": "number", "minLength": 2},
        {"type": "boolean", "maxLength": 12},
        {"type": "string", "minimum": 100},
        {"type": "array", "maximum": 999},
    ],
)
def test_incompatible_type_specific_keyword_is_compile_error(spec):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy_with_precondition(spec), source="test")
    assert exc.value.code == "PRECONDITION_TYPE_REQUIRED"


def test_empty_typed_precondition_is_compile_error():
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy_with_precondition({}), source="test")
    assert exc.value.code == "PRECONDITION_CONSTRAINT_REQUIRED"


def _compiled_precondition(spec):
    return compile_policy(
        policy_with_precondition(spec),
        source="test",
    ).preconditions[0]


def test_boolean_true_rejected_for_string_type():
    """True (bool) must not satisfy a string-typed precondition."""
    with pytest.raises(PreconditionError):
        _compiled_precondition({"type": "string"}).validate({"approval": True})


def test_empty_string_rejected_for_minlength():
    """Empty string must not satisfy a minLength constraint."""
    with pytest.raises(PreconditionError):
        _compiled_precondition(
            {"type": "string", "minLength": 1}
        ).validate({"approval": ""})


def test_zero_rejected_for_minimum():
    """Zero must not satisfy a minimum > 0 constraint."""
    with pytest.raises(PreconditionError):
        _compiled_precondition(
            {"type": "integer", "minimum": 1}
        ).validate({"approval": 0})


def test_none_rejected_for_any_type():
    """None must not satisfy a string-typed precondition."""
    with pytest.raises(PreconditionError):
        _compiled_precondition({"type": "string"}).validate({"approval": None})


def test_missing_key_rejected():
    """Missing context key must raise PreconditionError."""
    with pytest.raises(PreconditionError, match="Missing"):
        _compiled_precondition({"type": "string"}).validate({})


def test_wrong_enum_value_rejected():
    """Value not in enum must be rejected."""
    with pytest.raises(PreconditionError):
        _compiled_precondition(
            {"type": "string", "enum": ["a", "b", "c"]}
        ).validate({"approval": "d"})


def test_enum_only_constraint_does_not_treat_tuple_as_json_array():
    condition = _compiled_precondition({"enum": [["approved"]]})
    with pytest.raises(PreconditionError):
        condition.validate({"approval": ("approved",)})


@pytest.mark.parametrize(
    ("spec", "candidate"),
    [
        ({"type": "string", "pattern": "^APPROVED-[0-9]{6}$"}, True),
        ({"type": "string", "minLength": 2}, ["ok"]),
        ({"type": "string", "maxLength": 12}, 12),
        ({"type": "number", "minimum": 100}, "100"),
        ({"type": "integer", "maximum": 999}, True),
    ],
)
def test_declared_type_is_checked_before_type_specific_constraint(spec, candidate):
    with pytest.raises(PreconditionError):
        _compiled_precondition(spec).validate({"approval": candidate})


def test_compiled_precondition_accepts_matching_value():
    _compiled_precondition(
        {
            "type": "string",
            "pattern": "^(APPROVED|REJECTED)-[0-9]{2,4}$",
            "minLength": 11,
            "maxLength": 13,
        }
    ).validate({"approval": "APPROVED-123"})


def test_oversized_pattern_candidate_maps_to_precondition_error():
    with pytest.raises(PreconditionError) as exc:
        _compiled_precondition(
            {"type": "string", "pattern": "^x+$"}
        ).validate({"approval": "x" * 16_385})
    assert exc.value.code == "PATTERN_INPUT_TOO_LARGE"


def test_strict_compilation_rejects_bare_string_preconditions():
    policy = {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "pre_conditions": {"required": ["role_declared"]},
    }
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy, source="test")
    assert exc.value.code == "LEGACY_PRECONDITION_FORBIDDEN"


def test_explicit_legacy_authority_preserves_truthiness_semantics():
    policy = {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "pre_conditions": {"required": ["role_declared"]},
    }
    condition = compile_policy(
        policy,
        source="test",
        allow_legacy=True,
    ).preconditions[0]
    condition.validate({"role_declared": True})
    with pytest.raises(PreconditionError):
        condition.validate({"role_declared": False})
