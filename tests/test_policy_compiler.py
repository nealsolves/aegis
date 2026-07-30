"""Tests for the immutable policy compiler boundary."""

from __future__ import annotations

import copy

import pytest

from aegis._internal.errors import (
    PolicyValidationError,
    PreconditionError,
    SchemaValidationError,
)
from aegis._internal.policy_compiler import compile_policy


@pytest.fixture
def valid_policy() -> dict[str, object]:
    return {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "tools": {
            "allowed_tools": [
                {"name": "lookup", "max_calls": 2},
            ]
        },
        "risk": {"mode": "strict", "threshold": 0.8},
    }


def test_compile_policy_returns_detached_immutable_snapshot(valid_policy):
    """Changing caller-owned policy data must not change authorization data."""
    raw = copy.deepcopy(valid_policy)

    compiled = compile_policy(raw, source="test")

    raw["roles"].append("admin")

    assert compiled.roles == ("verifier",)
    assert not hasattr(compiled, "raw")


def test_compiled_policy_records_closed_profiles(valid_policy):
    """The compiler must bind the fixed policy and engine profiles."""
    compiled = compile_policy(valid_policy, source="test")

    assert compiled.policy_contract_version == "2.0"
    assert compiled.pattern_engine == "google-re2"
    assert compiled.canonicalization_profile == "aegis-json-v2"


@pytest.mark.parametrize(
    ("error_type", "default_code", "custom_code"),
    [
        (PolicyValidationError, "POLICY_SCHEMA_VALIDATION_ERROR", "POLICY_INVALID"),
        (PreconditionError, "PRECONDITION_FAILED", "PRECONDITION_INVALID"),
        (SchemaValidationError, "OUTPUT_SCHEMA_VALIDATION_ERROR", "SCHEMA_INVALID"),
    ],
)
def test_compiler_facing_errors_support_stable_specific_codes(
    error_type, default_code, custom_code
):
    """Compiler callers must be able to assign a specific machine-readable code."""
    assert error_type("failure").code == default_code
    assert error_type("failure", code=custom_code).code == custom_code
