"""Tests for the immutable policy compiler boundary."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from aegis._internal.errors import (
    PolicyValidationError,
    PreconditionError,
    SchemaValidationError,
)
from aegis._internal.policy_compiler import compile_policy


REPO_ROOT = Path(__file__).resolve().parents[1]


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


def test_supported_environment_matrix_is_provisional_until_hosted_lane_passes():
    """Docs must not claim a target matrix is supported before CI proves it."""
    environments = (
        REPO_ROOT / "docs" / "reference" / "SUPPORTED_ENVIRONMENTS.md"
    ).read_text(encoding="utf-8")
    normalized = " ".join(environments.split())

    assert "Security-boundary CI target matrix (provisional)" in environments
    assert "A lane becomes supported only after its corresponding hosted" in normalized
    for version in ("3.10", "3.11", "3.12", "3.13", "3.14"):
        assert f"| Python {version} | Target / provisional |" in environments
    for operating_system in (
        "macOS (Apple Silicon and Intel)",
        "Linux (x86-64)",
        "Windows (x86-64)",
    ):
        assert f"| {operating_system} | Target / provisional |" in environments
    assert "| Ubuntu | 3.10, 3.11, 3.12, 3.13, 3.14 |" in environments
    assert "| macOS | 3.10, 3.11, 3.12, 3.13, 3.14 |" in environments
    assert "| Windows | 3.10, 3.11, 3.12, 3.13, 3.14 |" in environments


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
