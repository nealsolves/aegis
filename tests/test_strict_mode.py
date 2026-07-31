"""Tests for strict mode enforcement (WS-13)."""

import warnings
from dataclasses import replace

import pytest

from aegis import AEGIS
from aegis._internal.enforcement import _validate_policy_strict
from aegis._internal.errors import PolicyValidationError
from aegis._internal.policy_compiler import compile_policy


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
BARE_STRING_POLICY = "tests/fixtures/bare_string_preconditions_policy.yaml"
TYPED_POLICY = "tests/fixtures/typed_preconditions_policy.yaml"
NO_PRECONDITIONS_POLICY = "tests/fixtures/no_preconditions_policy.yaml"


def _make_invocation(policy_file=POLICY):
    return {
        "policy_file": policy_file,
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-5-20250929",
        "role": "planner",
        "input": {"task": "analyse"},
        "output": {"result": "ok", "confidence": 0.9},
        "context": {"role_declared": True, "schema_exists": True},
    }


# --- Unit tests for _validate_policy_strict ---

def _compiled(*, roles=("planner",), preconditions=True):
    policy = {"policy_version": "1.0", "roles": list(roles)}
    if preconditions:
        policy["pre_conditions"] = {
            "required": {"k": {"type": "string"}},
        }
    return compile_policy(policy, source="strict-mode-test")


def test_strict_rejects_no_roles_unit():
    """Strict mode rejects an internally invalid compiled role set."""
    policy = replace(_compiled(), roles=())
    with pytest.raises(PolicyValidationError) as exc_info:
        _validate_policy_strict(policy, strict_mode=True)
    assert any("roles" in i for i in exc_info.value.details["issues"])


def test_strict_rejects_no_preconditions_unit():
    """Strict mode rejects compiled policy without preconditions."""
    policy = _compiled(preconditions=False)
    with pytest.raises(PolicyValidationError) as exc_info:
        _validate_policy_strict(policy, strict_mode=True)
    assert any("pre_conditions" in i for i in exc_info.value.details["issues"])


def test_strict_rejects_bare_string_preconditions_unit():
    """The compiler rejects bare-string preconditions before strict mode."""
    with pytest.raises(PolicyValidationError) as exc_info:
        compile_policy(
            {
                "policy_version": "1.0",
                "roles": ["planner"],
                "pre_conditions": {"required": ["key1"]},
            },
            source="strict-mode-test",
        )
    assert exc_info.value.code == "LEGACY_PRECONDITION_FORBIDDEN"


def test_strict_passes_valid_typed_policy_unit():
    """Strict mode accepts well-formed typed policy dict."""
    policy = _compiled()
    _validate_policy_strict(policy, strict_mode=True)  # Should not raise


def test_strict_collects_multiple_issues():
    """Strict mode reports all issues, not just the first."""
    policy = replace(_compiled(preconditions=False), roles=())
    with pytest.raises(PolicyValidationError) as exc_info:
        _validate_policy_strict(policy, strict_mode=True)
    issues = exc_info.value.details["issues"]
    assert len(issues) == 2


# --- Integration: strict mode via AEGIS.enforce() ---


def test_strict_rejects_bare_string_preconditions_e2e():
    """Strict compilation rejects bare-string preconditions."""
    aegis = AEGIS(strict_mode=True)
    inv = _make_invocation(BARE_STRING_POLICY)
    with pytest.raises(PolicyValidationError) as exc_info:
        aegis.enforce(inv)
    assert exc_info.value.code == "LEGACY_PRECONDITION_FORBIDDEN"


def test_strict_rejects_no_preconditions_e2e():
    """AEGIS(strict_mode=True) rejects policy without preconditions."""
    aegis = AEGIS(strict_mode=True)
    inv = _make_invocation(NO_PRECONDITIONS_POLICY)
    with pytest.raises(PolicyValidationError) as exc_info:
        aegis.enforce(inv)
    assert any("pre_conditions" in i for i in exc_info.value.details["issues"])


def test_strict_passes_typed_policy_e2e():
    """AEGIS(strict_mode=True) accepts typed precondition policy."""
    aegis = AEGIS(strict_mode=True)
    inv = _make_invocation(TYPED_POLICY)
    audit = aegis.enforce(inv)
    assert audit["enforcement_result"] == "PASS"


# --- Non-strict mode warns but doesn't raise ---


def test_nonstrict_rejects_bare_string():
    """Compiler strictness is independent of optional strict-mode diagnostics."""
    aegis = AEGIS(strict_mode=False)
    inv = _make_invocation(BARE_STRING_POLICY)
    with pytest.raises(PolicyValidationError) as exc_info:
        aegis.enforce(inv)
    assert exc_info.value.code == "LEGACY_PRECONDITION_FORBIDDEN"


def test_nonstrict_warns_no_preconditions():
    """Non-strict AEGIS warns for missing preconditions."""
    aegis = AEGIS(strict_mode=False)
    inv = _make_invocation(NO_PRECONDITIONS_POLICY)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        audit = aegis.enforce(inv)
    assert audit["enforcement_result"] == "PASS"
    user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
    assert any("pre_conditions" in str(x.message) for x in user_warnings)


# --- Standalone enforce_invocation unaffected ---


def test_standalone_enforce_uses_strict_compiler_boundary():
    """Standalone enforcement also rejects legacy authorization semantics."""
    from aegis import enforce_invocation

    inv = _make_invocation(BARE_STRING_POLICY)
    with pytest.raises(PolicyValidationError) as exc_info:
        enforce_invocation(inv)
    assert exc_info.value.code == "LEGACY_PRECONDITION_FORBIDDEN"
