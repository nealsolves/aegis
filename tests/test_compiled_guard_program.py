"""Security regressions for compiler-owned guard expression programs."""

from __future__ import annotations

import dataclasses
import pickle
from pathlib import Path

import pytest

from aegis._internal.enforcement import (
    _reconstruct_precall_result,
    enforce_pre_call,
)
from aegis._internal.errors import (
    InvocationValidationError,
    PolicyValidationError,
)
from aegis._internal.guards import evaluate_compiled_guards
from aegis._internal.policy_compiler import compile_policy


def _policy_with_guard(
    expression: str,
    *,
    conditions: dict | None = None,
    preconditions: dict | None = None,
) -> dict:
    policy = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": conditions or {
            "flag": {"type": "boolean", "default": True},
        },
        "guards": [
            {
                "when": {"condition": expression},
                "then": {
                    "post_conditions": {
                        "required": ["guard_matched"],
                    },
                },
            },
        ],
    }
    if preconditions is not None:
        policy["pre_conditions"] = {"required": preconditions}
    return policy


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "   ",
        "flag and",
        "flag trailing",
        "(",
        "flag )",
        "role == )",
        "\ud800",
    ],
)
def test_invalid_guard_expression_fails_policy_compilation(expression):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(
            _policy_with_guard(expression),
            source="invalid-guard",
        )

    assert exc.value.code == "GUARD_EXPRESSION_INVALID"
    assert exc.value.details["path"] == "$.guards[0].when.condition"


@pytest.mark.parametrize(
    "expression",
    [
        "undeclared_condition",
        'ambient_context == "value"',
        '"search" in ambient_tools',
        "object.attribute == value",
    ],
)
def test_guard_identifiers_must_use_closed_compiler_contract(expression):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(
            _policy_with_guard(expression),
            source="unknown-guard-identifier",
        )

    assert exc.value.code == "GUARD_EXPRESSION_INVALID"
    assert exc.value.details["path"] == "$.guards[0].when.condition"


def test_ordered_guard_comparison_requires_numeric_literal():
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(
            _policy_with_guard(
                'score > "five"',
                preconditions={"score": {"type": "number"}},
            ),
            source="nonnumeric-guard-literal",
        )

    assert exc.value.code == "GUARD_EXPRESSION_INVALID"
    assert exc.value.details["path"] == "$.guards[0].when.condition"


@pytest.mark.parametrize(
    "expression",
    [
        "x" * 4097,
        " and ".join(["flag"] * 130),
        " and ".join(["flag"] * 65),
        ("not " * 33) + "flag",
        ("(" * 33) + "flag" + (")" * 33),
    ],
)
def test_guard_compilation_is_bounded(expression):
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(
            _policy_with_guard(expression),
            source="bounded-guard",
        )

    assert exc.value.code == "GUARD_EXPRESSION_INVALID"
    assert exc.value.details["path"] == "$.guards[0].when.condition"


def test_compiled_guard_program_is_frozen_and_has_no_raw_ast_handles():
    compiled = compile_policy(
        _policy_with_guard("flag"),
        source="frozen-guard",
    )

    program = compiled.guards[0].program

    assert dataclasses.is_dataclass(program)
    assert dataclasses.is_dataclass(program.root)
    assert not hasattr(program, "__dict__")
    assert not hasattr(program.root, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        program.node_count = 999


def test_compiled_guard_runtime_never_calls_expression_parser(monkeypatch):
    policy = {
        "policy_version": "2.0",
        "roles": ["planner"],
        "conditions": {
            "enabled": {"type": "boolean", "default": True},
            "disabled": {"type": "boolean", "default": False},
        },
        "pre_conditions": {
            "required": {
                "score": {"type": "number"},
                "allowed_tools": {"type": "array"},
                "admin_roles": {"type": "array"},
            },
        },
        "guards": [
            {
                "when": {"condition": "enabled and not disabled"},
                "then": {
                    "post_conditions": {"required": ["logical"]},
                },
            },
            {
                "when": {"condition": "role == planner"},
                "then": {
                    "post_conditions": {"required": ["comparison"]},
                },
            },
            {
                "when": {"condition": "score >= 5"},
                "then": {
                    "post_conditions": {"required": ["numeric"]},
                },
            },
            {
                "when": {"condition": '"search" in allowed_tools'},
                "then": {
                    "post_conditions": {"required": ["membership"]},
                },
            },
            {
                "when": {"condition": "role in admin_roles"},
                "then": {
                    "post_conditions": {"required": ["reference_membership"]},
                },
            },
        ],
    }
    compiled = compile_policy(policy, source="parser-free-runtime")

    def parser_called(*_args, **_kwargs):
        raise AssertionError("guard parser reached compiled authorization")

    monkeypatch.setattr(
        "aegis._internal.guards.compile_guard_expression",
        parser_called,
    )
    monkeypatch.setattr(
        "aegis._internal.guards._Parser.parse",
        parser_called,
    )

    effective, evaluated, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {
            "score": 8,
            "allowed_tools": ["search"],
            "admin_roles": ["planner"],
        },
        invocation={
            "role": "planner",
            "context": {
                "score": 8,
                "allowed_tools": ["search"],
                "admin_roles": ["planner"],
            },
        },
    )

    assert [item["matched"] for item in evaluated] == [
        True,
        True,
        True,
        True,
        True,
    ]
    assert effective.postconditions == (
        "logical",
        "comparison",
        "numeric",
        "membership",
        "reference_membership",
    )


def test_compiled_numeric_guard_handles_large_integer_without_float_coercion():
    compiled = compile_policy(
        _policy_with_guard(
            "score > 5",
            preconditions={"score": {"type": "number"}},
        ),
        source="large-integer-guard",
    )
    large_integer = 10**4000

    _, evaluated, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {"score": large_integer},
        invocation={
            "role": "planner",
            "context": {"score": large_integer},
        },
    )

    assert evaluated[0]["matched"] is True


def _write_split_policy(path: Path) -> None:
    path.write_text(
        """
policy_version: "2.0"
roles: [planner]
conditions:
  enabled:
    type: boolean
    default: true
guards:
  - when:
      condition: enabled
    then:
      post_conditions:
        required: [guard_matched]
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _invocation(path: Path) -> dict:
    return {
        "policy_file": str(path),
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "guard"},
        "context": {},
    }


def test_pickle_restores_typed_guard_program_without_parsing(
    tmp_path,
    monkeypatch,
):
    policy_path = tmp_path / "guard-policy.yaml"
    _write_split_policy(policy_path)
    issued = enforce_pre_call(_invocation(policy_path))
    state = issued.__getstate__()

    assert "program" in state["_compiled_policy_dto"]["guards"][0]

    def parser_called(*_args, **_kwargs):
        raise AssertionError("guard parser reached DTO reconstruction")

    monkeypatch.setattr(
        "aegis._internal.guards.compile_guard_expression",
        parser_called,
    )
    monkeypatch.setattr(
        "aegis._internal.guards._Parser.parse",
        parser_called,
    )

    restored = pickle.loads(pickle.dumps(issued))

    assert restored._compiled_policy.guards[0].program.root is not None


def test_guard_program_dto_tampering_fails_content_digest(tmp_path):
    policy_path = tmp_path / "guard-policy.yaml"
    _write_split_policy(policy_path)
    issued = enforce_pre_call(_invocation(policy_path))
    state = issued.__getstate__()
    program = state["_compiled_policy_dto"]["guards"][0]["program"]
    program["root"]["op"] = "always"

    with pytest.raises(InvocationValidationError, match="compiled policy"):
        _reconstruct_precall_result(state)
