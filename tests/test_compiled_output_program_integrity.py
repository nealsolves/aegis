"""Security regressions for immutable compiled output validation programs."""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest
import re2

from aegis._internal.enforcement import (
    AEGIS,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import SchemaValidationError
from aegis._internal.policy_compiler import compile_policy


def _write_policy(path: Path) -> None:
    path.write_text(
        """
policy_version: "2.0"
roles: [planner]
pre_conditions:
  required:
    approved:
      type: boolean
output_schema:
  type: object
  properties:
    result:
      type: string
      pattern: "^ok$"
  required: [result]
  additionalProperties: false
workflow:
  max_steps: 2
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _invocation(policy_file: Path) -> dict:
    return {
        "policy_file": str(policy_file),
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "test"},
        "context": {"approved": True},
    }


def _attempt_reachable_runtime_mutation(program, mutation: str) -> None:
    if mutation == "schema":
        try:
            program.schema["required"].clear()
        except (AttributeError, TypeError):
            pass
        runtime = getattr(program, "validator", None)
        if runtime is not None:
            runtime.schema["required"].clear()
        return

    if mutation == "pattern":
        patterns = getattr(program, "patterns", None)
        if patterns is not None:
            object.__setattr__(
                patterns["^ok$"],
                "_compiled",
                re2.compile(".*"),
            )
        return

    raise AssertionError(f"unknown mutation: {mutation}")


def _invalid_output(mutation: str) -> dict:
    return {} if mutation == "schema" else {"result": "not-ok"}


@pytest.mark.parametrize("mutation", ["schema", "pattern"])
def test_split_phase_b_ignores_reachable_runtime_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Reachable validator state must not weaken authenticated split Phase B."""
    policy_file = tmp_path / "split-policy.yaml"
    _write_policy(policy_file)
    issued = enforce_pre_call(_invocation(policy_file))
    assert "_compiled_policy" not in issued.__slots__

    with pytest.raises(SchemaValidationError):
        enforce_post_call(issued, _invalid_output(mutation))


@pytest.mark.parametrize("mutation", ["schema", "pattern"])
def test_session_phase_b_ignores_reachable_runtime_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Pinned session Phase B must use the same immutable authenticated program."""
    policy_file = tmp_path / "session-policy.yaml"
    _write_policy(policy_file)
    governance = AEGIS()

    with governance.open_session(policy_file=str(policy_file)) as session:
        issued = session.enforce_step_pre_call(_invocation(policy_file))
        program = session._compiled_policy.output_validator
        assert program is not None

        _attempt_reachable_runtime_mutation(program, mutation)

        with pytest.raises(SchemaValidationError):
            session.enforce_step_post_call(issued, _invalid_output(mutation))
        session.cancel()


def test_compiled_output_program_exposes_only_immutable_state() -> None:
    """Compiled policy must expose no jsonschema, Registry, or RE2 runtime handle."""
    compiled = compile_policy(
        {
            "policy_version": "2.0",
            "roles": ["planner"],
            "output_schema": {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "pattern": "^ok$",
                    },
                },
                "required": ["result"],
            },
        },
        source="immutable-output-program",
    )
    program = compiled.output_validator
    assert program is not None

    assert not hasattr(program, "validator")
    assert not hasattr(program, "patterns")
    assert isinstance(program.program_digest, str)
    assert isinstance(program.pattern_sources, tuple)
    with pytest.raises(TypeError):
        program.schema["required"] = ()
    with pytest.raises(TypeError):
        program.schema["properties"]["result"]["pattern"] = ".*"


def test_pickle_restores_handle_for_the_same_private_output_program(
    tmp_path: Path,
) -> None:
    """Pickling copies identity, while output authority stays registry-private."""
    policy_file = tmp_path / "pickle-policy.yaml"
    _write_policy(policy_file)
    issued = enforce_pre_call(_invocation(policy_file))

    restored = pickle.loads(pickle.dumps(issued))
    assert restored == issued
    assert "_compiled_policy" not in restored.__slots__
    with pytest.raises(SchemaValidationError):
        enforce_post_call(restored, {"result": "not-ok"})
