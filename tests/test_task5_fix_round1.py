"""Security regressions for the Task 5 independent-review fix round."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

import pytest

from aegis._internal.cli import _lint_policy
from aegis._internal.compiled_policy import CompiledPolicyOverlay
from aegis._internal.enforcement import (
    AEGIS,
    _reconstruct_precall_result,
    enforce_post_call,
    enforce_pre_call,
)
from aegis._internal.errors import (
    InvocationValidationError,
    SchemaValidationError,
)
from aegis._internal.guards import evaluate_compiled_guards
from aegis._internal.policy_compiler import compile_policy
from aegis._internal.workflow_lint import lint_policy


def _split_policy(path: Path) -> None:
    path.write_text(
        """
policy_version: "2.0"
roles: [planner]
conditions:
  always:
    type: boolean
    default: true
  never:
    type: boolean
    default: false
tools:
  allowed_tools:
    - name: search
      max_calls: 2
risk:
  mode: strict
  threshold: 0.8
retry_policy:
  max_retries: 1
  backoff_ms: 5
pre_conditions:
  required:
    approved:
      type: boolean
post_conditions:
  required: [output_schema_valid]
output_schema:
  type: object
  properties:
    result:
      type: string
  required: [result]
guards:
  - when:
      condition: never
    then:
      tools:
        allowed_tools:
          - name: search
            max_calls: 1
workflow:
  max_steps: 2
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _pre_invocation(policy_file: Path) -> dict:
    return {
        "policy_file": str(policy_file),
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "test"},
        "context": {"approved": True},
    }


def test_split_dto_schema_tampering_cannot_bypass_phase_b(tmp_path: Path) -> None:
    """Changing the serialized compiled schema must fail before Phase B use."""
    policy_file = tmp_path / "policy.yaml"
    _split_policy(policy_file)
    issued = enforce_pre_call(_pre_invocation(policy_file))
    state = issued.__getstate__()
    state["_compiled_policy_dto"]["output_schema"]["required"] = []

    with pytest.raises(InvocationValidationError, match="compiled policy"):
        tampered = _reconstruct_precall_result(state)
        enforce_post_call(tampered, {})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda dto: dto["roles"].append("admin"),
        lambda dto: dto["conditions"].update(forged={"type": "boolean"}),
        lambda dto: dto["tools"][0].update(max_calls=200),
        lambda dto: dto["retry"].update(max_retries=10),
        lambda dto: dto["risk"].update(threshold=1.0),
        lambda dto: dto["preconditions"][0].update(declared_type="string"),
        lambda dto: dto["postconditions"].clear(),
        lambda dto: dto["guards"][0].update(condition="always"),
        lambda dto: dto["workflow"].update(max_steps=200),
        lambda dto: dto.update(source_identity="forged"),
        lambda dto: dto.update(declared_policy_version="forged"),
        lambda dto: dto.update(policy_contract_version="forged"),
        lambda dto: dto.update(pattern_engine="forged"),
        lambda dto: dto.update(canonicalization_profile="forged"),
    ],
)
def test_every_compiled_dto_field_is_bound_to_authenticated_content(
    tmp_path: Path,
    mutate: Callable[[dict], None],
) -> None:
    """Canonical DTO authentication must cover every authorization field."""
    policy_file = tmp_path / "policy.yaml"
    _split_policy(policy_file)
    issued = enforce_pre_call(_pre_invocation(policy_file))
    state = issued.__getstate__()
    mutate(state["_compiled_policy_dto"])

    with pytest.raises(InvocationValidationError, match="compiled policy"):
        _reconstruct_precall_result(state)


def test_authorization_objects_keep_no_policy_shaped_snapshots(
    tmp_path: Path,
) -> None:
    """Compiled authority and split tokens must not retain generic policy maps."""
    policy_file = tmp_path / "policy.yaml"
    _split_policy(policy_file)
    compiled = compile_policy(
        {
            "policy_version": "2.0",
            "roles": ["planner"],
        },
        source="snapshot-regression",
    )
    issued = enforce_pre_call(_pre_invocation(policy_file))

    assert not hasattr(compiled, "raw")
    assert not hasattr(compiled.authority, "restriction_values")
    assert not hasattr(issued, "effective_policy")
    assert not hasattr(issued, "_frozen_effective_policy")
    assert not hasattr(issued, "_frozen_policy_bytes")


def test_matching_typed_guard_effects_accumulate_without_recompilation() -> None:
    """Two typed effects must retain both independent added requirements."""
    compiled = compile_policy(
        {
            "policy_version": "2.0",
            "roles": ["planner"],
            "conditions": {
                "always": {"type": "boolean", "default": True},
            },
            "guards": [
                {
                    "when": {"condition": "always"},
                    "then": {
                        "pre_conditions": {
                            "required": {
                                "first": {"type": "boolean"},
                            },
                        },
                    },
                },
                {
                    "when": {"condition": "always"},
                    "then": {
                        "pre_conditions": {
                            "required": {
                                "second": {"type": "boolean"},
                            },
                        },
                    },
                },
            ],
        },
        source="typed-cumulative-guards",
    )

    assert all(
        isinstance(guard.effect, CompiledPolicyOverlay)
        for guard in compiled.guards
    )
    assert all(not hasattr(guard, "then") for guard in compiled.guards)

    effective, evaluated, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {"first": True, "second": True},
    )

    assert [item.name for item in effective.preconditions] == [
        "first",
        "second",
    ]
    assert [item["matched"] for item in evaluated] == [True, True]


def test_session_pins_one_compiled_policy_across_policy_file_changes(
    tmp_path: Path,
) -> None:
    """A session step cannot combine open-time workflow with reloaded authority."""
    policy_file = tmp_path / "session-policy.yaml"
    _split_policy(policy_file)
    governance = AEGIS()
    session = governance.open_session(policy_file=str(policy_file))

    replacement = """
policy_version: "2.0"
roles: [reviewer]
output_schema:
  type: object
workflow:
  max_steps: 200
""".strip()
    policy_file.write_text(replacement + "\n", encoding="utf-8")
    stat = policy_file.stat()
    os.utime(policy_file, (stat.st_atime + 2, stat.st_mtime + 2))

    step = session.enforce_step_pre_call(
        _pre_invocation(policy_file),
        step_id="pinned",
    )
    with pytest.raises(SchemaValidationError):
        session.enforce_step_post_call(step, {})


def test_policy_lint_and_cli_render_compiler_schema_diagnostics(
    tmp_path: Path,
) -> None:
    """Schema-invalid roles must use the shared compiler code and JSON path."""
    policy_file = tmp_path / "invalid-roles.yaml"
    policy_file.write_text(
        'policy_version: "2.0"\nroles: planner\n',
        encoding="utf-8",
    )

    findings = lint_policy(str(policy_file))
    cli_errors = _lint_policy(policy_file)

    assert findings == [
        {
            "code": "POLICY_SCHEMA_VALIDATION_ERROR",
            "message": (
                "Policy schema validation failed at $.roles: "
                "'planner' is not of type 'array'"
            ),
            "target_kind": "policy",
            "path": str(policy_file),
            "details": {"path": "$.roles", "validator": "type"},
        },
    ]
    assert cli_errors == [
        "[POLICY_SCHEMA_VALIDATION_ERROR] $.roles: "
        "Policy schema validation failed at $.roles: "
        "'planner' is not of type 'array'"
    ]
