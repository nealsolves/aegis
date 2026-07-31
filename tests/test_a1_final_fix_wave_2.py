"""Final whole-branch A1 security regressions."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import re2

from aegis._internal.cli import _lint_policy
from aegis._internal.enforcement import (
    AEGIS,
    _compiled_policy_to_dto,
    _reconstruct_precall_result,
    _validate_compiled_role,
    enforce_pre_call,
)
from aegis._internal.errors import (
    GovernanceViolationError,
    InvocationValidationError,
    PolicyLoadError,
    PolicyValidationError,
    PreconditionError,
    ToolConstraintViolationError,
)
from aegis._internal.guards import evaluate_compiled_guards
from aegis._internal.policy_compiler import compile_policy
from aegis._internal.policy_loader import (
    compile_composed_policy,
    load_policy,
)
from aegis._internal.tools import validate_tool_constraints
from aegis._internal.workflow_lint import lint_policy


def _tool_invocation() -> dict:
    return {
        "tool_calls": [{"name": "search", "call_id": "call-1"}],
    }


def _base_roles_policy() -> dict:
    return {
        "policy_version": "2.0",
        "roles": ["planner", "reviewer"],
    }


def _guard_policy(*effects: dict) -> dict:
    return {
        **_base_roles_policy(),
        "conditions": {
            "always": {"type": "boolean", "default": True},
        },
        "guards": [
            {
                "when": {"condition": "always"},
                "then": effect,
            }
            for effect in effects
        ],
    }


def _workflow_policy(sequence: list[str] | None) -> dict:
    policy = {
        "policy_version": "2.0",
        "roles": ["planner"],
    }
    if sequence is not None:
        policy["workflow"] = {"required_sequence": sequence}
    return policy


def _write_policy(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(body).strip() + "\n", encoding="utf-8")


def _precondition_policy(
    path: Path,
    *,
    deny_all_tools: bool = False,
) -> None:
    tools = "tools:\n  allowed_tools: []\n" if deny_all_tools else ""
    _write_policy(
        path,
        (
            'policy_version: "2.0"\n'
            "roles: [planner]\n"
            f"{tools}"
            "pre_conditions:\n"
            "  required:\n"
            "    code:\n"
            "      type: string\n"
            '      pattern: "^ok$"\n'
        ),
    )


def _pre_invocation(path: Path, *, code: str) -> dict:
    return {
        "policy_file": str(path),
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "test"},
        "context": {"code": code},
    }


def test_explicit_empty_tools_deny_all_but_absent_tools_remain_unconfigured():
    absent = compile_policy(
        _base_roles_policy(),
        source="tools-absent",
    )
    explicit_empty = compile_policy(
        {
            **_base_roles_policy(),
            "tools": {"allowed_tools": []},
        },
        source="tools-deny-all",
    )

    assert validate_tool_constraints(
        _tool_invocation(),
        absent.tools,
    ) == {"tools_checked": [], "violations": []}
    with pytest.raises(ToolConstraintViolationError):
        validate_tool_constraints(_tool_invocation(), explicit_empty.tools)


def test_tool_presence_is_typed_and_authenticated_in_compiled_dto(
    tmp_path: Path,
):
    policy_file = tmp_path / "deny-all-tools.yaml"
    _precondition_policy(
        policy_file,
        deny_all_tools=True,
    )
    issued = enforce_pre_call(_pre_invocation(policy_file, code="ok"))
    state = issued.__getstate__()
    dto = state["_compiled_policy_dto"]

    assert issued._compiled_policy.tools.configured is True
    assert dto["tools_configured"] is True

    dto["tools_configured"] = False
    with pytest.raises(InvocationValidationError, match="compiled policy"):
        _reconstruct_precall_result(state)


def test_static_role_subset_replaces_parent_allowlist():
    compiled = compile_composed_policy(
        _base_roles_policy(),
        {
            "policy_version": "2.0",
            "roles": ["reviewer"],
        },
    )

    assert compiled.roles == ("reviewer",)


def test_matched_guard_role_subset_excludes_parent_role():
    compiled = compile_policy(
        _guard_policy({"roles": ["reviewer"]}),
        source="guard-role-subset",
    )

    effective, _, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {},
    )

    assert effective.roles == ("reviewer",)
    with pytest.raises(GovernanceViolationError):
        _validate_compiled_role("planner", effective)


def test_cumulative_matched_role_subsets_preserve_narrow_allowlist():
    compiled = compile_policy(
        _guard_policy(
            {"roles": ["reviewer"]},
            {"roles": ["reviewer"]},
        ),
        source="cumulative-role-subset",
    )

    effective, _, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {},
    )

    assert effective.roles == ("reviewer",)


def test_replace_composition_cannot_shorten_inherited_required_sequence():
    parent = _workflow_policy(["collect", "review", "publish"])
    child = {
        **_workflow_policy(["collect", "publish"]),
        "composition_strategy": "replace",
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_composed_policy(parent, child)

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"


def test_explicit_unchanged_required_sequence_remains_exact():
    sequence = ["collect", "review", "publish"]

    compiled = compile_composed_policy(
        _workflow_policy(sequence),
        _workflow_policy(sequence),
    )

    assert tuple(compiled.workflow["required_sequence"]) == tuple(sequence)


def test_guard_must_keep_inherited_required_sequence_exact():
    sequence = ["collect", "review", "publish"]
    raw = {
        **_guard_policy(
            {"workflow": {"required_sequence": sequence}},
        ),
        "workflow": {"required_sequence": sequence},
    }

    compiled = compile_policy(raw, source="guard-sequence-exact")
    effective, _, _ = evaluate_compiled_guards(
        compiled,
        compiled.guards,
        {},
    )

    assert tuple(effective.workflow["required_sequence"]) == tuple(sequence)


def test_guard_cannot_shorten_inherited_required_sequence():
    raw = {
        **_guard_policy(
            {
                "workflow": {
                    "required_sequence": ["collect", "publish"],
                },
            },
        ),
        "workflow": {
            "required_sequence": ["collect", "review", "publish"],
        },
    }

    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(raw, source="guard-sequence-shortening")

    assert exc.value.code == "POLICY_WIDENING"
    assert exc.value.details["path"] == "workflow"


def test_file_lint_matches_runtime_for_widening_extends(tmp_path: Path):
    parent = tmp_path / "parent.yaml"
    child = tmp_path / "nested" / "child.yaml"
    _write_policy(
        parent,
        """
        policy_version: "2.0"
        roles: [planner]
        """,
    )
    _write_policy(
        child,
        """
        extends: "../parent.yaml"
        policy_version: "2.0"
        roles: [admin]
        """,
    )

    with pytest.raises(PolicyValidationError) as runtime:
        load_policy(str(child))
    findings = lint_policy(str(child))
    cli_errors = _lint_policy(child)

    assert runtime.value.code == "POLICY_WIDENING"
    assert runtime.value.details["path"] == "roles"
    assert findings[0]["code"] == runtime.value.code
    assert findings[0]["details"]["path"] == runtime.value.details["path"]
    assert cli_errors[0].startswith("[POLICY_WIDENING] roles:")


def test_file_lint_resolves_nested_source_relative_extends(tmp_path: Path):
    parent = tmp_path / "parent.yaml"
    middle = tmp_path / "nested" / "middle.yaml"
    child = tmp_path / "nested" / "deeper" / "child.yaml"
    _write_policy(
        parent,
        """
        policy_version: "2.0"
        roles: [planner, reviewer]
        """,
    )
    _write_policy(
        middle,
        """
        extends: "../parent.yaml"
        policy_version: "2.0"
        roles: [planner]
        """,
    )
    _write_policy(
        child,
        """
        extends: "../middle.yaml"
        policy_version: "2.0"
        roles: [planner]
        """,
    )

    assert lint_policy(str(child)) == []
    assert _lint_policy(child) == []
    assert load_policy(str(child))["roles"] == ["planner"]


@pytest.mark.parametrize("failure", ["cycle", "missing"])
def test_file_lint_surfaces_extends_load_failures(
    tmp_path: Path,
    failure: str,
):
    child = tmp_path / "child.yaml"
    if failure == "cycle":
        parent = tmp_path / "parent.yaml"
        _write_policy(
            parent,
            """
            extends: "child.yaml"
            policy_version: "2.0"
            roles: [planner]
            """,
        )
        extends = "parent.yaml"
    else:
        extends = "missing.yaml"
    _write_policy(
        child,
        f"""
        extends: "{extends}"
        policy_version: "2.0"
        roles: [planner]
        """,
    )

    with pytest.raises(PolicyLoadError):
        load_policy(str(child))

    findings = lint_policy(str(child))
    cli_errors = _lint_policy(child)
    assert findings[0]["code"] == "POLICY_LOAD_ERROR"
    assert cli_errors[0].startswith("[POLICY_LOAD_ERROR]")


def test_compiled_pattern_exposes_only_authenticated_immutable_metadata():
    compiled = compile_policy(
        {
            **_base_roles_policy(),
            "pre_conditions": {
                "required": {
                    "code": {
                        "type": "string",
                        "pattern": "^ok$",
                    },
                },
            },
        },
        source="pattern-surface",
    )
    pattern = compiled.preconditions[0].pattern
    assert pattern is not None

    assert not hasattr(pattern, "_compiled")
    assert not hasattr(pattern, "runtime")
    assert not hasattr(pattern, "registry")
    assert pattern.source == "^ok$"
    assert pattern.path.endswith(".code.pattern")
    assert isinstance(pattern.program_digest, str)
    assert pattern.source_max_bytes == 256
    assert pattern.input_max_bytes == 16_384


def test_pattern_runtime_mutation_cannot_weaken_pinned_session(
    tmp_path: Path,
):
    policy_file = tmp_path / "pattern.yaml"
    _precondition_policy(policy_file)
    governance = AEGIS()

    with governance.open_session(policy_file=str(policy_file)) as session:
        pattern = session._compiled_policy.preconditions[0].pattern
        assert pattern is not None
        if hasattr(pattern, "_compiled"):
            object.__setattr__(pattern, "_compiled", re2.compile(".*"))

        with pytest.raises(PreconditionError):
            session.enforce_step_pre_call(
                _pre_invocation(policy_file, code="not-ok"),
            )
        session.cancel()


def test_pattern_dto_reconstructs_from_authenticated_program_metadata(
    tmp_path: Path,
):
    policy_file = tmp_path / "pattern-dto.yaml"
    _precondition_policy(policy_file)
    issued = enforce_pre_call(_pre_invocation(policy_file, code="ok"))
    dto = _compiled_policy_to_dto(issued._compiled_policy)
    pattern = dto["preconditions"][0]["pattern"]

    assert set(pattern) == {
        "source",
        "path",
        "program_digest",
        "source_max_bytes",
        "input_max_bytes",
    }
    pattern["program_digest"] = "0" * 64
    state = issued.__getstate__()
    state["_compiled_policy_dto"] = dto
    with pytest.raises(InvocationValidationError, match="compiled policy"):
        _reconstruct_precall_result(state)
