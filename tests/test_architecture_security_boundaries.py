"""AST fitness tests for security-sensitive policy boundaries."""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_ENFORCEMENT = _ROOT / "aegis" / "_internal" / "enforcement.py"
_SESSION = _ROOT / "aegis" / "_internal" / "session.py"
_TOOLS = _ROOT / "aegis" / "_internal" / "tools.py"
_RISK = _ROOT / "aegis" / "_internal" / "risk_scoring.py"
_MODULES = {
    name: _ROOT / "aegis" / "_internal" / f"{name}.py"
    for name in (
        "compiled_policy",
        "policy_compiler",
        "policy_loader",
        "restrictions",
        "guards",
        "enforcement",
        "session",
        "tools",
        "risk_scoring",
        "retry",
        "workflow_lint",
        "cli",
    )
}

_AUTHORIZATION_FUNCTIONS = {
    "_run_phase_a",
    "_run_phase_b",
    "_run_pipeline",
    "_validate_policy_strict",
    "authorize_step_tool_call",
    "_evaluate_risk_condition",
}
_POLICY_NAMES = {
    "policy",
    "effective_policy",
    "original_policy",
}


def _functions(path: Path) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _authorization_violations(path: Path) -> list[str]:
    violations: list[str] = []
    for function in _functions(path):
        if function.name not in _AUTHORIZATION_FUNCTIONS:
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in _POLICY_NAMES
                and node.func.attr == "get"
            ):
                violations.append(
                    f"{path.name}:{node.lineno}:{function.name} "
                    f"calls {node.func.value.id}.get()"
                )
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in _POLICY_NAMES
            ):
                violations.append(
                    f"{path.name}:{node.lineno}:{function.name} "
                    f"indexes {node.value.id}[]"
                )
    return violations


def test_authorization_functions_do_not_read_raw_policy_mappings() -> None:
    """Raw mapping reads would bypass the compiler's closed semantics."""
    violations = [
        violation
        for path in (_ENFORCEMENT, _SESSION, _RISK)
        for violation in _authorization_violations(path)
    ]
    assert violations == []


def test_policy_loads_are_confined_to_immediate_compile_helper() -> None:
    """A new direct load_policy call would create an uncompiled authority path."""
    violations: list[str] = []
    for function in _functions(_ENFORCEMENT):
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "load_policy"
                and function.name != "_load_compiled_policy"
            ):
                violations.append(
                    f"{_ENFORCEMENT.name}:{node.lineno}:{function.name}"
                )
    assert violations == []


def test_tool_validation_has_no_raw_policy_compatibility_branch() -> None:
    """Authorization-time tool validation must accept compiled limits only."""
    source = _TOOLS.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(_TOOLS))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "validate_tool_constraints"
    )
    mapping_checks = [
        node.lineno
        for node in ast.walk(function)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and any(
                isinstance(arg, ast.Name) and arg.id == "Mapping"
                for arg in node.args
            )
        )
    ]
    assert mapping_checks == []


_COMPILE_ALLOWLIST = {
    ("enforcement", "_load_compiled_policy"),
    ("enforcement", "_compile_cached_policy"),
    ("policy_loader", "_compile_and_compare_composition"),
    ("retry", "with_retry"),
    ("workflow_lint", "lint_policy"),
    ("cli", "_lint_policy"),
    ("cli", "_validate_policy"),
}
_LOAD_ALLOWLIST = {
    ("enforcement", "_load_compiled_policy"),
    ("policy_loader", "*"),
    ("retry", "with_retry"),
    ("cli", "_validate_policy"),
}
_BANNED_SNAPSHOT_FIELDS = {
    "raw",
    "raw_policy",
    "restriction_values",
    "effective_policy",
    "_frozen_effective_policy",
    "_frozen_policy_bytes",
    "_serialized_policy_bytes",
}
_POLICY_ROOT_KEYS = {
    "roles",
    "conditions",
    "tools",
    "retry_policy",
    "risk",
    "pre_conditions",
    "post_conditions",
    "output_schema",
    "guards",
    "workflow",
}
_POLICY_VIEW_ALLOWLIST = {
    ("enforcement", "_compiled_gate_projection"),
    ("enforcement", "_compiled_policy_to_dto"),
    ("enforcement", "_compiled_overlay_to_dto"),
}
_COMPILED_BOUNDARIES = {
    "_run_phase_a": {"policy"},
    "_run_phase_b": {"effective_policy", "policy"},
    "_run_pipeline": {"policy"},
    "_validate_policy_strict": {"policy"},
    "evaluate_compiled_guards": {"policy"},
    "_apply_compiled_overlay": {"policy"},
    "_enforce_pre_call_compiled": {"policy"},
    "compute_compiled_risk_score": {"policy"},
}


def _annotation_text(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _fitness_violations(
    source: str,
    *,
    module_name: str,
) -> list[str]:
    """Find semantic boundary violations without relying on local variable names."""
    tree = ast.parse(source, filename=f"{module_name}.py")
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_name = node.name
            for call in (
                child for child in ast.walk(node) if isinstance(child, ast.Call)
            ):
                called = _call_name(call)
                if (
                    called == "compile_policy"
                    and (module_name, function_name) not in _COMPILE_ALLOWLIST
                ):
                    violations.append(
                        f"{module_name}:{call.lineno}:{function_name}:compile_policy"
                    )
                if (
                    called == "load_policy"
                    and (module_name, function_name) not in _LOAD_ALLOWLIST
                    and (module_name, "*") not in _LOAD_ALLOWLIST
                ):
                    violations.append(
                        f"{module_name}:{call.lineno}:{function_name}:load_policy"
                    )

            compiled_names = {
                arg.arg
                for arg in (*node.args.posonlyargs, *node.args.args)
                if _annotation_text(arg.annotation) == "CompiledPolicy"
            }
            changed = True
            while changed:
                changed = False
                for assignment in (
                    child
                    for child in ast.walk(node)
                    if isinstance(child, (ast.Assign, ast.AnnAssign))
                ):
                    value = assignment.value
                    targets = (
                        assignment.targets
                        if isinstance(assignment, ast.Assign)
                        else [assignment.target]
                    )
                    if (
                        isinstance(value, ast.Name)
                        and value.id in compiled_names
                    ):
                        for target in targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id not in compiled_names
                            ):
                                compiled_names.add(target.id)
                                changed = True
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in compiled_names
                    and child.func.attr == "get"
                ):
                    violations.append(
                        f"{module_name}:{child.lineno}:{function_name}:raw-get"
                    )
                if (
                    isinstance(child, ast.Subscript)
                    and isinstance(child.value, ast.Name)
                    and child.value.id in compiled_names
                ):
                    violations.append(
                        f"{module_name}:{child.lineno}:{function_name}:raw-index"
                    )

            required = _COMPILED_BOUNDARIES.get(function_name, set())
            annotations = {
                arg.arg: _annotation_text(arg.annotation)
                for arg in (*node.args.posonlyargs, *node.args.args)
            }
            for parameter in required:
                if "CompiledPolicy" not in annotations.get(parameter, ""):
                    violations.append(
                        f"{module_name}:{node.lineno}:{function_name}:"
                        f"{parameter}-not-compiled"
                    )

            for literal in (
                child for child in ast.walk(node) if isinstance(child, ast.Dict)
            ):
                keys = {
                    key.value
                    for key in literal.keys
                    if isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                }
                if (
                    len(keys & _POLICY_ROOT_KEYS) >= 4
                    and (module_name, function_name)
                    not in _POLICY_VIEW_ALLOWLIST
                    and module_name not in {"policy_compiler", "policy_loader"}
                ):
                    violations.append(
                        f"{module_name}:{literal.lineno}:{function_name}:"
                        "policy-shaped-snapshot"
                    )

        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            field_name = node.target.id
            annotation = _annotation_text(node.annotation)
            if (
                field_name in _BANNED_SNAPSHOT_FIELDS
                or (
                    "Mapping" in annotation
                    and "policy" in field_name.lower()
                )
            ):
                violations.append(
                    f"{module_name}:{node.lineno}:snapshot-field:{field_name}"
                )
        if (
            isinstance(node, ast.Attribute)
            and node.attr in _BANNED_SNAPSHOT_FIELDS
        ):
            violations.append(
                f"{module_name}:{node.lineno}:snapshot-attribute:{node.attr}"
            )
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "policy_from_restriction_values"
        ):
            violations.append(
                f"{module_name}:{node.lineno}:policy-snapshot-rebuilder"
            )
    return sorted(set(violations))


def test_full_authorization_module_set_obeys_compiled_boundary() -> None:
    """Every production authorization module must stay on typed authority."""
    violations = [
        violation
        for module_name, path in _MODULES.items()
        for violation in _fitness_violations(
            path.read_text(encoding="utf-8"),
            module_name=module_name,
        )
    ]
    assert violations == []


def test_fitness_analyzer_catches_prior_forbidden_patterns() -> None:
    """The fitness gate catches patterns by data flow and shape, not one name."""
    fixtures = {
        "guards": """
def evaluate_compiled_guards(policy: CompiledPolicy):
    authorized = policy
    reopened = compile_policy({"roles": authorized["roles"]})
    return reopened
""",
        "session": """
def enforce_step_pre_call(self, invocation):
    return load_policy(invocation["policy_file"])
""",
        "enforcement": """
from dataclasses import dataclass
from typing import Mapping
@dataclass
class Token:
    authority_blob: Mapping[str, object]
def issue():
    return {"roles": [], "tools": {}, "risk": {}, "workflow": {}}
""",
    }
    violations = [
        violation
        for module_name, source in fixtures.items()
        for violation in _fitness_violations(source, module_name=module_name)
    ]
    assert any("compile_policy" in item for item in violations)
    assert any("raw-index" in item for item in violations)
    assert any("load_policy" in item for item in violations)
    assert any("policy-shaped-snapshot" in item for item in violations)
