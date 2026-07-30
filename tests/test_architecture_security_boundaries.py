"""AST fitness tests for security-sensitive policy boundaries."""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_ENFORCEMENT = _ROOT / "aegis" / "_internal" / "enforcement.py"
_SESSION = _ROOT / "aegis" / "_internal" / "session.py"
_TOOLS = _ROOT / "aegis" / "_internal" / "tools.py"
_RISK = _ROOT / "aegis" / "_internal" / "risk_scoring.py"

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
