"""AST fitness tests for security-sensitive policy boundaries."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_ENFORCEMENT = _ROOT / "aegis" / "_internal" / "enforcement.py"
_SESSION = _ROOT / "aegis" / "_internal" / "session.py"
_EVIDENCE_FINALIZER = (
    _ROOT / "aegis" / "_internal" / "evidence_finalizer.py"
)
_OPERATION_REGISTRY = (
    _ROOT / "aegis" / "_internal" / "operation_registry.py"
)
_TOOLS = _ROOT / "aegis" / "_internal" / "tools.py"
_RISK = _ROOT / "aegis" / "_internal" / "risk_scoring.py"
_GATES = _ROOT / "aegis" / "_internal" / "gates.py"
_GATE_PROJECTION = _ROOT / "aegis" / "_internal" / "gate_projection.py"
_MODULES = {
    name: _ROOT / "aegis" / "_internal" / f"{name}.py"
    for name in (
        "compiled_policy",
        "conditions",
        "gates",
        "policy_compiler",
        "policy_loader",
        "provenance_gate",
        "restrictions",
        "guards",
        "enforcement",
        "schema_compiler",
        "session",
        "tools",
        "validator",
        "validator_hook",
        "risk_history",
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


def test_v2_sink_surface_has_no_mutable_delivery_controls() -> None:
    import aegis
    import aegis.sinks as sinks

    forbidden = {
        "emit_to_sink",
        "get_sink_failure_mode",
        "set_sink_failure_mode",
    }
    assert forbidden.isdisjoint(sinks.__all__)
    assert all(not hasattr(sinks, name) for name in forbidden)
    assert all(not hasattr(aegis, name) for name in forbidden)


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


def test_gate_projection_boundary_has_no_live_view_wrapper() -> None:
    """A wrapper with caller-owned backing data would reopen live authority."""
    violations = []
    for path in (_GATES, _GATE_PROJECTION):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations.extend(
            f"{path.name}:{node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "_ImmutableView"
        )
    assert violations == []


def test_custom_gate_calls_do_not_receive_compiled_policy_directly() -> None:
    """Compiled authority must cross the gate boundary only as a projection."""
    tree = ast.parse(_GATES.read_text(encoding="utf-8"), filename=str(_GATES))
    violations: list[str] = []
    for function in (
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        compiled_names = {
            argument.arg
            for argument in (*function.args.posonlyargs, *function.args.args)
            if "CompiledPolicy" in _annotation_text(argument.annotation)
        }
        for assignment in (
            node
            for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
        ):
            value = assignment.value
            if isinstance(value, ast.Name) and value.id in compiled_names:
                compiled_names.update(_assigned_names(assignment))
        for call in (
            node for node in ast.walk(function) if isinstance(node, ast.Call)
        ):
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "evaluate"
                and len(call.args) >= 2
                and isinstance(call.args[1], ast.Name)
                and call.args[1].id in compiled_names
            ):
                violations.append(f"{_GATES.name}:{call.lineno}:{function.name}")
    assert violations == []


def test_enforcement_branches_only_on_normalized_boundary_outcomes() -> None:
    """Raw gate, hook, and risk values must not make authorization decisions."""
    forbidden_attributes = {"passed", "failures", "decision", "exceeded", "mode"}
    violations: list[str] = []
    for path in (_ENFORCEMENT, _SESSION):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for branch in (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert))
        ):
            test = branch.test
            raw_attributes = {
                node.attr
                for node in ast.walk(test)
                if isinstance(node, ast.Attribute)
                and node.attr in forbidden_attributes
            }
            raw_decision_constants = {
                node.id
                for node in ast.walk(test)
                if isinstance(node, ast.Name)
                and node.id.startswith("VALIDATOR_")
            }
            if raw_attributes or raw_decision_constants:
                violations.append(
                    f"{path.name}:{branch.lineno}:"
                    f"{sorted(raw_attributes | raw_decision_constants)}"
                )
    assert violations == []


_COMPILE_ALLOWLIST = {
    ("enforcement", "_load_compiled_policy"),
    ("enforcement", "_compile_cached_policy"),
    ("policy_loader", "_compile_and_compare_composition"),
    ("policy_loader", "load_resolve_compile_policy"),
    ("retry", "with_retry"),
}
_LOAD_ALLOWLIST = {
    ("enforcement", "_load_compiled_policy"),
    ("policy_loader", "*"),
    ("retry", "with_retry"),
}
_DIAGNOSTIC_HELPER_ALLOWLIST = {
    ("workflow_lint", "lint_policy"),
    ("cli", "_lint_policy"),
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
_SEMANTIC_CALL_KINDS = {
    "compile_policy": "compile_policy",
    "load_policy": "load_policy",
    "load_resolve_compile_policy": "load_resolve_compile_policy",
    "enforce": "reload-capable-entrypoint",
    "enforce_invocation": "reload-capable-entrypoint",
    "enforce_invocation_async": "reload-capable-entrypoint",
    "enforce_pre_call": "reload-capable-entrypoint",
    "enforce_pre_call_async": "reload-capable-entrypoint",
}
_NARROW_RETAINED_MAPPING_FIELDS = {
    ("PreCallResult", "invocation_snapshot"),
    ("PreCallResult", "phase_a_metadata"),
    ("PreCallResult", "resolved_conditions"),
}


def _annotation_text(node: ast.AST | None) -> str:
    return ast.unparse(node) if node is not None else ""


def _annotation_guarantees_compiled_policy(node: ast.AST | None) -> bool:
    """Return whether the annotated value itself is a CompiledPolicy."""
    type_names = set(re.findall(r"\b[A-Za-z_]\w*\b", _annotation_text(node)))
    if "CompiledPolicy" not in type_names:
        return False
    return type_names <= {
        "CompiledPolicy",
        "None",
        "Optional",
        "Union",
    }


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _parent_maps(
    tree: ast.AST,
) -> tuple[dict[ast.AST, ast.AST], dict[ast.AST, str]]:
    parents: dict[ast.AST, ast.AST] = {}
    classes: dict[ast.AST, str] = {}

    def visit(node: ast.AST, class_name: str | None = None) -> None:
        next_class = node.name if isinstance(node, ast.ClassDef) else class_name
        if next_class is not None:
            classes[node] = next_class
        for child in ast.iter_child_nodes(node):
            parents[child] = node
            visit(child, next_class)

    visit(tree)
    return parents, classes


def _semantic_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for imported in node.names:
            kind = _SEMANTIC_CALL_KINDS.get(imported.name)
            if kind is not None:
                aliases[imported.asname or imported.name] = kind
    for name, kind in _SEMANTIC_CALL_KINDS.items():
        aliases.setdefault(name, kind)
    return aliases


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in targets if isinstance(target, ast.Name)]


def _call_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    imported_aliases: dict[str, str],
) -> dict[str, str]:
    aliases = dict(imported_aliases)
    changed = True
    while changed:
        changed = False
        for assignment in (
            child
            for child in ast.walk(function)
            if isinstance(child, (ast.Assign, ast.AnnAssign))
        ):
            value = assignment.value
            kind: str | None = None
            if isinstance(value, ast.Name):
                kind = aliases.get(value.id)
            elif isinstance(value, ast.Attribute):
                kind = _SEMANTIC_CALL_KINDS.get(value.attr)
            if kind is None:
                continue
            for name in _assigned_names(assignment):
                if aliases.get(name) != kind:
                    aliases[name] = kind
                    changed = True
    return aliases


def _semantic_call_kind(call: ast.Call, aliases: dict[str, str]) -> str | None:
    if isinstance(call.func, ast.Name):
        return aliases.get(call.func.id)
    if isinstance(call.func, ast.Attribute):
        return _SEMANTIC_CALL_KINDS.get(call.func.attr)
    return None


def _compiled_attributes(tree: ast.AST) -> set[str]:
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign):
            continue
        if not _annotation_guarantees_compiled_policy(node.annotation):
            continue
        if isinstance(node.target, ast.Attribute):
            attributes.add(node.target.attr)
        elif isinstance(node.target, ast.Name):
            attributes.add(node.target.id)

    changed = True
    while changed:
        changed = False
        for function in (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            compiled_names = {
                arg.arg
                for arg in (*function.args.posonlyargs, *function.args.args)
                if _annotation_guarantees_compiled_policy(arg.annotation)
            }
            for assignment in (
                child
                for child in ast.walk(function)
                if isinstance(child, (ast.Assign, ast.AnnAssign))
            ):
                value = assignment.value
                value_is_compiled = (
                    isinstance(value, ast.Name)
                    and value.id in compiled_names
                ) or (
                    isinstance(value, ast.Attribute)
                    and value.attr in attributes
                )
                if not value_is_compiled:
                    continue
                for target in (
                    assignment.targets
                    if isinstance(assignment, ast.Assign)
                    else [assignment.target]
                ):
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr not in attributes
                    ):
                        attributes.add(target.attr)
                        changed = True
                    elif (
                        isinstance(target, ast.Name)
                        and target.id not in compiled_names
                    ):
                        compiled_names.add(target.id)
    return attributes


def _compiled_return_names(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _annotation_guarantees_compiled_policy(node.returns)
    } | {
        "CompiledPolicy",
        "compile_policy",
        "load_resolve_compile_policy",
    }


def _compiled_local_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    compiled_attributes: set[str],
    compiled_returns: set[str],
    call_aliases: dict[str, str],
) -> set[str]:
    names = {
        arg.arg
        for arg in (*function.args.posonlyargs, *function.args.args)
        if _annotation_guarantees_compiled_policy(arg.annotation)
    }
    changed = True
    while changed:
        changed = False
        for assignment in (
            child
            for child in ast.walk(function)
            if isinstance(child, (ast.Assign, ast.AnnAssign))
        ):
            value = assignment.value
            value_is_compiled = (
                isinstance(value, ast.Name)
                and value.id in names
            ) or (
                isinstance(value, ast.Attribute)
                and value.attr in compiled_attributes
            ) or (
                isinstance(value, ast.Call)
                and (
                    _call_name(value) in compiled_returns
                    or _semantic_call_kind(value, call_aliases)
                    == "compile_policy"
                )
            )
            if not value_is_compiled:
                continue
            for name in _assigned_names(assignment):
                if name not in names:
                    names.add(name)
                    changed = True
    return names


def _compiled_expression(
    node: ast.AST,
    *,
    names: set[str],
    attributes: set[str],
) -> bool:
    return (
        isinstance(node, ast.Name)
        and node.id in names
    ) or (
        isinstance(node, ast.Attribute)
        and node.attr in attributes
    )


def _none_test(
    test: ast.AST,
    compiled_attributes: set[str],
) -> tuple[str, bool] | None:
    """Return (attribute, is_none_on_true_branch) for a compiled guard."""
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and len(test.comparators) == 1
        and isinstance(test.left, ast.Attribute)
        and test.left.attr in compiled_attributes
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    ):
        return None
    if isinstance(test.ops[0], ast.Is):
        return test.left.attr, True
    if isinstance(test.ops[0], ast.IsNot):
        return test.left.attr, False
    return None


def _node_is_within(node: ast.AST, statements: list[ast.stmt]) -> bool:
    return any(
        descendant is node
        for statement in statements
        for descendant in ast.walk(statement)
    )


def _reload_is_proven_unpinned(
    call: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    parents: dict[ast.AST, ast.AST],
    compiled_attributes: set[str],
) -> bool:
    current: ast.AST = call
    while current is not function and current in parents:
        parent = parents[current]
        if isinstance(parent, ast.If):
            guarded = _none_test(parent.test, compiled_attributes)
            if guarded is not None:
                _, none_on_true = guarded
                in_true = _node_is_within(call, parent.body)
                in_false = _node_is_within(call, parent.orelse)
                if (in_true and none_on_true) or (
                    in_false and not none_on_true
                ):
                    return True
        current = parent
    return False


def _retained_mapping_field(
    node: ast.AnnAssign,
    *,
    parents: dict[ast.AST, ast.AST],
    classes: dict[ast.AST, str],
) -> tuple[str, str] | None:
    annotation = _annotation_text(node.annotation).replace(" ", "")
    if (
        "Mapping[str,Any]" not in annotation
        and "Mapping[str,object]" not in annotation
    ):
        return None

    class_name = classes.get(node)
    if class_name is None:
        return None
    if isinstance(node.target, ast.Name):
        field_name = node.target.id
        if not isinstance(parents.get(node), ast.ClassDef):
            return None
    elif (
        isinstance(node.target, ast.Attribute)
        and isinstance(node.target.value, ast.Name)
        and node.target.value.id == "self"
    ):
        field_name = node.target.attr
    else:
        return None
    if (class_name, field_name) in _NARROW_RETAINED_MAPPING_FIELDS:
        return None
    return class_name, field_name


def _fitness_violations(
    source: str,
    *,
    module_name: str,
) -> list[str]:
    """Find semantic boundary violations without relying on local variable names."""
    tree = ast.parse(source, filename=f"{module_name}.py")
    parents, classes = _parent_maps(tree)
    imported_aliases = _semantic_import_aliases(tree)
    compiled_attributes = _compiled_attributes(tree)
    compiled_returns = _compiled_return_names(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_name = node.name
            aliases = _call_aliases(node, imported_aliases)
            for call in (
                child for child in ast.walk(node) if isinstance(child, ast.Call)
            ):
                called = _semantic_call_kind(call, aliases)
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
                if (
                    called == "load_resolve_compile_policy"
                    and (module_name, function_name)
                    not in _DIAGNOSTIC_HELPER_ALLOWLIST
                    and module_name != "policy_loader"
                ):
                    violations.append(
                        f"{module_name}:{call.lineno}:{function_name}:"
                        "load_resolve_compile_policy"
                    )
                if (
                    called == "reload-capable-entrypoint"
                    and compiled_attributes
                    and not _reload_is_proven_unpinned(
                        call,
                        node,
                        parents=parents,
                        compiled_attributes=compiled_attributes,
                    )
                ):
                    violations.append(
                        f"{module_name}:{call.lineno}:{function_name}:"
                        "reload-capable-entrypoint"
                    )

            compiled_names = _compiled_local_names(
                node,
                compiled_attributes=compiled_attributes,
                compiled_returns=compiled_returns,
                call_aliases=aliases,
            )
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and _compiled_expression(
                        child.func.value,
                        names=compiled_names,
                        attributes=compiled_attributes,
                    )
                    and child.func.attr == "get"
                ):
                    violations.append(
                        f"{module_name}:{child.lineno}:{function_name}:raw-get"
                    )
                if (
                    isinstance(child, ast.Subscript)
                    and _compiled_expression(
                        child.value,
                        names=compiled_names,
                        attributes=compiled_attributes,
                    )
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

        if isinstance(node, ast.AnnAssign):
            field_name = (
                node.target.id
                if isinstance(node.target, ast.Name)
                else (
                    node.target.attr
                    if isinstance(node.target, ast.Attribute)
                    else ""
                )
            )
            retained_mapping = _retained_mapping_field(
                node,
                parents=parents,
                classes=classes,
            )
            if field_name in _BANNED_SNAPSHOT_FIELDS or retained_mapping:
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


def test_fitness_analyzer_catches_reload_after_session_policy_pin() -> None:
    """A pinned branch must not call a public entrypoint that reloads policy."""
    source = """
class GovernanceSession:
    def __init__(self):
        self._compiled_policy: CompiledPolicy | None = None

    def enforce_step_pre_call(self, invocation):
        if self._compiled_policy is not None:
            return self._aigc.enforce_pre_call(invocation)
"""

    violations = _fitness_violations(source, module_name="session")

    assert len(violations) == 1
    assert violations[0].endswith(
        ":enforce_step_pre_call:reload-capable-entrypoint"
    )


def test_fitness_analyzer_resolves_local_compile_call_alias() -> None:
    """Assigning the compiler to another name must not evade the boundary."""
    source = """
def authorize(raw):
    compiler = compile_policy
    return compiler(raw, source="alias-bypass")
"""

    violations = _fitness_violations(source, module_name="guards")

    assert len(violations) == 1
    assert violations[0].endswith(":authorize:compile_policy")


def test_fitness_analyzer_resolves_imported_compile_call_alias() -> None:
    """An imported compiler alias must retain its security-sensitive identity."""
    source = """
from aegis._internal.policy_compiler import compile_policy as build_authority

def authorize(raw):
    return build_authority(raw, source="import-alias-bypass")
"""

    violations = _fitness_violations(source, module_name="guards")

    assert len(violations) == 1
    assert violations[0].endswith(":authorize:compile_policy")


def test_fitness_analyzer_rejects_diagnostic_load_without_compile() -> None:
    """The lint exception must not admit a loaded raw policy by itself."""
    source = """
def _lint_policy(path):
    policy = load_policy(path)
    return policy
"""

    violations = _fitness_violations(source, module_name="cli")

    assert len(violations) == 1
    assert violations[0].endswith(":_lint_policy:load_policy")


@pytest.mark.parametrize(
    "intervening",
    [
        "authorize_from_raw(policy)",
        "emit_metric()",
        "_ = policy.roles",
        '_ = policy["roles"]',
        '_ = policy.get("roles")',
        "alias = policy",
        "if should_skip:\n        return []",
        "if invalid:\n        raise ValueError('invalid')",
    ],
    ids=[
        "authorization-call",
        "unrelated-call",
        "attribute-read",
        "subscript-read",
        "get-read",
        "alias-assignment",
        "branch-early-return",
        "branch-exception",
    ],
)
def test_fitness_analyzer_rejects_intervening_raw_policy_consumer(
    intervening: str,
) -> None:
    """A lint load may flow only to compilation, never another consumer."""
    source = f"""
def _lint_policy(path):
    policy = load_policy(path)
    {intervening}
    return compile_policy(policy, source=str(path))
"""

    violations = _fitness_violations(source, module_name="cli")

    assert any(
        item.endswith(":_lint_policy:load_policy")
        for item in violations
    )


def test_fitness_analyzer_rejects_divergent_conditional_compile() -> None:
    """Every path from a raw load must compile that exact loaded value."""
    source = """
def _lint_policy(path, use_resolved):
    policy = load_policy(path)
    if use_resolved:
        return compile_policy(policy, source=str(path))
    return compile_policy({}, source=str(path))
"""

    violations = _fitness_violations(source, module_name="cli")

    assert any(
        item.endswith(":_lint_policy:load_policy")
        for item in violations
    )


def test_production_diagnostic_entrypoints_do_not_load_raw_policies() -> None:
    """Lint/CLI must call one typed source-aware diagnostic boundary."""
    entrypoints = {
        "workflow_lint": ("lint_policy",),
        "cli": ("_lint_policy", "_validate_policy"),
    }
    violations = []
    for module_name, function_names in entrypoints.items():
        tree = ast.parse(
            _MODULES[module_name].read_text(encoding="utf-8"),
        )
        for function in (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in function_names
        ):
            for call in (
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Call)
            ):
                if _call_name(call) in {"load_policy", "compile_policy"}:
                    violations.append(
                        f"{module_name}:{function.name}:{_call_name(call)}"
                    )

    assert violations == []


def test_fitness_analyzer_rejects_load_compile_flow_in_enforcement() -> None:
    """The diagnostic exception must never authorize a production load path."""
    source = """
def authorize(path):
    policy = load_policy(path)
    return compile_policy(policy, source=str(path))
"""

    violations = _fitness_violations(source, module_name="enforcement")

    assert any(item.endswith(":authorize:load_policy") for item in violations)
    assert any(item.endswith(":authorize:compile_policy") for item in violations)


def test_fitness_analyzer_propagates_compiled_attribute_identity() -> None:
    """A CompiledPolicy attribute alias must remain typed through assignment."""
    source = """
class Session:
    def __init__(self):
        self._compiled_policy: CompiledPolicy | None = None

    def authorize(self):
        authority = self._compiled_policy
        return authority["roles"]
"""

    violations = _fitness_violations(source, module_name="session")

    assert len(violations) == 1
    assert violations[0].endswith(":authorize:raw-index")


def test_fitness_analyzer_propagates_compiled_return_identity_to_get() -> None:
    """A typed CompiledPolicy return must remain typed through assignment."""
    source = """
class Session:
    def __init__(self):
        self._compiled_policy: CompiledPolicy | None = None

    def pinned(self) -> CompiledPolicy:
        return self._compiled_policy

    def authorize(self):
        authority = self.pinned()
        return authority.get("roles")
"""

    violations = _fitness_violations(source, module_name="session")

    assert len(violations) == 1
    assert violations[0].endswith(":authorize:raw-get")


def test_fitness_analyzer_rejects_arbitrarily_named_retained_policy_map() -> None:
    """A generic retained authority mapping must fail regardless of its name."""
    source = """
from dataclasses import dataclass
from typing import Any, Mapping

@dataclass
class Token:
    authority_blob: Mapping[str, Any]
"""

    violations = _fitness_violations(source, module_name="enforcement")

    assert len(violations) == 1
    assert violations[0].endswith(":snapshot-field:authority_blob")


def test_fitness_analyzer_allows_narrow_evidence_and_typed_dto_maps() -> None:
    """Narrow evidence and JsonValue DTO maps are not raw authority snapshots."""
    source = """
from dataclasses import dataclass
from typing import Any, Mapping

@dataclass
class PreCallResult:
    invocation_snapshot: Mapping[str, Any]
    phase_a_metadata: Mapping[str, Any]

@dataclass
class CompiledSchema:
    schema: Mapping[str, JsonValue]
"""

    assert _fitness_violations(source, module_name="enforcement") == []


def test_split_handles_expose_only_opaque_identity_fields() -> None:
    tree = ast.parse(_ENFORCEMENT.read_text(encoding="utf-8"))
    result_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "PreCallResult"
    )
    fields = {
        node.target.id
        for node in result_class.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
    }

    assert fields == {
        "operation_id",
        "issuer_id",
        "process_id",
        "correlation_id",
        "policy_digest",
        "canonicalization_profile",
    }


def test_legacy_portable_split_authority_is_absent() -> None:
    production = (
        _ENFORCEMENT.read_text(encoding="utf-8")
        + _SESSION.read_text(encoding="utf-8")
    )
    for forbidden in (
        "_consumed_token_registry",
        "_EnforcementToken",
        "_ENFORCEMENT_TOKEN",
        "_token_hmac",
        "_origin",
        "_consumed_token_ids",
        "_IS_SESSION_TOKEN",
        "_reconstruct_precall_result",
        "_compiled_policy_to_dto",
    ):
        assert re.search(rf"\b{re.escape(forbidden)}\b", production) is None


def test_registry_consumption_is_one_atomic_pop() -> None:
    tree = ast.parse(_OPERATION_REGISTRY.read_text(encoding="utf-8"))
    consume = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "consume"
    )
    calls = [
        node
        for node in ast.walk(consume)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
    ]

    assert sum(call.func.attr == "pop" for call in calls) == 1
    assert all(call.func.attr not in {"get", "__contains__"} for call in calls)


def _self_attribute_name(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return node.attr
    return None


def _method_definitions(
    function: ast.FunctionDef,
) -> list[tuple[str, ast.Assign | ast.AnnAssign, ast.AST]]:
    definitions: list[tuple[str, ast.Assign | ast.AnnAssign, ast.AST]] = []

    class MethodScopeCollector(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            for target in _assigned_names(node):
                definitions.append((target, node, node.value))
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            for target in _assigned_names(node):
                definitions.append((target, node, node.value))
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_comprehension(self, node: ast.comprehension) -> None:
            self.visit(node.iter)
            for condition in node.ifs:
                self.visit(condition)

    collector = MethodScopeCollector()
    for statement in function.body:
        collector.visit(statement)
    return definitions


def _source_position(node: ast.AST, *, end: bool = False) -> tuple[int, int]:
    line = getattr(node, "end_lineno" if end else "lineno", None)
    column = getattr(node, "end_col_offset" if end else "col_offset", None)
    return (line if line is not None else -1, column if column is not None else -1)


def _reaching_definition(
    name: str,
    use: ast.AST,
    definitions: list[tuple[str, ast.Assign | ast.AnnAssign, ast.AST]],
) -> tuple[ast.Assign | ast.AnnAssign, ast.AST] | None:
    preceding = [
        (assignment, value)
        for defined_name, assignment, value in definitions
        if defined_name == name and _source_position(assignment, end=True) <= _source_position(use)
    ]
    if not preceding:
        return None
    return max(preceding, key=lambda definition: _source_position(definition[0], end=True))


def _expression_origins(
    expression: ast.AST,
    definitions: list[tuple[str, ast.Assign | ast.AnnAssign, ast.AST]],
    *,
    seen: set[tuple[str, int, int]] | None = None,
) -> set[str]:
    if isinstance(expression, ast.Attribute):
        name = _self_attribute_name(expression)
        if name == "_attempts":
            return {"attempts"}
        if name == "_steps":
            return {"steps"}
    if isinstance(expression, ast.Name):
        definition = _reaching_definition(expression.id, expression, definitions)
        if definition is None:
            return set()
        visited = set() if seen is None else set(seen)
        definition_key = (expression.id, *_source_position(definition[0], end=True))
        if definition_key in visited:
            return set()
        visited.add(definition_key)
        return _expression_origins(
            definition[1],
            definitions,
            seen=visited,
        )
    origins: set[str] = set()
    for child in ast.iter_child_nodes(expression):
        origins.update(_expression_origins(child, definitions, seen=seen))
    return origins


def _bound_self_method(
    expression: ast.AST,
    definitions: list[tuple[str, ast.Assign | ast.AnnAssign, ast.AST]],
    *,
    seen: set[tuple[str, int, int]] | None = None,
) -> str | None:
    method = _self_attribute_name(expression)
    if method is not None:
        return method
    if not isinstance(expression, ast.Name):
        return None
    definition = _reaching_definition(expression.id, expression, definitions)
    if definition is None:
        return None
    visited = set() if seen is None else set(seen)
    definition_key = (expression.id, *_source_position(definition[0], end=True))
    if definition_key in visited:
        return None
    visited.add(definition_key)
    return _bound_self_method(
        definition[1],
        definitions,
        seen=visited,
    )


def _ancestor_with_lock(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, ast.With) and any(
            _self_attribute_name(item.context_expr) == "_attempt_lock"
            for item in parent.items
        ):
            return True
        parent = parents.get(parent)
    return False


def _is_terminal_state_guard(expression: ast.AST) -> bool:
    return (
        isinstance(expression, ast.Compare)
        and len(expression.ops) == 1
        and isinstance(expression.ops[0], ast.Is)
        and len(expression.comparators) == 1
        and isinstance(expression.comparators[0], ast.Attribute)
        and isinstance(expression.comparators[0].value, ast.Name)
        and expression.comparators[0].value.id == "AttemptFinalizationState"
        and expression.comparators[0].attr == "TERMINAL"
        and isinstance(expression.left, ast.Attribute)
        and isinstance(expression.left.value, ast.Name)
        and expression.left.value.id == "record"
        and expression.left.attr == "state"
    )


def _workflow_claim_boundary_violations(source: str) -> set[str]:
    """Return violations for workflow-claim allocation and provenance rules."""
    tree = ast.parse(source)
    session_class = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "GovernanceSession"
        ),
        None,
    )
    if session_class is None:
        return {"session-class-missing"}
    methods = {
        node.name: node
        for node in session_class.body
        if isinstance(node, ast.FunctionDef)
    }
    required = {"_allocate_step_index", "enforce_step_pre_call", "_do_finalize"}
    if not required <= methods.keys():
        return {"workflow-method-missing"}

    violations: set[str] = set()
    allocate = methods["_allocate_step_index"]
    increments = [
        node
        for node in ast.walk(allocate)
        if isinstance(node, ast.AugAssign)
        and _self_attribute_name(node.target) == "_next_step_index"
        and isinstance(node.op, ast.Add)
    ]
    parents, _ = _parent_maps(allocate)
    if len(increments) != 1 or not _ancestor_with_lock(increments[0], parents):
        violations.add("step-index-not-locked")

    pre_call = methods["enforce_step_pre_call"]
    pre_call_definitions = _method_definitions(pre_call)
    allocation_calls = [
        node
        for node in ast.walk(pre_call)
        if isinstance(node, ast.Call)
        and _self_attribute_name(node.func) == "_allocate_step_index"
    ]
    if len(allocation_calls) != 1:
        violations.add("step-index-allocation-missing")
    else:
        allocation_line = allocation_calls[0].lineno
        if any(
            isinstance(node, ast.Call)
            and _bound_self_method(node.func, pre_call_definitions)
            not in {None, "_assert_attempt_capacity"}
            and node.lineno < allocation_line
            for node in ast.walk(pre_call)
        ):
            violations.add("pre-allocation-call")

    finalize = methods["_do_finalize"]
    definitions = _method_definitions(finalize)
    allocated_assignments = [
        node
        for node in ast.walk(finalize)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and "allocated_count" in _assigned_names(node)
    ]
    finalize_parents, _ = _parent_maps(finalize)

    artifacts = [
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Dict)
        and any(
            isinstance(key, ast.Constant)
            and key.value in {"step_count", "invocations"}
            for key in node.keys
        )
    ]
    artifact = next(
        (
            node
            for node in artifacts
            if {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant)
            } >= {"step_count", "invocations"}
        ),
        None,
    )
    if artifact is None:
        return violations | {"workflow-claim-missing"}
    fields = {
        key.value: value
        for key, value in zip(artifact.keys, artifact.values)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    step_count = fields["step_count"]
    if not isinstance(step_count, ast.Name) or step_count.id != "allocated_count":
        violations.add("step-count-not-allocation")
    allocated_definition = _reaching_definition(
        "allocated_count", step_count, definitions
    )
    if (
        allocated_definition is None
        or _self_attribute_name(allocated_definition[1]) != "_next_step_index"
        or len(allocated_assignments) != 1
        or not _ancestor_with_lock(allocated_assignments[0], finalize_parents)
    ):
        violations.add("allocated-count-not-locked")

    invocations = fields["invocations"]
    if not isinstance(invocations, ast.ListComp) or len(invocations.generators) != 1:
        violations.add("workflow-claim-invalid")
        return violations
    generator = invocations.generators[0]
    if (
        generator.ifs
        or not isinstance(generator.iter, ast.Name)
        or generator.iter.id != "records"
    ):
        violations.add("claim-filtered")
    records_definition = _reaching_definition("records", generator.iter, definitions)
    records = records_definition[1] if records_definition is not None else None
    if (
        isinstance(records, ast.Call)
        and isinstance(records.func, ast.Name)
        and records.func.id == "filter"
    ):
        violations.add("claim-filtered")
    if records is None or "attempts" not in _expression_origins(records, definitions):
        violations.add("records-not-terminal-attempts")
    if records is not None and "steps" in _expression_origins(records, definitions):
        violations.add("claim-from-steps")
    record_comprehensions = [
        node for node in ast.walk(records) if isinstance(node, ast.GeneratorExp)
    ] if records is not None else []
    if (
        len(record_comprehensions) != 1
        or len(record_comprehensions[0].generators) != 1
        or record_comprehensions[0].generators[0].ifs != [
            next(
                (
                    test
                    for test in record_comprehensions[0].generators[0].ifs
                    if _is_terminal_state_guard(test)
                ),
                None,
            )
        ]
    ):
        violations.add("records-excludes-terminal-classes")
    claim_origins = _expression_origins(invocations, definitions)
    if "steps" in claim_origins:
        violations.add("claim-from-steps")
    if "attempts" not in claim_origins:
        violations.add("claim-not-terminal-attempts")
    return violations


_WORKFLOW_CLAIM_FIXTURE = """
class GovernanceSession:
    def _allocate_step_index(self, step_id, attempt_id):
        with self._attempt_lock:
            index = self._next_step_index
            self._next_step_index += 1
            self._attempts[index] = SessionAttempt(index, step_id, attempt_id, None)
            return index

    def enforce_step_pre_call(self, invocation):
        attempt = self._aigc._attempt_factory.allocate("pre", "workflow", invocation)
        step_index = self._allocate_step_index("step", attempt.attempt_id)
        return self._enforce_step_pre_call_attempt(invocation, attempt, step_index)

    def _do_finalize(self):
        with self._attempt_lock:
            allocated_count = self._next_step_index
            records = tuple(
                record
                for _, record in sorted(self._attempts.items())
                if record.state is AttemptFinalizationState.TERMINAL
            )
        artifact = {
            "step_count": allocated_count,
            "invocations": [
                {"step_index": record.step_index, "checksum": record.invocation_checksum}
                for record in records
            ],
        }
"""


def test_workflow_claim_fitness_rejects_preallocation_authorization_gate() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        attempt = self._aigc._attempt_factory.allocate",
        "        self._assert_accepting_new_step()\n"
        "        attempt = self._aigc._attempt_factory.allocate",
    )

    assert "pre-allocation-call" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_allows_only_attempt_capacity_before_allocation(
) -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        attempt = self._aigc._attempt_factory.allocate",
        "        self._assert_attempt_capacity()\n"
        "        attempt = self._aigc._attempt_factory.allocate",
    )

    assert "pre-allocation-call" not in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_aliased_preallocation_gate() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        attempt = self._aigc._attempt_factory.allocate",
        "        gate = self._assert_accepting_new_step\n"
        "        gate()\n"
        "        attempt = self._aigc._attempt_factory.allocate",
    )

    assert "pre-allocation-call" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_alias_rebound_after_allocation() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        attempt = self._aigc._attempt_factory.allocate",
        "        gate = self._assert_accepting_new_step\n"
        "        gate()\n"
        "        attempt = self._aigc._attempt_factory.allocate",
    ).replace(
        '        step_index = self._allocate_step_index("step", attempt.attempt_id)\n',
        '        step_index = self._allocate_step_index("step", attempt.attempt_id)\n'
        "        gate = lambda: None\n",
    )

    assert "pre-allocation-call" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_ignores_nested_gate_rebinding() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        attempt = self._aigc._attempt_factory.allocate",
        "        gate = self._assert_accepting_new_step\n"
        "        def helper():\n"
        "            gate = lambda: None\n"
        "        gate()\n"
        "        attempt = self._aigc._attempt_factory.allocate",
    )

    assert "pre-allocation-call" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_success_only_claim_filter() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "                for record in records\n",
        "                for record in records\n"
        "                if record.terminal in {TerminalClass.ALLOW, TerminalClass.WARN}\n",
    )

    assert "claim-filtered" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_filter_call_claim_source() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        artifact = {",
        "        filtered = filter(\n"
        "            lambda record: record.terminal in "
        "{TerminalClass.ALLOW, TerminalClass.WARN},\n"
        "            records,\n"
        "        )\n"
        "        artifact = {",
    ).replace("for record in records", "for record in filtered")

    assert "claim-filtered" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_records_rebound_after_artifact() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        artifact = {",
        "        records = filter(\n"
        "            lambda record: record.terminal in "
        "{TerminalClass.ALLOW, TerminalClass.WARN},\n"
        "            records,\n"
        "        )\n"
        "        artifact = {",
    ).replace(
        "            ],\n        }\n",
        "            ],\n        }\n"
        "        records = tuple(\n"
        "            record\n"
        "            for _, record in sorted(self._attempts.items())\n"
        "            if record.state is AttemptFinalizationState.TERMINAL\n"
        "        )\n",
    )

    assert "claim-filtered" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_ignores_nested_records_rebinding() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        artifact = {",
        "        records = filter(\n"
        "            lambda record: record.terminal in "
        "{TerminalClass.ALLOW, TerminalClass.WARN},\n"
        "            records,\n"
        "        )\n"
        "        def helper():\n"
        "            records = tuple(\n"
        "                record\n"
        "                for _, record in sorted(self._attempts.items())\n"
        "                if record.state is AttemptFinalizationState.TERMINAL\n"
        "            )\n"
        "        artifact = {",
    )

    assert "claim-filtered" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_step_count_from_terminal_records() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        '"step_count": allocated_count',
        '"step_count": len(records)',
    )

    assert "step-count-not-allocation" in _workflow_claim_boundary_violations(source)


def test_workflow_claim_fitness_rejects_aliased_legacy_steps_claim_source() -> None:
    source = _WORKFLOW_CLAIM_FIXTURE.replace(
        "        artifact = {",
        "        surviving_steps = self._steps\n        artifact = {",
    ).replace("for record in records", "for record in surviving_steps")

    assert "claim-from-steps" in _workflow_claim_boundary_violations(source)


def test_b4_claimed_set_docs_are_source_only_and_finalize_explicitly() -> None:
    public = (_ROOT / "docs" / "PUBLIC_INTEGRATION_CONTRACT.md").read_text(
        encoding="utf-8"
    )
    cli = (_ROOT / "docs" / "reference" / "WORKFLOW_CLI.md").read_text(
        encoding="utf-8"
    )
    quickstart = (_ROOT / "docs" / "reference" / "WORKFLOW_QUICKSTART.md").read_text(
        encoding="utf-8"
    )

    for text in (public, cli, quickstart):
        normalized = " ".join(text.lower().replace(">", "").split())
        assert "current-source-only" in normalized
        assert "aegis-ai-governance==0.9.0b1" in normalized
        assert "no later published version is assigned" in normalized
    normalized_quickstart = " ".join(quickstart.split())
    assert "`session.complete()` only transitions" in normalized_quickstart
    assert "`session.finalize()` or context-manager exit" in normalized_quickstart


def test_workflow_claims_are_locked_terminal_attempt_evidence() -> None:
    """Workflow signatures must cover every allocated terminal attempt, not survivors."""
    assert _workflow_claim_boundary_violations(
        _SESSION.read_text(encoding="utf-8")
    ) == set()


def test_terminal_attempt_state_machine_surrounds_acknowledged_delivery() -> None:
    """The same-index race must close before emission and commit after ack."""
    session_tree = ast.parse(_SESSION.read_text(encoding="utf-8"))
    state_class = next(
        node
        for node in session_tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "AttemptFinalizationState"
    )
    states = {
        node.value.value
        for node in state_class.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
    }
    assert states == {"allocated", "finalizing", "terminal"}

    finalizer_tree = ast.parse(
        _EVIDENCE_FINALIZER.read_text(encoding="utf-8")
    )
    finalize = next(
        node
        for node in ast.walk(finalizer_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "finalize"
    )
    reserve = next(
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "reserve"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "recorder"
    )
    emit = next(
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_emit_acknowledged"
    )
    commit = next(
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "commit"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "terminal_reservation"
    )
    assert reserve.lineno < emit.lineno < commit.lineno


def test_session_attempt_scope_binds_unforgeable_origin_recorder() -> None:
    """Session terminal claims must be authorized by the allocated capability."""
    tree = ast.parse(_SESSION.read_text(encoding="utf-8"))
    scope = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_attempt_finalization_scope"
    )
    boundary = next(
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "evidence_attempt"
    )
    keywords = {keyword.arg: keyword.value for keyword in boundary.keywords}
    recorder = keywords["terminal_recorder"]
    origin = keywords["terminal_origin"]
    assert (
        isinstance(recorder, ast.Call)
        and isinstance(recorder.func, ast.Name)
        and recorder.func.id == "_SessionTerminalRecorder"
    )
    assert (
        isinstance(origin, ast.Attribute)
        and isinstance(origin.value, ast.Name)
        and origin.value.id == "record"
        and origin.attr == "capability"
    )


def test_workflow_correlation_schema_condition_is_nonvacuous() -> None:
    """Any workflow marker must require the complete authoritative quartet."""
    quartet = {
        "session_id",
        "step_id",
        "step_index",
        "workflow_policy_digest",
    }
    schema_paths = (
        _ROOT / "schemas" / "audit_artifact.schema.json",
        _ROOT / "aegis" / "schemas" / "audit_artifact.schema.json",
    )
    assert schema_paths[0].read_bytes() == schema_paths[1].read_bytes()
    for path in schema_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        condition = schema["properties"]["context"]["allOf"][0]
        triggers = {
            required
            for branch in condition["if"]["anyOf"]
            for required in branch["required"]
        }
        assert triggers == {"step_index", "workflow_policy_digest"}
        assert set(condition["then"]["required"]) == quartet


def test_all_five_b4_docs_freeze_assurance_and_verifier_budgets() -> None:
    assurance = (
        "Workflow-signed proves integrity and order of the claimed supplied set. "
        "It does not prove the host disclosed every invocation. Completeness "
        "remains unproven until a trusted checkpoint binds the expected head/count."
    )
    budget = (
        "The verifier bounds claims and supplied artifacts to 1,024 entries "
        "each, measured input to 4 MiB, nesting to 32 levels, and reports to "
        "100 errors. Exceeding an input budget fails closed with "
        "`WORKFLOW_VERIFICATION_LIMIT_EXCEEDED`."
    )
    admission = (
        "A session admits at most 1,024 workflow attempts. A later request "
        "fails before attempt-envelope or step-index allocation with "
        "`SESSION_ATTEMPT_LIMIT_EXCEEDED`."
    )
    exception_summary = (
        "Exception-path workflow summaries contain only a bounded "
        "`exception_type` and stable `SESSION_BODY_EXCEPTION` reason code; "
        "raw exception messages are not signed."
    )
    docs = (
        _ROOT / "docs/architecture/AEGIS_THREAT_MODEL.md",
        _ROOT / "docs/architecture/ARCHITECTURAL_INVARIANTS.md",
        _ROOT / "docs/PUBLIC_INTEGRATION_CONTRACT.md",
        _ROOT / "docs/reference/WORKFLOW_CLI.md",
        _ROOT / "docs/reference/WORKFLOW_QUICKSTART.md",
    )

    for path in docs:
        collapsed = " ".join(path.read_text(encoding="utf-8").split())
        assert collapsed.count(assurance) == 1, path
        assert collapsed.count(budget) == 1, path
        assert collapsed.count(admission) == 1, path
        assert collapsed.count(exception_summary) == 1, path
        assert "#46" in collapsed, path


def test_workflow_verifier_checks_mapping_bytes_before_value_expansion() -> None:
    """Mapping-key bytes must be rejected before values enter the work stack."""
    source = (
        _ROOT / "aegis/_internal/workflow_verification.py"
    ).read_text(encoding="utf-8")
    mapping_branch = source.split("elif type(current) is dict:", 1)[1]
    key_preflight = mapping_branch.split(
        "for item in current.values():",
        1,
    )[0]

    assert "if total > byte_limit:" in key_preflight


def test_workflow_claim_provenance_uses_locked_terminal_state() -> None:
    """The concrete production AST must retain the claimed-set data flow."""
    tree = ast.parse(_SESSION.read_text(encoding="utf-8"), filename=str(_SESSION))
    session_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GovernanceSession"
    )
    methods = {
        node.name: node
        for node in session_class.body
        if isinstance(node, ast.FunctionDef)
    }

    allocate = methods["_allocate_step_index"]
    increments = [
        node
        for node in ast.walk(allocate)
        if isinstance(node, ast.AugAssign)
        and isinstance(node.target, ast.Attribute)
        and isinstance(node.target.value, ast.Name)
        and node.target.value.id == "self"
        and node.target.attr == "_next_step_index"
        and isinstance(node.op, ast.Add)
    ]
    assert len(increments) == 1
    parents, _ = _parent_maps(allocate)
    ancestors = []
    parent = parents.get(increments[0])
    while parent is not None:
        ancestors.append(parent)
        parent = parents.get(parent)
    assert any(
        isinstance(parent, ast.With)
        and any(
            isinstance(item.context_expr, ast.Attribute)
            and isinstance(item.context_expr.value, ast.Name)
            and item.context_expr.value.id == "self"
            and item.context_expr.attr == "_attempt_lock"
            for item in parent.items
        )
        for parent in ancestors
    )

    pre_call = methods["enforce_step_pre_call"]
    calls = [
        node
        for node in ast.walk(pre_call)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"
    ]
    allocation_call = next(
        call for call in calls if call.func.attr == "_allocate_step_index"
    )
    authorization_call = next(
        call for call in calls if call.func.attr == "_enforce_step_pre_call_attempt"
    )
    assert allocation_call.lineno < authorization_call.lineno

    finalize = methods["_do_finalize"]
    records_assignment = next(
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "records"
            for target in node.targets
        )
    )
    assert any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr == "_attempts"
        for node in ast.walk(records_assignment)
    )
    assert not any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr == "_steps"
        for node in ast.walk(records_assignment)
    )
    terminal_guards = [
        node
        for node in ast.walk(records_assignment)
        if isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Attribute)
        and isinstance(node.left.value, ast.Name)
        and node.left.value.id == "record"
        and node.left.attr == "state"
    ]
    assert len(terminal_guards) == 1
    terminal_guard = terminal_guards[0]
    assert (
        len(terminal_guard.ops) == 1
        and isinstance(terminal_guard.ops[0], ast.Is)
        and len(terminal_guard.comparators) == 1
        and isinstance(terminal_guard.comparators[0], ast.Attribute)
        and isinstance(terminal_guard.comparators[0].value, ast.Name)
        and terminal_guard.comparators[0].value.id == "AttemptFinalizationState"
        and terminal_guard.comparators[0].attr == "TERMINAL"
    )

    invocations_assignment = next(
        node
        for node in ast.walk(finalize)
        if isinstance(node, ast.Dict)
        and any(
            isinstance(key, ast.Constant) and key.value == "invocations"
            for key in node.keys
        )
    )
    invocations_value = invocations_assignment.values[
        next(
            index
            for index, key in enumerate(invocations_assignment.keys)
            if isinstance(key, ast.Constant) and key.value == "invocations"
        )
    ]
    assert isinstance(invocations_value, ast.ListComp)
    assert isinstance(invocations_value.generators[0].iter, ast.Name)
    assert invocations_value.generators[0].iter.id == "records"
    assert not any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr == "_steps"
        for node in ast.walk(invocations_value)
    )
