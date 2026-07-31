"""AST fitness tests for security-sensitive policy boundaries."""

from __future__ import annotations

import ast
from pathlib import Path
import re

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_ENFORCEMENT = _ROOT / "aegis" / "_internal" / "enforcement.py"
_SESSION = _ROOT / "aegis" / "_internal" / "session.py"
_TOOLS = _ROOT / "aegis" / "_internal" / "tools.py"
_RISK = _ROOT / "aegis" / "_internal" / "risk_scoring.py"
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
_DIAGNOSTIC_LOAD_COMPILE_ALLOWLIST = {
    ("workflow_lint", "lint_policy"),
    ("cli", "_lint_policy"),
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


def _diagnostic_load_flows_directly_to_compile(
    load_call: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    aliases: dict[str, str],
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """Prove a diagnostic load assignment is consumed by the next compiler."""
    assignment = parents.get(load_call)
    if (
        not isinstance(assignment, (ast.Assign, ast.AnnAssign))
        or assignment.value is not load_call
    ):
        return False
    assigned_names = _assigned_names(assignment)
    if len(assigned_names) != 1:
        return False
    loaded_name = assigned_names[0]

    later_semantic_calls = sorted(
        (
            candidate
            for candidate in ast.walk(function)
            if (
                isinstance(candidate, ast.Call)
                and candidate.lineno > load_call.lineno
                and _semantic_call_kind(candidate, aliases)
                in {"load_policy", "compile_policy"}
            )
        ),
        key=lambda candidate: (candidate.lineno, candidate.col_offset),
    )
    if not later_semantic_calls:
        return False
    compile_call = later_semantic_calls[0]
    if _semantic_call_kind(compile_call, aliases) != "compile_policy":
        return False
    if not any(
        isinstance(argument, ast.Name)
        and argument.id == loaded_name
        for argument in compile_call.args
    ):
        return False

    load_position = (load_call.lineno, load_call.col_offset)
    compile_position = (compile_call.lineno, compile_call.col_offset)
    for candidate in ast.walk(function):
        if (
            isinstance(candidate, ast.Name)
            and isinstance(candidate.ctx, ast.Load)
            and candidate.id == loaded_name
            and load_position
            < (candidate.lineno, candidate.col_offset)
            < compile_position
        ):
            return False

    for candidate in ast.walk(function):
        if (
            isinstance(
                candidate,
                (ast.Return, ast.Raise, ast.Break, ast.Continue),
            )
            and load_call.lineno
            < candidate.lineno
            < compile_call.lineno
        ):
            return False
        if (
            not isinstance(candidate, (ast.Assign, ast.AnnAssign))
            or candidate is assignment
            or not (
                load_call.lineno
                < candidate.lineno
                < compile_call.lineno
            )
        ):
            continue
        if loaded_name in _assigned_names(candidate):
            return False
    return True


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
    } | {"CompiledPolicy", "compile_policy"}


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
                    and not (
                        (module_name, function_name)
                        in _DIAGNOSTIC_LOAD_COMPILE_ALLOWLIST
                        and _diagnostic_load_flows_directly_to_compile(
                            call,
                            node,
                            aliases=aliases,
                            parents=parents,
                        )
                    )
                ):
                    violations.append(
                        f"{module_name}:{call.lineno}:{function_name}:load_policy"
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
        "_ = policy.roles",
        '_ = policy["roles"]',
        '_ = policy.get("roles")',
        "alias = policy",
        "if should_skip:\n        return []",
    ],
    ids=[
        "authorization-call",
        "attribute-read",
        "subscript-read",
        "get-read",
        "alias-assignment",
        "branch-early-return",
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
