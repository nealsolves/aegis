"""Architecture inventory for evidence finalization bypasses.

The detector resolves imported aliases and attribute calls so a bypass cannot be
hidden by renaming an import.  Task 3 drives invocation violations to zero;
Task 5 uses the same inventory to close the remaining workflow boundary.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "aegis"
FINALIZER = PRODUCTION / "_internal" / "evidence_finalizer.py"

FORBIDDEN_CALLS = {
    "emit_to_sink",
    "sign_artifact",
    "sign_artifact_with_metadata",
    "build_content_checksum_v2",
}


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    line: int
    call: str


class _CallInventory(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.aliases: dict[str, str] = {}
        self.violations: list[Violation] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        for imported in node.names:
            self.aliases[imported.asname or imported.name] = imported.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        forbidden: str | None = None
        if isinstance(node.func, ast.Name):
            imported_name = self.aliases.get(node.func.id)
            if imported_name in FORBIDDEN_CALLS:
                forbidden = imported_name
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in FORBIDDEN_CALLS:
                forbidden = node.func.attr
            elif node.func.attr == "emit":
                forbidden = "AuditSink.emit"
        if forbidden is not None:
            self.violations.append(
                Violation(
                    str(self.path.relative_to(ROOT)),
                    node.lineno,
                    forbidden,
                )
            )
        self.generic_visit(node)


def production_finalization_bypasses() -> tuple[Violation, ...]:
    violations: list[Violation] = []
    for path in sorted(PRODUCTION.rglob("*.py")):
        if path == FINALIZER:
            continue
        inventory = _CallInventory(path)
        inventory.visit(ast.parse(path.read_text(encoding="utf-8"), path))
        violations.extend(inventory.violations)
    return tuple(sorted(violations))


def test_all_production_evidence_crosses_the_finalizer() -> None:
    violations = production_finalization_bypasses()
    rendered = "\n".join(
        f"{item.path}:{item.line}: {item.call}" for item in violations
    )
    assert violations == (), f"evidence finalization bypasses:\n{rendered}"
