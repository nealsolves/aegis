#!/usr/bin/env python3
"""Check public docs, examples, starters, and demos for private imports."""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DOCS = {
    "README.md",
    "PROJECT.md",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
    "docs/reference/WORKFLOW_QUICKSTART.md",
    "docs/reference/WORKFLOW_CLI.md",
    "docs/reference/TROUBLESHOOTING.md",
    "docs/reference/STARTER_INDEX.md",
    "docs/reference/STARTER_RECIPES.md",
    "docs/reference/SUPPORTED_ENVIRONMENTS.md",
    "docs/reference/OPERATIONS_RUNBOOK.md",
    "docs/reference/external/README.md",
    "docs/reference/external/A2A_ADAPTER.md",
    "docs/reference/external/OPENAI_AGENTS_ADAPTER.md",
}
MD_IMPORT_RE = re.compile(r"^\s*(?:from\s+aegis\._internal|import\s+aegis\._internal)", re.MULTILINE)


def _git_files() -> list[str]:
    try:
        output = subprocess.check_output(["git", "ls-files"], cwd=REPO_ROOT, text=True)
        return output.splitlines()
    except (OSError, subprocess.CalledProcessError):
        return [str(path.relative_to(REPO_ROOT)) for path in REPO_ROOT.rglob("*") if path.is_file()]


def _is_public_candidate(rel: str) -> bool:
    if rel in PUBLIC_DOCS:
        return True
    if rel.startswith("examples/") and rel.endswith((".py", ".md")):
        return True
    if rel.startswith("demo-app-api/") and rel.endswith(".py") and "aegis-env/" not in rel:
        return True
    if rel.startswith("demo-app-react/src/") and rel.endswith((".ts", ".tsx")):
        return True
    return False


def _python_import_offenders(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders.extend(alias.name for alias in node.names if alias.name.startswith("aegis._internal"))
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("aegis._internal"):
            offenders.append(node.module)
    return offenders


def main() -> int:
    failures: list[str] = []
    for rel in _git_files():
        if not _is_public_candidate(rel):
            continue
        path = REPO_ROOT / rel
        if path.suffix == ".py":
            for module in _python_import_offenders(path):
                failures.append(f"{rel}: imports {module}")
        else:
            text = path.read_text(encoding="utf-8")
            if "aegis._internal" in text and (path.suffix != ".md" or MD_IMPORT_RE.search(text)):
                failures.append(f"{rel}: contains private aegis._internal import")

    if failures:
        print("Private imports found in public surfaces:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("PASS: no public aegis._internal imports found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
