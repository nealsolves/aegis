"""PR-11 public API and package-boundary hardening tests."""
from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOC_PATHS = [
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
]


def _tracked_public_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        text=True,
    )
    rels: list[str] = []
    for rel in output.splitlines():
        if rel in PUBLIC_DOC_PATHS:
            rels.append(rel)
            continue
        if rel.startswith("examples/") and rel.endswith((".py", ".md")):
            rels.append(rel)
            continue
        if rel.startswith("demo-app-api/") and rel.endswith(".py"):
            rels.append(rel)
            continue
        if rel.startswith("demo-app-react/src/") and rel.endswith((".ts", ".tsx")):
            rels.append(rel)
            continue
    return [REPO_ROOT / rel for rel in sorted(set(rels))]


def _python_import_modules(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_core_public_imports_are_available():
    import aegis
    from aegis import AEGIS
    from aegis import GovernanceSession, SessionPreCallResult
    from aegis import enforce_invocation, enforce_pre_call, enforce_post_call

    assert aegis.__version__ == "0.9.0b1"
    assert AEGIS is aegis.AEGIS
    assert GovernanceSession is aegis.GovernanceSession
    assert SessionPreCallResult is aegis.SessionPreCallResult
    assert callable(enforce_invocation)
    assert callable(enforce_pre_call)
    assert callable(enforce_post_call)
    assert callable(AEGIS().open_session)
    assert not hasattr(aegis, "open_session")


def test_optional_adapters_are_submodule_only_not_top_level_exports():
    import aegis

    optional_modules = {
        "aegis.bedrock_adapter": "BedrockTraceAdapter",
        "aegis.a2a_adapter": "A2AAdapter",
        "aegis.openai_agents_adapter": "OpenAIAgentsAdapter",
    }
    for module_name, class_name in optional_modules.items():
        module = importlib.import_module(module_name)
        assert hasattr(module, class_name), f"{module_name} missing {class_name}"
        assert not hasattr(aegis, class_name), (
            f"{class_name} must remain adapter-submodule scoped"
        )
        assert class_name not in getattr(aegis, "__all__", [])


def test_public_docs_examples_and_demos_do_not_import_internal_modules():
    offenders: list[str] = []
    for path in _tracked_public_files():
        rel = path.relative_to(REPO_ROOT)
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            imports = _python_import_modules(path)
            bad = [module for module in imports if module.startswith("aegis._internal")]
            offenders.extend(f"{rel}: import {module}" for module in bad)
        elif "from aegis._internal" in text or "import aegis._internal" in text:
            offenders.append(str(rel))
    assert offenders == []


def test_public_import_boundary_script_passes():
    result = subprocess.run(
        [sys.executable, "scripts/check_public_docs_no_internal_imports.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
