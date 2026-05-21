#!/usr/bin/env python3
"""Run the PR-11 v0.9.0 source-beta functional validation harness."""
from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(name: str, cmd: list[str], *, cwd: Path = REPO_ROOT, optional: bool = False) -> dict:
    print(f"\n== {name} ==")
    print("$ " + " ".join(cmd))
    result = subprocess.run(cmd, cwd=cwd, text=True)
    status = "PASS" if result.returncode == 0 else ("SKIP" if optional else "FAIL")
    print(f"[{status}] {name} exit={result.returncode}")
    return {
        "name": name,
        "cmd": cmd,
        "cwd": str(cwd),
        "returncode": result.returncode,
        "optional": optional,
        "status": status,
    }


def _react_available() -> bool:
    return (REPO_ROOT / "demo-app-react" / "node_modules").is_dir() and shutil.which("npm") is not None


def main() -> int:
    print("AEGIS v0.9.0 source-beta full functionality harness")
    print(f"Repo root: {REPO_ROOT}")
    print(f"Python:    {sys.version.split()[0]} ({sys.executable})")
    print(f"Platform:  {platform.platform()}")
    print(f"CWD:       {Path.cwd()}")
    print(f"Network:   not required by default harness path")

    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10+ is required", file=sys.stderr)
        return 1

    results: list[dict] = []
    pr11_tests = [
        "tests/test_pr11_public_api_boundary.py",
        "tests/test_pr11_release_truth.py",
        "tests/test_pr11_invocation_regression.py",
        "tests/test_pr11_split_enforcement_regression.py",
        "tests/test_pr11_workflow_governance_core.py",
        "tests/test_pr11_workflow_cli.py",
        "tests/test_pr11_starter_profiles.py",
        "tests/test_pr11_diagnostic_reason_codes.py",
        "tests/test_pr11_workflow_trace_export_integrity.py",
        "tests/test_pr11_optional_adapter_boundaries.py",
        "tests/test_pr11_session_replay_concurrency.py",
        "tests/test_pr11_packaging_smoke.py",
    ]
    results.append(_run("pr11_pytest", [sys.executable, "-m", "pytest", *pr11_tests]))
    results.append(_run("beta_proof", [sys.executable, "scripts/validate_v090_beta_proof.py"]))
    results.append(_run("brand_version_parity", [sys.executable, "scripts/check_brand_and_version_parity.py"]))
    results.append(_run("public_no_internal_imports", [sys.executable, "scripts/check_public_docs_no_internal_imports.py"]))
    results.append(_run("demo_api_tests", [sys.executable, "-m", "pytest"], cwd=REPO_ROOT / "demo-app-api"))

    if _react_available():
        results.append(_run("react_tests", ["npm", "test"], cwd=REPO_ROOT / "demo-app-react"))
        results.append(_run("react_build", ["npm", "run", "build"], cwd=REPO_ROOT / "demo-app-react"))
    else:
        results.append({
            "name": "react_tests",
            "cmd": ["npm", "test"],
            "cwd": str(REPO_ROOT / "demo-app-react"),
            "returncode": 0,
            "optional": True,
            "status": "SKIP",
            "reason": "npm or demo-app-react/node_modules not available",
        })
        print("\n== react_tests ==\n[SKIP] npm or demo-app-react/node_modules not available")

    if importlib.util.find_spec("build") is not None:
        build_out = Path(tempfile.mkdtemp(prefix="aegis_pr11_build_"))
        results.append(
            _run("packaging_build", [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(build_out)])
        )
    else:
        results.append({
            "name": "packaging_build",
            "cmd": [sys.executable, "-m", "build"],
            "cwd": str(REPO_ROOT),
            "returncode": 0,
            "optional": True,
            "status": "SKIP",
            "reason": "build module not installed",
        })
        print("\n== packaging_build ==\n[SKIP] build module not installed")

    failed = [r for r in results if r["status"] == "FAIL"]
    print("\n== Summary ==")
    print(json.dumps({"summary": "FAIL" if failed else "PASS", "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
