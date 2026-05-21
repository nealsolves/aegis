"""PR-11 starter profile end-to-end tests."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "aegis", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _load_module(script: Path):
    spec = importlib.util.spec_from_file_location(f"starter_{script.parent.name}", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _generate(tmp_path: Path, profile: str) -> Path:
    out_dir = tmp_path / profile
    result = _run_cli(["workflow", "init", "--profile", profile, "--output-dir", str(out_dir)], Path.cwd())
    assert result.returncode == 0, result.stderr
    return out_dir


def test_all_starter_profiles_generate_validate_lint_and_run(tmp_path):
    cases = {
        "minimal": ("run_minimal_workflow", 2),
        "standard": ("run_standard_workflow", 3),
        "regulated-high-assurance": ("run_regulated_workflow", 2),
    }
    for profile, (func_name, expected_steps) in cases.items():
        starter = _generate(tmp_path, profile)
        validate = _run_cli(["policy", "validate", str(starter / "policy.yaml")], Path.cwd())
        lint = _run_cli(["workflow", "lint", str(starter), "--json"], Path.cwd())
        assert validate.returncode == 0, validate.stderr
        assert lint.returncode == 0, lint.stderr
        assert json.loads(lint.stdout)[0]["findings"] == []

        mod = _load_module(starter / "workflow_example.py")
        artifact = getattr(mod, func_name)()
        assert artifact["status"] == "COMPLETED"
        assert len(artifact["steps"]) == expected_steps

        source = (starter / "workflow_example.py").read_text(encoding="utf-8")
        assert "aegis._internal" not in source
        for forbidden in ["AWS_ACCESS_KEY", "OPENAI_API_KEY", "A2A"]:
            assert forbidden not in source


def test_regulated_profile_failure_diagnosis_and_documented_fix(tmp_path):
    starter = _generate(tmp_path, "regulated-high-assurance")
    workflow_py = starter / "workflow_example.py"
    original = workflow_py.read_text(encoding="utf-8")
    broken = original.replace(
        '                        "source_ids": ["doc-001", "doc-002"],\n',
        "",
    ).replace(
        '                        "source_ids": ["analysis-step-1"],\n',
        "",
    )
    assert broken != original
    workflow_py.write_text(broken, encoding="utf-8")

    run = subprocess.run(
        [sys.executable, str(workflow_py)],
        cwd=starter,
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0

    doctor = _run_cli(["workflow", "doctor", str(starter), "--json"], Path.cwd())
    assert doctor.returncode == 0
    codes = [f["code"] for f in json.loads(doctor.stdout)]
    assert "WORKFLOW_SOURCE_REQUIRED" in codes

    workflow_py.write_text(original, encoding="utf-8")
    mod = _load_module(workflow_py)
    assert mod.run_regulated_workflow()["status"] == "COMPLETED"
