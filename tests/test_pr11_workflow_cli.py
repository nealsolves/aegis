"""PR-11 workflow CLI smoke and contract tests."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "aegis", *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_top_level_help_has_no_traceback():
    result = _run(["--help"])
    assert result.returncode == 0
    assert "Aegis Governance SDK CLI" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_policy_init_lint_and_validate_round_trip(tmp_path):
    policy = tmp_path / "policy.yaml"
    init = _run(["policy", "init", "--profile", "minimal", "--output", str(policy)])
    assert init.returncode == 0, init.stderr
    assert policy.is_file()

    lint = _run(["policy", "lint", str(policy)])
    validate = _run(["policy", "validate", str(policy)])
    assert lint.returncode == 0, lint.stderr
    assert validate.returncode == 0, validate.stderr
    assert "OK" in lint.stdout
    assert "OK" in validate.stdout


def test_workflow_init_profiles_generate_public_runnable_starters(tmp_path):
    profiles = ["minimal", "standard", "regulated-high-assurance"]
    for profile in profiles:
        out_dir = tmp_path / profile
        result = _run(["workflow", "init", "--profile", profile, "--output-dir", str(out_dir)])
        assert result.returncode == 0, result.stderr
        assert (out_dir / "policy.yaml").is_file()
        assert (out_dir / "workflow_example.py").is_file()
        assert (out_dir / "README.md").is_file()
        source = (out_dir / "workflow_example.py").read_text(encoding="utf-8")
        assert "aegis._internal" not in source

        lint = _run(["workflow", "lint", str(out_dir), "--json"])
        assert lint.returncode == 0, lint.stderr
        parsed = json.loads(lint.stdout)
        assert parsed[0]["findings"] == []


def test_workflow_doctor_user_error_shape_has_reason_and_next_action(tmp_path):
    starter = tmp_path / "starter"
    _run(["workflow", "init", "--profile", "minimal", "--output-dir", str(starter)])
    (starter / "workflow_example.py").write_text(
        "from aegis._internal import errors\n",
        encoding="utf-8",
    )

    result = _run(["workflow", "doctor", str(starter), "--json"])
    assert result.returncode == 1
    findings = json.loads(result.stdout)
    assert any(f["code"] == "WORKFLOW_STARTER_INTEGRITY_ERROR" for f in findings)
    assert all("next_action" in f and f["next_action"] for f in findings)
    assert "Traceback" not in result.stderr


def test_workflow_trace_export_and_compliance_lineage_cli(tmp_path):
    from aegis import AEGIS, JsonFileAuditSink

    jsonl = tmp_path / "audit.jsonl"
    sink = JsonFileAuditSink(jsonl)
    with AEGIS(sink=sink).open_session() as session:
        pre = session.enforce_step_pre_call({
            "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
            "model_provider": "openai",
            "model_identifier": "gpt-4",
            "role": "planner",
            "input": {"query": "test"},
            "context": {"role_declared": True, "schema_exists": True},
        })
        session.enforce_step_post_call(pre, {"result": "answer", "confidence": 0.95})
        session.complete()

    trace = _run(["workflow", "trace", "--input", str(jsonl)])
    export = _run(["workflow", "export", "--input", str(jsonl), "--mode", "audit"])
    compliance = _run(["compliance", "export", "--input", str(jsonl), "--lineage"])
    assert trace.returncode == 0, trace.stderr
    assert export.returncode == 0, export.stderr
    assert compliance.returncode == 0, compliance.stderr
    assert json.loads(trace.stdout)[0]["status"] == "COMPLETED"
    assert json.loads(export.stdout)["export_mode"] == "audit"
    assert "lineage" in json.loads(compliance.stdout)


def test_expected_user_errors_do_not_emit_tracebacks(tmp_path):
    missing = tmp_path / "missing.jsonl"
    commands = [
        ["workflow", "trace", "--input", str(missing)],
        ["workflow", "export", "--input", str(missing), "--mode", "audit"],
        ["policy", "lint", str(missing)],
    ]
    for args in commands:
        result = _run(args)
        assert result.returncode == 1
        assert "Traceback" not in result.stdout + result.stderr
