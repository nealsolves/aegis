#!/usr/bin/env python3
"""Build and validate the AEGIS v0.9.0 beta distribution candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import venv
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_DISTRIBUTION = "aegis-ai-governance"
EXPECTED_STEM = "aegis_ai_governance"
EXPECTED_VERSION = "0.9.0b1"
EXPECTED_RUNTIME_DEPENDENCIES = {"PyYAML>=6.0", "jsonschema>=4.0"}
EXPECTED_WHEEL = f"{EXPECTED_STEM}-{EXPECTED_VERSION}-py3-none-any.whl"
EXPECTED_SDIST = f"{EXPECTED_STEM}-{EXPECTED_VERSION}.tar.gz"
PROVIDER_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "OPENAI_",
    "ANTHROPIC_",
)


class CandidateValidationError(RuntimeError):
    """Raised when a release-candidate proof gate fails."""


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        rendered = " ".join(command)
        raise CandidateValidationError(
            f"command failed ({result.returncode}): {rendered}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def _venv_python(venv_dir: Path) -> Path:
    bindir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    executable = "python.exe" if sys.platform == "win32" else "python"
    return bindir / executable


def _venv_cli(venv_dir: Path) -> Path:
    bindir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    executable = "aegis.exe" if sys.platform == "win32" else "aegis"
    return bindir / executable


def _clean_env(venv_dir: Path) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    removed = sorted(
        key
        for key in env
        if any(key.startswith(prefix) for prefix in PROVIDER_ENV_PREFIXES)
    )
    for key in removed:
        env.pop(key, None)
    bindir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env, removed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inspect_artifacts(dist_dir: Path) -> dict[str, object]:
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if [path.name for path in wheels] != [EXPECTED_WHEEL]:
        raise CandidateValidationError(
            f"expected only {EXPECTED_WHEEL}, got {[path.name for path in wheels]}"
        )
    if [path.name for path in sdists] != [EXPECTED_SDIST]:
        raise CandidateValidationError(
            f"expected only {EXPECTED_SDIST}, got {[path.name for path in sdists]}"
        )

    wheel = wheels[0]
    sdist = sdists[0]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = next(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser(policy=default).parsebytes(
            archive.read(metadata_name)
        )
        if metadata["Name"] != EXPECTED_DISTRIBUTION:
            raise CandidateValidationError(
                f"wheel Name is {metadata['Name']!r}, expected "
                f"{EXPECTED_DISTRIBUTION!r}"
            )
        if metadata["Version"] != EXPECTED_VERSION:
            raise CandidateValidationError(
                f"wheel Version is {metadata['Version']!r}, expected "
                f"{EXPECTED_VERSION!r}"
            )
        requirements = set(metadata.get_all("Requires-Dist", []))
        if not EXPECTED_RUNTIME_DEPENDENCIES.issubset(requirements):
            raise CandidateValidationError(
                "wheel runtime dependencies changed: "
                f"{sorted(requirements)}"
            )
        required_members = {
            "aegis/__init__.py",
            "aegis/__main__.py",
            "aegis/cli.py",
            "aegis/py.typed",
        }
        missing = sorted(required_members.difference(names))
        if missing:
            raise CandidateValidationError(
                f"wheel is missing required members: {missing}"
            )
        if not any(
            name.startswith("aegis/schemas/") and name.endswith(".json")
            for name in names
        ):
            raise CandidateValidationError("wheel contains no packaged schemas")

    with tarfile.open(sdist, "r:gz") as archive:
        roots = {Path(name).parts[0] for name in archive.getnames() if name}
        expected_root = f"{EXPECTED_STEM}-{EXPECTED_VERSION}"
        if roots != {expected_root}:
            raise CandidateValidationError(
                f"sdist root is {sorted(roots)}, expected {[expected_root]}"
            )

    return {
        "wheel": {
            "filename": wheel.name,
            "sha256": _sha256(wheel),
            "size_bytes": wheel.stat().st_size,
        },
        "sdist": {
            "filename": sdist.name,
            "sha256": _sha256(sdist),
            "size_bytes": sdist.stat().st_size,
        },
    }


def _run_starter(
    cli: Path,
    python: Path,
    env: dict[str, str],
    root: Path,
    profile: str,
) -> Path:
    starter = root / profile
    _run(
        [
            str(cli),
            "workflow",
            "init",
            "--profile",
            profile,
            "--output-dir",
            str(starter),
        ],
        cwd=root,
        env=env,
    )
    _run(
        [str(cli), "policy", "validate", str(starter / "policy.yaml")],
        cwd=root,
        env=env,
    )
    lint = _run(
        [str(cli), "workflow", "lint", str(starter), "--json"],
        cwd=root,
        env=env,
    )
    lint_payload = json.loads(lint.stdout)
    if lint_payload[0]["findings"]:
        raise CandidateValidationError(
            f"{profile} starter lint findings: {lint_payload[0]['findings']}"
        )
    run = _run(
        [str(python), str(starter / "workflow_example.py")],
        cwd=starter,
        env=env,
    )
    if "Status:  COMPLETED" not in run.stdout:
        raise CandidateValidationError(
            f"{profile} starter did not report COMPLETED:\n{run.stdout}"
        )
    return starter


def _break_regulated_starter(workflow_path: Path) -> str:
    original = workflow_path.read_text(encoding="utf-8")
    broken_lines = [
        line for line in original.splitlines(keepends=True)
        if '"source_ids":' not in line
    ]
    broken = "".join(broken_lines)
    if broken == original:
        raise CandidateValidationError(
            "regulated starter did not contain source_ids to remove"
        )
    workflow_path.write_text(broken, encoding="utf-8")
    return original


def _prove_failure_doctor_fix(
    cli: Path,
    python: Path,
    env: dict[str, str],
    starter: Path,
) -> None:
    workflow = starter / "workflow_example.py"
    original = _break_regulated_starter(workflow)
    failed = subprocess.run(
        [str(python), str(workflow)],
        cwd=starter,
        env=env,
        capture_output=True,
        text=True,
    )
    if failed.returncode == 0:
        raise CandidateValidationError(
            "broken regulated starter unexpectedly completed"
        )

    doctor = _run(
        [str(cli), "workflow", "doctor", str(starter), "--json"],
        cwd=starter.parent,
        env=env,
    )
    codes = [finding["code"] for finding in json.loads(doctor.stdout)]
    if "WORKFLOW_SOURCE_REQUIRED" not in codes:
        raise CandidateValidationError(
            f"doctor did not report WORKFLOW_SOURCE_REQUIRED: {codes}"
        )

    workflow.write_text(original, encoding="utf-8")
    repaired = _run(
        [str(python), str(workflow)],
        cwd=starter,
        env=env,
    )
    if "Status:  COMPLETED" not in repaired.stdout:
        raise CandidateValidationError(
            f"repaired regulated starter did not complete:\n{repaired.stdout}"
        )


def _write_trace_runner(path: Path, policy: Path, jsonl: Path) -> None:
    path.write_text(
        "from aegis import AEGIS, JsonFileAuditSink\n"
        f"policy = {str(policy)!r}\n"
        f"jsonl = {str(jsonl)!r}\n"
        "with AEGIS(sink=JsonFileAuditSink(jsonl)).open_session("
        "policy_file=policy) as session:\n"
        "    pre = session.enforce_step_pre_call({\n"
        "        'policy_file': policy,\n"
        "        'model_provider': 'local-fixture',\n"
        "        'model_identifier': 'no-provider-call',\n"
        "        'role': 'ai-assistant',\n"
        "        'input': {'prompt': 'trace candidate'},\n"
        "        'context': {\n"
        "            'caller_id': 'distribution-proof',\n"
        "            'authorization': 'Bearer must-not-project',\n"
        "        },\n"
        "    }, step_id='candidate-step')\n"
        "    session.enforce_step_post_call(\n"
        "        pre,\n"
        "        {'result': 'local simulated response'},\n"
        "        step_metadata={'governance': {\n"
        "            'rationale': 'distribution_candidate_proof',\n"
        "            'decision_basis': ['local_fixture'],\n"
        "            'operator_action': 'none',\n"
        "            'provider_payload': {'api_key': 'must-not-project'},\n"
        "        }},\n"
        "    )\n"
        "    session.complete()\n",
        encoding="utf-8",
    )


def _prove_trace_and_exports(
    cli: Path,
    python: Path,
    env: dict[str, str],
    root: Path,
    policy: Path,
) -> None:
    jsonl = root / "candidate-audit.jsonl"
    runner = root / "trace_runner.py"
    _write_trace_runner(runner, policy, jsonl)
    _run([str(python), str(runner)], cwd=root, env=env)

    trace = _run(
        [str(cli), "workflow", "trace", "--input", str(jsonl)],
        cwd=root,
        env=env,
    )
    audit = _run(
        [
            str(cli),
            "workflow",
            "export",
            "--input",
            str(jsonl),
            "--mode",
            "audit",
        ],
        cwd=root,
        env=env,
    )
    operator = _run(
        [
            str(cli),
            "workflow",
            "export",
            "--input",
            str(jsonl),
            "--mode",
            "operator",
        ],
        cwd=root,
        env=env,
    )
    compliance = _run(
        [
            str(cli),
            "compliance",
            "export",
            "--input",
            str(jsonl),
            "--lineage",
        ],
        cwd=root,
        env=env,
    )

    if json.loads(trace.stdout)[0]["status"] != "COMPLETED":
        raise CandidateValidationError("workflow trace did not report COMPLETED")
    audit_payload = json.loads(audit.stdout)
    operator_payload = json.loads(operator.stdout)
    compliance_payload = json.loads(compliance.stdout)
    if audit_payload["export_mode"] != "audit":
        raise CandidateValidationError("audit export mode mismatch")
    if operator_payload["export_mode"] != "operator":
        raise CandidateValidationError("operator export mode mismatch")
    if "lineage" not in compliance_payload:
        raise CandidateValidationError("compliance export omitted lineage")
    public_outputs = audit.stdout
    for forbidden in ("Bearer", "api_key", "must-not-project"):
        if forbidden in public_outputs:
            raise CandidateValidationError(
                f"export leaked forbidden value marker {forbidden!r}"
            )


def _prove_fresh_install(
    wheel: Path,
    work_dir: Path,
) -> dict[str, object]:
    venv_dir = (work_dir / "venv").resolve()
    venv.create(venv_dir, with_pip=True, clear=True)
    python = _venv_python(venv_dir)
    cli = _venv_cli(venv_dir)
    env, removed_provider_variables = _clean_env(venv_dir)

    _run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check",
         str(wheel)],
        cwd=work_dir,
        env=env,
    )
    probe = _run(
        [
            str(python),
            "-c",
            "from importlib.metadata import version; "
            "from pathlib import Path; "
            "import aegis; "
            f"print(version('{EXPECTED_DISTRIBUTION}')); "
            "print(aegis.__version__); "
            "print(Path(aegis.__file__).resolve())",
        ],
        cwd=work_dir,
        env=env,
    )
    lines = probe.stdout.splitlines()
    if lines[:2] != [EXPECTED_VERSION, EXPECTED_VERSION]:
        raise CandidateValidationError(
            f"installed metadata/runtime versions mismatch: {lines[:2]}"
        )
    imported_path = Path(lines[2])
    if not imported_path.is_relative_to(venv_dir):
        raise CandidateValidationError(
            f"aegis imported outside fresh venv: {imported_path}"
        )
    if imported_path.is_relative_to(REPO_ROOT):
        raise CandidateValidationError(
            f"aegis leaked from source checkout: {imported_path}"
        )

    help_result = _run([str(cli), "--help"], cwd=work_dir, env=env)
    if "workflow" not in help_result.stdout:
        raise CandidateValidationError("installed aegis CLI omitted workflow commands")

    starters = {
        profile: _run_starter(cli, python, env, work_dir, profile)
        for profile in ("minimal", "standard", "regulated-high-assurance")
    }
    _prove_failure_doctor_fix(
        cli,
        python,
        env,
        starters["regulated-high-assurance"],
    )
    _prove_trace_and_exports(
        cli,
        python,
        env,
        work_dir,
        starters["minimal"] / "policy.yaml",
    )
    return {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "import_path": str(imported_path),
        "provider_credentials_removed": removed_provider_variables,
        "profiles": {
            "minimal": "COMPLETED",
            "standard": "COMPLETED",
            "regulated-high-assurance": "FAIL_DOCTOR_FIX_COMPLETED",
        },
        "trace": "COMPLETED",
        "exports": ["audit", "operator", "compliance-lineage"],
    }


def _write_report(path: Path | None, report: dict[str, object]) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")


def _run_stage(
    report: dict[str, object],
    name: str,
    operation: Callable[[], object],
) -> object:
    started = time.monotonic()
    result = operation()
    stages = report.setdefault("stages", [])
    assert isinstance(stages, list)
    stages.append(
        {
            "name": name,
            "status": "PASS",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--output-json", type=Path)
    args = parser.parse_args()

    dist_dir = args.dist_dir.resolve()
    report: dict[str, object] = {
        "schema_version": 1,
        "distribution": EXPECTED_DISTRIBUTION,
        "version": EXPECTED_VERSION,
        "status": "FAIL",
        "stages": [],
    }

    try:
        if not args.no_build:
            dist_dir.mkdir(parents=True, exist_ok=True)
            if any(dist_dir.iterdir()):
                raise CandidateValidationError(
                    f"refusing to build into non-empty directory: {dist_dir}"
                )
            _run_stage(
                report,
                "build_wheel_and_sdist",
                lambda: _run(
                    [
                        sys.executable,
                        "-m",
                        "build",
                        "--outdir",
                        str(dist_dir),
                    ],
                    cwd=REPO_ROOT,
                    env=os.environ.copy(),
                ),
            )
        artifacts = _run_stage(
            report,
            "inspect_artifacts",
            lambda: _inspect_artifacts(dist_dir),
        )
        assert isinstance(artifacts, dict)
        report["artifacts"] = artifacts
        wheel = dist_dir / EXPECTED_WHEEL
        with tempfile.TemporaryDirectory(prefix="aegis_v090_wheel_proof_") as tmp:
            installed = _run_stage(
                report,
                "fresh_wheel_end_to_end",
                lambda: _prove_fresh_install(wheel, Path(tmp)),
            )
        report["installed_workflow"] = installed
        report["status"] = "PASS"
        _write_report(args.output_json, report)
        return 0
    except Exception as exc:
        stages = report.setdefault("stages", [])
        assert isinstance(stages, list)
        stages.append(
            {
                "name": "failure",
                "status": "FAIL",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        _write_report(args.output_json, report)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
