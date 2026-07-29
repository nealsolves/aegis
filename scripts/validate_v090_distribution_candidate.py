#!/usr/bin/env python3
"""Build and validate the AEGIS v0.9.0 beta distribution candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
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

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:  # pragma: no cover - setup-python always supplies pip
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name


REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_DISTRIBUTION = "aegis-ai-governance"
EXPECTED_STEM = "aegis_ai_governance"
EXPECTED_VERSION = "0.9.0b1"
EXPECTED_RUNTIME_DEPENDENCIES = {"PyYAML>=6.0", "jsonschema>=4.0"}
EXPECTED_EXTRA_DEPENDENCIES = {
    'build>=1.2; extra == "dev"',
    'pytest>=8.0; extra == "dev"',
    'pytest-cov>=6.0; extra == "dev"',
    'pytest-asyncio>=1.0; extra == "dev"',
    'flake8>=7.0; extra == "dev"',
    'openai-agents>=0.0.7; extra == "openai-agents"',
    'boto3>=1.43.0; extra == "aws-kms"',
    'google-cloud-kms>=3.15.0; extra == "gcp-kms"',
    'google-crc32c>=1.7.1; extra == "gcp-kms"',
    'cryptography>=45.0.1; extra == "gcp-kms"',
}
EXPECTED_EXTRAS = {"dev", "openai-agents", "aws-kms", "gcp-kms"}
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


def _canonical_sha256(value: object) -> str:
    def normalize(item: object) -> object:
        if isinstance(item, float) and item.is_integer():
            return int(item)
        if isinstance(item, dict):
            return {key: normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        return item

    payload = json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _marker_operand_key(operand: object) -> tuple[str, str]:
    kind = type(operand).__name__.lower()
    value = getattr(operand, "value", None)
    if kind not in {"variable", "value"} or type(value) is not str:
        raise CandidateValidationError("requirement marker operand is invalid")
    return kind, value


def _canonical_marker(node: object) -> object:
    if type(node) is tuple and len(node) == 3:
        left, operator, right = node
        left_key = _marker_operand_key(left)
        right_key = _marker_operand_key(right)
        operator_value = getattr(operator, "value", None)
        if type(operator_value) is not str:
            raise CandidateValidationError(
                "requirement marker operator is invalid"
            )
        if (
            operator_value in {"==", "!="}
            and left_key[0] == "value"
            and right_key[0] == "variable"
        ):
            left_key, right_key = right_key, left_key
        return left_key, operator_value, right_key
    if type(node) is list:
        canonical = tuple(_canonical_marker(item) for item in node)
        return canonical[0] if len(canonical) == 1 else canonical
    if type(node) is str and node in {"and", "or"}:
        return node
    raise CandidateValidationError("requirement marker structure is invalid")


def _marker_mentions_extra(marker: object) -> bool:
    if marker == ("variable", "extra"):
        return True
    if type(marker) is tuple:
        return any(_marker_mentions_extra(item) for item in marker)
    return False


def _requirement_key(value: str) -> tuple[object, ...]:
    try:
        requirement = Requirement(value)
        marker = (
            None
            if requirement.marker is None
            else _canonical_marker(requirement.marker._markers)
        )
        return (
            canonicalize_name(requirement.name),
            tuple(
                sorted(canonicalize_name(extra) for extra in requirement.extras)
            ),
            str(requirement.specifier),
            requirement.url,
            marker,
        )
    except CandidateValidationError:
        raise
    except Exception as error:
        raise CandidateValidationError(
            f"invalid requirement metadata: {value!r}"
        ) from error


def _partition_requirements(
    requirements: object,
) -> tuple[set[tuple[object, ...]], set[tuple[object, ...]]]:
    if not isinstance(requirements, (list, set, tuple)):
        raise CandidateValidationError("requirement metadata is invalid")
    runtime: set[tuple[object, ...]] = set()
    extras: set[tuple[object, ...]] = set()
    for value in requirements:
        if not isinstance(value, str):
            raise CandidateValidationError("requirement metadata is invalid")
        key = _requirement_key(str(value))
        marker = key[-1]
        if marker is None:
            runtime.add(key)
        elif _marker_mentions_extra(marker):
            extras.add(key)
        else:
            raise CandidateValidationError(
                f"requirement marker is not extra-scoped: {value!r}"
            )
    return runtime, extras


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
        runtime_requirements, extra_requirements = _partition_requirements(
            metadata.get_all("Requires-Dist", [])
        )
        expected_runtime, _ = _partition_requirements(
            EXPECTED_RUNTIME_DEPENDENCIES
        )
        _, expected_extras = _partition_requirements(
            EXPECTED_EXTRA_DEPENDENCIES
        )
        if runtime_requirements != expected_runtime:
            raise CandidateValidationError(
                "wheel runtime dependencies changed: "
                f"{sorted(runtime_requirements)}"
            )
        if extra_requirements != expected_extras:
            raise CandidateValidationError(
                "wheel optional dependencies changed: "
                f"{sorted(extra_requirements)}"
            )
        extras = set(metadata.get_all("Provides-Extra", []))
        if extras != EXPECTED_EXTRAS:
            raise CandidateValidationError(
                f"wheel extras changed: {sorted(extras)}"
            )
        required_members = {
            "aegis/__init__.py",
            "aegis/__main__.py",
            "aegis/cli.py",
            "aegis/py.typed",
            "aegis/integrations/__init__.py",
            "aegis/integrations/kms.py",
            "aegis/integrations/_kms_common.py",
            "aegis/integrations/aws_kms.py",
            "aegis/integrations/google_cloud_kms.py",
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
    function_name, expected_steps = {
        "minimal": ("run_minimal_workflow", 2),
        "standard": ("run_standard_workflow", 3),
        "regulated-high-assurance": ("run_regulated_workflow", 2),
    }[profile]
    artifact_marker = "__AEGIS_ARTIFACT__"
    runner = (
        "import importlib.util,json,sys;"
        "spec=importlib.util.spec_from_file_location('_aegis_starter',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(module);"
        f"artifact=getattr(module,{function_name!r})();"
        f"print({artifact_marker!r}+json.dumps(artifact,sort_keys=True))"
    )
    run = _run(
        [str(python), "-c", runner, str(starter / "workflow_example.py")],
        cwd=starter,
        env=env,
    )
    artifact_lines = [
        line.removeprefix(artifact_marker)
        for line in run.stdout.splitlines()
        if line.startswith(artifact_marker)
    ]
    if len(artifact_lines) != 1:
        raise CandidateValidationError(
            f"{profile} starter did not emit one workflow artifact:\n{run.stdout}"
        )
    artifact = json.loads(artifact_lines[0])
    if artifact.get("status") != "COMPLETED":
        raise CandidateValidationError(
            f"{profile} starter did not report COMPLETED: {artifact.get('status')!r}"
        )
    if len(artifact.get("steps", [])) != expected_steps:
        raise CandidateValidationError(
            f"{profile} starter step count mismatch: "
            f"{len(artifact.get('steps', []))}, expected {expected_steps}"
        )
    if profile == "standard":
        approval_checkpoints = artifact.get("approval_checkpoints", [])
        if not approval_checkpoints or not all(
            checkpoint.get("checkpoint_id") == "starter-approval-001"
            and checkpoint.get("status") == "approved"
            for checkpoint in approval_checkpoints
        ):
            raise CandidateValidationError(
                "standard starter omitted its approval checkpoint evidence"
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

    trace_payload = json.loads(trace.stdout)[0]
    if trace_payload["status"] != "COMPLETED":
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
    if trace_payload["unresolved_checksums"]:
        raise CandidateValidationError(
            "workflow trace has unresolved invocation checksums"
        )
    if audit_payload["integrity"]["unresolved_count"] != 0:
        raise CandidateValidationError(
            "audit export has unresolved invocation checksums"
        )
    if operator_payload["integrity"]["unresolved_count"] != 0:
        raise CandidateValidationError(
            "operator export has unresolved invocation checksums"
        )

    audit_sessions = audit_payload["sessions"]
    operator_sessions = operator_payload["sessions"]
    if len(audit_sessions) != 1 or len(operator_sessions) != 1:
        raise CandidateValidationError("exports did not contain exactly one session")
    session_id = trace_payload["session_id"]
    if not session_id or {
        audit_sessions[0]["session_id"],
        operator_sessions[0]["session_id"],
    } != {session_id}:
        raise CandidateValidationError("trace/export session IDs do not correlate")

    trace_steps = trace_payload["steps"]
    audit_steps = audit_sessions[0]["steps"]
    operator_steps = operator_sessions[0]["steps"]
    trace_checksums = [
        step["invocation_artifact_checksum"] for step in trace_steps
    ]
    if not trace_checksums or any(
        not step.get("resolved") or not checksum
        for step, checksum in zip(trace_steps, trace_checksums)
    ):
        raise CandidateValidationError(
            "trace steps do not resolve invocation artifact checksums"
        )
    if [step["invocation_artifact_checksum"] for step in audit_steps] != trace_checksums:
        raise CandidateValidationError(
            "audit export invocation checksums do not match the trace"
        )
    if [step["invocation_artifact_checksum"] for step in operator_steps] != trace_checksums:
        raise CandidateValidationError(
            "operator export invocation checksums do not match the trace"
        )
    for step, expected_checksum in zip(operator_steps, trace_checksums):
        invocation = step.get("invocation_artifact")
        if not isinstance(invocation, dict):
            raise CandidateValidationError(
                "operator export omitted a correlated invocation artifact"
            )
        if _canonical_sha256(invocation) != expected_checksum:
            raise CandidateValidationError(
                "operator export invocation artifact checksum mismatch"
            )
        if invocation.get("context", {}).get("session_id") != session_id:
            raise CandidateValidationError(
                "invocation artifact session ID does not match workflow session"
            )
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
    _run(
        [str(python), "-m", "pip", "check"],
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
        "dependency_check": "PASS",
        "profiles": {
            "minimal": "COMPLETED",
            "standard": "COMPLETED_WITH_APPROVAL_CHECKPOINT",
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
