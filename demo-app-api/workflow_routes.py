"""
v0.9.0 workflow governance demo routes.

Uses real AEGIS.open_session() — no fake backend behavior.
All imports are from the public aegis API only (no aegis._internal).
"""
from __future__ import annotations

import atexit
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

import aegis.presets as presets
from aegis import JsonFileAuditSink

from bounded_yaml import ensure_bounded_json_response
from demo_errors import (
    DemoPublicError,
    current_request_id,
    log_internal_failure,
    public_demo_error,
    safe_demo_message,
)
from demo_limits import SUBPROCESS_TIMEOUT_SECONDS
from demo_runtime import (
    DemoAegisModuleProxy,
    demo_aegis,
    demo_aegis_with_sink,
    logical_policy_ref,
)

router = APIRouter(prefix="/api/workflow/v090", tags=["workflow-v090"])

# Per-run state keyed by run_id returned from the failure scenario.
# Bounded to prevent unbounded temp-dir growth; evicted entries are cleaned up.
_MAX_RUNS = 20
# run_id -> {"starter_dir": str, "artifact": dict, "original_source": str}
_run_state: dict[str, dict] = {}
_POLICY_TMPDIR = tempfile.TemporaryDirectory(prefix="aegis_demo_policies_")
_policy_cache: dict[str, str] = {}


def _store_run(starter_dir: str, artifact: dict, original_source: str) -> str:
    """Store per-run failure state; return a new opaque run_id."""
    run_id = uuid.uuid4().hex
    if len(_run_state) >= _MAX_RUNS:
        oldest_id = next(iter(_run_state))
        old = _run_state.pop(oldest_id)
        shutil.rmtree(old["starter_dir"], ignore_errors=True)
    _run_state[run_id] = {
        "starter_dir": starter_dir,
        "artifact": artifact,
        "original_source": original_source,
    }
    return run_id


def _cleanup_temp_artifacts() -> None:
    for run in _run_state.values():
        shutil.rmtree(run["starter_dir"], ignore_errors=True)
    _run_state.clear()
    _policy_cache.clear()
    _POLICY_TMPDIR.cleanup()


atexit.register(_cleanup_temp_artifacts)


def _get_policy_path(profile: str) -> str:
    """Write preset policy YAML to a managed temp dir, cache and return the path."""
    if profile in _policy_cache:
        return _policy_cache[profile]
    preset_map = {
        "minimal": presets.MinimalPreset,
        "standard": presets.StandardPreset,
        "regulated": presets.RegulatedHighAssurancePreset,
    }
    preset = preset_map[profile]()
    policy_path = Path(_POLICY_TMPDIR.name) / f"{profile}.yaml"
    policy_path.write_text(preset.policy_yaml, encoding="utf-8")
    _policy_cache[profile] = str(policy_path)
    return str(policy_path)


def _sim(prompt: str) -> dict:
    return {"result": f"Response to: {prompt[:60]}"}


def _operation_error(
    code: str,
    *,
    status_code: int,
) -> DemoPublicError:
    return DemoPublicError(code, safe_demo_message(code), status_code)


def _run_demo_subprocess(
    args: Sequence[str],
    *,
    request_id: str,
) -> subprocess.CompletedProcess[str]:
    """Execute one demo CLI process with a fixed deadline and safe failures."""

    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        log_internal_failure(
            request_id=request_id,
            operation="workflow_subprocess",
            error=None,
            exception_class=type(exc).__name__,
            diagnostic=f"stdout={exc.stdout!s}\nstderr={exc.stderr!s}",
            public_code="DEMO_OPERATION_TIMEOUT",
        )
        raise _operation_error(
            "DEMO_OPERATION_TIMEOUT",
            status_code=503,
        ) from None
    except OSError as exc:
        log_internal_failure(
            request_id=request_id,
            operation="workflow_subprocess",
            error=exc,
            public_code="DEMO_OPERATION_FAILED",
        )
        raise _operation_error(
            "DEMO_OPERATION_FAILED",
            status_code=500,
        ) from None

    if result.returncode != 0:
        log_internal_failure(
            request_id=request_id,
            operation="workflow_subprocess",
            error=None,
            exception_class="SubprocessNonzeroExit",
            diagnostic=f"returncode={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}",
            public_code="DEMO_OPERATION_FAILED",
        )
    return result


def _safe_doctor_findings(
    raw: object,
    *,
    starter_dir: Path,
) -> list[dict[str, str]]:
    """Project CLI findings onto the five-field public doctor contract."""

    if not isinstance(raw, list):
        raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
    fields = ("code", "severity", "message", "next_action", "target_kind")
    required_fields = frozenset(("code", "severity", "message"))
    projected: list[dict[str, str]] = []
    forbidden = (str(starter_dir), "/private/", "/tmp/", "\\private\\", "\\tmp\\")
    for item in raw:
        if not isinstance(item, Mapping):
            raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
        finding: dict[str, str] = {}
        for field in fields:
            value = item.get(field)
            if value is None and field not in required_fields:
                continue
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 512
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
                or any(marker in value for marker in forbidden)
            ):
                raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
            finding[field] = value
        projected.append(finding)
    return projected


def _safe_trace_payload(raw: object) -> list[dict]:
    """Validate trace JSON without mutating or redacting finalized evidence."""

    if not isinstance(raw, list) or not raw or not all(isinstance(item, dict) for item in raw):
        raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
    ensure_bounded_json_response(raw)
    return raw


def _generate_starter_dir(profile: str) -> str:
    starter_dir = tempfile.mkdtemp(
        prefix=f"aegis_demo_{profile}_",
        dir=_POLICY_TMPDIR.name,
    )
    result = _run_demo_subprocess(
        [
            sys.executable,
            "-m",
            "aegis",
            "workflow",
            "init",
            "--profile",
            profile,
            "--output-dir",
            starter_dir,
        ],
        request_id=current_request_id(),
    )
    if result.returncode != 0:
        shutil.rmtree(starter_dir, ignore_errors=True)
        raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
    return starter_dir


def _load_workflow_module(starter_dir: str):
    workflow_py = Path(starter_dir) / "workflow_example.py"
    module_name = f"_aegis_demo_workflow_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, workflow_py)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load workflow module from {workflow_py}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "aegis"):
        mod.aegis = DemoAegisModuleProxy(mod.aegis, starter_dir)
    return mod


def _run_workflow_module(
    starter_dir: str,
    func_name: str,
) -> tuple[dict | None, dict[str, str] | None]:
    mod = _load_workflow_module(starter_dir)
    try:
        artifact = getattr(mod, func_name)("policy.yaml")
        return artifact, None
    except Exception as exc:  # noqa: BLE001
        request_id = current_request_id()
        log_internal_failure(
            request_id=request_id,
            operation="workflow_module",
            error=exc,
            public_code="AEGIS_ENFORCEMENT_FAILED",
        )
        return (
            getattr(mod, "LAST_WORKFLOW_ARTIFACT", None),
            public_demo_error("AEGIS_ENFORCEMENT_FAILED"),
        )


def _break_regulated_starter(starter_dir: str) -> str:
    workflow_py = Path(starter_dir) / "workflow_example.py"
    original_source = workflow_py.read_text(encoding="utf-8")
    broken_source = original_source.replace(
        '                    "source_ids": ["doc-001", "doc-002"],\n',
        "",
    ).replace(
        '                    "source_ids": ["analysis-step-1"],\n',
        "",
    )
    if broken_source == original_source:
        raise RuntimeError("could not apply regulated starter failure edit")
    workflow_py.write_text(broken_source, encoding="utf-8")
    return original_source


class WorkflowRunRequest(BaseModel):
    scenario: Literal["minimal", "standard", "failure", "regulated"]
    run_id: str | None = None


@router.post("/run")
def run_workflow(req: WorkflowRunRequest):
    if req.scenario == "minimal":
        policy_file = logical_policy_ref(
            _POLICY_TMPDIR.name,
            _get_policy_path("minimal"),
        )
        governance = demo_aegis(_POLICY_TMPDIR.name)
        with governance.open_session(policy_file=policy_file) as session:
            for prompt in ["Analyze the document.", "Summarize the findings."]:
                pre = session.enforce_step_pre_call({
                    "policy_file": policy_file,
                    "input": {"prompt": prompt},
                    "context": {"caller_id": "demo"},
                    "model_provider": "anthropic",
                    "model_identifier": "claude-sonnet-4-6",
                    "role": "ai-assistant",
                })
                session.enforce_step_post_call(pre, _sim(prompt))
            session.complete()
        return {"artifact": session.workflow_artifact, "error": None}

    elif req.scenario == "standard":
        policy_file = logical_policy_ref(
            _POLICY_TMPDIR.name,
            _get_policy_path("standard"),
        )
        governance = demo_aegis(_POLICY_TMPDIR.name)
        with governance.open_session(policy_file=policy_file) as session:
            pre1 = session.enforce_step_pre_call({
                "policy_file": policy_file,
                "input": {"prompt": "Draft a proposal."},
                "context": {"phase": "pre-approval", "caller_id": "demo"},
                "model_provider": "anthropic",
                "model_identifier": "claude-sonnet-4-6",
                "role": "ai-assistant",
            })
            session.enforce_step_post_call(pre1, _sim("Draft a proposal."))
            session.pause()
            session.resume()
            for prompt in ["Finalize the proposal.", "Generate summary."]:
                pre = session.enforce_step_pre_call({
                    "policy_file": policy_file,
                    "input": {"prompt": prompt},
                    "context": {"phase": "post-approval", "caller_id": "demo"},
                    "model_provider": "anthropic",
                    "model_identifier": "claude-sonnet-4-6",
                    "role": "ai-assistant",
                })
                session.enforce_step_post_call(pre, _sim(prompt))
            session.complete()
        return {"artifact": session.workflow_artifact, "error": None}

    elif req.scenario == "regulated":
        if req.run_id is not None and req.run_id in _run_state:
            run = _run_state[req.run_id]
            starter_dir = run["starter_dir"]
            (Path(starter_dir) / "workflow_example.py").write_text(
                run["original_source"],
                encoding="utf-8",
            )
            artifact, error = _run_workflow_module(
                starter_dir,
                "run_regulated_workflow",
            )
            run["artifact"] = artifact or {}
            return {"artifact": artifact, "error": error, "run_id": req.run_id}

        starter_dir = _generate_starter_dir("regulated-high-assurance")
        artifact, error = _run_workflow_module(starter_dir, "run_regulated_workflow")
        return {"artifact": artifact, "error": error}

    else:  # failure
        starter_dir = _generate_starter_dir("regulated-high-assurance")
        original_source = _break_regulated_starter(starter_dir)
        artifact, error = _run_workflow_module(starter_dir, "run_regulated_workflow")
        run_id = _store_run(starter_dir, artifact or {}, original_source)
        return {"artifact": artifact, "error": error, "run_id": run_id}


@router.post("/compare")
def compare_workflows():
    """Run the same prompt governed vs ungoverned and return both results."""
    policy_file = logical_policy_ref(
        _POLICY_TMPDIR.name,
        _get_policy_path("minimal"),
    )
    prompt = "Summarize the quarterly report."

    governance = demo_aegis(_POLICY_TMPDIR.name)
    with governance.open_session(policy_file=policy_file) as session:
        pre = session.enforce_step_pre_call({
            "policy_file": policy_file,
            "input": {"prompt": prompt},
            "context": {"caller_id": "demo"},
            "model_provider": "anthropic",
            "model_identifier": "claude-sonnet-4-6",
            "role": "ai-assistant",
        })
        session.enforce_step_post_call(pre, _sim(prompt))
        session.complete()
    governed_artifact = session.workflow_artifact

    ungoverned_artifact = {
        "status": "ok",
        "enforcement_result": "PASS",
        "policy_version": "ungoverned",
        "audit_available": False,
        "result": _sim(prompt)["result"],
    }

    return {
        "governed": {"artifact": governed_artifact, "error": None},
        "ungoverned": {"artifact": ungoverned_artifact, "error": None},
    }


@router.get("/diagnose")
def diagnose_last_failure(run_id: str | None = None):
    """Run aegis workflow doctor on the starter dir for a specific run.

    ``run_id`` is returned by POST /run when scenario='failure'.  When omitted
    the most recent failure is used (single-user convenience fallback).
    """
    if run_id is not None:
        run = _run_state.get(run_id)
    else:
        run = list(_run_state.values())[-1] if _run_state else None

    if run is None:
        return {"findings": [], "source": "no_prior_failure"}

    starter_dir = run["starter_dir"]
    result = _run_demo_subprocess(
        [sys.executable, "-m", "aegis", "workflow", "doctor",
         starter_dir, "--json"],
        request_id=current_request_id(),
    )
    # Parse findings regardless of exit code: doctor exits 1 for ERROR-severity
    # findings, which are exactly the ones we want to surface to the user.
    try:
        raw_findings = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError as exc:
        log_internal_failure(
            request_id=current_request_id(),
            operation="workflow_doctor_projection",
            error=exc,
            public_code="DEMO_OPERATION_FAILED",
        )
        raise _operation_error("DEMO_OPERATION_FAILED", status_code=500) from None
    findings = _safe_doctor_findings(raw_findings, starter_dir=Path(starter_dir))
    return {"findings": findings, "source": "failure_starter_dir"}


@router.get("/trace")
def trace_evidence():
    """Run a governed 2-step minimal session with a JSONL sink and return the workflow trace.

    Implements the evidence view: produces real workflow + invocation artifacts,
    writes them to a temp JSONL file via JsonFileAuditSink, then reconstructs the
    timeline via 'aegis workflow trace'. No fake backend behavior.
    """
    policy_file = logical_policy_ref(
        _POLICY_TMPDIR.name,
        _get_policy_path("minimal"),
    )
    jsonl_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, dir=_POLICY_TMPDIR.name
    )
    jsonl_path = jsonl_file.name
    jsonl_file.close()
    try:
        sink = JsonFileAuditSink(jsonl_path)
        governance = demo_aegis_with_sink(_POLICY_TMPDIR.name, sink)
        prompts = ["Analyze the document.", "Summarize the findings."]
        with governance.open_session(policy_file=policy_file) as session:
            for prompt in prompts:
                pre = session.enforce_step_pre_call({
                    "policy_file": policy_file,
                    "input": {"prompt": prompt},
                    "context": {"caller_id": "demo-evidence"},
                    "model_provider": "anthropic",
                    "model_identifier": "claude-sonnet-4-6",
                    "role": "ai-assistant",
                })
                session.enforce_step_post_call(pre, {"result": f"Response to: {prompt[:60]}"})
            session.complete()

        result = _run_demo_subprocess(
            [sys.executable, "-m", "aegis", "workflow", "trace", "--input", jsonl_path],
            request_id=current_request_id(),
        )
        if result.returncode != 0:
            raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
        if not result.stdout.strip():
            raise _operation_error("DEMO_OPERATION_FAILED", status_code=500)
        try:
            traces = _safe_trace_payload(json.loads(result.stdout))
        except json.JSONDecodeError as exc:
            log_internal_failure(
                request_id=current_request_id(),
                operation="workflow_trace_projection",
                error=exc,
                public_code="DEMO_OPERATION_FAILED",
            )
            raise _operation_error("DEMO_OPERATION_FAILED", status_code=500) from None
        return {"traces": traces, "artifact": session.workflow_artifact}
    finally:
        try:
            Path(jsonl_path).unlink()
        except OSError as exc:
            log_internal_failure(
                request_id=current_request_id(),
                operation="workflow_trace_cleanup",
                error=exc,
                public_code="DEMO_OPERATION_FAILED",
            )
