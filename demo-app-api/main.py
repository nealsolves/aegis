import copy
import json
import secrets
import uuid
from datetime import date
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from bounded_yaml import ensure_bounded_json_response, load_bounded_yaml
from scenarios import SCENARIOS
from aegis import (
    AIGCError, HMACSigner, build_content_checksum_v2,
    verify_artifact, verify_chain_detailed,
    validate_policy_dates,
    PolicyValidationError,
)
from aegis.policy_loader import (
    merge_policies,
    COMPOSITION_INTERSECT,
    COMPOSITION_UNION,
    COMPOSITION_REPLACE,
)
from gates import GATES, get_gate_info
from loaders import InMemoryPolicyLoader
import yaml as yaml_lib
from workflow_routes import router as workflow_router
from demo_contract import API_CONTRACT_VERSION, demo_source, installed_sdk_version
from demo_edge import DemoEdgeMiddleware
from demo_errors import (
    DemoPublicError,
    current_request_id,
    log_internal_failure,
    public_demo_error,
    public_error_response,
    request_id_from_scope,
    safe_demo_message,
)
from demo_runtime import demo_aegis
from demo_routes import router as demo_router

ALLOWED_ORIGINS = (
    "https://nealsolves.github.io",
    "http://localhost:5173",
    "http://localhost:3000",
)

api = FastAPI(title="AEGIS Demo API", version="0.9.0b1", redirect_slashes=False)


def _route_template(request: Request) -> str | None:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else None


def _log_normalized_error(
    request: Request,
    *,
    code: str,
    operation: str,
    error: BaseException | None,
    exception_class: str | None = None,
    diagnostic: str | None = None,
) -> str:
    request_id = request_id_from_scope(request.scope)
    log_internal_failure(
        request_id=request_id,
        operation=operation,
        error=error,
        public_code=code,
        method=request.method,
        route_template=_route_template(request),
        identity_source=getattr(request.state, "limiter_identity_source", None),
        exception_class=exception_class,
        diagnostic=diagnostic,
    )
    return request_id


@api.exception_handler(DemoPublicError)
async def _demo_public_error_handler(
    request: Request,
    exc: DemoPublicError,
) -> JSONResponse:
    request_id = _log_normalized_error(
        request,
        code=exc.code,
        operation="intentional_public_failure",
        error=exc,
    )
    return public_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        request_id=request_id,
        headers=exc.headers,
    )


@api.exception_handler(RequestValidationError)
async def _request_validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    code = "INVALID_REQUEST"
    request_id = _log_normalized_error(
        request,
        code=code,
        operation="request_validation",
        error=None,
        exception_class=type(exc).__name__,
        diagnostic="request validation failed",
    )
    return public_error_response(
        status_code=422,
        code=code,
        message=safe_demo_message(code),
        request_id=request_id,
    )


@api.exception_handler(StarletteHTTPException)
async def _http_error_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    if exc.status_code == 404:
        code = "NOT_FOUND"
    elif exc.status_code == 405:
        code = "METHOD_NOT_ALLOWED"
    elif 400 <= exc.status_code < 500:
        code = "INVALID_REQUEST"
    else:
        code = "DEMO_OPERATION_FAILED"
    request_id = _log_normalized_error(
        request,
        code=code,
        operation="http_exception",
        error=None,
        exception_class=type(exc).__name__,
        diagnostic=f"normalized HTTP status {exc.status_code}",
    )
    return public_error_response(
        status_code=exc.status_code,
        code=code,
        message=safe_demo_message(code),
        request_id=request_id,
        headers=exc.headers,
    )


@api.exception_handler(Exception)
async def _unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    code = "INTERNAL_ERROR"
    request_id = _log_normalized_error(
        request,
        code=code,
        operation="unhandled_route_exception",
        error=exc,
    )
    return public_error_response(
        status_code=500,
        code=code,
        message=safe_demo_message(code),
        request_id=request_id,
    )


api.include_router(workflow_router)
api.include_router(demo_router)

SAMPLE_POLICIES_DIR = Path(__file__).resolve().parent / "sample_policies"

MEDICAL_FACTORS = [
    {"name": "no_output_schema", "weight": 0.15, "condition": "no_output_schema"},
    {"name": "broad_roles",      "weight": 0.15, "condition": "broad_roles"},
    {"name": "missing_guards",   "weight": 0.20, "condition": "missing_guards"},
    {"name": "external_model",   "weight": 0.30, "condition": "external_model"},
    {"name": "no_preconditions", "weight": 0.20, "condition": "no_preconditions"},
]


def _public_governance_error(exc: AIGCError) -> dict[str, str]:
    code = getattr(exc, "code", "AEGIS_ENFORCEMENT_FAILED")
    try:
        safe_demo_message(code)
    except KeyError:
        code = "AEGIS_ENFORCEMENT_FAILED"
    return public_demo_error(code)


def _public_request_failure(code: str = "INVALID_REQUEST") -> DemoPublicError:
    return DemoPublicError(code, safe_demo_message(code), 422)


def _build_full_invocation(scenario: dict, policy_path: str) -> dict:
    return {
        "policy_file": policy_path,
        "model_provider": scenario["model_provider"],
        "model_identifier": scenario["model_id"],
        "role": scenario["role"],
        "input": {"query": scenario["prompt"]},
        "output": scenario["output"],
        "context": scenario["context"],
    }


def _build_pre_call_invocation(scenario: dict, policy_path: str) -> dict:
    return {
        "policy_file": policy_path,
        "model_provider": scenario["model_provider"],
        "model_identifier": scenario["model_id"],
        "role": scenario["role"],
        "input": {"query": scenario["prompt"]},
        "context": scenario["context"],
    }


@api.get("/api/scenarios/{scenario_key}")
def get_scenario(scenario_key: str):
    if scenario_key not in SCENARIOS:
        raise _public_request_failure()
    s = SCENARIOS[scenario_key]
    return {
        "prompt": s["prompt"],
        "context": s["context"],
        "policy": s["policy"],
        "model_provider": s["model_provider"],
        "model_id": s["model_id"],
        "role": s["role"],
    }


@api.get("/health")
def health():
    source = demo_source()
    return {
        "status": "ok",
        "api_contract_version": API_CONTRACT_VERSION,
        "sdk_version": installed_sdk_version(),
        "source": {
            "branch": source.branch,
            "commit": source.commit,
        },
    }


@api.get("/api/scenarios")
def list_scenarios():
    return {"scenarios": list(SCENARIOS.keys())}


@api.get("/api/policies")
def list_policies():
    names = sorted(p.name for p in SAMPLE_POLICIES_DIR.glob("*.yaml"))
    return {"policies": names}


class EnforceRequest(BaseModel):
    scenario_key: str
    mode: Literal["strict", "risk_scored", "warn_only"] = "risk_scored"
    flow: Literal["unified", "split"] = "unified"


@api.post("/api/enforce")
def enforce(req: EnforceRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]

    aegis = demo_aegis(
        SAMPLE_POLICIES_DIR,
        risk_config={"mode": req.mode, "threshold": 0.7, "factors": MEDICAL_FACTORS}
    )
    try:
        if req.flow == "split":
            pre_call_result = aegis.enforce_pre_call(_build_pre_call_invocation(scenario, policy_ref))
            artifact = aegis.enforce_post_call(pre_call_result, scenario["output"])
        else:
            artifact = aegis.enforce(_build_full_invocation(scenario, policy_ref))
        return {"artifact": artifact, "error": None}
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)
        return {"artifact": artifact, "error": _public_governance_error(exc)}


@api.post("/api/sign/generate-key")
def generate_key():
    return {"key": secrets.token_hex(32)}


class SignEnforceRequest(BaseModel):
    scenario_key: str = "signing_basic"
    key: str


@api.post("/api/sign/enforce")
def sign_enforce(req: SignEnforceRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]
    try:
        key_bytes = bytes.fromhex(req.key)
    except ValueError:
        raise _public_request_failure() from None
    signer = HMACSigner(key=key_bytes)
    aegis = demo_aegis(SAMPLE_POLICIES_DIR, signer=signer)

    try:
        artifact = aegis.enforce(_build_full_invocation(scenario, policy_ref))
        return {"artifact": artifact, "error": None}
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)
        return {"artifact": artifact, "error": _public_governance_error(exc)}


class VerifySignatureRequest(BaseModel):
    artifact: dict
    key: str


@api.post("/api/sign/verify")
def verify_signature(req: VerifySignatureRequest):
    try:
        key_bytes = bytes.fromhex(req.key)
    except ValueError:
        raise _public_request_failure() from None
    signer = HMACSigner(key=key_bytes)
    valid = verify_artifact(req.artifact, signer)
    return {"valid": valid}


class ChainAppendRequest(BaseModel):
    scenario_key: str
    chain_id: str | None = None
    previous_checksum: str | None = None
    chain_index: int = 0


@api.post("/api/chain/append")
def chain_append(req: ChainAppendRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]
    chain_id = req.chain_id or str(uuid.uuid4())

    aegis = demo_aegis(SAMPLE_POLICIES_DIR)
    try:
        artifact = aegis.enforce(_build_full_invocation(scenario, policy_ref))
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)
        if not artifact:
            raise DemoPublicError(
                "AEGIS_ENFORCEMENT_FAILED",
                safe_demo_message("AEGIS_ENFORCEMENT_FAILED"),
                422,
            ) from None

    # Inject chain fields — mirrors AuditChain.append()
    unsigned = {
        key: value
        for key, value in artifact.items()
        if key not in {"checksum", "signature", "signature_metadata"}
    }
    unsigned["chain_id"] = chain_id
    unsigned["chain_index"] = req.chain_index
    unsigned["previous_audit_checksum"] = req.previous_checksum
    artifact = build_content_checksum_v2(unsigned)
    artifact["signature"] = None

    return {"artifact": artifact, "chain_id": chain_id}


class ChainVerifyRequest(BaseModel):
    artifacts: list[dict]


@api.post("/api/chain/verify")
def chain_verify(req: ChainVerifyRequest):
    report = verify_chain_detailed(req.artifacts)
    return {
        "valid": report.internal_valid,
        "content_integrity": report.content_integrity.value,
        "chain_continuity": report.chain_continuity.value,
        "signature_status": report.signature_status.value,
        "anchor_status": report.anchor_status.value,
        "completeness": report.completeness.value,
        "errors": [
            {"code": error.code, "message": error.message, "index": error.index}
            for error in report.errors
        ],
    }


class ChainTamperRequest(BaseModel):
    artifacts: list[dict]
    index: int


class ComposeRequest(BaseModel):
    parent_yaml: str
    child_yaml: str
    strategy: Literal["intersect", "union", "replace"] = "intersect"


_STRATEGY_MAP = {
    "intersect": COMPOSITION_INTERSECT,
    "union": COMPOSITION_UNION,
    "replace": COMPOSITION_REPLACE,
}


@api.post("/api/compose")
def compose_policies(req: ComposeRequest):
    base = load_bounded_yaml(req.parent_yaml)
    child = load_bounded_yaml(req.child_yaml)
    strategy = _STRATEGY_MAP[req.strategy]

    try:
        merged = merge_policies(base, child, composition_strategy=strategy)
        merged.pop("extends", None)
        merged.pop("composition_strategy", None)
    except Exception as exc:
        log_internal_failure(
            request_id=current_request_id(),
            operation="compose_policies",
            error=exc,
            public_code="INVALID_REQUEST",
            method="POST",
            route_template="/api/compose",
        )
        raise DemoPublicError(
            "INVALID_REQUEST",
            safe_demo_message("INVALID_REQUEST"),
            422,
        ) from None

    # Escalation detection
    base_roles = set(base.get("roles", []))
    merged_roles = set(merged.get("roles", []))
    base_tools = {t["name"] for t in base.get("tools", {}).get("allowed_tools", []) if isinstance(t, dict) and "name" in t}
    merged_tools = {t["name"] for t in merged.get("tools", {}).get("allowed_tools", []) if isinstance(t, dict) and "name" in t}
    base_post = set(base.get("post_conditions", {}).get("required", []))
    merged_post = set(merged.get("post_conditions", {}).get("required", []))

    escalations: list[str] = []
    new_roles = merged_roles - base_roles
    if new_roles:
        escalations.append(f"New roles not in base: {sorted(new_roles)}")
    new_tools = merged_tools - base_tools
    if new_tools:
        escalations.append(f"New tools not in base: {sorted(new_tools)}")
    removed_post = base_post - merged_post
    if removed_post:
        escalations.append(f"Postconditions removed: {sorted(removed_post)}")

    diff = {
        "kept_roles": sorted(base_roles & merged_roles),
        "removed_roles": sorted(base_roles - merged_roles),
        "added_roles": sorted(new_roles),
    }

    response = {
        "merged_yaml": yaml_lib.safe_dump(merged, default_flow_style=False),
        "escalations": escalations,
        "diff": diff,
        "error": None,
    }
    ensure_bounded_json_response(response)
    return response


@api.post("/api/chain/tamper")
def chain_tamper(req: ChainTamperRequest):
    artifacts = copy.deepcopy(req.artifacts)
    if not (0 <= req.index < len(artifacts)):
        raise _public_request_failure()
    artifact = artifacts[req.index]
    current = artifact.get("enforcement_result", "PASS")
    artifact["enforcement_result"] = "FAIL" if current == "PASS" else "PASS"
    # Intentionally do NOT recompute checksum — that's what makes it tampered
    return {"artifacts": artifacts}


class LoadPolicyRequest(BaseModel):
    policy_name: str


@api.post("/api/policy/load")
def load_policy_endpoint(req: LoadPolicyRequest):
    path = (SAMPLE_POLICIES_DIR / req.policy_name).resolve()
    if not path.is_relative_to(SAMPLE_POLICIES_DIR.resolve()):
        raise DemoPublicError(
            "ACCESS_DENIED",
            safe_demo_message("ACCESS_DENIED"),
            404,
        )
    if not path.exists():
        raise DemoPublicError(
            "POLICY_NOT_FOUND",
            safe_demo_message("POLICY_NOT_FOUND"),
            404,
        )
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        log_internal_failure(
            request_id=current_request_id(),
            operation="read_demo_policy",
            error=exc,
            public_code="DEMO_OPERATION_FAILED",
            method="POST",
            route_template="/api/policy/load",
        )
        raise DemoPublicError(
            "DEMO_OPERATION_FAILED",
            safe_demo_message("DEMO_OPERATION_FAILED"),
            500,
        ) from None
    policy = load_bounded_yaml(text)
    response = {"policy": policy, "yaml_text": text, "error": None}
    ensure_bounded_json_response(response)
    return response


class ValidateDatesRequest(BaseModel):
    effective_date: str | None = None
    expiration_date: str | None = None
    reference_date: str | None = None


class LoadInMemoryRequest(BaseModel):
    yaml_text: str


@api.post("/api/policy/load-inmemory")
def load_policy_inmemory(req: LoadInMemoryRequest):
    loader = InMemoryPolicyLoader(req.yaml_text)
    policy = loader.load("inline")
    response = {
        "policy": policy,
        "yaml_text": req.yaml_text,
        "loader_class": "InMemoryPolicyLoader",
        "error": None,
    }
    ensure_bounded_json_response(response)
    return response


@api.post("/api/policy/validate-dates")
def validate_dates_endpoint(req: ValidateDatesRequest):
    policy: dict = {}
    if req.effective_date:
        policy["effective_date"] = req.effective_date
    if req.expiration_date:
        policy["expiration_date"] = req.expiration_date

    ref = date.fromisoformat(req.reference_date) if req.reference_date else date.today()

    try:
        evidence = validate_policy_dates(policy, clock=lambda: ref)
        return {
            "in_range": evidence.get("active", True),
            "evidence": evidence,
            "error": None,
        }
    except PolicyValidationError as exc:
        return {
            "in_range": False,
            "evidence": {},
            "error": public_demo_error("POLICY_DATE_INVALID"),
        }


class PolicyTestRequest(BaseModel):
    policy_name: str


@api.post("/api/policy/test")
def run_policy_tests(req: PolicyTestRequest):
    path = (SAMPLE_POLICIES_DIR / req.policy_name).resolve()
    if not path.is_relative_to(SAMPLE_POLICIES_DIR.resolve()):
        return {"results": [], "error": public_demo_error("ACCESS_DENIED")}
    if not path.exists():
        return {"results": [], "error": public_demo_error("POLICY_NOT_FOUND")}
    policy_ref = path.relative_to(SAMPLE_POLICIES_DIR.resolve()).as_posix()

    cases = [
        ({
            "name": "valid role passes",
            "role": "doctor",
            "context": {
                "domain": "medical",
                "role_declared": True,
                "schema_exists": True,
                "human_review_required": True,
            },
        }, "PASS"),
        ({
            "name": "unauthorized role fails",
            "role": "unknown_role",
            "context": {
                "domain": "medical",
                "role_declared": True,
                "schema_exists": True,
                "human_review_required": True,
            },
        }, "FAIL"),
        ({
            "name": "missing precondition fails",
            "role": "doctor",
            "context": {
                "domain": "medical",
                "schema_exists": True,
                "human_review_required": True,
            },
        }, "FAIL"),
    ]

    results = []
    all_met_expectations = True
    for case, expected in cases:
        invocation = {
            "policy_file": policy_ref,
            "role": case["role"],
            "model_provider": "mock",
            "model_identifier": "mock-model",
            "input": {"query": "What is the dosage?"},
            "output": {"result": "500mg"},
            "context": case["context"],
        }
        try:
            demo_aegis(SAMPLE_POLICIES_DIR).enforce(invocation)
            enforcement_result = "PASS"
            failure_reason = None
        except AIGCError:
            enforcement_result = "FAIL"
            failure_reason = safe_demo_message("AEGIS_ENFORCEMENT_FAILED")
        all_met_expectations = all_met_expectations and enforcement_result == expected
        results.append({
            "name": case["name"],
            "enforcement_result": enforcement_result,
            "passed": enforcement_result == "PASS",
            "failure_reason": failure_reason,
        })

    return {
        "results": results,
        "all_met_expectations": all_met_expectations,
        "error": None,
    }


class Lab8KBRequest(BaseModel):
    scenario_key: str = "kb_sourced_pass"


@api.post("/api/lab8/query-kb")
def lab8_query_kb(req: Lab8KBRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]

    from aegis import ProvenanceGate
    aegis_instance = demo_aegis(
        SAMPLE_POLICIES_DIR,
        custom_gates=[ProvenanceGate()],
    )
    invocation = _build_full_invocation(scenario, policy_ref)
    source_ids = scenario["context"].get("provenance", {}).get("source_ids", [])

    try:
        artifact = aegis_instance.enforce(invocation)
        return {"artifact": artifact, "source_ids": source_ids, "error": None}
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)
        return {
            "artifact": artifact,
            "source_ids": source_ids,
            "error": _public_governance_error(exc),
        }


class Lab9CompareRequest(BaseModel):
    scenario_key: str = "low_risk_faq"


@api.post("/api/lab9/compare")
def lab9_compare(req: Lab9CompareRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]

    # Governed path — strict mode exposes full policy impact (risk threshold enforced)
    aegis_instance = demo_aegis(
        SAMPLE_POLICIES_DIR,
        risk_config={"mode": "strict", "threshold": 0.7, "factors": MEDICAL_FACTORS}
    )
    governed_artifact = None
    governed_error = None
    try:
        governed_artifact = aegis_instance.enforce(_build_full_invocation(scenario, policy_ref))
    except AIGCError as exc:
        governed_artifact = getattr(exc, "audit_artifact", None)
        governed_error = _public_governance_error(exc)

    # Ungoverned path — synthetic record representing raw model output with no enforcement
    ungoverned_artifact = {
        "enforcement_result": "PASS",
        "model_provider": scenario["model_provider"],
        "model_identifier": scenario["model_id"],
        "role": scenario["role"],
        "policy_version": "ungoverned",
        "metadata": {
            "gates_evaluated": [],
            "risk_scoring": None,
            "mode": "ungoverned",
        },
        "output": scenario["output"],
    }

    return {
        # Top-level artifact key so useApi auto-ingests the governed result into auditHistory
        "artifact": governed_artifact,
        "governed": {"artifact": governed_artifact, "error": governed_error},
        "ungoverned": {"artifact": ungoverned_artifact, "error": None},
        "scenario_key": req.scenario_key,
    }


class Lab10SplitRequest(BaseModel):
    scenario_key: str = "split_precall_block"
    mode: Literal["strict", "risk_scored", "warn_only"] = "risk_scored"


@api.post("/api/lab10/split-trace")
def lab10_split_trace(req: Lab10SplitRequest):
    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()
    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]

    aegis_instance = demo_aegis(
        SAMPLE_POLICIES_DIR,
        risk_config={"mode": req.mode, "threshold": 0.7, "factors": MEDICAL_FACTORS}
    )
    pre_invocation = _build_pre_call_invocation(scenario, policy_ref)

    try:
        pre_result = aegis_instance.enforce_pre_call(pre_invocation)
    except AIGCError as exc:
        # Phase A blocked
        artifact = getattr(exc, "audit_artifact", None)
        meta = (artifact or {}).get("metadata", {})
        return {
            "phase_a": {
                "result": "FAIL",
                "gates_evaluated": meta.get("pre_call_gates_evaluated", []),
                "failures": (artifact or {}).get("failures", []),
                "blocked": True,
            },
            "phase_b": None,
            "artifact": artifact,
            "combined_result": "FAIL",
            "error": _public_governance_error(exc),
        }

    # PreCallResult is intentionally opaque. Phase metadata becomes public only
    # through the finalized artifact returned by post-call enforcement.
    phase_a = {
        "result": "PASS",
        "gates_evaluated": [],
        "failures": [],
        "blocked": False,
    }

    # Phase B
    try:
        artifact = aegis_instance.enforce_post_call(pre_result, scenario["output"])
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)
        meta = (artifact or {}).get("metadata", {})
        phase_a["gates_evaluated"] = meta.get("pre_call_gates_evaluated", [])
        return {
            "phase_a": phase_a,
            "phase_b": {
                "result": "FAIL",
                "gates_evaluated": meta.get("post_call_gates_evaluated", []),
                "failures": (artifact or {}).get("failures", []),
                "blocked": True,
            },
            "artifact": artifact,
            "combined_result": "FAIL",
            "error": _public_governance_error(exc),
        }

    meta = artifact.get("metadata", {})
    phase_a["gates_evaluated"] = meta.get("pre_call_gates_evaluated", [])
    phase_b = {
        "result": artifact["enforcement_result"],
        "gates_evaluated": meta.get("post_call_gates_evaluated", []),
        "failures": artifact.get("failures") or [],
        "blocked": artifact["enforcement_result"] == "FAIL",
    }

    return {
        "phase_a": phase_a,
        "phase_b": phase_b,
        "artifact": artifact,
        "combined_result": artifact["enforcement_result"],
        "error": None,
    }


@api.get("/api/gate/{gate_name}")
def get_gate(gate_name: str):
    gate = GATES.get(gate_name)
    if not gate:
        return {"error": public_demo_error("UNKNOWN_DEMO_ID")}
    return get_gate_info(gate)


class GateRunRequest(BaseModel):
    gate_name: str
    scenario_key: str


@api.post("/api/gate/run")
def run_gate(req: GateRunRequest):
    gate = GATES.get(req.gate_name)
    if not gate:
        return {
            "artifact": None,
            "gate_result": None,
            "error": public_demo_error("UNKNOWN_DEMO_ID"),
        }

    if req.scenario_key not in SCENARIOS:
        raise _public_request_failure()

    scenario = SCENARIOS[req.scenario_key]
    policy_ref = scenario["policy"]
    policy_path = SAMPLE_POLICIES_DIR / policy_ref
    aegis = demo_aegis(SAMPLE_POLICIES_DIR, custom_gates=[gate])

    invocation = _build_full_invocation(scenario, policy_ref)

    try:
        artifact = aegis.enforce(invocation)
    except AIGCError as exc:
        artifact = getattr(exc, "audit_artifact", None)

    # Run gate with the same policy and context used during enforcement
    with open(policy_path, encoding="utf-8") as _f:
        policy_dict = load_bounded_yaml(_f.read())
    direct_result = gate.evaluate(invocation, policy_dict, scenario["context"])

    return {
        "artifact": artifact,
        "gate_result": {
            "name": req.gate_name,
            "insertion_point": gate.insertion_point,
            "passed": direct_result.passed,
            "failures": direct_result.failures,
            "metadata": direct_result.metadata,
        },
        "error": None,
    }


cors_app = CORSMiddleware(
    api,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "Retry-After"],
)
app = DemoEdgeMiddleware(cors_app, allowed_origins=ALLOWED_ORIGINS)
