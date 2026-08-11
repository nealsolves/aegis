"""
Core enforcement logic.

Combines:
- policy loading
- validation
- error handling
- audit logging triggers
- audit sink emission
- risk scoring
- custom enforcement gates
- OpenTelemetry instrumentation
"""

from __future__ import annotations

import asyncio
import copy
import functools
import json
import logging
import re
import time as _time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, NoReturn, Sequence

if TYPE_CHECKING:
    from aegis._internal.session import GovernanceSession

import warnings

from aegis._internal.audit import DEFAULT_REDACTION_PATTERNS
from aegis._internal.attempts import AttemptFactory
from aegis._internal.chain_linker import ChainLinker
from aegis._internal.evidence_diagnostics import EvidenceDiagnostics

from aegis._internal.policy_loader import (
    _bind_policy_authority,
    load_policy,
    PolicyCache,
    PolicyLoaderBase,
)
from aegis._internal.compiled_policy import (
    CompiledPolicy,
    freeze,
)
from aegis._internal.policy_compiler import (
    compile_policy,
    resolve_runtime_risk,
)
from aegis._internal.audit import build_audit_evidence_body, sanitize_failure_message
from aegis._internal.guards import evaluate_compiled_guards
from aegis._internal.tools import validate_tool_constraints
from aegis._internal.evidence_finalizer import (
    _EvidenceAbort,
    evidence_attempt,
    finalize_legacy_invocation_artifact as emit_to_sink,
)
from aegis._internal.risk_scoring import (
    compute_compiled_risk_score,
    normalize_risk_result,
    RiskScore,
)
from aegis._internal.signing import ArtifactSigner
from aegis._internal.gates import (
    EnforcementGate,
    run_gates_normalized,
    sort_gates,
    validate_gate,
    INSERTION_PRE_AUTHORIZATION,
    INSERTION_POST_AUTHORIZATION,
    INSERTION_PRE_OUTPUT,
    INSERTION_POST_OUTPUT,
)
from aegis._internal.gate_projection import GateProjectionFactory
from aegis._internal.telemetry import (
    enforcement_span,
    record_gate_event,
    record_enforcement_result,
)
from aegis._internal.errors import (
    AIGCError,
    AuditSinkError,
    ConditionResolutionError,
    CustomGateViolationError,
    EvidenceConfigurationError,
    FeatureNotImplementedError,
    GovernanceViolationError,
    GuardEvaluationError,
    InvocationValidationError,
    PolicyLoadError,
    PolicyValidationError,
    PreconditionError,
    RiskThresholdError,
    SchemaValidationError,
    ToolConstraintViolationError,
)
from aegis._internal.sinks import AuditSink
from aegis._internal.operation_registry import (
    OperationHandle,
    OperationRecord,
    OperationRegistry,
)

logger = logging.getLogger("aegis.enforcement")

_MODULE_ATTEMPT_FACTORY = AttemptFactory()
_MODULE_EVIDENCE_DIAGNOSTICS = EvidenceDiagnostics()
_MODULE_OPERATION_REGISTRY = OperationRegistry()


@dataclass(frozen=True, slots=True)
class _PolicyAuthority:
    invocation: Mapping[str, Any]
    requested_policy_ref: str
    bound_policy_ref: str
    loader: PolicyLoaderBase


_POLICY_AUTHORITY_OVERRIDE: ContextVar[_PolicyAuthority | None] = ContextVar(
    "aegis_policy_authority_override",
    default=None,
)


@contextmanager
def _policy_authority_scope(authority: _PolicyAuthority):
    token = _POLICY_AUTHORITY_OVERRIDE.set(authority)
    try:
        yield authority
    finally:
        _POLICY_AUTHORITY_OVERRIDE.reset(token)


def _effective_policy_authority(
    policy_file: str,
    configured_loader: PolicyLoaderBase | None,
    *,
    invocation: Mapping[str, Any],
) -> _PolicyAuthority:
    if configured_loader is not None:
        return _PolicyAuthority(
            invocation,
            policy_file,
            policy_file,
            configured_loader,
        )
    override = _POLICY_AUTHORITY_OVERRIDE.get()
    if (
        override is not None
        and invocation is override.invocation
        and policy_file == override.requested_policy_ref
    ):
        return override
    bound_ref, loader = _bind_policy_authority(policy_file, None)
    return _PolicyAuthority(invocation, policy_file, bound_ref, loader)


def _validate_chain_linker(
    chain_linker: ChainLinker | None,
) -> ChainLinker | None:
    if chain_linker is not None and (
        not callable(getattr(chain_linker, "reserve", None))
        or not callable(getattr(chain_linker, "reconcile", None))
    ):
        raise TypeError("chain_linker must provide reserve() and reconcile()")
    return chain_linker


class _ModuleEnforcementRuntime:
    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self._sink: AuditSink | None = None
        self._signer: ArtifactSigner | None = None
        self._chain_linker: ChainLinker | None = None
        self._policy_loader: PolicyLoaderBase | None = None
        self._sealed = False

    def configure(
        self,
        *,
        sink: AuditSink,
        signer: ArtifactSigner | None,
        chain_linker: ChainLinker | None,
        policy_loader: PolicyLoaderBase | None,
    ) -> None:
        if not isinstance(sink, AuditSink):
            raise TypeError("sink must be an AuditSink")
        if policy_loader is not None and not isinstance(
            policy_loader,
            PolicyLoaderBase,
        ):
            raise TypeError("policy_loader must be a PolicyLoaderBase")
        with self._lock:
            if self._sealed:
                raise RuntimeError("module enforcement runtime is sealed")
            self._sink = sink
            self._signer = signer
            self._chain_linker = _validate_chain_linker(chain_linker)
            self._policy_loader = policy_loader

    def begin(
        self,
    ) -> tuple[
        AuditSink,
        ArtifactSigner | None,
        ChainLinker | None,
        PolicyLoaderBase | None,
    ]:
        with self._lock:
            self._sealed = True
            if self._sink is None:
                raise EvidenceConfigurationError()
            return (
                self._sink,
                self._signer,
                self._chain_linker,
                self._policy_loader,
            )

    def reset_for_test(self) -> None:
        with self._lock:
            self._sink = None
            self._signer = None
            self._chain_linker = None
            self._policy_loader = None
            self._sealed = False


_MODULE_RUNTIME = _ModuleEnforcementRuntime()


def configure_module_enforcement(
    *,
    sink: AuditSink,
    signer: ArtifactSigner | None = None,
    chain_linker: ChainLinker | None = None,
    policy_loader: PolicyLoaderBase | None = None,
) -> None:
    """Configure the private module runtime once, before governed traffic."""
    _MODULE_RUNTIME.configure(
        sink=sink,
        signer=signer,
        chain_linker=chain_linker,
        policy_loader=policy_loader,
    )


def _reset_module_enforcement_for_test() -> None:
    global _MODULE_EVIDENCE_DIAGNOSTICS, _MODULE_OPERATION_REGISTRY

    _MODULE_RUNTIME.reset_for_test()
    _MODULE_EVIDENCE_DIAGNOSTICS = EvidenceDiagnostics()
    _MODULE_OPERATION_REGISTRY = OperationRegistry()


def _module_policy_loader_for_retry() -> PolicyLoaderBase | None:
    """Return the loader from the sealed module enforcement snapshot."""
    _, _, _, policy_loader = _MODULE_RUNTIME.begin()
    return policy_loader


def _attempt_invocation(
    function_name: str,
    args: tuple[Any, ...],
    instance_scoped: bool,
) -> object:
    index = 1 if instance_scoped else 0
    candidate = args[index] if len(args) > index else object()
    if "post_call" not in function_name:
        return candidate
    # Split handoff tokens are caller-owned objects until the wrapped function
    # authenticates their frozen evidence. Allocate the minimum identity now;
    # the trusted artifact body supplies identity after token verification.
    return object()


def _evidence_attempt_boundary(
    entry_point: str,
    mode: str,
    *,
    inherit_outer_attempt: bool = False,
):
    """Allocate attempt identity before a public entry parses its arguments."""
    def decorate(function):
        if asyncio.iscoroutinefunction(function):
            @functools.wraps(function)
            async def async_boundary(*args, **kwargs):
                owner = args[0] if args else None
                factory = getattr(owner, "_attempt_factory", None)
                instance_scoped = isinstance(factory, AttemptFactory)
                factory = factory or _MODULE_ATTEMPT_FACTORY
                attempt_invocation = _attempt_invocation(
                    function.__name__,
                    args,
                    instance_scoped,
                )
                attempt = factory.allocate(
                    entry_point,
                    mode,
                    attempt_invocation,
                )
                if instance_scoped:
                    runtime_sink = owner._sink
                    runtime_signer = owner._signer
                    runtime_failure_mode = owner._on_sink_failure
                    runtime_diagnostics = owner._evidence_diagnostics
                    runtime_chain_linker = owner._chain_linker
                    runtime_policy_loader = owner._policy_loader
                else:
                    (
                        runtime_sink,
                        runtime_signer,
                        runtime_chain_linker,
                        runtime_policy_loader,
                    ) = _MODULE_RUNTIME.begin()
                    runtime_failure_mode = "raise"
                    runtime_diagnostics = _MODULE_EVIDENCE_DIAGNOSTICS
                try:
                    with evidence_attempt(
                        attempt,
                        sink=runtime_sink,
                        signer=runtime_signer,
                        failure_mode=runtime_failure_mode,
                        diagnostics=runtime_diagnostics,
                        chain_linker=runtime_chain_linker,
                        inherit_outer_attempt=inherit_outer_attempt,
                    ):
                        if (
                            isinstance(attempt_invocation, Mapping)
                            and isinstance(
                                attempt_invocation.get("policy_file"),
                                str,
                            )
                        ):
                            try:
                                authority = _effective_policy_authority(
                                    attempt_invocation["policy_file"],
                                    runtime_policy_loader,
                                    invocation=attempt_invocation,
                                )
                            except PolicyLoadError:
                                return await function(*args, **kwargs)
                            with _policy_authority_scope(authority):
                                return await function(*args, **kwargs)
                        return await function(*args, **kwargs)
                except _EvidenceAbort as abort:
                    raise abort.error from abort

            return async_boundary

        @functools.wraps(function)
        def boundary(*args, **kwargs):
            owner = args[0] if args else None
            factory = getattr(owner, "_attempt_factory", None)
            instance_scoped = isinstance(factory, AttemptFactory)
            factory = factory or _MODULE_ATTEMPT_FACTORY
            attempt_invocation = _attempt_invocation(
                function.__name__,
                args,
                instance_scoped,
            )
            attempt = factory.allocate(
                entry_point,
                mode,
                attempt_invocation,
            )
            if instance_scoped:
                runtime_sink = owner._sink
                runtime_signer = owner._signer
                runtime_failure_mode = owner._on_sink_failure
                runtime_diagnostics = owner._evidence_diagnostics
                runtime_chain_linker = owner._chain_linker
                runtime_policy_loader = owner._policy_loader
            else:
                (
                    runtime_sink,
                    runtime_signer,
                    runtime_chain_linker,
                    runtime_policy_loader,
                ) = _MODULE_RUNTIME.begin()
                runtime_failure_mode = "raise"
                runtime_diagnostics = _MODULE_EVIDENCE_DIAGNOSTICS
            try:
                with evidence_attempt(
                    attempt,
                    sink=runtime_sink,
                    signer=runtime_signer,
                    failure_mode=runtime_failure_mode,
                    diagnostics=runtime_diagnostics,
                    chain_linker=runtime_chain_linker,
                    inherit_outer_attempt=inherit_outer_attempt,
                ):
                    if (
                        isinstance(attempt_invocation, Mapping)
                        and isinstance(
                            attempt_invocation.get("policy_file"),
                            str,
                        )
                    ):
                        try:
                            authority = _effective_policy_authority(
                                attempt_invocation["policy_file"],
                                runtime_policy_loader,
                                invocation=attempt_invocation,
                            )
                        except PolicyLoadError:
                            return function(*args, **kwargs)
                        with _policy_authority_scope(authority):
                            return function(*args, **kwargs)
                    return function(*args, **kwargs)
            except _EvidenceAbort as abort:
                raise abort.error from abort

        return boundary

    return decorate


# ── Canonical gate IDs (append-only; order matters) ──────────────
GATE_GUARDS = "guard_evaluation"
GATE_ROLE = "role_validation"
GATE_PRECONDS = "precondition_validation"
GATE_TOOLS = "tool_constraint_validation"
GATE_SCHEMA = "schema_validation"
GATE_POSTCONDS = "postcondition_validation"
GATE_RISK = "risk_scoring"

AUTHORIZATION_GATES = (GATE_GUARDS, GATE_ROLE, GATE_PRECONDS, GATE_TOOLS)
OUTPUT_GATES = (GATE_SCHEMA, GATE_POSTCONDS)


def _load_compiled_policy(
    invocation: Mapping[str, Any],
    *,
    loader: PolicyLoaderBase | None,
) -> CompiledPolicy:
    """Load once and immediately close the authorization representation."""
    policy_file = invocation["policy_file"]
    authority = _effective_policy_authority(
        policy_file,
        loader,
        invocation=invocation,
    )
    raw = load_policy(
        authority.bound_policy_ref,
        loader=authority.loader,
    )
    return compile_policy(
        raw,
        source=authority.requested_policy_ref,
        allow_legacy=False,
    )


def _compile_cached_policy(
    invocation: Mapping[str, Any],
    *,
    cache: PolicyCache,
    loader: PolicyLoaderBase | None,
) -> CompiledPolicy:
    """Compile exactly once after the instance cache load boundary."""
    policy_file = invocation["policy_file"]
    authority = _effective_policy_authority(
        policy_file,
        loader,
        invocation=invocation,
    )
    raw = cache.get_or_load(
        authority.bound_policy_ref,
        loader=authority.loader,
    )
    return compile_policy(
        raw,
        source=authority.requested_policy_ref,
        allow_legacy=False,
    )


def _plain_compiled_value(value: Any) -> Any:
    """Thaw a compiler-owned JSON snapshot for audit/custom-gate consumers."""
    if isinstance(value, Mapping):
        return {
            key: _plain_compiled_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_plain_compiled_value(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_plain_compiled_value(item) for item in value)
    return copy.deepcopy(value)


def _compiled_gate_projection(
    policy: CompiledPolicy,
) -> Mapping[str, Any]:
    """Derive a non-authoritative compatibility view for custom gates."""
    return GateProjectionFactory.policy(policy)


def _compiled_audit_projection(policy: CompiledPolicy) -> dict[str, str]:
    """Expose only compiler-owned metadata required by audit generation."""
    return {"policy_version": policy.declared_policy_version}


def _validate_compiled_role(role: str, policy: CompiledPolicy) -> None:
    if role not in policy.roles:
        raise GovernanceViolationError(
            f"Unauthorized role '{role}'",
            code="ROLE_NOT_ALLOWED",
            details={"role": role, "allowed_roles": list(policy.roles)},
        )


def _validate_compiled_preconditions(
    context: Mapping[str, Any],
    policy: CompiledPolicy,
) -> list[str]:
    satisfied: list[str] = []
    for precondition in policy.preconditions:
        precondition.validate(context)
        satisfied.append(precondition.name)
    return satisfied


def _validate_compiled_postconditions(
    policy: CompiledPolicy,
    *,
    schema_valid: bool,
) -> list[str]:
    satisfied: list[str] = []
    for condition in policy.postconditions:
        if condition == "output_schema_valid" and schema_valid:
            satisfied.append(condition)
            continue
        if condition == "output_schema_valid":
            raise GovernanceViolationError(
                "Postcondition 'output_schema_valid' requires output_schema validation",
                code="POSTCONDITION_FAILED",
                details={"postcondition": condition},
            )
        raise GovernanceViolationError(
            f"Unsupported postcondition: {condition}",
            code="UNSUPPORTED_POSTCONDITION",
            details={"postcondition": condition},
        )
    return satisfied


def _record_gate(gates: list[str], gate_id: str) -> None:
    """Append gate_id to the running gates_evaluated list (append-only)."""
    gates.append(gate_id)


# ── PreCallResult handoff token ──────────────────────────────────


@dataclass(frozen=True, slots=True)
class PreCallResult:
    """Opaque identity for one registry-backed split enforcement operation."""

    operation_id: str
    issuer_id: str
    process_id: int
    correlation_id: str
    policy_digest: str
    canonicalization_profile: str


def _operation_handle(result: PreCallResult) -> OperationHandle:
    return OperationHandle(
        operation_id=result.operation_id,
        issuer_id=result.issuer_id,
        process_id=result.process_id,
        policy_digest=result.policy_digest,
        canonicalization_profile=result.canonicalization_profile,
    )


def _issue_pre_call_result(
    registry: OperationRegistry,
    *,
    compiled_policy: CompiledPolicy,
    invocation_snapshot: Mapping[str, Any],
    phase_a_metadata: Mapping[str, Any],
    guards_evaluated_engine: Sequence[Mapping[str, Any]],
    conditions_resolved: Mapping[str, Any],
    grouped_gates: Mapping[str, Sequence[EnforcementGate]],
) -> PreCallResult:
    private_phase_a_state = {
        **copy.deepcopy(dict(phase_a_metadata)),
        "guards_evaluated_engine": [
            dict(item) for item in guards_evaluated_engine
        ],
        "conditions_resolved": copy.deepcopy(dict(conditions_resolved)),
    }
    record = OperationRecord(
        compiled_policy=compiled_policy,
        invocation_snapshot=freeze(dict(invocation_snapshot)),
        phase_a_metadata=freeze(private_phase_a_state),
        grouped_gates=MappingProxyType(
            {point: tuple(gates) for point, gates in grouped_gates.items()}
        ),
    )
    handle = registry.issue(record)
    return PreCallResult(
        operation_id=handle.operation_id,
        issuer_id=handle.issuer_id,
        process_id=handle.process_id,
        correlation_id=uuid.uuid4().hex,
        policy_digest=handle.policy_digest,
        canonicalization_profile=handle.canonicalization_profile,
    )


def _emit_split_validation_failure(
    exc: InvocationValidationError,
    *,
    record: OperationRecord | None = None,
    sink: AuditSink | None = None,
    sink_failure_mode: str = "raise",
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> None:
    safe_invocation = (
        _plain_compiled_value(record.invocation_snapshot)
        if record is not None
        else {
            "policy_file": "unknown",
            "model_provider": "unknown",
            "model_identifier": "unknown",
            "role": "unknown",
            "input": {},
            "context": {},
        }
    )
    safe_invocation["output"] = {}
    artifact = _generate_pre_pipeline_fail_artifact(
        safe_invocation,
        exc,
        redaction_patterns=redaction_patterns,
    )
    artifact.setdefault("metadata", {})["enforcement_mode"] = "split"
    exc.audit_artifact = artifact
    try:
        if sink is None:
            emit_to_sink(artifact)
        else:
            emit_to_sink(
                artifact,
                sink=sink,
                failure_mode=sink_failure_mode,
            )
    except AuditSinkError as sink_exc:
        logger.error(
            "Sink emission failed on split validation FAIL path: %s",
            sink_exc,
        )


def _run_registry_post_call(
    registry: OperationRegistry,
    pre_call_result: object,
    output: object,
    *,
    sink: AuditSink | None = None,
    sink_failure_mode: str = "raise",
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    signer: ArtifactSigner | None = None,
    risk_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(pre_call_result, PreCallResult):
        exc = InvocationValidationError(
            "enforce_post_call() requires a PreCallResult from "
            "enforce_pre_call()",
            details={"received_type": type(pre_call_result).__name__},
        )
        _emit_split_validation_failure(
            exc,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
        )
        raise exc

    try:
        record = registry.consume(_operation_handle(pre_call_result))
    except InvocationValidationError as exc:
        _emit_split_validation_failure(
            exc,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
        )
        raise

    return _run_consumed_post_call(
        record,
        output,
        sink=sink,
        sink_failure_mode=sink_failure_mode,
        redaction_patterns=redaction_patterns,
        signer=signer,
        risk_config=risk_config,
    )


def _run_consumed_post_call(
    record: OperationRecord,
    output: object,
    *,
    sink: AuditSink | None = None,
    sink_failure_mode: str = "raise",
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    signer: ArtifactSigner | None = None,
    risk_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Phase B after the caller has atomically consumed *record*."""

    if not isinstance(output, dict):
        exc = InvocationValidationError(
            "enforce_post_call() output must be a dict",
            details={"field": "output"},
        )
        _emit_split_validation_failure(
            exc,
            record=record,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
        )
        raise exc
    try:
        json.dumps(output, allow_nan=False, sort_keys=True)
    except (TypeError, ValueError) as json_exc:
        exc = InvocationValidationError(
            "enforce_post_call() output is not JSON-serializable: "
            f"{json_exc}",
            details={"field": "output"},
        )
        _emit_split_validation_failure(
            exc,
            record=record,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
        )
        raise exc from json_exc

    full_invocation = _plain_compiled_value(record.invocation_snapshot)
    full_invocation["output"] = output
    phase_a_metadata = _plain_compiled_value(record.phase_a_metadata)
    guards_evaluated_engine = [
        dict(item)
        for item in phase_a_metadata.pop("guards_evaluated_engine", ())
    ]
    conditions_resolved = dict(
        phase_a_metadata.pop("conditions_resolved", {})
    )
    phase_a_gates = list(phase_a_metadata.get("gates_evaluated", []))
    all_custom_metadata = dict(
        phase_a_metadata.get("all_custom_metadata", {})
    )

    with enforcement_span(
        "aegis.enforce_post_call",
        attributes={
            "aegis.policy_file": full_invocation.get("policy_file", ""),
            "aegis.role": full_invocation.get("role", ""),
            "aegis.enforcement_mode": "split",
        },
    ) as span:
        return _run_phase_b(
            record.compiled_policy,
            record.compiled_policy,
            full_invocation,
            phase_a_gates=phase_a_gates,
            phase_a_metadata=phase_a_metadata,
            phase_a_extra={
                "preconditions_satisfied": phase_a_metadata.get(
                    "preconditions_satisfied",
                    [],
                ),
                "tool_constraints": phase_a_metadata.get(
                    "tool_constraints",
                    {},
                ),
            },
            guards_evaluated_engine=guards_evaluated_engine,
            conditions_resolved=conditions_resolved,
            all_custom_metadata=all_custom_metadata,
            grouped_gates=record.grouped_gates,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
            signer=signer,
            risk_config=risk_config,
            enforcement_mode="split",
            pre_call_timestamp=phase_a_metadata.get("pre_call_timestamp"),
            span=span,
        )


# ── Invocation validation (three layers) ─────────────────────────

REQUIRED_CORE_KEYS = (
    "policy_file",
    "model_provider",
    "model_identifier",
    "role",
    "input",
    "context",
)

REQUIRED_INVOCATION_KEYS = REQUIRED_CORE_KEYS + ("output",)


def _validate_invocation_core(invocation: Mapping[str, Any]) -> None:
    """Validate fields common to both unified and pre-call invocations."""
    if not isinstance(invocation, Mapping):
        raise InvocationValidationError(
            "Invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
    missing = [key for key in REQUIRED_CORE_KEYS if key not in invocation]
    if missing:
        raise InvocationValidationError(
            "Invocation is missing required fields",
            details={"missing_fields": missing},
        )

    string_keys = ("policy_file", "model_provider", "model_identifier", "role")
    for key in string_keys:
        if not isinstance(invocation[key], str) or not invocation[key]:
            raise InvocationValidationError(
                f"Invocation field '{key}' must be a non-empty string",
                details={"field": key},
            )

    for key in ("input", "context"):
        if not isinstance(invocation[key], dict):
            raise InvocationValidationError(
                f"Invocation field '{key}' must be an object",
                details={"field": key},
            )

    for key in ("input", "context"):
        try:
            json.dumps(invocation[key], allow_nan=False, sort_keys=True)
        except (TypeError, ValueError) as e:
            raise InvocationValidationError(
                f"Invocation field '{key}' is not JSON-serializable: {e}",
                details={"field": key},
            ) from e


def _validate_invocation(invocation: Mapping[str, Any]) -> None:
    """Validate a complete unified invocation (requires output)."""
    _validate_invocation_core(invocation)
    if "output" not in invocation:
        raise InvocationValidationError(
            "Invocation is missing required fields",
            details={"missing_fields": ["output"]},
        )
    if not isinstance(invocation["output"], dict):
        raise InvocationValidationError(
            "Invocation field 'output' must be an object",
            details={"field": "output"},
        )
    try:
        json.dumps(invocation["output"], allow_nan=False, sort_keys=True)
    except (TypeError, ValueError) as e:
        raise InvocationValidationError(
            f"Invocation field 'output' is not JSON-serializable: {e}",
            details={"field": "output"},
        ) from e


def _validate_pre_call_invocation(invocation: Mapping[str, Any]) -> None:
    """Validate a pre-call invocation before any model output exists."""
    _validate_invocation_core(invocation)
    if "output" in invocation:
        raise InvocationValidationError(
            "Invocation field 'output' is not allowed during pre-call "
            "enforcement",
            details={"field": "output"},
        )


def _map_exception_to_failure_gate(exc: Exception) -> str:
    """Map exception type to failure gate identifier.

    Check subclasses before parent classes to ensure correct mapping.
    All returned values must be members of the failure_gate enum in
    schemas/audit_artifact.schema.json.
    """
    # Check subclasses before parent classes to ensure correct mapping.
    if isinstance(exc, FeatureNotImplementedError):
        return "feature_not_implemented"
    if isinstance(exc, InvocationValidationError):
        return "invocation_validation"
    if isinstance(exc, PolicyValidationError):
        # Risk-config validation errors carry "invalid_mode" in details;
        # route them to the risk_scoring gate for triage fidelity.
        if (
            isinstance(getattr(exc, "details", None), dict)
            and "invalid_mode" in exc.details
        ):
            return "risk_scoring"
        return "invocation_validation"
    if isinstance(exc, PolicyLoadError):
        return "invocation_validation"
    if isinstance(exc, GuardEvaluationError):
        return "guard_evaluation"
    if isinstance(exc, ConditionResolutionError):
        return "condition_resolution"
    if isinstance(exc, AuditSinkError):
        return "sink_emission"
    if isinstance(exc, RiskThresholdError):
        return "risk_scoring"
    if isinstance(exc, ToolConstraintViolationError):
        return "tool_validation"
    if isinstance(exc, PreconditionError):
        return "precondition_validation"
    if isinstance(exc, SchemaValidationError):
        return "schema_validation"
    if isinstance(exc, CustomGateViolationError):
        return "custom_gate_violation"
    if isinstance(exc, GovernanceViolationError):
        if "role" in str(exc).lower():
            return "role_validation"
        return "postcondition_validation"
    return "invocation_validation"


def _make_custom_gate_runner(
    grouped_gates: dict[str, list[EnforcementGate]],
    invocation: Mapping[str, Any],
    gates_evaluated: list[str],
    all_custom_metadata: dict[str, Any],
):
    """Create a closure that runs custom gates at a given insertion point.

    Returns a callable ``(insertion_point, policy_view) -> None`` that
    raises CustomGateViolationError on failure.
    """

    def _run_custom_gates_at(
        insertion_point: str,
        policy_view: dict[str, Any],
    ) -> None:
        gates_at = grouped_gates.get(insertion_point, [])
        if not gates_at:
            return
        failures, meta, outcome = run_gates_normalized(
            gates_at, invocation, policy_view, {},
            gates_evaluated, [],
        )
        if meta:
            all_custom_metadata.update(meta)
        if not outcome.allows_continuation:
            raise CustomGateViolationError.from_outcome(
                outcome,
                details={"insertion_point": insertion_point},
            )

    return _run_custom_gates_at


def _build_phase_a_mid_pipeline_fail_artifact(
    invocation_without_output: Mapping[str, Any],
    policy: CompiledPolicy,
    exc: AIGCError,
    phase_a_gates: list[str],
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> dict[str, Any]:
    """Build and return the FAIL artifact for a mid-pipeline Phase A failure.

    Does NOT emit to sink or attach the artifact to exc — the caller is
    responsible for both.

    :param invocation_without_output: Invocation dict (output will be {})
    :param policy: Strictly compiled policy
    :param exc: The AIGCError that caused the failure
    :param phase_a_gates: Gates evaluated before the failure
    :param redaction_patterns: Optional patterns for failure message sanitization
    :return: FAIL audit artifact dict
    """
    safe_inv = dict(invocation_without_output)
    safe_inv["output"] = {}

    failure_gate = _map_exception_to_failure_gate(exc)
    raw_reason = str(exc)
    failure_reason, reason_redacted = sanitize_failure_message(
        raw_reason, redaction_patterns,
    )
    redacted_fields: list[str] = list(reason_redacted)
    failures = None
    if hasattr(exc, "details") and exc.details:
        sanitized_msg, msg_redacted = sanitize_failure_message(
            str(exc), redaction_patterns,
        )
        for r in msg_redacted:
            if r not in redacted_fields:
                redacted_fields.append(r)
        failures = [
            {
                "code": exc.__class__.__name__,
                "message": sanitized_msg,
                "field": (
                    exc.details.get("field")
                    if isinstance(exc.details, dict)
                    else None
                ),
            }
        ]

    fail_metadata: dict[str, Any] = {
        "enforcement_mode": "split_pre_call_only",
        "pre_call_gates_evaluated": list(phase_a_gates),
        "redacted_fields": redacted_fields,
    }

    _ctx_prov = (safe_inv.get("context") or {}).get("provenance")
    _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

    return build_audit_evidence_body(
        safe_inv,
        _compiled_audit_projection(policy),
        enforcement_result="FAIL",
        failures=failures,
        failure_gate=failure_gate,
        failure_reason=failure_reason,
        metadata=fail_metadata,
        provenance=_provenance,
    )


def _run_phase_a(
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    *,
    custom_gates: list[EnforcementGate] | None = None,
    grouped_gates: dict[str, list[EnforcementGate]] | None = None,
    span: Any = None,
    gates_evaluated: list[str] | None = None,
) -> tuple[
    CompiledPolicy,         # effective_policy
    list[dict[str, Any]],   # guards_evaluated (from guard engine)
    dict[str, Any],         # conditions_resolved
    dict[str, Any],         # all_custom_metadata
    list[str],              # gates_evaluated (pipeline gate list)
    dict[str, Any],         # phase_a_extra (preconditions, tools, etc.)
]:
    """Execute Phase A enforcement (pre-call gates).

    Runs gates 1-7: pre_auth custom gates, guard evaluation, role validation,
    precondition validation, tool constraint validation, post_auth custom gates.

    The caller may pass a mutable ``gates_evaluated`` list; on exception the
    caller can inspect the partial progress that was recorded before the
    failure.

    Returns: (effective_policy, guards_evaluated_from_engine,
              conditions_resolved, all_custom_metadata,
              gates_evaluated_list, phase_a_extra)
    """
    # ── PIPELINE_CONTRACT ────────────────────────────────────────
    # Do not reorder authorization gates after output gates.
    # Authorization: guard_evaluation -> role_validation ->
    #                precondition_validation -> tool_constraint_validation
    # Output:        schema_validation -> postcondition_validation
    # Enforced by:   tests/test_pre_action_boundary.py
    # ─────────────────────────────────────────────────────────────

    if gates_evaluated is None:
        gates_evaluated = []
    if grouped_gates is None:
        grouped_gates = sort_gates(custom_gates or [])

    all_custom_metadata: dict[str, Any] = {}
    _run_custom_gates_at = _make_custom_gate_runner(
        grouped_gates, invocation, gates_evaluated, all_custom_metadata,
    )

    # ── Pre-authorization custom gates ──────────────
    _run_custom_gates_at(
        INSERTION_PRE_AUTHORIZATION,
        _compiled_gate_projection(policy),
    )

    effective_policy = policy
    guards_evaluated_engine: list[dict[str, Any]] = []
    conditions_resolved: dict[str, Any] = {}
    if policy.guards or policy.conditions:
        logger.debug(
            "Evaluating guards and conditions for policy %s",
            invocation.get("policy_file"),
        )
        effective_policy, guards_evaluated_engine, conditions_resolved = (
            evaluate_compiled_guards(
                policy,
                policy.guards,
                invocation["context"],
                invocation=invocation,
            )
        )
    _record_gate(gates_evaluated, GATE_GUARDS)
    record_gate_event(span, GATE_GUARDS)
    logger.debug(
        "Guards evaluated: %d results", len(guards_evaluated_engine),
    )

    _validate_compiled_role(invocation["role"], effective_policy)
    _record_gate(gates_evaluated, GATE_ROLE)
    record_gate_event(span, GATE_ROLE)
    logger.debug("Role validated: %s", invocation["role"])

    preconditions_satisfied = _validate_compiled_preconditions(
        invocation["context"], effective_policy,
    )
    _record_gate(gates_evaluated, GATE_PRECONDS)
    record_gate_event(span, GATE_PRECONDS)
    logger.debug("Preconditions satisfied: %s", preconditions_satisfied)

    tool_validation_result = validate_tool_constraints(
        invocation, effective_policy.tools,
    )
    _record_gate(gates_evaluated, GATE_TOOLS)
    record_gate_event(span, GATE_TOOLS)
    logger.debug("Tool constraints validated")

    # ── Post-authorization custom gates ─────────────
    _run_custom_gates_at(
        INSERTION_POST_AUTHORIZATION,
        _compiled_gate_projection(effective_policy),
    )

    phase_a_extra = {
        "preconditions_satisfied": preconditions_satisfied,
        "tool_constraints": tool_validation_result,
    }

    return (
        effective_policy,
        guards_evaluated_engine,
        conditions_resolved,
        all_custom_metadata,
        gates_evaluated,
        phase_a_extra,
    )


def _run_phase_b(
    effective_policy: CompiledPolicy,
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    *,
    phase_a_gates: list[str],
    phase_a_metadata: dict[str, Any],
    phase_a_extra: dict[str, Any],
    guards_evaluated_engine: list[dict[str, Any]],
    conditions_resolved: dict[str, Any],
    all_custom_metadata: dict[str, Any],
    grouped_gates: dict[str, list[EnforcementGate]] | None = None,
    sink: Any = None,
    sink_failure_mode: str | None = None,
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    signer: ArtifactSigner | None = None,
    risk_config: dict[str, Any] | None = None,
    enforcement_mode: str = "unified",
    pre_call_timestamp: int | None = None,
    span: Any = None,
) -> dict[str, Any]:
    """Execute Phase B enforcement (post-call gates + artifact emission).

    Runs gates 8-13: pre_output custom gates, schema validation,
    postcondition validation, post_output custom gates, risk scoring,
    audit artifact generation.

    Returns: PASS audit artifact
    Raises: AIGCError on FAIL (with artifact attached)
    """
    audit_policy = _compiled_audit_projection(policy)
    _sink_kw: dict[str, Any] = {}
    if sink is not None:
        _sink_kw["sink"] = sink
    if sink_failure_mode is not None:
        _sink_kw["failure_mode"] = sink_failure_mode
    if signer is not None:
        _sink_kw["signer"] = signer

    if grouped_gates is None:
        grouped_gates = sort_gates([])

    # Phase B has its own gates_evaluated list; will be merged or
    # separated in the metadata depending on enforcement_mode.
    phase_b_gates: list[str] = []

    # Build the custom gate runner for Phase B using phase_b_gates
    phase_b_custom_metadata: dict[str, Any] = {}
    _run_custom_gates_at = _make_custom_gate_runner(
        grouped_gates, invocation, phase_b_gates, phase_b_custom_metadata,
    )

    try:
        # ── Pre-output custom gates ─────────────────────
        _run_custom_gates_at(
            INSERTION_PRE_OUTPUT,
            _compiled_gate_projection(effective_policy),
        )

        schema_validation = "skipped"
        schema_valid = False
        if effective_policy.output_validator is not None:
            effective_policy.output_validator.validate(invocation["output"])
            schema_validation = "passed"
            schema_valid = True
            logger.debug("Output schema validation passed")
        _record_gate(phase_b_gates, GATE_SCHEMA)
        record_gate_event(span, GATE_SCHEMA)

        postconditions_satisfied = _validate_compiled_postconditions(
            effective_policy,
            schema_valid=schema_valid,
        )
        _record_gate(phase_b_gates, GATE_POSTCONDS)
        record_gate_event(span, GATE_POSTCONDS)
        logger.debug(
            "Postconditions satisfied: %s", postconditions_satisfied,
        )

        # ── Post-output custom gates ────────────────────
        _run_custom_gates_at(
            INSERTION_POST_OUTPUT,
            _compiled_gate_projection(effective_policy),
        )

        # ── Risk scoring ────────────────────────────────
        risk_result: RiskScore | None = None
        effective_risk_config = resolve_runtime_risk(
            effective_policy.risk,
            risk_config,
        )
        if effective_risk_config.configured:
            risk_result = compute_compiled_risk_score(
                invocation, effective_policy,
                risk_config=effective_risk_config,
            )
            _record_gate(phase_b_gates, GATE_RISK)
            record_gate_event(
                span, GATE_RISK,
                details={"score": risk_result.score},
            )

            risk_outcome = normalize_risk_result(risk_result)
            if not risk_outcome.allows_continuation:
                raise RiskThresholdError(
                    f"Risk authorization denied: {risk_outcome.reason_code}",
                    details={
                        **risk_result.to_dict(),
                        "reason_code": risk_outcome.reason_code,
                        "terminal": risk_outcome.terminal.value,
                    },
                )
            if risk_outcome.terminal.value == "warn":
                logger.warning(
                    "Risk score %.3f reached threshold %.3f (%s)",
                    risk_result.score,
                    risk_result.threshold,
                    risk_outcome.reason_code,
                )

        # Merge custom metadata from Phase A and Phase B
        merged_custom_metadata = dict(all_custom_metadata)
        if phase_b_custom_metadata:
            merged_custom_metadata.update(phase_b_custom_metadata)

        # Build metadata based on enforcement_mode
        if enforcement_mode == "unified":
            combined_gates = list(phase_a_gates) + list(phase_b_gates)
            metadata: dict[str, Any] = {
                "preconditions_satisfied": phase_a_extra.get(
                    "preconditions_satisfied", [],
                ),
                "postconditions_satisfied": postconditions_satisfied,
                "schema_validation": schema_validation,
                "guards_evaluated": guards_evaluated_engine,
                "conditions_resolved": conditions_resolved,
                "tool_constraints": phase_a_extra.get(
                    "tool_constraints", {},
                ),
                "gates_evaluated": combined_gates,
                "enforcement_mode": "unified",
            }
        else:
            # split mode
            post_call_timestamp = int(_time.time())
            metadata = {
                "preconditions_satisfied": phase_a_extra.get(
                    "preconditions_satisfied", [],
                ),
                "postconditions_satisfied": postconditions_satisfied,
                "schema_validation": schema_validation,
                "guards_evaluated": guards_evaluated_engine,
                "conditions_resolved": conditions_resolved,
                "tool_constraints": phase_a_extra.get(
                    "tool_constraints", {},
                ),
                "enforcement_mode": "split",
                "pre_call_gates_evaluated": list(phase_a_gates),
                "post_call_gates_evaluated": list(phase_b_gates),
                "pre_call_timestamp": pre_call_timestamp,
                "post_call_timestamp": post_call_timestamp,
            }

        if merged_custom_metadata:
            metadata["custom_gate_metadata"] = dict(
                sorted(merged_custom_metadata.items()),
            )

        if risk_result is not None:
            metadata["risk_scoring"] = risk_result.to_dict()

        # Extract caller-supplied provenance from invocation context so it
        # flows into the audit artifact and is available to AuditLineage.
        # Guard: scalar provenance (e.g. from ProvenanceGate migration stubs)
        # must not reach _normalize_provenance() which calls .items().
        _ctx_prov = (invocation.get("context") or {}).get("provenance")
        _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

        audit_record = build_audit_evidence_body(
            invocation,
            audit_policy,
            enforcement_result="PASS",
            metadata=metadata,
            risk_score=(
                risk_result.score if risk_result is not None else None
            ),
            provenance=_provenance,
        )

        emit_to_sink(audit_record, **_sink_kw)
        record_enforcement_result(
            span, "PASS",
            policy_file=invocation.get("policy_file"),
            role=invocation.get("role"),
            risk_score=(
                risk_result.score if risk_result is not None else None
            ),
            enforcement_mode=enforcement_mode,
        )
        logger.info(
            "Enforcement complete: PASS [policy=%s, role=%s]",
            invocation.get("policy_file"),
            invocation.get("role"),
        )
        return audit_record

    except AIGCError as exc:
        # Build combined gates list for FAIL artifact metadata
        if enforcement_mode == "unified":
            all_gates = list(phase_a_gates) + list(phase_b_gates)
        else:
            all_gates = list(phase_b_gates)

        failure_gate = _map_exception_to_failure_gate(exc)
        raw_reason = str(exc)
        failure_reason, reason_redacted = sanitize_failure_message(
            raw_reason, redaction_patterns,
        )

        redacted_fields: list[str] = list(reason_redacted)
        failures = None
        if hasattr(exc, "details") and exc.details:
            sanitized_msg, msg_redacted = sanitize_failure_message(
                str(exc), redaction_patterns,
            )
            for r in msg_redacted:
                if r not in redacted_fields:
                    redacted_fields.append(r)
            failures = [
                {
                    "code": exc.__class__.__name__,
                    "message": sanitized_msg,
                    "field": (
                        exc.details.get("field")
                        if isinstance(exc.details, dict)
                        else None
                    ),
                }
            ]
            # For CustomGateViolationError, surface the individual gate
            # failures (with their specific codes) instead of the synthetic
            # wrapper, so callers can inspect per-gate failure codes.
            if (
                isinstance(exc, CustomGateViolationError)
                and isinstance(exc.details, dict)
                and exc.details.get("custom_gate_failures")
            ):
                # Sanitize each gate failure message for PII/secrets before
                # surfacing — custom gates may inadvertently echo user input.
                sanitized_gate_failures = []
                for gf in exc.details["custom_gate_failures"]:
                    if not isinstance(gf, dict):
                        # Gate returned a non-dict failure entry.  Normalize
                        # it so a malformed gate cannot crash the error path
                        # before the FAIL artifact is attached/emitted.
                        # Apply the same sanitization as dict entries — the
                        # raw value may contain user input or secrets.
                        gf_raw_msg, gf_redacted = sanitize_failure_message(
                            str(gf), redaction_patterns,
                        )
                        for r in gf_redacted:
                            if r not in redacted_fields:
                                redacted_fields.append(r)
                        sanitized_gate_failures.append({
                            "code": "CUSTOM_GATE_MALFORMED_FAILURE",
                            "message": gf_raw_msg,
                            "field": None,
                        })
                        continue
                    gf_msg = str(gf.get("message", ""))
                    sanitized_gf_msg, gf_redacted = sanitize_failure_message(
                        gf_msg, redaction_patterns,
                    )
                    for r in gf_redacted:
                        if r not in redacted_fields:
                            redacted_fields.append(r)
                    sanitized_gate_failures.append({**gf, "message": sanitized_gf_msg})
                failures = sanitized_gate_failures

        if enforcement_mode == "unified":
            fail_metadata: dict[str, Any] = {
                "gates_evaluated": all_gates,
                "redacted_fields": redacted_fields,
                "enforcement_mode": "unified",
            }
        else:
            post_call_timestamp = int(_time.time())
            fail_metadata = {
                "enforcement_mode": "split",
                "pre_call_gates_evaluated": list(phase_a_gates),
                "post_call_gates_evaluated": all_gates,
                "pre_call_timestamp": pre_call_timestamp,
                "post_call_timestamp": post_call_timestamp,
                "redacted_fields": redacted_fields,
            }

        if isinstance(exc, RiskThresholdError) and isinstance(
            getattr(exc, "details", None), dict,
        ):
            fail_metadata["risk_scoring"] = exc.details

        _ctx_prov = (invocation.get("context") or {}).get("provenance")
        _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

        audit_record = build_audit_evidence_body(
            invocation,
            audit_policy,
            enforcement_result="FAIL",
            failures=failures,
            failure_gate=failure_gate,
            failure_reason=failure_reason,
            metadata=fail_metadata,
            provenance=_provenance,
        )

        exc.audit_artifact = audit_record
        try:
            emit_to_sink(audit_record, **_sink_kw)
        except AuditSinkError as sink_exc:
            # Log sink failure but never let it replace the governance
            # exception.  The audit artifact is already attached to exc;
            # evidence must not be lost even when the sink is in
            # "raise" mode.
            logger.error(
                "Sink emission failed on FAIL path "
                "(artifact preserved): %s",
                sink_exc,
            )
        record_enforcement_result(
            span, "FAIL",
            policy_file=invocation.get("policy_file"),
            role=invocation.get("role"),
            enforcement_mode=enforcement_mode,
        )
        logger.error(
            "Enforcement failed at gate '%s': %s",
            failure_gate,
            failure_reason,
        )
        logger.info(
            "Enforcement complete: FAIL [gate=%s, policy=%s, role=%s]",
            failure_gate,
            invocation.get("policy_file"),
            invocation.get("role"),
        )
        raise


def _run_pipeline(
    policy: CompiledPolicy,
    invocation: Mapping[str, Any],
    *,
    sink: Any = None,
    sink_failure_mode: str | None = None,
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    signer: ArtifactSigner | None = None,
    custom_gates: list[EnforcementGate] | None = None,
    risk_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Run the enforcement pipeline against a pre-loaded policy.

    Shared by enforce_invocation (sync) and enforce_invocation_async (async).
    Generates and emits an audit artifact on both PASS and FAIL.

    :param policy: Pre-loaded and strictly compiled policy
    :param invocation: Validated invocation dict
    :param sink: Explicit sink to use (None = use global default via sentinel)
    :param sink_failure_mode: Explicit failure mode (None = use global default)
    :param redaction_patterns: Patterns for failure message sanitization
    :param signer: Optional artifact signer
    :param custom_gates: Optional custom enforcement gates
    :param risk_config: Optional risk scoring configuration override
    :return: PASS audit artifact
    :raises: AIGCError subclasses on governance violation (FAIL audit emitted first)
    """
    _sink_kw: dict[str, Any] = {}
    if sink is not None:
        _sink_kw["sink"] = sink
    if sink_failure_mode is not None:
        _sink_kw["failure_mode"] = sink_failure_mode
    if signer is not None:
        _sink_kw["signer"] = signer

    grouped_gates = sort_gates(custom_gates or [])

    with enforcement_span(
        "aegis.enforce_invocation",
        attributes={
            "aegis.policy_file": invocation.get("policy_file", ""),
            "aegis.role": invocation.get("role", ""),
        },
    ) as span:
        # Phase A may raise AIGCError; we catch it to generate the FAIL
        # artifact (same as the old monolithic try/except).
        # Pass a mutable list so we can read partial progress on failure.
        phase_a_gates: list[str] = []
        try:
            (
                effective_policy,
                guards_evaluated_engine,
                conditions_resolved,
                all_custom_metadata,
                phase_a_gates,
                phase_a_extra,
            ) = _run_phase_a(
                policy, invocation,
                grouped_gates=grouped_gates,
                span=span,
                gates_evaluated=phase_a_gates,
            )
        except AIGCError as exc:
            # Phase A failure in unified mode -- generate FAIL artifact
            # with the gates that were evaluated before the failure.
            failure_gate = _map_exception_to_failure_gate(exc)
            raw_reason = str(exc)
            failure_reason, reason_redacted = sanitize_failure_message(
                raw_reason, redaction_patterns,
            )
            redacted_fields: list[str] = list(reason_redacted)
            failures = None
            if hasattr(exc, "details") and exc.details:
                sanitized_msg, msg_redacted = sanitize_failure_message(
                    str(exc), redaction_patterns,
                )
                for r in msg_redacted:
                    if r not in redacted_fields:
                        redacted_fields.append(r)
                failures = [
                    {
                        "code": exc.__class__.__name__,
                        "message": sanitized_msg,
                        "field": (
                            exc.details.get("field")
                            if isinstance(exc.details, dict)
                            else None
                        ),
                    }
                ]

            fail_metadata: dict[str, Any] = {
                "gates_evaluated": list(phase_a_gates),
                "redacted_fields": redacted_fields,
                "enforcement_mode": "unified",
            }
            if isinstance(exc, RiskThresholdError) and isinstance(
                getattr(exc, "details", None), dict,
            ):
                fail_metadata["risk_scoring"] = exc.details

            _ctx_prov = (invocation.get("context") or {}).get("provenance")
            _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

            audit_record = build_audit_evidence_body(
                invocation,
                _compiled_audit_projection(policy),
                enforcement_result="FAIL",
                failures=failures,
                failure_gate=failure_gate,
                failure_reason=failure_reason,
                metadata=fail_metadata,
                provenance=_provenance,
            )
            exc.audit_artifact = audit_record
            try:
                emit_to_sink(audit_record, **_sink_kw)
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on FAIL path "
                    "(artifact preserved): %s",
                    sink_exc,
                )
            record_enforcement_result(
                span, "FAIL",
                policy_file=invocation.get("policy_file"),
                role=invocation.get("role"),
                enforcement_mode="unified",
            )
            logger.error(
                "Enforcement failed at gate '%s': %s",
                failure_gate,
                failure_reason,
            )
            logger.info(
                "Enforcement complete: FAIL [gate=%s, policy=%s, role=%s]",
                failure_gate,
                invocation.get("policy_file"),
                invocation.get("role"),
            )
            raise

        return _run_phase_b(
            effective_policy,
            policy,
            invocation,
            phase_a_gates=phase_a_gates,
            phase_a_metadata={},
            phase_a_extra=phase_a_extra,
            guards_evaluated_engine=guards_evaluated_engine,
            conditions_resolved=conditions_resolved,
            all_custom_metadata=all_custom_metadata,
            grouped_gates=grouped_gates,
            sink=sink,
            sink_failure_mode=sink_failure_mode,
            redaction_patterns=redaction_patterns,
            signer=signer,
            risk_config=risk_config,
            enforcement_mode="unified",
            span=span,
        )


@_evidence_attempt_boundary("enforce_invocation", "unified")
def enforce_invocation(invocation: Mapping[str, Any]) -> dict[str, Any]:
    """
    Enforce all governance rules for a model invocation (synchronous).

    :param invocation: Dict with:
      - "policy_file": path to policy
      - "input": model input
      - "output": model output (to be validated)
      - "context": additional context
      - "model_provider", "model_identifier", "role": identity fields
    :return: audit artifact (PASS or FAIL)
    :raises: AIGCError subclasses on governance violation (after audit emission)
    """
    if not isinstance(invocation, Mapping):
        _exc = InvocationValidationError(
            "Invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
        _safe = {
            "policy_file": "unknown", "model_provider": "unknown",
            "model_identifier": "unknown", "role": "unknown",
            "input": {}, "output": {}, "context": {},
        }
        _artifact = _generate_pre_pipeline_fail_artifact(_safe, _exc)
        _artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
        _exc.audit_artifact = _artifact
        try:
            emit_to_sink(_artifact)
        except AuditSinkError as _sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s", _sink_exc,
            )
        raise _exc

    try:
        _validate_invocation(invocation)
        policy = _load_compiled_policy(
            invocation,
            loader=None,
        )
    except AIGCError as exc:
        artifact = _generate_pre_pipeline_fail_artifact(invocation, exc)
        # Unified entry point: stamp enforcement_mode so consumers can
        # branch consistently (Round 2 audit Finding 4, spec §11.2).
        artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
        exc.audit_artifact = artifact
        try:
            emit_to_sink(artifact)
        except AuditSinkError as sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s",
                sink_exc,
            )
        raise
    return _run_pipeline(policy, invocation)


@_evidence_attempt_boundary("enforce_invocation_async", "unified")
async def enforce_invocation_async(
    invocation: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Enforce all governance rules for a model invocation (asynchronous).

    Policy file I/O runs in a thread pool via asyncio.to_thread to avoid
    blocking the event loop.  The enforcement pipeline itself is synchronous
    (CPU-bound and fast).

    Produces identical results to enforce_invocation() given the same inputs.

    :param invocation: Same shape as enforce_invocation()
    :return: audit artifact (PASS or FAIL)
    :raises: AIGCError subclasses on governance violation (after audit emission)
    """
    if not isinstance(invocation, Mapping):
        _exc = InvocationValidationError(
            "Invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
        _safe = {
            "policy_file": "unknown", "model_provider": "unknown",
            "model_identifier": "unknown", "role": "unknown",
            "input": {}, "output": {}, "context": {},
        }
        _artifact = _generate_pre_pipeline_fail_artifact(_safe, _exc)
        _artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
        _exc.audit_artifact = _artifact
        try:
            emit_to_sink(_artifact)
        except AuditSinkError as _sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s", _sink_exc,
            )
        raise _exc

    try:
        _validate_invocation(invocation)
        policy = await asyncio.to_thread(
            _load_compiled_policy,
            invocation,
            loader=None,
        )
    except AIGCError as exc:
        artifact = _generate_pre_pipeline_fail_artifact(invocation, exc)
        artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
        exc.audit_artifact = artifact
        try:
            emit_to_sink(artifact)
        except AuditSinkError as sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s",
                sink_exc,
            )
        raise
    return _run_pipeline(policy, invocation)


@_evidence_attempt_boundary("enforce_pre_call", "split_pre_call")
def enforce_pre_call(
    invocation: Mapping[str, Any],
    *,
    custom_gates: list[EnforcementGate] | None = None,
) -> PreCallResult:
    """Enforce pre-call governance checks (Phase A).

    Accepts an invocation dict WITHOUT 'output'. Runs all pre-call gates:
    custom pre_authorization gates, guard evaluation, role validation,
    precondition validation, tool constraint validation, post_authorization
    gates.

    :param invocation: Dict with policy_file, model_provider,
                       model_identifier, role, input, context
                       (no output required)
    :param custom_gates: Optional custom enforcement gates
    :return: PreCallResult token for use with enforce_post_call()
    :raises: AIGCError subclasses on governance violation
             (FAIL artifact emitted)
    """
    if not isinstance(invocation, Mapping):
        _exc = InvocationValidationError(
            "Invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
        _safe = {
            "policy_file": "unknown", "model_provider": "unknown",
            "model_identifier": "unknown", "role": "unknown",
            "input": {}, "output": {}, "context": {},
        }
        _artifact = _generate_pre_pipeline_fail_artifact(_safe, _exc)
        _artifact.setdefault("metadata", {})["enforcement_mode"] = (
            "split_pre_call_only"
        )
        _exc.audit_artifact = _artifact
        try:
            emit_to_sink(_artifact)
        except AuditSinkError as _sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s", _sink_exc,
            )
        raise _exc

    try:
        _validate_pre_call_invocation(invocation)
        policy = _load_compiled_policy(
            invocation,
            loader=None,
        )
    except AIGCError as exc:
        # Generate pre-pipeline fail artifact for split mode.
        # output is {} (no output in pre-call).
        safe_inv = dict(invocation)
        safe_inv.setdefault("output", {})
        artifact = _generate_pre_pipeline_fail_artifact(safe_inv, exc)
        artifact.setdefault("metadata", {})["enforcement_mode"] = (
            "split_pre_call_only"
        )
        exc.audit_artifact = artifact
        try:
            emit_to_sink(artifact)
        except AuditSinkError as sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s",
                sink_exc,
            )
        raise

    grouped_gates = sort_gates(custom_gates or [])
    pre_call_timestamp = int(_time.time())
    with enforcement_span(
        "aegis.enforce_pre_call",
        attributes={
            "aegis.policy_file": invocation.get("policy_file", ""),
            "aegis.role": invocation.get("role", ""),
            "aegis.enforcement_mode": "split",
        },
    ) as span:
        phase_a_gates: list[str] = []
        try:
            (
                effective_policy,
                guards_evaluated_engine,
                conditions_resolved,
                all_custom_metadata,
                phase_a_gates,
                phase_a_extra,
            ) = _run_phase_a(
                policy, invocation,
                grouped_gates=grouped_gates,
                span=span,
                gates_evaluated=phase_a_gates,
            )
        except AIGCError as exc:
            # Mid-pipeline Phase A FAIL: generate artifact with output={}
            audit_record = _build_phase_a_mid_pipeline_fail_artifact(
                invocation, policy, exc, phase_a_gates,
            )
            exc.audit_artifact = audit_record
            try:
                emit_to_sink(audit_record)
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on FAIL path "
                    "(artifact preserved): %s",
                    sink_exc,
                )
            failure_gate = _map_exception_to_failure_gate(exc)
            failure_reason = sanitize_failure_message(str(exc), None)[0]
            record_enforcement_result(
                span, "FAIL",
                policy_file=invocation.get("policy_file"),
                role=invocation.get("role"),
                enforcement_mode="split",
            )
            logger.error(
                "Enforcement failed at gate '%s': %s",
                failure_gate,
                failure_reason,
            )
            raise

        # Build invocation snapshot (exactly 6 required fields, no output).
        # Deep-copy mutable nested fields so callers cannot tamper with
        # the stored snapshot between Phase A and Phase B (Finding 3).
        invocation_snapshot = {
            "policy_file": invocation["policy_file"],
            "model_provider": invocation["model_provider"],
            "model_identifier": invocation["model_identifier"],
            "role": invocation["role"],
            "input": copy.deepcopy(invocation["input"]),
            "context": copy.deepcopy(invocation["context"]),
        }

        phase_a_metadata = {
            "gates_evaluated": list(phase_a_gates),
            "pre_call_timestamp": pre_call_timestamp,
            **phase_a_extra,
            "all_custom_metadata": all_custom_metadata,
        }

        record_enforcement_result(
            span, "PASS_PHASE_A",
            policy_file=invocation.get("policy_file"),
            role=invocation.get("role"),
            enforcement_mode="split",
        )

        return _issue_pre_call_result(
            _MODULE_OPERATION_REGISTRY,
            compiled_policy=effective_policy,
            invocation_snapshot=invocation_snapshot,
            phase_a_metadata=phase_a_metadata,
            guards_evaluated_engine=guards_evaluated_engine,
            conditions_resolved=conditions_resolved,
            grouped_gates=grouped_gates,
        )


@_evidence_attempt_boundary("enforce_post_call", "split_post_call")
def enforce_post_call(
    pre_call_result: PreCallResult,
    output: dict[str, Any],
) -> dict[str, Any]:
    """Enforce post-call governance checks (Phase B).

    Consumes a PreCallResult from enforce_pre_call() plus the model output.
    One-time use: raises InvocationValidationError on reuse.

    :param pre_call_result: Token from enforce_pre_call()
    :param output: Model output dict
    :return: PASS audit artifact
    :raises: InvocationValidationError on invalid/reused pre_call_result
             or output
    :raises: AIGCError subclasses on governance violation
             (FAIL artifact emitted)
    """
    return _run_registry_post_call(
        _MODULE_OPERATION_REGISTRY,
        pre_call_result,
        output,
    )


@_evidence_attempt_boundary("enforce_pre_call_async", "split_pre_call")
async def enforce_pre_call_async(
    invocation: Mapping[str, Any],
    *,
    custom_gates: list[EnforcementGate] | None = None,
) -> PreCallResult:
    """Async equivalent of enforce_pre_call().

    Policy file I/O runs in a thread pool via asyncio.to_thread.
    """
    if not isinstance(invocation, Mapping):
        _exc = InvocationValidationError(
            "Invocation must be a mapping object",
            details={"received_type": type(invocation).__name__},
        )
        _safe = {
            "policy_file": "unknown", "model_provider": "unknown",
            "model_identifier": "unknown", "role": "unknown",
            "input": {}, "output": {}, "context": {},
        }
        _artifact = _generate_pre_pipeline_fail_artifact(_safe, _exc)
        _artifact.setdefault("metadata", {})["enforcement_mode"] = (
            "split_pre_call_only"
        )
        _exc.audit_artifact = _artifact
        try:
            emit_to_sink(_artifact)
        except AuditSinkError as _sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s", _sink_exc,
            )
        raise _exc

    try:
        _validate_pre_call_invocation(invocation)
        policy = await asyncio.to_thread(
            _load_compiled_policy,
            invocation,
            loader=None,
        )
    except AIGCError as exc:
        safe_inv = dict(invocation)
        safe_inv.setdefault("output", {})
        artifact = _generate_pre_pipeline_fail_artifact(safe_inv, exc)
        artifact.setdefault("metadata", {})["enforcement_mode"] = (
            "split_pre_call_only"
        )
        exc.audit_artifact = artifact
        try:
            emit_to_sink(artifact)
        except AuditSinkError as sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s",
                sink_exc,
            )
        raise

    # The enforcement pipeline itself is synchronous (CPU-bound).
    # We loaded the policy async above; now run the rest synchronously.
    grouped_gates = sort_gates(custom_gates or [])
    pre_call_timestamp = int(_time.time())
    with enforcement_span(
        "aegis.enforce_pre_call",
        attributes={
            "aegis.policy_file": invocation.get("policy_file", ""),
            "aegis.role": invocation.get("role", ""),
            "aegis.enforcement_mode": "split",
        },
    ) as span:
        phase_a_gates: list[str] = []
        try:
            (
                effective_policy,
                guards_evaluated_engine,
                conditions_resolved,
                all_custom_metadata,
                phase_a_gates,
                phase_a_extra,
            ) = _run_phase_a(
                policy, invocation,
                grouped_gates=grouped_gates,
                span=span,
                gates_evaluated=phase_a_gates,
            )
        except AIGCError as exc:
            # Mid-pipeline Phase A FAIL: generate artifact with output={}
            audit_record = _build_phase_a_mid_pipeline_fail_artifact(
                invocation, policy, exc, phase_a_gates,
            )
            exc.audit_artifact = audit_record
            try:
                emit_to_sink(audit_record)
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on FAIL path "
                    "(artifact preserved): %s",
                    sink_exc,
                )
            failure_gate = _map_exception_to_failure_gate(exc)
            failure_reason = sanitize_failure_message(str(exc), None)[0]
            record_enforcement_result(
                span, "FAIL",
                policy_file=invocation.get("policy_file"),
                role=invocation.get("role"),
                enforcement_mode="split",
            )
            logger.error(
                "Enforcement failed at gate '%s': %s",
                failure_gate,
                failure_reason,
            )
            raise

        invocation_snapshot = {
            "policy_file": invocation["policy_file"],
            "model_provider": invocation["model_provider"],
            "model_identifier": invocation["model_identifier"],
            "role": invocation["role"],
            "input": copy.deepcopy(invocation["input"]),
            "context": copy.deepcopy(invocation["context"]),
        }

        phase_a_metadata = {
            "gates_evaluated": list(phase_a_gates),
            "pre_call_timestamp": pre_call_timestamp,
            **phase_a_extra,
            "all_custom_metadata": all_custom_metadata,
        }

        record_enforcement_result(
            span, "PASS_PHASE_A",
            policy_file=invocation.get("policy_file"),
            role=invocation.get("role"),
            enforcement_mode="split",
        )

        return _issue_pre_call_result(
            _MODULE_OPERATION_REGISTRY,
            compiled_policy=effective_policy,
            invocation_snapshot=invocation_snapshot,
            phase_a_metadata=phase_a_metadata,
            guards_evaluated_engine=guards_evaluated_engine,
            conditions_resolved=conditions_resolved,
            grouped_gates=grouped_gates,
        )


@_evidence_attempt_boundary("enforce_post_call_async", "split_post_call")
async def enforce_post_call_async(
    pre_call_result: PreCallResult,
    output: dict[str, Any],
) -> dict[str, Any]:
    """Async equivalent of enforce_post_call().

    enforce_post_call() is synchronous (CPU-bound); just call it directly.
    """
    return enforce_post_call.__wrapped__(pre_call_result, output)


def _validate_policy_strict(
    policy: CompiledPolicy,
    strict_mode: bool,
) -> None:
    """Validate policy strictness.

    In strict mode, raises PolicyValidationError for weak policies.
    In non-strict mode, emits UserWarning for weak policies.
    """
    issues: list[str] = []

    if not policy.roles:
        issues.append("Policy must define non-empty 'roles' list")

    if not policy.preconditions:
        issues.append("Policy must define 'pre_conditions.required'")

    if strict_mode:
        if issues:
            raise PolicyValidationError(
                "Strict mode policy validation failed",
                details={"issues": issues},
            )
    else:
        for issue in issues:
            warnings.warn(issue, UserWarning, stacklevel=3)


def _generate_pre_pipeline_fail_artifact(
    invocation: Mapping[str, Any],
    exc: AIGCError,
    *,
    redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> dict[str, Any]:
    """Generate a schema-valid FAIL artifact for failures before _run_pipeline.

    This covers invocation validation, policy loading, and strict-mode
    validation failures that occur before the enforcement pipeline starts
    (Invariant D — every enforcement attempt must produce an artifact).
    """
    failure_gate = _map_exception_to_failure_gate(exc)
    failure_reason, reason_redacted = sanitize_failure_message(
        str(exc), redaction_patterns
    )

    # Build a minimal but valid invocation-like dict for artifact generation.
    # Pre-pipeline failures may not have a loaded policy, and field values
    # may be invalid types (the validation error may be about that), so we
    # defensively coerce to expected types.
    def _safe_str(v: Any, default: str = "unknown") -> str:
        return v if isinstance(v, str) and v else default

    def _safe_dict(v: Any) -> dict:
        if not isinstance(v, dict):
            return {}
        try:
            json.dumps(v, allow_nan=False, sort_keys=True)
            return v
        except (TypeError, ValueError):
            return {}

    # Extract provenance from the raw context BEFORE _safe_dict() may collapse
    # it.  If context contains any non-JSON-serializable entry alongside a valid
    # provenance mapping, _safe_dict() would drop the whole context to {}, losing
    # provenance.  Reading from the raw invocation here preserves it.
    _raw_ctx = invocation.get("context")
    _ctx_prov = (
        _raw_ctx.get("provenance") if isinstance(_raw_ctx, Mapping) else None
    )
    _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

    safe_invocation = {
        "policy_file": _safe_str(invocation.get("policy_file")),
        "model_provider": _safe_str(invocation.get("model_provider")),
        "model_identifier": _safe_str(invocation.get("model_identifier")),
        "role": _safe_str(invocation.get("role")),
        "input": _safe_dict(invocation.get("input")),
        "output": _safe_dict(invocation.get("output")),
        "context": _safe_dict(invocation.get("context")),
    }

    failures = [
        {
            "code": exc.__class__.__name__,
            "message": failure_reason,
            "field": (
                exc.details.get("field")
                if isinstance(getattr(exc, "details", None), dict)
                else None
            ),
        }
    ]

    return build_audit_evidence_body(
        safe_invocation,
        {},  # no policy loaded yet
        enforcement_result="FAIL",
        failures=failures,
        failure_gate=failure_gate,
        failure_reason=failure_reason,
        metadata={
            "gates_evaluated": [],
            "redacted_fields": list(reason_redacted),
            "pre_pipeline_failure": True,
        },
        provenance=_provenance,
    )


@_evidence_attempt_boundary("governed.wrapped_function", "split_function")
def emit_split_fn_failure_artifact(
    pre_call_result: "PreCallResult",
    exc: Exception,
) -> dict[str, Any]:
    """Generate and emit a FAIL artifact when the wrapped function raises
    after Phase A PASS in split decorator mode.

    The artifact captures the Phase A invocation context (no output) and
    records the wrapped function failure for observability. The exception
    is NOT modified; callers should re-raise it unchanged.

    :param pre_call_result: Token from enforce_pre_call() (Phase A PASS)
    :param exc: Exception raised by the wrapped function
    :return: Emitted FAIL audit artifact
    """
    if not isinstance(pre_call_result, PreCallResult):
        raise InvocationValidationError(
            "emit_split_fn_failure_artifact() requires a PreCallResult",
            details={"received_type": type(pre_call_result).__name__},
        )
    record = _MODULE_OPERATION_REGISTRY.consume(
        _operation_handle(pre_call_result)
    )
    inv_snap = _plain_compiled_value(record.invocation_snapshot)
    inv_snap.setdefault("output", {})
    policy = _compiled_audit_projection(record.compiled_policy)
    phase_a_metadata = _plain_compiled_value(record.phase_a_metadata)

    failure_reason, _ = sanitize_failure_message(
        f"{type(exc).__name__}: {exc}", None,
    )
    failures = [
        {
            "code": type(exc).__name__,
            "message": failure_reason,
            "field": None,
        }
    ]

    _ctx_prov = (inv_snap.get("context") or {}).get("provenance")
    _provenance = _ctx_prov if isinstance(_ctx_prov, Mapping) else None

    artifact = build_audit_evidence_body(
        inv_snap,
        policy,
        enforcement_result="FAIL",
        failures=failures,
        failure_gate="wrapped_function_error",
        failure_reason=failure_reason,
        metadata={
            "enforcement_mode": "split",
            "pre_call_gates_evaluated": phase_a_metadata.get(
                "gates_evaluated", []
            ),
        },
        provenance=_provenance,
    )

    try:
        emit_to_sink(artifact)
    except AuditSinkError as sink_exc:
        logger.error(
            "Sink emission failed on wrapped-function FAIL path: %s",
            sink_exc,
        )

    return artifact


class AEGIS:
    """Instance-scoped AEGIS configuration and enforcement entry point.

    All configuration (sink, enforcement mode, redaction patterns) is
    immutable after construction. Thread-safe: enforce() may be called
    from multiple threads concurrently without touching global state.

    Usage::

        from aegis import AEGIS, JsonFileAuditSink

        aegis = AEGIS(sink=JsonFileAuditSink("audit.jsonl"))
        artifact = aegis.enforce(invocation)
    """

    def __init__(
        self,
        *,
        sink: Any | None = None,
        on_sink_failure: str = "raise",
        strict_mode: bool = False,
        redaction_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
        signer: ArtifactSigner | None = None,
        chain_linker: ChainLinker | None = None,
        custom_gates: list[EnforcementGate] | None = None,
        policy_loader: PolicyLoaderBase | None = None,
        risk_config: dict[str, Any] | None = None,
    ) -> None:
        """
        :param sink: AuditSink instance for artifact persistence
        :param on_sink_failure: V2 failure mode; only "raise" is accepted
        :param strict_mode: Enable strict governance validation
        :param redaction_patterns: Custom redaction patterns
        :param signer: Artifact signer for signing audit artifacts
        :param chain_linker: Host-owned invocation chain placement provider
        :param custom_gates: Custom enforcement gates
        :param policy_loader: Custom policy loader implementation
        :param risk_config: Risk scoring configuration override
        """
        if on_sink_failure != "raise":
            raise ValueError(
                "AEGIS v2 only supports 'raise' for on_sink_failure"
            )
        if sink is None:
            raise EvidenceConfigurationError()
        if not isinstance(sink, AuditSink):
            raise TypeError("sink must be an AuditSink")
        self._sink = sink
        self._on_sink_failure = on_sink_failure
        self._strict_mode = strict_mode
        self._redaction_patterns = (
            redaction_patterns
            if redaction_patterns is not None
            else DEFAULT_REDACTION_PATTERNS
        )
        self._signer = signer
        self._chain_linker = _validate_chain_linker(chain_linker)
        self._custom_gates = list(custom_gates or [])
        self._policy_loader = policy_loader
        self._risk_config = risk_config
        self._policy_cache = PolicyCache()
        self._operation_registry = OperationRegistry()
        self._attempt_factory = AttemptFactory()
        self._evidence_diagnostics = EvidenceDiagnostics()
        self._validator_hooks: list[Any] = []

        # Validate custom gates at construction time
        for gate in self._custom_gates:
            validate_gate(gate)

    def _set_validator_hooks(self, hooks: Sequence[Any] | None) -> None:
        """Internal-only wiring point for session validator hooks."""
        self._validator_hooks = list(hooks or [])

    @property
    def sink(self) -> Any | None:
        return self._sink

    @property
    def strict_mode(self) -> bool:
        return self._strict_mode

    @property
    def on_sink_failure(self) -> str:
        return self._on_sink_failure

    @property
    def signer(self) -> ArtifactSigner | None:
        return self._signer

    @property
    def policy_cache(self) -> PolicyCache:
        """Per-instance policy cache."""
        return self._policy_cache

    def evidence_diagnostics(self):
        """Return an immutable snapshot of evidence-loss counters."""
        return self._evidence_diagnostics.snapshot()

    def open_session(
        self,
        *,
        session_id: str | None = None,
        policy_file: str | None = None,
        metadata: dict | None = None,
    ) -> "GovernanceSession":
        """Open a governed workflow session (instance-scoped).

        :param session_id: Caller-supplied identifier; UUID4 generated if omitted
        :param policy_file: Session-level policy override; if set, all steps use
            this policy regardless of per-invocation policy_file
        :param metadata: Host metadata attached to the workflow artifact
        :return: GovernanceSession context manager
        """
        import uuid as _uuid
        from aegis._internal.session import GovernanceSession
        sid = str(_uuid.uuid4()) if session_id is None else session_id
        return GovernanceSession(self, sid, policy_file, metadata)

    @_evidence_attempt_boundary("AEGIS.enforce", "unified")
    def enforce(self, invocation: Mapping[str, Any]) -> dict[str, Any]:
        """Enforce governance rules (synchronous).

        Uses instance-owned sink, failure mode, and policy cache — no global
        state is mutated (Invariant B — per-instance isolation).

        :param invocation: Invocation dict with required fields
        :return: Audit artifact dict
        :raises: AIGCError subclasses on governance violation
        """
        if not isinstance(invocation, Mapping):
            _exc = InvocationValidationError(
                "Invocation must be a mapping object",
                details={"received_type": type(invocation).__name__},
            )
            _safe = {
                "policy_file": "unknown", "model_provider": "unknown",
                "model_identifier": "unknown", "role": "unknown",
                "input": {}, "output": {}, "context": {},
            }
            _artifact = _generate_pre_pipeline_fail_artifact(
                _safe, _exc,
                redaction_patterns=self._redaction_patterns,
            )
            _artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
            _exc.audit_artifact = _artifact
            try:
                emit_to_sink(
                    _artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as _sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    _sink_exc,
                )
            raise _exc

        try:
            _validate_invocation(invocation)
            policy = _compile_cached_policy(
                invocation,
                cache=self._policy_cache,
                loader=self._policy_loader,
            )
            _validate_policy_strict(policy, self._strict_mode)
        except AIGCError as exc:
            artifact = _generate_pre_pipeline_fail_artifact(
                invocation, exc,
                redaction_patterns=self._redaction_patterns,
            )
            artifact.setdefault("metadata", {})["enforcement_mode"] = (
                "unified"
            )
            exc.audit_artifact = artifact
            try:
                emit_to_sink(
                    artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    sink_exc,
                )
            raise

        return _run_pipeline(
            policy,
            invocation,
            sink=self._sink,
            sink_failure_mode=self._on_sink_failure,
            redaction_patterns=self._redaction_patterns,
            signer=self._signer,
            custom_gates=self._custom_gates,
            risk_config=self._risk_config,
        )

    @_evidence_attempt_boundary("AEGIS.enforce_pre_call", "split_pre_call")
    def enforce_pre_call(
        self, invocation: Mapping[str, Any],
    ) -> PreCallResult:
        """Enforce pre-call governance checks (Phase A), instance-scoped.

        Uses instance-owned policy cache and configuration.
        Returns a PreCallResult for use with enforce_post_call().

        :param invocation: Dict with policy_file, model_provider,
                           model_identifier, role, input, context
        :return: PreCallResult token
        :raises: AIGCError subclasses on governance violation
        """
        policy = self._prepare_pre_call_policy(invocation, policy=None)
        return self._run_pre_call_compiled(invocation, policy)

    def _raise_pre_call_boundary_failure(
        self,
        invocation: object,
        exc: AIGCError,
    ) -> NoReturn:
        """Attach and emit the canonical split-boundary failure artifact."""
        if isinstance(invocation, Mapping):
            safe_inv = dict(invocation)
            safe_inv.setdefault("output", {})
        else:
            safe_inv = {
                "policy_file": "unknown",
                "model_provider": "unknown",
                "model_identifier": "unknown",
                "role": "unknown",
                "input": {},
                "output": {},
                "context": {},
            }
        artifact = _generate_pre_pipeline_fail_artifact(
            safe_inv,
            exc,
            redaction_patterns=self._redaction_patterns,
        )
        artifact.setdefault("metadata", {})["enforcement_mode"] = (
            "split_pre_call_only"
        )
        exc.audit_artifact = artifact
        try:
            emit_to_sink(
                artifact,
                sink=self._sink,
                failure_mode=self._on_sink_failure,
            )
        except AuditSinkError as sink_exc:
            logger.error(
                "Sink emission failed on pre-pipeline FAIL path: %s",
                sink_exc,
            )
        raise exc

    def _prepare_pre_call_policy(
        self,
        invocation: Mapping[str, Any],
        *,
        policy: CompiledPolicy | None,
    ) -> CompiledPolicy:
        """Apply split-boundary invariants once and return exact authority."""
        try:
            _validate_pre_call_invocation(invocation)
            prepared_policy = policy
            if prepared_policy is None:
                prepared_policy = _compile_cached_policy(
                    invocation,
                    cache=self._policy_cache,
                    loader=self._policy_loader,
                )
            _validate_policy_strict(prepared_policy, self._strict_mode)
            return prepared_policy
        except AIGCError as exc:
            self._raise_pre_call_boundary_failure(invocation, exc)

    def _enforce_pre_call_compiled(
        self,
        invocation: Mapping[str, Any],
        policy: CompiledPolicy,
    ) -> PreCallResult:
        """Run Phase A from an already-authorized compiled policy object."""
        prepared_policy = self._prepare_pre_call_policy(
            invocation,
            policy=policy,
        )
        return self._run_pre_call_compiled(invocation, prepared_policy)

    def _run_pre_call_compiled(
        self,
        invocation: Mapping[str, Any],
        policy: CompiledPolicy,
    ) -> PreCallResult:
        """Run Phase A after the shared split-boundary validation."""
        grouped_gates = sort_gates(self._custom_gates)
        pre_call_timestamp = int(_time.time())
        with enforcement_span(
            "aegis.enforce_pre_call",
            attributes={
                "aegis.policy_file": invocation.get("policy_file", ""),
                "aegis.role": invocation.get("role", ""),
                "aegis.enforcement_mode": "split",
            },
        ) as span:
            phase_a_gates: list[str] = []
            try:
                (
                    effective_policy,
                    guards_evaluated_engine,
                    conditions_resolved,
                    all_custom_metadata,
                    phase_a_gates,
                    phase_a_extra,
                ) = _run_phase_a(
                    policy, invocation,
                    grouped_gates=grouped_gates,
                    span=span,
                    gates_evaluated=phase_a_gates,
                )
            except AIGCError as exc:
                safe_inv = dict(invocation)
                safe_inv["output"] = {}
                audit_record = _build_phase_a_mid_pipeline_fail_artifact(
                    safe_inv, policy, exc, phase_a_gates,
                    self._redaction_patterns,
                )
                exc.audit_artifact = audit_record
                try:
                    emit_to_sink(
                        audit_record,
                        sink=self._sink,
                        failure_mode=self._on_sink_failure,
                    )
                except AuditSinkError as sink_exc:
                    logger.error(
                        "Sink emission failed on FAIL path "
                        "(artifact preserved): %s",
                        sink_exc,
                    )
                record_enforcement_result(
                    span, "FAIL",
                    policy_file=invocation.get("policy_file"),
                    role=invocation.get("role"),
                    enforcement_mode="split",
                )
                logger.error(
                    "Enforcement failed during Phase A: %s", exc,
                )
                raise

            invocation_snapshot = {
                "policy_file": invocation["policy_file"],
                "model_provider": invocation["model_provider"],
                "model_identifier": invocation["model_identifier"],
                "role": invocation["role"],
                "input": copy.deepcopy(invocation["input"]),
                "context": copy.deepcopy(invocation["context"]),
            }

            phase_a_metadata = {
                "gates_evaluated": list(phase_a_gates),
                "pre_call_timestamp": pre_call_timestamp,
                **phase_a_extra,
                "all_custom_metadata": all_custom_metadata,
            }

            record_enforcement_result(
                span, "PASS_PHASE_A",
                policy_file=invocation.get("policy_file"),
                role=invocation.get("role"),
                enforcement_mode="split",
            )

            return _issue_pre_call_result(
                self._operation_registry,
                compiled_policy=effective_policy,
                invocation_snapshot=invocation_snapshot,
                phase_a_metadata=phase_a_metadata,
                guards_evaluated_engine=guards_evaluated_engine,
                conditions_resolved=conditions_resolved,
                grouped_gates=grouped_gates,
            )

    @_evidence_attempt_boundary("AEGIS.enforce_post_call", "split_post_call")
    def enforce_post_call(
        self,
        pre_call_result: PreCallResult,
        output: dict[str, Any],
    ) -> dict[str, Any]:
        """Enforce post-call governance checks (Phase B), instance-scoped.

        Consumes a PreCallResult from enforce_pre_call(). One-time use.

        :param pre_call_result: Token from enforce_pre_call()
        :param output: Model output dict
        :return: PASS audit artifact
        :raises: AIGCError subclasses on governance violation
        """
        return _run_registry_post_call(
            self._operation_registry,
            pre_call_result,
            output,
            sink=self._sink,
            sink_failure_mode=self._on_sink_failure,
            redaction_patterns=self._redaction_patterns,
            signer=self._signer,
            risk_config=self._risk_config,
        )

    @_evidence_attempt_boundary(
        "AEGIS.enforce_post_call",
        "split_post_call",
        inherit_outer_attempt=True,
    )
    def _enforce_consumed_post_call(
        self,
        record: OperationRecord,
        output: object,
    ) -> dict[str, Any]:
        """Run session Phase B for an operation already consumed atomically."""
        return _run_consumed_post_call(
            record,
            output,
            sink=self._sink,
            sink_failure_mode=self._on_sink_failure,
            redaction_patterns=self._redaction_patterns,
            signer=self._signer,
            risk_config=self._risk_config,
        )

    @_evidence_attempt_boundary(
        "AEGIS.enforce_post_call",
        "split_post_call",
        inherit_outer_attempt=True,
    )
    def _reject_consumed_post_call(
        self,
        exc: InvocationValidationError,
        record: OperationRecord | None = None,
    ) -> NoReturn:
        """Finalize one session Phase B rejection through instance evidence."""
        _emit_split_validation_failure(
            exc,
            record=record,
            sink=self._sink,
            sink_failure_mode=self._on_sink_failure,
            redaction_patterns=self._redaction_patterns,
        )
        raise exc

    @_evidence_attempt_boundary("AEGIS.enforce_pre_call_async", "split_pre_call")
    async def enforce_pre_call_async(
        self, invocation: Mapping[str, Any],
    ) -> PreCallResult:
        """Async equivalent of enforce_pre_call(), instance-scoped.

        Policy file I/O runs in a thread pool via asyncio.to_thread.
        The enforcement pipeline itself is synchronous (CPU-bound).
        """
        if not isinstance(invocation, Mapping):
            _exc = InvocationValidationError(
                "Invocation must be a mapping object",
                details={"received_type": type(invocation).__name__},
            )
            _safe = {
                "policy_file": "unknown", "model_provider": "unknown",
                "model_identifier": "unknown", "role": "unknown",
                "input": {}, "output": {}, "context": {},
            }
            _artifact = _generate_pre_pipeline_fail_artifact(
                _safe, _exc,
                redaction_patterns=self._redaction_patterns,
            )
            _artifact.setdefault("metadata", {})["enforcement_mode"] = (
                "split_pre_call_only"
            )
            _exc.audit_artifact = _artifact
            try:
                emit_to_sink(
                    _artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as _sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    _sink_exc,
                )
            raise _exc

        try:
            _validate_pre_call_invocation(invocation)
            policy = await asyncio.to_thread(
                _compile_cached_policy,
                invocation,
                cache=self._policy_cache,
                loader=self._policy_loader,
            )
            _validate_policy_strict(policy, self._strict_mode)
        except AIGCError as exc:
            safe_inv = dict(invocation)
            safe_inv.setdefault("output", {})
            artifact = _generate_pre_pipeline_fail_artifact(
                safe_inv, exc,
                redaction_patterns=self._redaction_patterns,
            )
            artifact.setdefault("metadata", {})["enforcement_mode"] = (
                "split_pre_call_only"
            )
            exc.audit_artifact = artifact
            try:
                emit_to_sink(
                    artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    sink_exc,
                )
            raise

        grouped_gates = sort_gates(self._custom_gates)
        pre_call_timestamp = int(_time.time())
        with enforcement_span(
            "aegis.enforce_pre_call",
            attributes={
                "aegis.policy_file": invocation.get("policy_file", ""),
                "aegis.role": invocation.get("role", ""),
                "aegis.enforcement_mode": "split",
            },
        ) as span:
            phase_a_gates: list[str] = []
            try:
                (
                    effective_policy,
                    guards_evaluated_engine,
                    conditions_resolved,
                    all_custom_metadata,
                    phase_a_gates,
                    phase_a_extra,
                ) = _run_phase_a(
                    policy, invocation,
                    grouped_gates=grouped_gates,
                    span=span,
                    gates_evaluated=phase_a_gates,
                )
            except AIGCError as exc:
                safe_inv = dict(invocation)
                safe_inv["output"] = {}
                audit_record = _build_phase_a_mid_pipeline_fail_artifact(
                    safe_inv, policy, exc, phase_a_gates,
                    self._redaction_patterns,
                )
                exc.audit_artifact = audit_record
                try:
                    emit_to_sink(
                        audit_record,
                        sink=self._sink,
                        failure_mode=self._on_sink_failure,
                    )
                except AuditSinkError as sink_exc:
                    logger.error(
                        "Sink emission failed on FAIL path "
                        "(artifact preserved): %s",
                        sink_exc,
                    )
                record_enforcement_result(
                    span, "FAIL",
                    policy_file=invocation.get("policy_file"),
                    role=invocation.get("role"),
                    enforcement_mode="split",
                )
                logger.error(
                    "Enforcement failed during Phase A: %s", exc,
                )
                raise

            invocation_snapshot = {
                "policy_file": invocation["policy_file"],
                "model_provider": invocation["model_provider"],
                "model_identifier": invocation["model_identifier"],
                "role": invocation["role"],
                "input": copy.deepcopy(invocation["input"]),
                "context": copy.deepcopy(invocation["context"]),
            }

            phase_a_metadata = {
                "gates_evaluated": list(phase_a_gates),
                "pre_call_timestamp": pre_call_timestamp,
                **phase_a_extra,
                "all_custom_metadata": all_custom_metadata,
            }

            record_enforcement_result(
                span, "PASS_PHASE_A",
                policy_file=invocation.get("policy_file"),
                role=invocation.get("role"),
                enforcement_mode="split",
            )

            return _issue_pre_call_result(
                self._operation_registry,
                compiled_policy=effective_policy,
                invocation_snapshot=invocation_snapshot,
                phase_a_metadata=phase_a_metadata,
                guards_evaluated_engine=guards_evaluated_engine,
                conditions_resolved=conditions_resolved,
                grouped_gates=grouped_gates,
            )

    @_evidence_attempt_boundary("AEGIS.enforce_post_call_async", "split_post_call")
    async def enforce_post_call_async(
        self,
        pre_call_result: PreCallResult,
        output: dict[str, Any],
    ) -> dict[str, Any]:
        """Async equivalent of enforce_post_call(), instance-scoped.

        enforce_post_call() is synchronous (CPU-bound); just delegate.
        """
        return AEGIS.enforce_post_call.__wrapped__(self, pre_call_result, output)

    @_evidence_attempt_boundary("AEGIS.enforce_async", "unified")
    async def enforce_async(
        self, invocation: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Enforce governance rules (asynchronous).

        Uses instance-owned sink, failure mode, and policy cache — no global
        state is mutated (Invariant B — per-instance isolation).

        :param invocation: Invocation dict with required fields
        :return: Audit artifact dict
        :raises: AIGCError subclasses on governance violation
        """
        if not isinstance(invocation, Mapping):
            _exc = InvocationValidationError(
                "Invocation must be a mapping object",
                details={"received_type": type(invocation).__name__},
            )
            _safe = {
                "policy_file": "unknown", "model_provider": "unknown",
                "model_identifier": "unknown", "role": "unknown",
                "input": {}, "output": {}, "context": {},
            }
            _artifact = _generate_pre_pipeline_fail_artifact(
                _safe, _exc,
                redaction_patterns=self._redaction_patterns,
            )
            _artifact.setdefault("metadata", {})["enforcement_mode"] = "unified"
            _exc.audit_artifact = _artifact
            try:
                emit_to_sink(
                    _artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as _sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    _sink_exc,
                )
            raise _exc

        try:
            _validate_invocation(invocation)
            policy = await asyncio.to_thread(
                _compile_cached_policy,
                invocation,
                cache=self._policy_cache,
                loader=self._policy_loader,
            )
            _validate_policy_strict(policy, self._strict_mode)
        except AIGCError as exc:
            artifact = _generate_pre_pipeline_fail_artifact(
                invocation, exc,
                redaction_patterns=self._redaction_patterns,
            )
            artifact.setdefault("metadata", {})["enforcement_mode"] = (
                "unified"
            )
            exc.audit_artifact = artifact
            try:
                emit_to_sink(
                    artifact,
                    sink=self._sink,
                    failure_mode=self._on_sink_failure,
                )
            except AuditSinkError as sink_exc:
                logger.error(
                    "Sink emission failed on pre-pipeline FAIL path: %s",
                    sink_exc,
                )
            raise

        return _run_pipeline(
            policy,
            invocation,
            sink=self._sink,
            sink_failure_mode=self._on_sink_failure,
            redaction_patterns=self._redaction_patterns,
            signer=self._signer,
            custom_gates=self._custom_gates,
            risk_config=self._risk_config,
        )


# Backward-compatibility alias for the pre-rebrand public class name.
AIGC = AEGIS
