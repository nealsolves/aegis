"""
GovernanceSession and SessionPreCallResult — v0.9.0 workflow primitives.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import unicodedata
import uuid
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import wraps
from typing import TYPE_CHECKING, Any, NoReturn

from aegis._internal.errors import (
    AIGCError,
    AuditSinkError,
    EvidenceFinalizationError,
    InvocationValidationError,
    SessionStateError,
)
from aegis._internal.audit import checksum as _audit_checksum
from aegis._internal.canonicalization import (
    CanonicalizationError,
    normalize_json_v2,
)
from aegis._internal.evidence_finalizer import (
    _EvidenceAbort,
    _frozen_mapping,
    _plain_json,
    evidence_attempt,
    finalize_legacy_invocation_artifact,
    finalize_legacy_workflow_artifact,
)
from aegis._internal.outcomes import TerminalClass
from aegis._internal.tools import validate_tool_constraints
from aegis._internal.workflow_limits import MAX_WORKFLOW_ATTEMPTS

if TYPE_CHECKING:
    from aegis._internal.compiled_policy import CompiledPolicy
    from aegis._internal.enforcement import AEGIS
    from aegis._internal.operation_registry import OperationRecord

logger = logging.getLogger(__name__)


def _session_locked(method: Any) -> Any:
    """Serialize lifecycle and pending-operation mutations per session."""
    @wraps(method)
    def locked(self: Any, *args: Any, **kwargs: Any) -> Any:
        with self._lifecycle_lock:
            return method(self, *args, **kwargs)

    return locked


# ---------------------------------------------------------------------------
# Lifecycle constants
# ---------------------------------------------------------------------------

STATE_OPEN = "OPEN"
STATE_PAUSED = "PAUSED"
STATE_FAILED = "FAILED"
STATE_COMPLETED = "COMPLETED"
STATE_CANCELED = "CANCELED"
STATE_FINALIZED = "FINALIZED"

TERMINAL_STATES = {STATE_FAILED, STATE_COMPLETED, STATE_CANCELED}
PRE_TERMINAL_STATES = {STATE_OPEN, STATE_PAUSED}

# Maps session state → workflow artifact status
_ARTIFACT_STATUS_MAP = {
    STATE_COMPLETED: "COMPLETED",
    STATE_FAILED: "FAILED",
    STATE_CANCELED: "CANCELED",
    STATE_OPEN: "INCOMPLETE",
    STATE_PAUSED: "INCOMPLETE",
}

# Valid forward transitions: from_state → allowed to_states
_VALID_TRANSITIONS: dict[str, set[str]] = {
    STATE_OPEN: {STATE_PAUSED, STATE_FAILED, STATE_COMPLETED, STATE_CANCELED},
    STATE_PAUSED: {STATE_OPEN, STATE_FAILED, STATE_COMPLETED, STATE_CANCELED},
    STATE_FAILED: set(),
    STATE_COMPLETED: set(),
    STATE_CANCELED: set(),
    STATE_FINALIZED: set(),
}

_A2A_PROTOCOL_VERSION = "1.0"
_A2A_ALLOWED_PROTOCOL_BINDINGS = frozenset({"JSONRPC", "HTTP+JSON"})
_A2A_GRPC_BINDINGS = frozenset({"grpc"})
# U+0261 (LATIN SMALL LETTER SCRIPT G) is not normalized by NFKC; map it to
# ASCII g explicitly so unicode lookalikes cannot bypass the gRPC guard.
_A2A_GRPC_CHAR_MAP = {ord("ɡ"): "g"}


# ---------------------------------------------------------------------------
# SessionPreCallResult — opaque step operation identity
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SessionPreCallResult:
    """Single-use operation handle from GovernanceSession Phase A.

    Authorization state remains in the owning AEGIS operation registry. The
    handle cannot be completed through the
    module-level enforce_post_call(); use GovernanceSession.enforce_step_post_call().
    """

    session_id: str
    step_id: str
    participant_id: str | None
    operation_id: str
    issuer_id: str
    process_id: int
    correlation_id: str
    policy_digest: str
    canonicalization_profile: str
    step_index: int

    def __post_init__(self) -> None:
        if type(self.step_index) is not int or self.step_index < 0:
            raise InvocationValidationError(
                "Session operation handle step_index is invalid",
                code="OPERATION_HANDLE_INVALID",
            )


class AttemptFinalizationState(str, Enum):
    """Closed lifecycle for one allocated workflow attempt."""

    ALLOCATED = "allocated"
    FINALIZING = "finalizing"
    TERMINAL = "terminal"


class _AttemptCapability:
    __slots__ = ()


class _FinalizationCapability:
    __slots__ = ()


@dataclass(frozen=True, slots=True)
class SessionAttempt:
    """One allocated workflow attempt, retained in per-session order."""

    step_index: int
    step_id: str
    attempt_id: int
    invocation_checksum: str | None
    terminal: TerminalClass | None = None
    state: AttemptFinalizationState = AttemptFinalizationState.ALLOCATED
    participant_id: str | None = None
    workflow_policy_digest: str | None = None
    role: str = "unknown"
    capability: object = field(
        default_factory=_AttemptCapability,
        repr=False,
        compare=False,
    )
    finalization_capability: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            self.state is AttemptFinalizationState.ALLOCATED
            and self.invocation_checksum is not None
            and self.terminal is not None
        ):
            object.__setattr__(
                self,
                "state",
                AttemptFinalizationState.TERMINAL,
            )


class _SessionTerminalReservation:
    """Opaque reserve/commit acknowledgement for one invocation emission."""

    __slots__ = (
        "_session",
        "_step_index",
        "_attempt_capability",
        "_finalization_capability",
        "_checksum",
        "_terminal",
        "_lock",
        "_resolved",
    )

    def __init__(
        self,
        session: "GovernanceSession",
        step_index: int,
        attempt_capability: object,
        finalization_capability: object,
        checksum: str,
        terminal: TerminalClass,
    ) -> None:
        self._session = session
        self._step_index = step_index
        self._attempt_capability = attempt_capability
        self._finalization_capability = finalization_capability
        self._checksum = checksum
        self._terminal = terminal
        self._lock = threading.Lock()
        self._resolved = False

    def commit(self, content_checksum: str) -> None:
        with self._lock:
            if self._resolved:
                raise SessionStateError(
                    "Terminal reservation is already resolved",
                    code="SESSION_ATTEMPT_CONFLICT",
                )
            if content_checksum != self._checksum:
                raise SessionStateError(
                    "Terminal reservation checksum changed",
                    code="SESSION_ATTEMPT_CONFLICT",
                )
            self._session._commit_terminal_reservation(
                self._step_index,
                self._attempt_capability,
                self._finalization_capability,
                self._checksum,
                self._terminal,
            )
            self._resolved = True

    def abort(self) -> None:
        with self._lock:
            if self._resolved:
                return
            self._session._abort_terminal_reservation(
                self._step_index,
                self._attempt_capability,
                self._finalization_capability,
            )
            self._resolved = True


class _SessionTerminalRecorder:
    __slots__ = ("_session", "_step_index")

    def __init__(self, session: "GovernanceSession", step_index: int) -> None:
        self._session = session
        self._step_index = step_index

    def reserve(
        self,
        artifact: MappingABC[str, Any],
        terminal: TerminalClass,
        origin: object,
    ) -> _SessionTerminalReservation:
        return self._session._reserve_terminal_attempt(
            self._step_index,
            artifact,
            terminal,
            origin,
        )


def _inner_result(session_result: SessionPreCallResult) -> Any:
    """Rebuild the public invocation handle for the owning instance runtime."""
    from aegis._internal.enforcement import PreCallResult

    return PreCallResult(
        operation_id=session_result.operation_id,
        issuer_id=session_result.issuer_id,
        process_id=session_result.process_id,
        correlation_id=session_result.correlation_id,
        policy_digest=session_result.policy_digest,
        canonicalization_profile=session_result.canonicalization_profile,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _checksum(artifact: dict) -> str:
    """Return a v2 content checksum or hash a non-artifact JSON value with v2."""
    return _audit_checksum(artifact)


_MAX_WORKFLOW_IDENTITY_LENGTH = 512
_POLICY_CORRELATION_DOMAIN = b"aegis-workflow-policy-correlation-v1\x00"


def _safe_workflow_identity(value: object) -> tuple[str, bool]:
    """Return a bounded v2 string plus whether the caller value was valid."""
    if (
        type(value) is str
        and bool(value.strip())
        and len(value) <= _MAX_WORKFLOW_IDENTITY_LENGTH
    ):
        try:
            normalized = normalize_json_v2(value)
        except CanonicalizationError:
            pass
        else:
            if type(normalized) is str:
                return normalized, True
    return "unknown", False


def _safe_attempt_failure(exc: BaseException) -> tuple[str, str]:
    """Map internal exceptions to bounded evidence without copying raw text."""
    raw_code = getattr(exc, "code", None)
    code = (
        raw_code
        if isinstance(raw_code, str)
        and raw_code
        and len(raw_code) <= 128
        and raw_code.isascii()
        else "INTERNAL_ENFORCEMENT_ERROR"
    )
    if isinstance(exc, AIGCError):
        return code, "Governance enforcement denied the workflow attempt"
    if type(exc).__name__ == "CancelledError":
        return "WORKFLOW_ATTEMPT_CANCELED", (
            "Workflow attempt was canceled before completion"
        )
    return "INTERNAL_ENFORCEMENT_ERROR", (
        "Workflow attempt failed during internal enforcement"
    )


def _precompilation_policy_digest(state: str, policy_file: str) -> str:
    """Commit to AEGIS's pre-compilation policy state without raw disclosure."""
    payload = (
        _POLICY_CORRELATION_DOMAIN
        + state.encode("ascii")
        + b"\x00"
        + policy_file.encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def _compute_policy_file(
    session_policy_file: str | None,
    step_policy_files: list[str | None],
) -> str | None:
    """Compute artifact policy_file per the finalization normalization rule.

    Priority order:
    0. No steps completed (empty list) → null
    1. Session-level override set → that value
    2. All steps used the same effective policy_file → that value
    3. Heterogeneous step policies → null
    """
    if not step_policy_files:
        # Rule 0: no completed steps
        return None
    if session_policy_file is not None:
        # Rule 1: session-level override always wins
        return session_policy_file
    unique = set(step_policy_files)
    if len(unique) == 1:
        # Rule 2: all steps used the same policy
        return next(iter(unique))
    # Rule 3: heterogeneous
    return None


def _a2a_protocol_constraints(
    raw_constraints: Any,
    *,
    session_id: str,
    step_id: str,
) -> dict[str, Any]:
    """Resolve A2A protocol constraints and fail closed on malformed values."""
    if not isinstance(raw_constraints, dict):
        from aegis._internal.errors import WorkflowProtocolViolationError
        raise WorkflowProtocolViolationError(
            "A2A protocol constraints must be a mapping",
            details={
                "session_id": session_id,
                "step_id": step_id,
                "protocol": "a2a",
                "reason_code": "WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            },
        )

    version = raw_constraints.get("protocol_version", _A2A_PROTOCOL_VERSION)
    allowed = raw_constraints.get(
        "allowed_protocol_bindings",
        ["JSONRPC", "HTTP+JSON"],
    )
    require_task_state = raw_constraints.get("require_task_state", True)

    if version != _A2A_PROTOCOL_VERSION:
        from aegis._internal.errors import WorkflowProtocolViolationError
        raise WorkflowProtocolViolationError(
            "A2A protocol_version must be '1.0'",
            details={
                "session_id": session_id,
                "step_id": step_id,
                "protocol": "a2a",
                "protocol_version": version,
                "reason_code": "WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            },
        )
    allowed_bindings_valid = False
    if isinstance(allowed, (list, tuple)) and allowed:
        allowed_list = list(allowed)
        allowed_bindings_valid = (
            all(isinstance(binding, str) for binding in allowed_list)
            and len(set(allowed_list)) == len(allowed_list)
            and all(binding in _A2A_ALLOWED_PROTOCOL_BINDINGS for binding in allowed_list)
        )
    if not allowed_bindings_valid:
        from aegis._internal.errors import WorkflowProtocolViolationError
        raise WorkflowProtocolViolationError(
            "A2A allowed_protocol_bindings must contain unique JSONRPC or HTTP+JSON values",
            details={
                "session_id": session_id,
                "step_id": step_id,
                "protocol": "a2a",
                "allowed_protocol_bindings": allowed,
                "reason_code": "WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            },
        )
    if not isinstance(require_task_state, bool):
        from aegis._internal.errors import WorkflowProtocolViolationError
        raise WorkflowProtocolViolationError(
            "A2A require_task_state must be a boolean",
            details={
                "session_id": session_id,
                "step_id": step_id,
                "protocol": "a2a",
                "require_task_state": require_task_state,
                "reason_code": "WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            },
        )

    return {
        "protocol_version": version,
        "allowed_protocol_bindings": list(allowed),
        "require_task_state": require_task_state,
    }


def _raise_a2a_protocol_error(
    message: str,
    *,
    session_id: str,
    step_id: str,
    required_version: str,
    allowed_bindings: list[str],
    reason_code: str,
    extra_details: dict[str, Any] | None = None,
) -> NoReturn:
    from aegis._internal.errors import WorkflowProtocolViolationError
    details: dict[str, Any] = {
        "session_id": session_id,
        "step_id": step_id,
        "protocol": "a2a",
        "required_protocol_version": required_version,
        "allowed_protocol_bindings": allowed_bindings,
        "reason_code": reason_code,
    }
    if extra_details:
        details.update(extra_details)
    raise WorkflowProtocolViolationError(message, details=details)


def _a2a_binding_is_grpc(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = normalized.translate(_A2A_GRPC_CHAR_MAP)
    return normalized in _A2A_GRPC_BINDINGS


def _a2a_transport_is_grpc(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = normalized.translate(_A2A_GRPC_CHAR_MAP)
    return normalized == "grpc"


def _validate_a2a_protocol_evidence(
    evidence: Any,
    constraints: dict[str, Any],
    *,
    session_id: str,
    step_id: str,
) -> None:
    """Validate A2A evidence for callers that bypass A2AAdapter."""
    required_version = constraints["protocol_version"]
    allowed_bindings = constraints["allowed_protocol_bindings"]

    if not isinstance(evidence, dict):
        _raise_a2a_protocol_error(
            "A2A protocol evidence must be a mapping",
            session_id=session_id,
            step_id=step_id,
            required_version=required_version,
            allowed_bindings=allowed_bindings,
            reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
        )

    if (
        _a2a_transport_is_grpc(evidence.get("transport"))
        or _a2a_binding_is_grpc(evidence.get("selected_protocol_binding"))
        or _a2a_binding_is_grpc(evidence.get("protocol_binding"))
        or _a2a_binding_is_grpc(evidence.get("protocolBinding"))
    ):
        _raise_a2a_protocol_error(
            "gRPC transport is not supported for a2a in v0.9.0",
            session_id=session_id,
            step_id=step_id,
            required_version=required_version,
            allowed_bindings=allowed_bindings,
            reason_code="WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED",
            extra_details={"transport": evidence.get("transport")},
        )

    _camel_binding = evidence.get("protocolBinding")
    if "protocolBinding" in evidence and _camel_binding is not None and not isinstance(
        _camel_binding, str
    ):
        _raise_a2a_protocol_error(
            "A2A evidence protocolBinding must be a string",
            session_id=session_id,
            step_id=step_id,
            required_version=required_version,
            allowed_bindings=allowed_bindings,
            reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
            extra_details={
                "protocol_binding_type": type(_camel_binding).__name__,
            },
        )

    for _binding_key in (
        "selected_protocol_binding",
        "protocol_binding",
        "protocolBinding",
    ):
        _selected = evidence.get(_binding_key)
        if _selected is not None and (
            not isinstance(_selected, str) or _selected not in allowed_bindings
        ):
            _raise_a2a_protocol_error(
                f"A2A evidence {_binding_key}={_selected!r} is not in allowed_protocol_bindings",
                session_id=session_id,
                step_id=step_id,
                required_version=required_version,
                allowed_bindings=allowed_bindings,
                reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
                extra_details={
                    _binding_key: _selected,
                    f"{_binding_key}_type": type(_selected).__name__,
                },
            )

    interfaces = evidence.get("supportedInterfaces")
    if not isinstance(interfaces, list) or not interfaces:
        _raise_a2a_protocol_error(
            "A2A evidence must include a non-empty supportedInterfaces list",
            session_id=session_id,
            step_id=step_id,
            required_version=required_version,
            allowed_bindings=allowed_bindings,
            reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
        )

    # First pass: validate structure before anything else.
    for index, interface in enumerate(interfaces):
        if not isinstance(interface, dict):
            _raise_a2a_protocol_error(
                "A2A supportedInterfaces entries must be mappings",
                session_id=session_id,
                step_id=step_id,
                required_version=required_version,
                allowed_bindings=allowed_bindings,
                reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
                extra_details={"interface_index": index},
            )
        binding = interface.get("protocolBinding")
        if "protocolBinding" in interface and not isinstance(binding, str):
            _raise_a2a_protocol_error(
                "A2A supportedInterfaces[].protocolBinding must be a string",
                session_id=session_id,
                step_id=step_id,
                required_version=required_version,
                allowed_bindings=allowed_bindings,
                reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
                extra_details={
                    "interface_index": index,
                    "protocol_binding_type": type(binding).__name__,
                },
            )

    # Second pass: scan ALL interfaces for gRPC markers before accepting any
    # binding. A gRPC entry at the required version (or the only interface) is
    # rejected regardless of position. An older-version gRPC entry alongside a
    # valid non-gRPC required-version entry is allowed — it will not be selected.
    for index, interface in enumerate(interfaces):
        binding = interface.get("protocolBinding")
        version = interface.get("protocolVersion")
        has_grpc_marker = (
            _a2a_binding_is_grpc(binding)
            or _a2a_transport_is_grpc(interface.get("transport"))
        )
        if has_grpc_marker and (version == required_version or len(interfaces) == 1):
            _raise_a2a_protocol_error(
                "gRPC transport is not supported for a2a in v0.9.0",
                session_id=session_id,
                step_id=step_id,
                required_version=required_version,
                allowed_bindings=allowed_bindings,
                reason_code="WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED",
                extra_details={"interface_index": index},
            )
        if (
            version == required_version
            and isinstance(binding, str)
            and binding not in _A2A_ALLOWED_PROTOCOL_BINDINGS
        ):
            _raise_a2a_protocol_error(
                "A2A evidence supportedInterfaces[].protocolBinding must be "
                "JSONRPC or HTTP+JSON for the governed protocol version",
                session_id=session_id,
                step_id=step_id,
                required_version=required_version,
                allowed_bindings=allowed_bindings,
                reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
                extra_details={
                    "interface_index": index,
                    "protocol_binding": binding,
                },
            )

    version_match_seen = False
    for interface in interfaces:
        binding = interface.get("protocolBinding")
        version = interface.get("protocolVersion")
        if version == required_version:
            version_match_seen = True
            if binding in allowed_bindings:
                return

    if not version_match_seen:
        _raise_a2a_protocol_error(
            "A2A evidence must include supportedInterfaces[] entry with "
            f"protocolVersion == {required_version!r}",
            session_id=session_id,
            step_id=step_id,
            required_version=required_version,
            allowed_bindings=allowed_bindings,
            reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
        )

    _raise_a2a_protocol_error(
        "A2A evidence must include supportedInterfaces[] entry with an allowed "
        "protocolBinding",
        session_id=session_id,
        step_id=step_id,
        required_version=required_version,
        allowed_bindings=allowed_bindings,
        reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
    )


# ---------------------------------------------------------------------------
# GovernanceSession
# ---------------------------------------------------------------------------

class GovernanceSession:
    """Context manager for governed multi-step workflow sessions.

    Obtained via ``AEGIS.open_session()``. Manages the lifecycle::

        OPEN → PAUSED | FAILED | COMPLETED | CANCELED → FINALIZED

    ``__exit__`` never suppresses exceptions.  Clean exit from a pre-terminal
    state auto-finalizes to INCOMPLETE.  Exception exit records failure context,
    transitions to FAILED, emits a FAILED workflow artifact, and re-raises.
    """

    def __init__(
        self,
        aegis: "AEGIS",
        session_id: str,
        policy_file: str | None,
        metadata: dict | None,
        *,
        state_scope: Any | None = None,
    ) -> None:
        normalized_session_id, session_id_valid = _safe_workflow_identity(
            session_id
        )
        if not session_id_valid:
            raise InvocationValidationError(
                "session_id must be a non-empty bounded v2 string",
                code="WORKFLOW_SESSION_ID_INVALID",
            )
        self._aigc = aegis
        self._session_id = normalized_session_id
        self._policy_file = policy_file
        self._metadata = dict(metadata or {})
        self._state_scope = state_scope
        self._lifecycle_lock = threading.RLock()
        self._attempt_lock = threading.Lock()
        self._next_step_index = 0
        self._attempts: dict[int, SessionAttempt] = {}

        self._state = STATE_OPEN
        self._started_at = int(time.time())
        self._finalized_at: int | None = None

        # operation_id → {"step_id": str,
        #              "participant_id": str | None,
        #              "effective_policy_file": str | None,
        #              "tool_calls_count": int,
        #              "step_index": int,
        #              "attempt": AttemptEnvelope,
        #              "context": dict[str, Any]}
        self._pending_results: dict[str, dict[str, Any]] = {}

        # Ordered step records for the workflow artifact
        self._steps: list[dict[str, Any]] = []
        # Effective policy_file per completed step (for normalization rule)
        self._step_policy_files: list[str | None] = []

        self._failure_summary: dict[str, Any] | None = None
        self._workflow_artifact: dict[str, Any] | None = None

        # Approval checkpoint records — populated by pause()/resume()
        self._approval_records: list[dict[str, Any]] = []

        # ValidatorHooks evaluated at each enforce_step_pre_call (internal-only
        # contract wired from the owning AEGIS instance).
        self._validator_hooks: list[Any] = list(
            getattr(self._aigc, "_validator_hooks", ())
        )
        # Evidence records for the workflow artifact
        self._validator_hook_evidence: list[dict[str, Any]] = []

        # Workflow budget constraints and policy fields — loaded via AEGIS's own cache+loader
        # (Fix 1: never call load_policy() directly here, which would bypass any custom loader)
        # Initialize defaults first (for when policy_file is None or load fails)
        self._max_steps: int | None = None
        self._max_total_tool_calls: int | None = None
        self._participants: list[dict] | None = None
        self._participants_by_id: dict[str, dict] = {}
        self._required_sequence: list[str] | None = None
        self._allowed_transitions: dict[str, list[str]] | None = None
        self._allowed_agent_roles: list[str] | None = None
        self._handoffs: list[dict] | None = None
        self._escalation: dict | None = None
        self._protocol_constraints: dict | None = None
        self._compiled_policy: "CompiledPolicy | None" = None
        self._sequence_position: int = 0
        self._last_completed_step_id: str | None = None
        self._last_completed_participant_id: str | None = None

        if policy_file is not None:
            from aegis._internal.enforcement import _compile_cached_policy

            _policy = _compile_cached_policy(
                {"policy_file": policy_file},
                cache=self._aigc._policy_cache,
                loader=self._aigc._policy_loader,
            )
            self._compiled_policy = _policy
            _wf = _policy.workflow
            try:
                self._max_steps = _wf.get("max_steps")
                self._max_total_tool_calls = _wf.get("max_total_tool_calls")
                self._participants = _wf.get("participants")
                self._participants_by_id = {
                    p["id"]: p for p in (self._participants or [])
                }
                self._required_sequence = _wf.get("required_sequence")
                self._allowed_transitions = _wf.get("allowed_transitions")
                self._allowed_agent_roles = _wf.get("allowed_agent_roles")
                self._handoffs = _wf.get("handoffs")
                self._escalation = _wf.get("escalation")
                self._protocol_constraints = _wf.get("protocol_constraints")
            except (AttributeError, KeyError, TypeError):
                # The compiler owns structural validation; this protects only
                # against an internally inconsistent compiled workflow value.
                raise

        # Budget counters
        self._authorized_step_count: int = 0
        self._total_tool_calls_consumed: int = 0

        # Escalation re-fire guard: True while an escalation is pending approval
        # for the current step. Cleared in enforce_step_post_call on success.
        self._escalation_in_progress: bool = False

        # Adapter-managed step state (keyed by operation_id).  Populated by
        # external adapters (e.g. OpenAIAgentsAdapter) to track dynamic tool
        # calls and interruption checkpoints for a given pending step.
        self._adapter_step_states: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def state(self) -> str:
        return self._state

    @property
    def workflow_artifact(self) -> dict[str, Any] | None:
        return self._workflow_artifact

    def protocol_constraints_for(self, protocol: str) -> Any:
        """Return workflow protocol constraints for adapter-managed protocol seams."""
        constraints = (self._protocol_constraints or {}).get(protocol)
        if constraints is None:
            return {}
        if not isinstance(constraints, dict):
            return constraints
        return dict(constraints)

    def participant_for(self, participant_id: str) -> dict[str, Any] | None:
        """Return a workflow participant declaration for adapter binding checks."""
        participant = self._participants_by_id.get(participant_id)
        return dict(participant) if participant is not None else None

    def _resolve_policy_correlation_digest(self, policy_file: str) -> str:
        """Resolve compiled authority or a stable pre-compilation commitment."""
        if self._compiled_policy is not None:
            return self._compiled_policy.policy_digest
        if policy_file == "unknown":
            return _precompilation_policy_digest("policyless", "unknown")
        from aegis._internal.enforcement import _compile_cached_policy

        try:
            compiled = _compile_cached_policy(
                {"policy_file": policy_file},
                cache=self._aigc._policy_cache,
                loader=self._aigc._policy_loader,
            )
        except BaseException:
            return _precompilation_policy_digest("unresolved", policy_file)
        return compiled.policy_digest

    def _bind_policy_correlation_digest(
        self,
        step_index: int,
        digest: str,
    ) -> None:
        with self._attempt_lock:
            current = self._attempts[step_index]
            if current.state is not AttemptFinalizationState.ALLOCATED:
                raise SessionStateError(
                    "Policy correlation must be bound before finalization",
                    code="SESSION_ATTEMPT_CONFLICT",
                )
            self._attempts[step_index] = replace(
                current,
                workflow_policy_digest=digest,
            )

    def _allocate_step_index(
        self,
        step_id: str,
        attempt_id: int,
        *,
        participant_id: str | None = None,
        workflow_policy_digest: str | None = None,
        role: str = "unknown",
    ) -> int:
        """Atomically reserve a permanent index for one workflow attempt."""
        with self._attempt_lock:
            if self._next_step_index >= MAX_WORKFLOW_ATTEMPTS:
                raise self._attempt_limit_error()
            index = self._next_step_index
            self._next_step_index += 1
            self._attempts[index] = SessionAttempt(
                step_index=index,
                step_id=step_id,
                attempt_id=attempt_id,
                invocation_checksum=None,
                participant_id=participant_id,
                workflow_policy_digest=workflow_policy_digest,
                role=role,
            )
            return index

    def _attempt_limit_error(self) -> SessionStateError:
        return SessionStateError(
            "Session workflow attempt limit exceeded",
            code="SESSION_ATTEMPT_LIMIT_EXCEEDED",
            details={
                "session_id": self._session_id,
                "max_workflow_attempts": MAX_WORKFLOW_ATTEMPTS,
            },
        )

    def _assert_attempt_capacity(self) -> None:
        """Reject before allocating an envelope when the session is full."""
        with self._attempt_lock:
            if self._next_step_index >= MAX_WORKFLOW_ATTEMPTS:
                raise self._attempt_limit_error()

    def record_terminal_attempt(
        self,
        step_index: int,
        invocation_checksum: str,
        terminal: TerminalClass,
    ) -> None:
        """Atomically bind one allocated attempt to one terminal artifact."""
        if type(step_index) is not int or step_index < 0:
            raise SessionStateError(
                "Terminal attempt index is invalid",
                code="SESSION_ATTEMPT_UNKNOWN",
                details={"session_id": self._session_id, "step_index": step_index},
            )
        if (
            not isinstance(invocation_checksum, str)
            or len(invocation_checksum) != 64
            or any(char not in "0123456789abcdef" for char in invocation_checksum)
        ):
            raise SessionStateError(
                "Terminal attempt checksum is invalid",
                code="SESSION_ATTEMPT_CONFLICT",
                details={"session_id": self._session_id, "step_index": step_index},
            )
        if type(terminal) is not TerminalClass:
            raise SessionStateError(
                "Terminal attempt class is invalid",
                code="SESSION_ATTEMPT_CONFLICT",
                details={"session_id": self._session_id, "step_index": step_index},
            )
        with self._attempt_lock:
            current = self._attempts.get(step_index)
            if current is None:
                raise SessionStateError(
                    "Terminal artifact references an unknown session attempt",
                    code="SESSION_ATTEMPT_UNKNOWN",
                    details={
                        "session_id": self._session_id,
                        "step_index": step_index,
                    },
                )
            if current.state is AttemptFinalizationState.FINALIZING:
                raise SessionStateError(
                    "Session attempt finalization is already in progress",
                    code="SESSION_ATTEMPT_FINALIZING",
                    details={
                        "session_id": self._session_id,
                        "step_index": step_index,
                    },
                )
            if current.state is AttemptFinalizationState.TERMINAL:
                duplicate = (
                    current.invocation_checksum == invocation_checksum
                    and current.terminal is terminal
                )
                raise SessionStateError(
                    "Session attempt already has a terminal artifact",
                    code=(
                        "SESSION_ATTEMPT_DUPLICATE"
                        if duplicate
                        else "SESSION_ATTEMPT_CONFLICT"
                    ),
                    details={
                        "session_id": self._session_id,
                        "step_index": step_index,
                    },
                )
            finalization_capability = _FinalizationCapability()
            self._attempts[step_index] = replace(
                current,
                state=AttemptFinalizationState.FINALIZING,
                finalization_capability=finalization_capability,
            )
            self._attempts[step_index] = replace(
                current,
                invocation_checksum=invocation_checksum,
                terminal=terminal,
                state=AttemptFinalizationState.TERMINAL,
                finalization_capability=None,
            )

    def _reserve_terminal_attempt(
        self,
        step_index: int,
        artifact: MappingABC[str, Any],
        terminal: TerminalClass,
        origin: object,
    ) -> _SessionTerminalReservation:
        """Validate origin/correlation and reserve before sink emission."""
        if type(terminal) is not TerminalClass:
            raise SessionStateError(
                "Terminal attempt class is invalid",
                code="SESSION_ATTEMPT_CONFLICT",
            )
        checksum = artifact.get("checksum")
        context = artifact.get("context")
        with self._attempt_lock:
            current = self._attempts.get(step_index)
            if current is None:
                raise SessionStateError(
                    "Terminal artifact references an unknown session attempt",
                    code="SESSION_ATTEMPT_UNKNOWN",
                )
            if origin is not current.capability:
                raise SessionStateError(
                    "Terminal artifact origin does not own this session attempt",
                    code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
                )
            if current.state is AttemptFinalizationState.FINALIZING:
                raise SessionStateError(
                    "Session attempt finalization is already in progress",
                    code="SESSION_ATTEMPT_FINALIZING",
                )
            if current.state is AttemptFinalizationState.TERMINAL:
                duplicate = (
                    current.invocation_checksum == checksum
                    and current.terminal is terminal
                )
                raise SessionStateError(
                    "Session attempt already has a terminal artifact",
                    code=(
                        "SESSION_ATTEMPT_DUPLICATE"
                        if duplicate
                        else "SESSION_ATTEMPT_CONFLICT"
                    ),
                )
            participant_matches = (
                context.get("participant_id") == current.participant_id
                if current.participant_id is not None
                else "participant_id" not in context
            ) if type(context) is dict else False
            correlation_matches = (
                type(artifact) is dict
                and artifact.get("audit_schema_version") == "2.0"
                and "workflow_schema_version" not in artifact
                and type(context) is dict
                and context.get("session_id") == self._session_id
                and context.get("step_id") == current.step_id
                and type(context.get("step_index")) is int
                and context.get("step_index") == current.step_index
                and participant_matches
                and (
                    current.workflow_policy_digest is None
                    or context.get("workflow_policy_digest")
                    == current.workflow_policy_digest
                )
                and (
                    current.role == "unknown"
                    or artifact.get("role") == current.role
                )
            )
            if not correlation_matches:
                raise SessionStateError(
                    "Terminal artifact does not match its allocated origin",
                    code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
                )
            if (
                not isinstance(checksum, str)
                or len(checksum) != 64
                or any(char not in "0123456789abcdef" for char in checksum)
            ):
                raise SessionStateError(
                    "Terminal attempt checksum is invalid",
                    code="SESSION_ATTEMPT_CONFLICT",
                )
            finalization_capability = _FinalizationCapability()
            self._attempts[step_index] = replace(
                current,
                state=AttemptFinalizationState.FINALIZING,
                finalization_capability=finalization_capability,
            )
        return _SessionTerminalReservation(
            self,
            step_index,
            origin,
            finalization_capability,
            checksum,
            terminal,
        )

    def _commit_terminal_reservation(
        self,
        step_index: int,
        attempt_capability: object,
        finalization_capability: object,
        invocation_checksum: str,
        terminal: TerminalClass,
    ) -> None:
        with self._attempt_lock:
            current = self._attempts.get(step_index)
            if (
                current is None
                or current.capability is not attempt_capability
                or current.finalization_capability is not finalization_capability
                or current.state is not AttemptFinalizationState.FINALIZING
            ):
                raise SessionStateError(
                    "Terminal reservation no longer owns the session attempt",
                    code="SESSION_ATTEMPT_CONFLICT",
                )
            self._attempts[step_index] = replace(
                current,
                invocation_checksum=invocation_checksum,
                terminal=terminal,
                state=AttemptFinalizationState.TERMINAL,
                finalization_capability=None,
            )

    def _abort_terminal_reservation(
        self,
        step_index: int,
        attempt_capability: object,
        finalization_capability: object,
    ) -> None:
        with self._attempt_lock:
            current = self._attempts.get(step_index)
            if current is None or current.capability is not attempt_capability:
                return
            if (
                current.state is AttemptFinalizationState.FINALIZING
                and current.finalization_capability is finalization_capability
            ):
                self._attempts[step_index] = replace(
                    current,
                    state=AttemptFinalizationState.ALLOCATED,
                    finalization_capability=None,
                )

    def finalized_attempts(self) -> tuple[SessionAttempt, ...]:
        """Return immutable terminal records in allocated index order."""
        with self._attempt_lock:
            return tuple(
                record
                for _, record in sorted(self._attempts.items())
                if record.state is AttemptFinalizationState.TERMINAL
            )

    def _attempt_finalization_scope(self, step_index: int, attempt: Any):
        with self._attempt_lock:
            record = self._attempts.get(step_index)
            if record is None or record.attempt_id != attempt.attempt_id:
                raise SessionStateError(
                    "Evidence attempt does not own the allocated step index",
                    code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
                )
        return evidence_attempt(
            attempt,
            sink=self._aigc._sink,
            signer=self._aigc._signer,
            failure_mode=self._aigc._on_sink_failure,
            diagnostics=self._aigc._evidence_diagnostics,
            chain_linker=self._aigc._chain_linker,
            terminal_recorder=_SessionTerminalRecorder(self, step_index),
            terminal_origin=record.capability,
        )

    def _finalize_rejected_attempt(
        self,
        invocation: object,
        *,
        resolved_step_id: str,
        participant_id: str | None,
        attempt: Any,
        step_index: int,
        exc: BaseException,
    ) -> None:
        """Emit terminal evidence for a rejection before an operation is issued."""
        context = _plain_json(attempt.context)
        context.update(
            session_id=self._session_id,
            step_id=resolved_step_id,
            step_index=step_index,
        )
        with self._attempt_lock:
            workflow_policy_digest = self._attempts[
                step_index
            ].workflow_policy_digest
        if workflow_policy_digest is None:  # pragma: no cover - allocation invariant
            raise SessionStateError(
                "Workflow policy correlation was not bound",
                code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
            )
        context["workflow_policy_digest"] = workflow_policy_digest
        if participant_id is not None:
            context["participant_id"] = participant_id
        code, message = _safe_attempt_failure(exc)
        terminal = (
            TerminalClass.DENY
            if isinstance(exc, AIGCError)
            else TerminalClass.EXECUTION_FAILURE
        )
        from aegis._internal.enforcement import _map_exception_to_failure_gate

        failure_metadata: dict[str, Any] = {
            "enforcement_mode": "split_pre_call_only"
        }
        stateful_decisions = getattr(exc, "stateful_decisions", None)
        if stateful_decisions:
            failure_metadata["stateful_decisions"] = _plain_json(
                list(stateful_decisions)
            )
        artifact = {
            "policy_file": attempt.policy_file,
            "model_provider": attempt.model_provider,
            "model_identifier": attempt.model_identifier,
            "role": attempt.role,
            "context": context,
            "enforcement_result": "FAIL",
            "failures": [
                {"code": code, "message": message, "field": None}
            ],
            "failure_gate": (
                _map_exception_to_failure_gate(exc)
                if isinstance(exc, AIGCError)
                else "wrapped_function_error"
            ),
            "failure_reason": message,
            "metadata": failure_metadata,
        }
        finalized = finalize_legacy_invocation_artifact(
            artifact,
            invocation=invocation,
            attempt=attempt,
            terminal=terminal,
        )
        if isinstance(exc, AIGCError):
            exc.audit_artifact = finalized

    @_session_locked
    def register_adapter_step_state(
        self,
        session_result: SessionPreCallResult,
        state: dict[str, Any],
    ) -> None:
        """Register adapter-owned state for a pending governed step."""
        self._assert_open()
        self._assert_owns(session_result)
        if session_result.operation_id not in self._pending_results:
            raise InvocationValidationError(
                "Token not registered in this session",
                details={"operation_id": session_result.operation_id},
            )
        pending = self._pending_results[session_result.operation_id]
        if pending.get("tool_calls_count", 0):
            raise InvocationValidationError(
                "Static and dynamic tool-call charging are mutually exclusive",
                details={"operation_id": session_result.operation_id},
            )
        self._adapter_step_states[session_result.operation_id] = state

    @_session_locked
    def adapter_step_state(
        self,
        session_result: SessionPreCallResult,
    ) -> dict[str, Any] | None:
        """Return adapter-owned state for a pending governed step, if present."""
        self._assert_open()
        self._assert_owns(session_result)
        return self._adapter_step_states.get(session_result.operation_id)

    @_session_locked
    def pop_adapter_step_state(
        self,
        session_result: SessionPreCallResult,
    ) -> dict[str, Any]:
        """Remove and return adapter-owned state for a pending governed step."""
        self._assert_open()
        self._assert_owns(session_result)
        return self._adapter_step_states.pop(session_result.operation_id, {})

    @_session_locked
    def discard_adapter_step(
        self,
        session_result: SessionPreCallResult,
        *,
        rollback_authorization: bool = False,
    ) -> None:
        """Invalidate an adapter-prepared pending step without running Phase B."""
        self._discard_pending_step(
            session_result,
            rollback_authorization=rollback_authorization,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "GovernanceSession":
        return self

    @_session_locked
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> bool:
        if self._state == STATE_FINALIZED:
            return False  # already finalized

        if exc_type is not None:
            # Exception path: move to FAILED and record context
            if self._state not in TERMINAL_STATES:
                safe_exception_type, _ = _safe_workflow_identity(
                    exc_type.__name__
                )
                self._failure_summary = {
                    "exception_type": safe_exception_type,
                    "reason_code": "SESSION_BODY_EXCEPTION",
                }
                self._state = STATE_FAILED
            # Suppress sink errors here — original exception must take precedence
            try:
                self._do_finalize()
            except Exception:  # noqa: BLE001
                logger.error(
                    "Workflow artifact sink emission failed during exception cleanup "
                    "for session %s (original exception takes precedence)",
                    self._session_id,
                )
        else:
            # Clean exit: respect failure_mode so on_sink_failure="raise" propagates
            self._do_finalize()

        return False  # never suppress exceptions

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def _assert_accepting_new_step(self) -> None:
        """Reject step authorization unless the session is OPEN (not PAUSED)."""
        if self._state != STATE_OPEN:
            raise SessionStateError(
                f"Session is not accepting new steps (state={self._state!r}); "
                f"call resume() first if the session is PAUSED",
                details={"session_id": self._session_id, "state": self._state},
            )

    def _assert_open(self) -> None:
        """Reject step completion unless the session is OPEN or PAUSED."""
        if self._state not in PRE_TERMINAL_STATES:
            raise SessionStateError(
                f"Session is not accepting steps (state={self._state!r})",
                details={"session_id": self._session_id, "state": self._state},
            )

    def _transition(self, to_state: str) -> None:
        allowed = _VALID_TRANSITIONS.get(self._state, set())
        if to_state not in allowed:
            raise SessionStateError(
                f"Invalid session transition: {self._state!r} → {to_state!r}",
                details={
                    "session_id": self._session_id,
                    "from_state": self._state,
                    "to_state": to_state,
                },
            )
        self._state = to_state

    @_session_locked
    def pause(
        self,
        *,
        approval_id: str | None = None,
        approver_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Pause the session (OPEN → PAUSED) and record an approval checkpoint."""
        self._transition(STATE_PAUSED)
        checkpoint: dict[str, Any] = {
            "checkpoint_id": approval_id or str(uuid.uuid4()),
            "paused_at": int(time.time()),
            "approver_id": approver_id,
            "reason": reason,
            "status": "pending",
            "resumed_at": None,
            "approval_note": None,
            "denial_reason": None,
        }
        self._approval_records.append(checkpoint)

    @_session_locked
    def resume(
        self,
        *,
        approval_id: str | None = None,
        approver_id: str | None = None,
        approval_note: str | None = None,
    ) -> None:
        """Resume a paused session (PAUSED → OPEN) and close the pending checkpoint.

        Fix 5: if approval_id is supplied it must match the pending checkpoint's
        checkpoint_id — mismatched IDs are rejected with SessionStateError.
        """
        if self._state != STATE_PAUSED:
            raise SessionStateError(
                f"resume() requires a PAUSED session (state={self._state!r})",
                details={
                    "session_id": self._session_id,
                    "current_state": self._state,
                },
            )

        pending = [
            rec for rec in reversed(self._approval_records) if rec["status"] == "pending"
        ]
        if not pending:
            raise SessionStateError(
                "resume() requires a pending approval checkpoint",
                details={
                    "session_id": self._session_id,
                    "current_state": self._state,
                    "pending_approval_ids": [],
                },
            )

        target = pending[0]
        if approval_id is not None:
            target = next(
                (rec for rec in pending if rec["checkpoint_id"] == approval_id),
                None,
            )
            if target is None:
                raise SessionStateError(
                    f"approval_id mismatch: expected {pending[0]['checkpoint_id']!r}, "
                    f"got {approval_id!r}",
                    details={
                        "session_id": self._session_id,
                        "expected_approval_id": pending[0]["checkpoint_id"],
                        "pending_approval_ids": [rec["checkpoint_id"] for rec in pending],
                        "provided_approval_id": approval_id,
                    },
                )

        self._transition(STATE_OPEN)
        target["status"] = "approved"
        target["resumed_at"] = int(time.time())
        if approver_id is not None:
            target["approver_id"] = approver_id
        target["approval_note"] = approval_note

    @_session_locked
    def deny_approval(
        self,
        *,
        approval_id: str | None = None,
        approver_id: str | None = None,
        denial_reason: str | None = None,
    ) -> None:
        """Deny a pending approval checkpoint. Session remains PAUSED."""
        # State guard: must be PAUSED with at least one pending checkpoint
        _pending = [r for r in self._approval_records if r["status"] == "pending"]
        if self._state != STATE_PAUSED or not _pending:
            raise SessionStateError(
                f"deny_approval() requires a PAUSED session with a pending checkpoint "
                f"(state={self._state!r})",
                details={
                    "session_id": self._session_id,
                    "current_state": self._state,
                },
            )
        # Find target checkpoint
        if approval_id is not None:
            target = next(
                (r for r in self._approval_records
                 if r["checkpoint_id"] == approval_id and r["status"] == "pending"),
                None,
            )
            if target is None:
                raise SessionStateError(
                    f"No pending checkpoint with approval_id={approval_id!r}",
                    details={
                        "session_id": self._session_id,
                        "approval_id": approval_id,
                    },
                )
        else:
            # Most recent pending
            target = _pending[-1]
        target["status"] = "denied"
        if approver_id is not None:
            target["approver_id"] = approver_id
        target["denial_reason"] = denial_reason
        target["resumed_at"] = None
        # Session stays PAUSED — do NOT transition

    @_session_locked
    def complete(self) -> None:
        """Mark the session as successfully completed (OPEN/PAUSED → COMPLETED)."""
        if self._pending_results:
            raise SessionStateError(
                "Cannot complete session with pending authorized step(s); "
                "complete or discard every SessionPreCallResult before finalizing",
                details={
                    "session_id": self._session_id,
                    "pending_token_count": len(self._pending_results),
                    "pending_step_ids": [
                        entry.get("step_id")
                        for entry in self._pending_results.values()
                    ],
                },
            )
        for rec in self._approval_records:
            if rec["status"] != "approved":
                raise SessionStateError(
                    f"Cannot complete session with unresolved approval checkpoint"
                    f" {rec['checkpoint_id']!r} (status={rec['status']!r})",
                    details={
                        "session_id": self._session_id,
                        "unresolved_checkpoint_id": rec["checkpoint_id"],
                        "checkpoint_status": rec["status"],
                    },
                )
        self._transition(STATE_COMPLETED)

    @_session_locked
    def cancel(self) -> None:
        """Cancel the session (OPEN/PAUSED → CANCELED)."""
        self._cancel_pending_operations()
        self._transition(STATE_CANCELED)

    @_session_locked
    def finalize(self, *, status: str | None = None) -> dict[str, Any]:
        """Explicitly finalize and emit the workflow artifact.

        May be called from any non-finalized state. OPEN or PAUSED emits
        ``INCOMPLETE``; terminal states emit their corresponding status.
        """
        if self._state == STATE_FINALIZED:
            raise SessionStateError(
                "Session is already finalized",
                details={"session_id": self._session_id},
            )
        if status is not None and status not in {
            "COMPLETED",
            "FAILED",
            "CANCELED",
            "INCOMPLETE",
        }:
            raise SessionStateError(
                f"Invalid workflow artifact status: {status!r}",
                details={"session_id": self._session_id, "status": status},
            )
        if status == "COMPLETED" and self._state != STATE_COMPLETED:
            self.complete()
        return self._do_finalize(status=status)

    def _do_finalize(self, *, status: str | None = None) -> dict[str, Any]:
        """Internal finalization — emits artifact and transitions to FINALIZED."""
        self._cancel_pending_operations()
        with self._attempt_lock:
            allocated_count = self._next_step_index
            records = tuple(
                record
                for _, record in sorted(self._attempts.items())
                if record.state is AttemptFinalizationState.TERMINAL
            )
        if len(records) != allocated_count:
            raise SessionStateError(
                "Every allocated session attempt requires terminal evidence",
                code="SESSION_ATTEMPT_INCOMPLETE",
                details={
                    "session_id": self._session_id,
                    "allocated_attempt_count": allocated_count,
                    "terminal_attempt_count": len(records),
                },
            )
        indices = [record.step_index for record in records]
        if indices != list(range(allocated_count)):
            raise SessionStateError(
                "Session attempt indices must be gapless and unique",
                code="SESSION_ATTEMPT_GAP",
                details={
                    "session_id": self._session_id,
                    "allocated_attempt_count": allocated_count,
                    "terminal_attempt_indices": indices,
                },
            )
        evidence_attempt = self._aigc._attempt_factory.allocate(
            "GovernanceSession.finalize",
            "workflow",
            {"policy_file": self._policy_file},
        )
        self._finalized_at = int(time.time())

        artifact_status = status or _ARTIFACT_STATUS_MAP.get(
            self._state,
            "INCOMPLETE",
        )
        if artifact_status == "COMPLETED" and any(
            record.terminal not in {TerminalClass.ALLOW, TerminalClass.WARN}
            for record in records
        ):
            raise SessionStateError(
                "A completed session cannot contain failed or canceled attempts",
                code="SESSION_ATTEMPT_NOT_SUCCESSFUL",
                details={"session_id": self._session_id},
            )
        policy_file = _compute_policy_file(
            self._policy_file,
            self._step_policy_files,
        )

        artifact: dict[str, Any] = {
            "artifact_type": "workflow",
            "session_id": self._session_id,
            "policy_file": policy_file,
            "status": artifact_status,
            "started_at": self._started_at,
            "finalized_at": self._finalized_at,
            "steps": list(self._steps),
            "invocation_audit_checksums": [
                s["invocation_artifact_checksum"] for s in self._steps
            ],
            "step_count": allocated_count,
            "invocations": [
                {
                    "step_index": record.step_index,
                    "checksum": record.invocation_checksum,
                }
                for record in records
            ],
            "failure_summary": self._failure_summary,
            "approval_checkpoints": list(self._approval_records),
            "validator_hook_evidence": list(self._validator_hook_evidence),
            "metadata": self._metadata,
        }

        finalize_legacy_workflow_artifact(
            artifact,
            attempt=evidence_attempt,
            diagnostics=self._aigc._evidence_diagnostics,
            sink=self._aigc._sink,
            failure_mode=self._aigc._on_sink_failure,
            signer=self._aigc._signer,
        )

        self._workflow_artifact = artifact
        self._state = STATE_FINALIZED

        return artifact

    def _cancel_pending_operations(self) -> None:
        """Burn and terminally finalize every still-live session operation."""
        pending = tuple(self._pending_results.items())
        for operation_id, _entry in pending:
            self._aigc._operation_registry.cancel_operation(operation_id)
        for operation_id, entry in pending:
            self._finalize_canceled_entry(entry)
            self._pending_results.pop(operation_id, None)
            self._adapter_step_states.pop(operation_id, None)

    def _finalize_canceled_entry(self, entry: dict[str, Any]) -> None:
        """Finalize terminal canceled evidence after its handle is burned."""
        attempt = entry["attempt"]
        step_index = entry["step_index"]
        stateful_decisions = [
            *(entry.get("static_stateful_decisions") or ()),
            *(entry.get("stateful_decisions") or ()),
        ]
        metadata: dict[str, Any] = {"enforcement_mode": "split"}
        if stateful_decisions:
            metadata["stateful_decisions"] = _plain_json(stateful_decisions)
        cancellation = {
            "policy_file": attempt.policy_file,
            "model_provider": attempt.model_provider,
            "model_identifier": attempt.model_identifier,
            "role": attempt.role,
            "context": _plain_json(entry["context"]),
            "enforcement_result": "FAIL",
            "failures": [
                {
                    "code": "CANCELED",
                    "message": "Session closed before Phase B completion",
                    "field": None,
                }
            ],
            "failure_gate": "wrapped_function_error",
            "failure_reason": "Session closed before Phase B completion",
            "metadata": metadata,
        }
        with self._attempt_finalization_scope(step_index, attempt):
            try:
                finalize_legacy_invocation_artifact(
                    cancellation,
                    attempt=attempt,
                    terminal=TerminalClass.EXECUTION_FAILURE,
                )
            except _EvidenceAbort as abort:
                error = abort.error
                error.__cause__ = None
                raise error

    def _finalize_internal_phase_b_failure(
        self,
        entry: dict[str, Any],
        exc: BaseException,
    ) -> None:
        """Terminalize an unexpected Phase B failure after handle consumption."""
        attempt = entry["attempt"]
        code, message = _safe_attempt_failure(exc)
        stateful_decisions = [
            *(entry.get("static_stateful_decisions") or ()),
            *(entry.get("stateful_decisions") or ()),
        ]
        metadata: dict[str, Any] = {"enforcement_mode": "split"}
        if stateful_decisions:
            metadata["stateful_decisions"] = _plain_json(stateful_decisions)
        artifact = {
            "policy_file": attempt.policy_file,
            "model_provider": attempt.model_provider,
            "model_identifier": attempt.model_identifier,
            "role": attempt.role,
            "context": _plain_json(entry["context"]),
            "enforcement_result": "FAIL",
            "failures": [
                {
                    "code": code,
                    "message": message,
                    "field": None,
                }
            ],
            "failure_gate": "wrapped_function_error",
            "failure_reason": message,
            "metadata": metadata,
        }
        try:
            finalize_legacy_invocation_artifact(
                artifact,
                attempt=attempt,
                terminal=TerminalClass.EXECUTION_FAILURE,
            )
        except _EvidenceAbort as abort:
            error = abort.error
            error.__cause__ = None
            raise error

    def _finalize_dynamic_stateful_failure(
        self,
        entry: dict[str, Any],
        exc: AIGCError,
    ) -> None:
        """Terminalize a dispatched dynamic tool denial with state evidence."""
        from aegis._internal.enforcement import _map_exception_to_failure_gate

        attempt = entry["attempt"]
        code, message = _safe_attempt_failure(exc)
        artifact = {
            "policy_file": attempt.policy_file,
            "model_provider": attempt.model_provider,
            "model_identifier": attempt.model_identifier,
            "role": attempt.role,
            "context": _plain_json(entry["context"]),
            "enforcement_result": "FAIL",
            "failures": [{"code": code, "message": message, "field": None}],
            "failure_gate": _map_exception_to_failure_gate(exc),
            "failure_reason": message,
            "metadata": {
                "enforcement_mode": "split",
                "stateful_decisions": _plain_json(
                    entry.get("stateful_decisions") or []
                ),
            },
        }
        with self._attempt_finalization_scope(entry["step_index"], attempt):
            try:
                finalized = finalize_legacy_invocation_artifact(
                    artifact,
                    attempt=attempt,
                    terminal=TerminalClass.DENY,
                )
            except _EvidenceAbort as abort:
                error = abort.error
                error.__cause__ = None
                raise error
        exc.audit_artifact = finalized

    # ------------------------------------------------------------------
    # Step enforcement
    # ------------------------------------------------------------------

    def _assert_handle_shape(self, session_result: SessionPreCallResult) -> None:
        if not isinstance(session_result, SessionPreCallResult):
            raise InvocationValidationError(
                "Session operation handle is invalid",
                code="OPERATION_HANDLE_INVALID",
                details={"received_type": type(session_result).__name__},
            )
        if (
            not isinstance(session_result.session_id, str)
            or not isinstance(session_result.step_id, str)
            or (
                session_result.participant_id is not None
                and not isinstance(session_result.participant_id, str)
            )
            or not isinstance(session_result.operation_id, str)
            or not isinstance(session_result.issuer_id, str)
            or type(session_result.process_id) is not int
            or not isinstance(session_result.correlation_id, str)
            or not isinstance(session_result.policy_digest, str)
            or not isinstance(session_result.canonicalization_profile, str)
            or type(session_result.step_index) is not int
            or session_result.step_index < 0
        ):
            raise InvocationValidationError(
                "Session operation handle fields are invalid",
                code="OPERATION_HANDLE_INVALID",
            )

    def _assert_owns(self, session_result: SessionPreCallResult) -> None:
        self._assert_handle_shape(session_result)
        if session_result.session_id != self._session_id:
            raise InvocationValidationError(
                "Token belongs to a different session",
                details={
                    "token_session_id": session_result.session_id,
                    "this_session_id": self._session_id,
                },
            )

    def _emit_post_validation_failure(
        self,
        exc: InvocationValidationError,
    ) -> None:
        self._aigc._reject_consumed_post_call(exc)

    def _consume_post_call_operation(
        self,
        session_result: SessionPreCallResult,
    ) -> OperationRecord:
        """Consume one authenticated session operation before Phase B parsing."""
        from aegis._internal.enforcement import _operation_handle

        operation_id = session_result.operation_id
        try:
            record = self._aigc._operation_registry.consume(
                _operation_handle(_inner_result(session_result)),
            )
        except BaseException as exc:
            self._aigc._operation_registry.cancel_operation(operation_id)
            self._pending_results.pop(operation_id, None)
            self._adapter_step_states.pop(operation_id, None)
            if isinstance(exc, InvocationValidationError):
                self._aigc._reject_consumed_post_call(exc)
            raise

        self._pending_results.pop(operation_id, None)
        self._adapter_step_states.pop(operation_id, None)
        return record

    @_session_locked
    def authorize_step_tool_call(
        self,
        session_result: SessionPreCallResult,
        *,
        tool_name: str,
        tool_call_id: str | None = None,
    ) -> None:
        """Authorize a dynamic tool call within an open governed step (adapter seam).

        Called by adapters (e.g. ``OpenAIAgentsAdapter``) for each intercepted
        tool call.  Enforces the session tool-call budget and records summary
        evidence.  Does NOT enforce per-step tool allow-lists — the adapter is
        responsible for surface-level filtering before calling this method.

        :param session_result: Token from ``enforce_step_pre_call``.
        :param tool_name: Name of the tool being authorized.
        :param tool_call_id: Optional opaque call identifier for evidence.
        :raises SessionStateError: if the session is not OPEN or PAUSED.
        :raises WorkflowSessionTokenInvalidError: if the token is not registered.
        :raises InvocationValidationError: if adapter state has not been registered for this token.
        :raises WorkflowToolBudgetExceededError: if the session budget is exhausted.
        """
        self._assert_open()
        self._assert_owns(session_result)

        if session_result.operation_id not in self._pending_results:
            from aegis._internal.errors import WorkflowSessionTokenInvalidError
            raise WorkflowSessionTokenInvalidError(
                "Token not registered in this session",
                details={"operation_id": session_result.operation_id},
            )

        adapter_state = self._adapter_step_states.get(session_result.operation_id)
        if adapter_state is None:
            raise InvocationValidationError(
                "authorize_step_tool_call requires adapter state to be registered; "
                "call register_adapter_step_state before authorizing tool calls",
                details={"operation_id": session_result.operation_id},
            )
        from aegis._internal.enforcement import _operation_handle

        def _authorize_active_record(record: Any) -> None:
            from aegis._internal.errors import StateProviderContractError
            from aegis._internal.stateful_enforcement import (
                MAX_STATEFUL_DECISIONS,
            )

            observed_tool_calls = list(
                adapter_state.get("dynamic_tool_calls") or []
            )
            projected_call = {"name": tool_name, "id": tool_call_id}
            validate_tool_constraints(
                {"tool_calls": [*observed_tool_calls, projected_call]},
                record.compiled_policy.tools,
            )
            projected = self._total_tool_calls_consumed + 1
            if (
                self._max_total_tool_calls is not None
                and projected > self._max_total_tool_calls
            ):
                from aegis._internal.errors import (
                    WorkflowToolBudgetExceededError,
                )
                raise WorkflowToolBudgetExceededError(
                    f"Session tool-call budget exceeded (dynamic): "
                    f"max_total_tool_calls={self._max_total_tool_calls}, "
                    f"current={self._total_tool_calls_consumed}",
                    details={
                        "session_id": self._session_id,
                        "max_total_tool_calls": self._max_total_tool_calls,
                        "total_tool_calls_consumed": (
                            self._total_tool_calls_consumed
                        ),
                        "tool_name": tool_name,
                    },
                )

            pending = self._pending_results[session_result.operation_id]
            if len(pending.get("stateful_decisions") or ()) >= MAX_STATEFUL_DECISIONS:
                raise StateProviderContractError({"reason": "evidence_capacity"})

            stateful_decisions = self._aigc._admit_stateful_tool_call(
                record.compiled_policy,
                tool_name,
                state_scope=self._state_scope,
            )
            if stateful_decisions:
                pending.setdefault("stateful_decisions", []).extend(
                    stateful_decisions
                )

            self._total_tool_calls_consumed += 1
            adapter_state["dynamic_tool_calls_count"] = (
                adapter_state.get("dynamic_tool_calls_count", 0) + 1
            )
            adapter_state.setdefault("dynamic_tool_calls", []).append({
                "name": tool_name,
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                "authorized_at": int(time.time()),
            })

        try:
            self._aigc._operation_registry.apply(
                _operation_handle(_inner_result(session_result)),
                _authorize_active_record,
            )
        except AIGCError as exc:
            attached = getattr(exc, "stateful_decisions", None)
            if not attached:
                raise
            entry = self._pending_results[session_result.operation_id]
            entry.setdefault("stateful_decisions", []).extend(
                _plain_json(list(attached))
            )
            self._aigc._operation_registry.cancel_operation(
                session_result.operation_id
            )
            self._pending_results.pop(session_result.operation_id, None)
            self._adapter_step_states.pop(session_result.operation_id, None)
            self._finalize_dynamic_stateful_failure(entry, exc)
            raise

    def _discard_pending_step(
        self,
        session_result: SessionPreCallResult,
        *,
        rollback_authorization: bool = False,
    ) -> None:
        """Internal adapter seam: invalidate a pending step without Phase B.

        ``rollback_authorization=True`` decrements ``_authorized_step_count`` only
        when the token is still pending (not yet consumed).  It is a no-op for
        Phase-B failure paths because ``enforce_step_post_call`` marks the token
        consumed before raising, causing the early-return below.  This is
        intentional: ``_authorized_step_count`` tracks steps that *passed Phase A*,
        not steps that completed Phase B.  A failed Phase-B attempt still consumed
        an authorization slot.
        """
        self._assert_open()
        self._assert_owns(session_result)

        operation_id = session_result.operation_id
        entry = self._pending_results.get(operation_id)
        if entry is None:
            return

        self._aigc._operation_registry.cancel_operation(operation_id)
        self._finalize_canceled_entry(entry)
        self._pending_results.pop(operation_id, None)
        self._adapter_step_states.pop(operation_id, None)

        if rollback_authorization and self._authorized_step_count > 0:
            self._authorized_step_count -= 1

    @_session_locked
    def enforce_step_pre_call(
        self,
        invocation: dict[str, Any],
        *,
        step_id: str | None = None,
        participant_id: str | None = None,
    ) -> SessionPreCallResult:
        """Enforce Phase A governance for one workflow step.

        :param invocation: Invocation dict (same fields as enforce_pre_call)
        :param step_id: Caller-supplied step identifier; UUID4 generated if omitted
        :param participant_id: Optional participant identifier
        :return: SessionPreCallResult token (pass to enforce_step_post_call)
        """
        self._assert_attempt_capacity()
        raw_step_id: object = (
            str(uuid.uuid4()) if step_id is None else step_id
        )
        resolved_step_id, step_id_valid = _safe_workflow_identity(raw_step_id)
        if participant_id is None:
            resolved_participant_id = None
            participant_id_valid = True
        else:
            (
                resolved_participant_id,
                participant_id_valid,
            ) = _safe_workflow_identity(participant_id)
        attempt = self._aigc._attempt_factory.allocate(
            "GovernanceSession.enforce_step_pre_call",
            "workflow",
            invocation,
        )
        step_index = self._allocate_step_index(
            resolved_step_id,
            attempt.attempt_id,
            participant_id=resolved_participant_id,
            role=attempt.role,
        )
        self._bind_policy_correlation_digest(
            step_index,
            self._resolve_policy_correlation_digest(attempt.policy_file),
        )
        with self._attempt_finalization_scope(step_index, attempt):
            try:
                if not step_id_valid or not participant_id_valid:
                    raise InvocationValidationError(
                        "Workflow step identity must be a non-empty bounded "
                        "v2 string",
                        code="WORKFLOW_STEP_IDENTITY_INVALID",
                    )
                try:
                    normalized_invocation = normalize_json_v2(invocation)
                except (MemoryError, RecursionError) as exc:
                    raise InvocationValidationError(
                        "Invocation exceeds the v2 normalization boundary",
                        code="INVOCATION_CANONICALIZATION_FAILED",
                    ) from exc
                if type(normalized_invocation) is not dict:
                    raise InvocationValidationError(
                        "Invocation must be a plain v2 JSON object",
                        code="INVOCATION_CANONICALIZATION_FAILED",
                    )
                return self._enforce_step_pre_call_attempt(
                    normalized_invocation,
                    step_id=(resolved_step_id if step_id is not None else None),
                    resolved_step_id=resolved_step_id,
                    participant_id=resolved_participant_id,
                    attempt=attempt,
                    step_index=step_index,
                )
            except BaseException as exc:
                if isinstance(exc, _EvidenceAbort):
                    error = exc.error
                    error.__cause__ = None
                    raise error
                with self._attempt_lock:
                    finalization_started = (
                        self._attempts[step_index].state
                        is not AttemptFinalizationState.ALLOCATED
                    )
                if not finalization_started:
                    try:
                        self._finalize_rejected_attempt(
                            invocation,
                            resolved_step_id=resolved_step_id,
                            participant_id=resolved_participant_id,
                            attempt=attempt,
                            step_index=step_index,
                            exc=exc,
                        )
                    except _EvidenceAbort as abort:
                        error = abort.error
                        error.__cause__ = None
                        raise error
                raise

    def _enforce_step_pre_call_attempt(
        self,
        invocation: dict[str, Any],
        *,
        step_id: str | None,
        resolved_step_id: str,
        participant_id: str | None,
        attempt: Any,
        step_index: int,
    ) -> SessionPreCallResult:
        """Run Phase A after the session attempt identity is bound."""
        self._assert_accepting_new_step()

        # Budget check: max_steps (Fix 4: raise WorkflowStepBudgetExceededError,
        # not WorkflowToolBudgetExceededError, so doctor gives the right remediation)
        if (
            self._max_steps is not None
            and self._authorized_step_count >= self._max_steps
        ):
            from aegis._internal.errors import WorkflowStepBudgetExceededError
            raise WorkflowStepBudgetExceededError(
                f"Session step budget exceeded: max_steps={self._max_steps}, "
                f"authorized={self._authorized_step_count}",
                details={
                    "session_id": self._session_id,
                    "max_steps": self._max_steps,
                    "authorized_step_count": self._authorized_step_count,
                },
            )

        # 5A1: Participant enforcement
        if self._participants_by_id:
            from aegis._internal.errors import WorkflowParticipantMismatchError
            if participant_id is None:
                raise WorkflowParticipantMismatchError(
                    "participants declared in policy but no participant_id supplied for this step",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "reason_code": "WORKFLOW_PARTICIPANT_ID_REQUIRED",
                    },
                )
            if participant_id not in self._participants_by_id:
                raise WorkflowParticipantMismatchError(
                    f"participant_id={participant_id!r} not in declared participants",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "participant_id": participant_id,
                        "declared_participant_ids": list(self._participants_by_id),
                    },
                )
            _part = self._participants_by_id[participant_id]
            _part_roles = _part.get("roles")
            _invoc_role = invocation.get("role")
            if _part_roles and _invoc_role not in _part_roles:
                raise WorkflowParticipantMismatchError(
                    f"invocation role={_invoc_role!r} not in participant "
                    f"{participant_id!r} allowed roles: {_part_roles}",
                    details={
                        "session_id": self._session_id,
                        "participant_id": participant_id,
                        "invocation_role": _invoc_role,
                        "allowed_roles": _part_roles,
                        "reason_code": "WORKFLOW_PARTICIPANT_ROLE_MISMATCH",
                    },
                )

        # 5B: Required sequence enforcement
        if (
            self._required_sequence is not None
            and self._sequence_position < len(self._required_sequence)
        ):
            from aegis._internal.errors import WorkflowSequenceViolationError
            expected_step_id = self._required_sequence[self._sequence_position]
            if step_id is None:
                raise WorkflowSequenceViolationError(
                    f"required_sequence declared: step_id is required at position "
                    f"{self._sequence_position} (expected {expected_step_id!r})",
                    details={
                        "session_id": self._session_id,
                        "sequence_position": self._sequence_position,
                        "expected_step_id": expected_step_id,
                        "reason_code": "WORKFLOW_SEQUENCE_STEP_ID_REQUIRED",
                    },
                )
            if resolved_step_id != expected_step_id:
                raise WorkflowSequenceViolationError(
                    f"required_sequence violation: expected "
                    f"step_id={expected_step_id!r} at position "
                    f"{self._sequence_position}, got {resolved_step_id!r}",
                    details={
                        "session_id": self._session_id,
                        "sequence_position": self._sequence_position,
                        "expected_step_id": expected_step_id,
                        "actual_step_id": resolved_step_id,
                    },
                )
            # Do NOT advance _sequence_position here — advance in post_call on success

        # 5C: Allowed transitions enforcement
        if self._allowed_transitions is not None and self._last_completed_step_id is not None:
            from aegis._internal.errors import WorkflowTransitionDeniedError
            if step_id is None:
                raise WorkflowTransitionDeniedError(
                    "allowed_transitions declared: step_id is required to verify transition",
                    details={
                        "session_id": self._session_id,
                        "last_completed_step_id": self._last_completed_step_id,
                        "reason_code": "WORKFLOW_TRANSITION_STEP_ID_REQUIRED",
                    },
                )
            _allowed_to = self._allowed_transitions.get(self._last_completed_step_id, [])
            if resolved_step_id not in _allowed_to:
                raise WorkflowTransitionDeniedError(
                    f"Transition from {self._last_completed_step_id!r} to {resolved_step_id!r} "
                    f"is not in allowed_transitions",
                    details={
                        "session_id": self._session_id,
                        "from_step_id": self._last_completed_step_id,
                        "to_step_id": resolved_step_id,
                        "allowed_transitions": _allowed_to,
                    },
                )
        # Note: first step (_last_completed_step_id is None) has no transition check

        # 5D: Allowed agent roles enforcement
        if self._allowed_agent_roles is not None:
            from aegis._internal.errors import WorkflowRoleViolationError
            _invoc_role = invocation.get("role")
            if _invoc_role not in self._allowed_agent_roles:
                raise WorkflowRoleViolationError(
                    f"invocation role={_invoc_role!r} not in "
                    f"allowed_agent_roles: {self._allowed_agent_roles}",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "invocation_role": _invoc_role,
                        "allowed_agent_roles": self._allowed_agent_roles,
                    },
                )

        # 5E: Protocol constraints enforcement
        if self._protocol_constraints is not None:
            from aegis._internal.errors import WorkflowProtocolViolationError
            _ctx_value = invocation.get("context")
            if _ctx_value is None:
                _ctx = {}
            elif isinstance(_ctx_value, MappingABC):
                _ctx = _ctx_value
            else:
                raise WorkflowProtocolViolationError(
                    "invocation['context'] must be a mapping when "
                    "protocol_constraints are declared",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "context_type": type(_ctx_value).__name__,
                        "reason_code": "WORKFLOW_PROTOCOL_CONTEXT_INVALID",
                    },
                )
            _top_protocol = invocation.get("protocol")
            _context_protocol = _ctx.get("protocol")
            if (
                _top_protocol is not None
                and _context_protocol is not None
                and _top_protocol != _context_protocol
            ):
                raise WorkflowProtocolViolationError(
                    "Conflicting protocol declarations in invocation['protocol'] "
                    "and invocation['context']['protocol']",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "protocol": _top_protocol,
                        "context_protocol": _context_protocol,
                        "reason_code": "WORKFLOW_PROTOCOL_CONFLICT",
                    },
                )
            _protocol = _top_protocol or _context_protocol
            if _protocol is None:
                raise WorkflowProtocolViolationError(
                    "protocol_constraints declared but no protocol specified in invocation "
                    "(set invocation['protocol'] or invocation['context']['protocol'])",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "reason_code": "WORKFLOW_PROTOCOL_REQUIRED",
                    },
                )
            if _protocol not in self._protocol_constraints:
                raise WorkflowProtocolViolationError(
                    f"Protocol {_protocol!r} not in declared protocol_constraints sections: "
                    f"{list(self._protocol_constraints)}",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "protocol": _protocol,
                        "declared_protocols": list(self._protocol_constraints),
                    },
                )
            _proto_evidence = _ctx.get("protocol_evidence")
            if not isinstance(_proto_evidence, dict) or _protocol not in _proto_evidence:
                raise WorkflowProtocolViolationError(
                    f"No evidence for protocol {_protocol!r} in context['protocol_evidence']",
                    details={
                        "session_id": self._session_id,
                        "step_id": resolved_step_id,
                        "protocol": _protocol,
                    },
                )
            # Participant protocol check
            if participant_id and self._participants_by_id:
                _part = self._participants_by_id.get(participant_id)
                if _part:
                    _part_protos = _part.get("protocols")
                    if _part_protos and _protocol not in _part_protos:
                        raise WorkflowProtocolViolationError(
                            f"Protocol {_protocol!r} not in participant "
                            f"{participant_id!r} allowed protocols",
                            details={
                                "session_id": self._session_id,
                                "participant_id": participant_id,
                                "protocol": _protocol,
                                "allowed_protocols": _part_protos,
                            },
                        )
            # Protocol-family-specific runtime checks
            _evidence_for_protocol = _proto_evidence.get(_protocol, {})
            if _protocol == "bedrock":
                # Alias-backed identity required when participant declares bedrock protocol
                if participant_id and self._participants_by_id:
                    _part = self._participants_by_id.get(participant_id)
                    if _part and "bedrock" in (_part.get("protocols") or []):
                        if not _evidence_for_protocol.get("alias_backed"):
                            raise WorkflowProtocolViolationError(
                                "Bedrock governed binding requires alias-backed identity; "
                                "set context['protocol_evidence']"
                                "['bedrock']['alias_backed'] = True",
                                details={
                                    "session_id": self._session_id,
                                    "participant_id": participant_id,
                                    "protocol": "bedrock",
                                },
                            )
            elif _protocol == "a2a":
                _raw_a2a_constraints = self._protocol_constraints.get("a2a")
                if _raw_a2a_constraints is None:
                    _raw_a2a_constraints = {}
                _a2a_constraints = _a2a_protocol_constraints(
                    _raw_a2a_constraints,
                    session_id=self._session_id,
                    step_id=resolved_step_id,
                )
                _validate_a2a_protocol_evidence(
                    _evidence_for_protocol,
                    _a2a_constraints,
                    session_id=self._session_id,
                    step_id=resolved_step_id,
                )

        # 5F: Handoffs enforcement
        if (
            self._handoffs is not None
            and self._last_completed_participant_id is not None
            and participant_id is not None
            and self._last_completed_participant_id != participant_id
        ):
            from aegis._internal.errors import WorkflowHandoffDeniedError
            _allowed_handoffs = {(h["from"], h["to"]) for h in self._handoffs}
            if (self._last_completed_participant_id, participant_id) not in _allowed_handoffs:
                raise WorkflowHandoffDeniedError(
                    f"Handoff from participant {self._last_completed_participant_id!r} to "
                    f"{participant_id!r} is not in allowed handoffs",
                    details={
                        "session_id": self._session_id,
                        "from_participant_id": self._last_completed_participant_id,
                        "to_participant_id": participant_id,
                    },
                )

        # 5G: Escalation enforcement
        if self._escalation is not None and self._state == STATE_OPEN:
            from aegis._internal.errors import WorkflowApprovalRequiredError
            _esc_n = self._escalation.get("require_approval_after_steps")
            _esc_roles = self._escalation.get("require_approval_for_roles") or []
            _invoc_role_esc = invocation.get("role")
            _need_approval = False
            _esc_reason = None
            _esc_rule = None
            # Skip re-firing escalation if already in progress for this step
            # (post-resume retry). Once the step succeeds in enforce_step_post_call,
            # _escalation_in_progress is cleared so the next trigger fires normally.
            if self._escalation_in_progress:
                _need_approval = False
            else:
                if (
                    _esc_n is not None
                    and self._authorized_step_count > 0
                    and self._authorized_step_count % _esc_n == 0
                ):
                    _need_approval = True
                    _esc_reason = f"Escalation: approval required after every {_esc_n} steps"
                    _esc_rule = f"require_approval_after_steps={_esc_n}"
                if _esc_roles and _invoc_role_esc in _esc_roles:
                    _need_approval = True
                    _esc_reason = f"Escalation: approval required for role {_invoc_role_esc!r}"
                    _esc_rule = f"require_approval_for_roles includes {_invoc_role_esc!r}"
            if _need_approval:
                _esc_checkpoint_id = str(uuid.uuid4())
                self._escalation_in_progress = True
                self.pause(
                    approval_id=_esc_checkpoint_id,
                    reason=_esc_reason,
                )
                raise WorkflowApprovalRequiredError(
                    _esc_reason or "Escalation: approval required",
                    details={
                        "session_id": self._session_id,
                        "checkpoint_id": _esc_checkpoint_id,
                        "escalation_rule": _esc_rule,
                    },
                )

        # Build enriched invocation: apply session-level policy override, then
        # inject workflow correlation fields into context
        enriched = dict(invocation)
        if self._policy_file is not None:
            enriched["policy_file"] = self._policy_file
        effective_policy_file: str | None = enriched.get("policy_file")

        _ctx_raw = enriched.get("context")
        if _ctx_raw is None:
            ctx: dict[str, Any] = {}
        elif isinstance(_ctx_raw, MappingABC):
            ctx = dict(_ctx_raw)
        else:
            raise InvocationValidationError(
                "invocation['context'] must be a mapping",
                details={
                    "session_id": self._session_id,
                    "step_id": resolved_step_id,
                    "context_type": type(_ctx_raw).__name__,
                    "reason_code": "WORKFLOW_PROTOCOL_CONTEXT_INVALID",
                },
            )
        ctx["session_id"] = self._session_id
        ctx["step_id"] = resolved_step_id
        ctx["step_index"] = step_index
        ctx.pop("workflow_policy_digest", None)
        ctx.pop("participant_id", None)
        with self._attempt_lock:
            workflow_policy_digest = self._attempts[
                step_index
            ].workflow_policy_digest
        if workflow_policy_digest is None:  # pragma: no cover - allocation invariant
            raise SessionStateError(
                "Workflow policy correlation was not bound",
                code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
            )
        ctx["workflow_policy_digest"] = workflow_policy_digest
        if participant_id is not None:
            ctx["participant_id"] = participant_id
        enriched["context"] = ctx

        # Budget check: max_total_tool_calls counted from invocation at pre_call time
        # (Fix 2: invocation-time count matches existing tools.py contract and audit
        # evidence — never count from output)
        _tool_calls_this_step = len(enriched.get("tool_calls") or [])
        _projected_total = self._total_tool_calls_consumed + _tool_calls_this_step
        if (
            self._max_total_tool_calls is not None
            and _projected_total > self._max_total_tool_calls
        ):
            from aegis._internal.errors import WorkflowToolBudgetExceededError
            raise WorkflowToolBudgetExceededError(
                f"Session tool-call budget exceeded: "
                f"max_total_tool_calls={self._max_total_tool_calls}, "
                f"projected={_projected_total}",
                details={
                    "session_id": self._session_id,
                    "max_total_tool_calls": self._max_total_tool_calls,
                    "total_tool_calls_consumed": self._total_tool_calls_consumed,
                    "tool_calls_this_step": _tool_calls_this_step,
                },
            )

        effective_policy = self._aigc._prepare_pre_call_policy(
            enriched,
            policy=self._compiled_policy,
        )
        if effective_policy.policy_digest != workflow_policy_digest:
            raise SessionStateError(
                "Workflow policy changed after attempt correlation",
                code="SESSION_ATTEMPT_ORIGIN_MISMATCH",
            )

        def _run_session_hooks() -> None:
            # Hooks run after ordinary stateless Phase A but before the final
            # stateful admission and operation-handle issuance.
            if not self._validator_hooks:
                return
            from aegis._internal.validator_hook import (
                ValidatorHookEnvelope,
                _invoke_hook,
                normalize_hook_result,
            )
            from aegis._internal.errors import WorkflowHookDeniedError
            for _hook in self._validator_hooks:
                _obs_at = int(time.time() * 1000)
                _envelope = ValidatorHookEnvelope(
                    hook_schema_version="1.0",
                    session_id=self._session_id,
                    step_id=resolved_step_id,
                    participant_id=participant_id,
                    invocation=enriched,
                    deadline_ms=_hook.timeout_ms,
                    observed_at=_obs_at,
                    policy_file=effective_policy_file,
                    invocation_checksum=_checksum(enriched),
                )
                _result = _invoke_hook(_hook, _envelope)
                _outcome = normalize_hook_result(_result)
                self._validator_hook_evidence.append({
                    "hook_id": _result.hook_id,
                    "hook_version": _result.hook_version,
                    "step_id": resolved_step_id,
                    "decision": _result.decision,
                    "reason_code": _outcome.reason_code,
                    "explanation": _result.explanation,
                    "attempt": _result.attempt,
                    "latency_ms": _result.latency_ms,
                    "observed_at": _result.observed_at,
                    "stale_result": _result.stale_result,
                    "provenance": _result.provenance,
                })
                if not _outcome.allows_continuation:
                    raise WorkflowHookDeniedError(
                        f"Validator hook {_result.hook_id!r} blocked step "
                        f"{resolved_step_id!r}: terminal="
                        f"{_outcome.terminal.value!r}, "
                        f"reason_code={_outcome.reason_code!r}",
                        details={
                            "session_id": self._session_id,
                            "step_id": resolved_step_id,
                            "hook_id": _result.hook_id,
                            "decision": _result.decision,
                            "reason_code": _outcome.reason_code,
                            "terminal": _outcome.terminal.value,
                        },
                    )

        inner_result = self._aigc._enforce_pre_call_compiled(
            enriched,
            effective_policy,
            state_scope=self._state_scope,
            before_stateful=_run_session_hooks,
        )

        from aegis._internal.enforcement import _operation_handle

        static_stateful_decisions = self._aigc._operation_registry.apply(
            _operation_handle(inner_result),
            lambda record: _plain_json(record.phase_a_metadata).get(
                "stateful_decisions", []
            ),
        )

        self._pending_results[inner_result.operation_id] = {
            "step_id": resolved_step_id,
            "participant_id": participant_id,
            "effective_policy_file": effective_policy_file,
            "tool_calls_count": _tool_calls_this_step,
            "step_index": step_index,
            "attempt": attempt,
            "context": _frozen_mapping(ctx),
            "static_stateful_decisions": static_stateful_decisions,
        }

        # Increment only after all checks pass — pre-call rejection must not
        # corrupt the authorized step counter.  Counts "steps authorized" (Phase A
        # passed), not "steps completed" (Phase B passed).
        self._authorized_step_count += 1

        return SessionPreCallResult(
            session_id=self._session_id,
            step_id=resolved_step_id,
            participant_id=participant_id,
            operation_id=inner_result.operation_id,
            issuer_id=inner_result.issuer_id,
            process_id=inner_result.process_id,
            correlation_id=inner_result.correlation_id,
            policy_digest=inner_result.policy_digest,
            canonicalization_profile=inner_result.canonicalization_profile,
            step_index=step_index,
        )

    @_session_locked
    def enforce_step_post_call(
        self,
        session_result: SessionPreCallResult,
        output: dict[str, Any],
        *,
        step_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Enforce Phase B governance for one workflow step.

        :param session_result: Token from enforce_step_pre_call
        :param output: Model output dict
        :param step_metadata: Optional host-supplied metadata stored under
            ``steps[i]["metadata"]`` in the workflow artifact (additive only;
            does not alter existing step keys). AEGIS records this but does not
            interpret it at runtime.
        :return: Invocation PASS audit artifact
        """
        try:
            self._assert_handle_shape(session_result)
        except InvocationValidationError as exc:
            self._emit_post_validation_failure(exc)
            raise

        operation_id = session_result.operation_id
        entry = self._pending_results.get(operation_id)
        if entry is None:
            exc = InvocationValidationError(
                "Operation belongs to a different session, is unknown, or "
                "has been consumed",
                code="OPERATION_NOT_ACTIVE",
                details={"operation_id": operation_id},
            )
            self._emit_post_validation_failure(exc)
            raise exc
        if (
            session_result.session_id != self._session_id
            or session_result.step_id != entry["step_id"]
            or session_result.participant_id != entry["participant_id"]
            or session_result.step_index != entry["step_index"]
        ):
            exc = InvocationValidationError(
                "Session operation metadata does not match minted values",
                code="OPERATION_SESSION_METADATA_MISMATCH",
                details={
                    "session_id": self._session_id,
                    "registered_step_id": entry["step_id"],
                },
            )
            self._emit_post_validation_failure(exc)
            raise exc
        with self._attempt_finalization_scope(
            entry["step_index"],
            entry["attempt"],
        ):
            try:
                return self._enforce_step_post_call_attempt(
                    session_result,
                    output,
                    step_metadata=step_metadata,
                    entry=entry,
                )
            except _EvidenceAbort as abort:
                error = abort.error
                error.__cause__ = None
                raise error
            except (AuditSinkError, EvidenceFinalizationError):
                # The instance evidence boundary already diagnosed this one
                # finalization attempt.  A fallback emission would double-count
                # the same delivery/finalization failure.
                raise
            except BaseException as exc:
                with self._attempt_lock:
                    finalization_started = (
                        self._attempts[entry["step_index"]].state
                        is not AttemptFinalizationState.ALLOCATED
                    )
                if not finalization_started:
                    self._aigc._operation_registry.cancel_operation(operation_id)
                    self._pending_results.pop(operation_id, None)
                    self._adapter_step_states.pop(operation_id, None)
                    self._finalize_internal_phase_b_failure(entry, exc)
                raise

    def _enforce_step_post_call_attempt(
        self,
        session_result: SessionPreCallResult,
        output: dict[str, Any],
        *,
        step_metadata: dict[str, Any] | None,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Run Phase B while its allocated session attempt is bound."""
        self._assert_open()

        # Pop first: no caller-controlled wrapper, metadata, or output field is
        # interpreted until this authenticated attempt owns the operation.
        record = self._consume_post_call_operation(session_result)

        dynamic_stateful_decisions = entry.get("stateful_decisions") or []
        if dynamic_stateful_decisions:
            from aegis._internal.compiled_policy import freeze
            phase_a_metadata = _plain_json(record.phase_a_metadata)
            phase_a_metadata["stateful_decisions"] = [
                *phase_a_metadata.get("stateful_decisions", ()),
                *dynamic_stateful_decisions,
            ]
            record = replace(
                record,
                phase_a_metadata=freeze(phase_a_metadata),
            )

        if (
            session_result.session_id != self._session_id
            or session_result.step_id != entry["step_id"]
            or session_result.participant_id != entry["participant_id"]
            or session_result.step_index != entry["step_index"]
        ):
            self._aigc._reject_consumed_post_call(
                InvocationValidationError(
                    "Session operation metadata does not match minted values",
                    code="OPERATION_SESSION_METADATA_MISMATCH",
                    details={
                        "session_id": self._session_id,
                        "registered_step_id": entry["step_id"],
                    },
                ),
                record,
            )

        if step_metadata is not None and not isinstance(step_metadata, dict):
            self._aigc._reject_consumed_post_call(
                InvocationValidationError(
                    "step_metadata must be a mapping when provided",
                    details={
                        "session_id": self._session_id,
                        "step_id": entry["step_id"],
                        "metadata_type": type(step_metadata).__name__,
                    },
                ),
                record,
            )

        inv_artifact = self._aigc._enforce_consumed_post_call(record, output)

        # Increment tool-call counter from the invocation dict (consistent with
        # pre_call budget check — both use invocation-time count). Budget is
        # enforced entirely at pre-call; this increment can never exceed the limit.
        self._total_tool_calls_consumed += entry["tool_calls_count"]

        # Step record uses REGISTRY values — never trusts token fields after verification
        inv_checksum = _checksum(inv_artifact)
        step_record: dict[str, Any] = {
            "step_id": entry["step_id"],
            "participant_id": entry["participant_id"],
            "invocation_artifact_checksum": inv_checksum,
        }
        if step_metadata is not None:
            step_record["metadata"] = dict(step_metadata)
        self._steps.append(step_record)
        self._step_policy_files.append(entry["effective_policy_file"])

        # Advance tracking state for sequence, transitions, and handoffs
        self._sequence_position += 1
        self._last_completed_step_id = entry["step_id"]
        self._last_completed_participant_id = entry["participant_id"]
        self._escalation_in_progress = False  # Step completed — clear escalation gate

        return inv_artifact
