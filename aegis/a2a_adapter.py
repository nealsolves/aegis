"""A2A adapter for AEGIS governance (source-only beta).

Not re-exported from the top-level ``aegis`` package.
No A2A SDK dependency is required; hosts may pass dictionaries, Pydantic-like
objects, or protobuf-like objects converted lazily when protobuf support is
available.

AEGIS owns governance validation and additive workflow evidence. The host owns
A2A transport, Agent Card discovery, clients, retries, credentials, streaming,
task polling, task execution, and business state.
"""
from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from aegis._internal.errors import (
    InvocationValidationError,
    WorkflowParticipantMismatchError,
    WorkflowProtocolViolationError,
    WorkflowSessionTokenInvalidError,
    WorkflowUnsupportedBindingError,
)

if TYPE_CHECKING:
    from aegis._internal.session import GovernanceSession

logger = logging.getLogger(__name__)

_ADAPTER_VERSION = "0.9.0-beta"
_PROTOCOL_VERSION = "1.0"
_SUPPORTED_PROTOCOL_BINDINGS = frozenset({"JSONRPC", "HTTP+JSON"})
_GRPC_BINDINGS = frozenset({"grpc"})
_SECRET_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
)
_REQUEST_METADATA_STRING_PREVIEW = 128
_MAX_SKILL_SUMMARIES = 50
_MAX_TASK_UPDATE_SUMMARIES = 100

_TASK_STATES = frozenset({
    "TASK_STATE_UNSPECIFIED",
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_AUTH_REQUIRED",
})
# JSON wire values used by JSONRPC and HTTP+JSON transports (A2A spec §4).
# Maps to the canonical proto enum name stored in governance artifacts.
_JSON_TO_TASK_STATE: dict[str, str] = {
    "submitted": "TASK_STATE_SUBMITTED",
    "working": "TASK_STATE_WORKING",
    "completed": "TASK_STATE_COMPLETED",
    "failed": "TASK_STATE_FAILED",
    "canceled": "TASK_STATE_CANCELED",
    "input-required": "TASK_STATE_INPUT_REQUIRED",
    "rejected": "TASK_STATE_REJECTED",
    "auth-required": "TASK_STATE_AUTH_REQUIRED",
}
_TERMINAL_TASK_STATES = frozenset({
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
})


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _to_mapping(value: Mapping[str, Any] | Any, *, label: str) -> dict[str, Any]:
    """Normalize supported host-supplied objects into plain dictionaries."""
    if isinstance(value, MappingABC):
        return dict(value)

    if hasattr(value, "model_dump"):
        try:
            converted = value.model_dump(by_alias=True)
        except TypeError:
            converted = value.model_dump()
        except Exception as err:  # noqa: BLE001
            raise InvocationValidationError(
                f"{label} could not be converted with model_dump(by_alias=True)",
                details={"label": label},
            ) from err
        if not isinstance(converted, MappingABC):
            raise InvocationValidationError(
                f"{label} model_dump(by_alias=True) did not return a mapping",
                details={"label": label, "type": type(converted).__name__},
            )
        return dict(converted)

    if hasattr(value, "dict"):
        try:
            converted = value.dict(by_alias=True)
        except TypeError:
            converted = value.dict()
        except Exception as err:  # noqa: BLE001
            raise InvocationValidationError(
                f"{label} could not be converted with dict(by_alias=True)",
                details={"label": label},
            ) from err
        if not isinstance(converted, MappingABC):
            raise InvocationValidationError(
                f"{label} dict(by_alias=True) did not return a mapping",
                details={"label": label, "type": type(converted).__name__},
            )
        return dict(converted)

    if hasattr(value, "DESCRIPTOR"):
        try:
            from google.protobuf.json_format import MessageToDict
        except ImportError as err:
            raise InvocationValidationError(
                f"{label} is protobuf-like; pass a JSON/dict representation or "
                "install protobuf conversion support",
                details={"label": label, "type": type(value).__name__},
            ) from err
        converted = MessageToDict(value)
        if not isinstance(converted, MappingABC):
            raise InvocationValidationError(
                f"{label} protobuf conversion did not return a mapping",
                details={"label": label, "type": type(converted).__name__},
            )
        return dict(converted)

    raise InvocationValidationError(
        f"{label} must be a mapping or supported SDK model object",
        details={"label": label, "type": type(value).__name__},
    )


def _redacted_request_metadata(
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, MappingABC):
        raise InvocationValidationError(
            "request_metadata must be a mapping when provided",
            details={"type": type(metadata).__name__},
        )

    redacted: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key)
        key_lower = key_text.lower()
        if any(fragment in key_lower for fragment in _SECRET_KEY_FRAGMENTS):
            continue
        if not _is_scalar(value):
            continue
        if isinstance(value, str) and len(value) > _REQUEST_METADATA_STRING_PREVIEW:
            value = value[:_REQUEST_METADATA_STRING_PREVIEW] + "...[truncated]"
        redacted[key_text] = value
    return redacted


def _summarize_capabilities(capabilities: Any) -> dict[str, Any]:
    if not isinstance(capabilities, MappingABC):
        return {}
    return {
        str(key): value
        for key, value in capabilities.items()
        if _is_scalar(value)
    }


def _summarize_skills(agent_card: Mapping[str, Any]) -> list[dict[str, Any]]:
    skills = agent_card.get("skills")
    if skills is None:
        return []
    if not isinstance(skills, list):
        raise InvocationValidationError(
            "Agent Card skills must be a list when present",
            details={"reason_code": "WORKFLOW_PROTOCOL_A2A_AGENT_CARD_INVALID"},
        )

    summaries: list[dict[str, Any]] = []
    for index, skill in enumerate(skills):
        if not isinstance(skill, MappingABC):
            raise InvocationValidationError(
                "Agent Card skills entries must be mappings",
                details={
                    "skill_index": index,
                    "reason_code": "WORKFLOW_PROTOCOL_A2A_AGENT_CARD_INVALID",
                },
            )
        summary: dict[str, Any] = {}
        if _is_scalar(skill.get("id")):
            summary["id"] = skill.get("id")
        if _is_scalar(skill.get("name")):
            summary["name"] = skill.get("name")
        if "tags" in skill:
            tags = skill.get("tags")
            if not isinstance(tags, list) or not all(_is_scalar(tag) for tag in tags):
                raise InvocationValidationError(
                    "Agent Card skill tags must be a list of scalar values",
                    details={
                        "skill_index": index,
                        "reason_code": "WORKFLOW_PROTOCOL_A2A_AGENT_CARD_INVALID",
                    },
                )
            summary["tags"] = list(tags)
        input_modes = skill.get("inputModes")
        output_modes = skill.get("outputModes")
        if input_modes is not None:
            if not isinstance(input_modes, list):
                raise InvocationValidationError(
                    "Agent Card skill inputModes must be a list when present",
                    details={"skill_index": index},
                )
            summary["input_modes_count"] = len(input_modes)
        if output_modes is not None:
            if not isinstance(output_modes, list):
                raise InvocationValidationError(
                    "Agent Card skill outputModes must be a list when present",
                    details={"skill_index": index},
                )
            summary["output_modes_count"] = len(output_modes)
        if index < _MAX_SKILL_SUMMARIES:
            summaries.append(summary)
    return summaries


def _summarize_interfaces(agent_card: Mapping[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for interface in agent_card.get("supportedInterfaces") or []:
        summary: dict[str, Any] = {}
        if _is_scalar(interface.get("url")):
            summary["url"] = interface.get("url")
        if "protocolBinding" in interface:
            summary["protocolBinding"] = interface.get("protocolBinding")
        if "protocolVersion" in interface:
            summary["protocolVersion"] = interface.get("protocolVersion")
        summaries.append(summary)
    return summaries


def _workflow_protocol_error(
    message: str,
    *,
    reason_code: str,
    details: dict[str, Any] | None = None,
) -> WorkflowProtocolViolationError:
    error_details = {"protocol": "a2a", "reason_code": reason_code}
    if details:
        error_details.update(details)
    return WorkflowProtocolViolationError(message, details=error_details)


def _a2a_constraints(session: "GovernanceSession") -> dict[str, Any]:
    try:
        constraints = session.protocol_constraints_for("a2a")
    except Exception as err:  # noqa: BLE001
        raise _workflow_protocol_error(
            "A2A protocol constraints must be a mapping",
            reason_code="WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
        ) from err
    if not isinstance(constraints, MappingABC):
        raise _workflow_protocol_error(
            "A2A protocol constraints must be a mapping",
            reason_code="WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            details={"type": type(constraints).__name__},
        )
    version = constraints.get("protocol_version", _PROTOCOL_VERSION)
    allowed = constraints.get(
        "allowed_protocol_bindings",
        ["JSONRPC", "HTTP+JSON"],
    )
    require_task_state = constraints.get("require_task_state", True)

    if version != _PROTOCOL_VERSION:
        raise _workflow_protocol_error(
            "A2A protocol_version must be '1.0'",
            reason_code="WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            details={"protocol_version": version},
        )
    if (
        not isinstance(allowed, (list, tuple))
        or not allowed
        or len(set(allowed)) != len(allowed)
        or any(binding not in _SUPPORTED_PROTOCOL_BINDINGS for binding in allowed)
    ):
        raise _workflow_protocol_error(
            "A2A allowed_protocol_bindings must contain unique JSONRPC or HTTP+JSON values",
            reason_code="WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            details={"allowed_protocol_bindings": allowed},
        )
    if not isinstance(require_task_state, bool):
        raise _workflow_protocol_error(
            "A2A require_task_state must be a boolean",
            reason_code="WORKFLOW_PROTOCOL_A2A_CONSTRAINTS_INVALID",
            details={"require_task_state": require_task_state},
        )

    return {
        "protocol_version": version,
        "allowed_protocol_bindings": list(allowed),
        "require_task_state": require_task_state,
    }


def _validate_agent_card(
    agent_card: Mapping[str, Any] | Any,
    constraints: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    card = _to_mapping(agent_card, label="agent_card")

    name = card.get("name")
    if not isinstance(name, str) or not name.strip():
        raise InvocationValidationError(
            "Agent Card name must be a non-empty string",
            details={"reason_code": "WORKFLOW_PROTOCOL_A2A_AGENT_CARD_INVALID"},
        )

    interfaces = card.get("supportedInterfaces")
    if not isinstance(interfaces, list) or not interfaces:
        raise _workflow_protocol_error(
            "A2A Agent Card must include a non-empty supportedInterfaces list",
            reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
        )

    required_version = constraints.get("protocol_version", _PROTOCOL_VERSION)
    allowed_bindings = constraints.get(
        "allowed_protocol_bindings",
        ["JSONRPC", "HTTP+JSON"],
    )
    version_match_seen = False

    for index, interface in enumerate(interfaces):
        if not isinstance(interface, MappingABC):
            raise InvocationValidationError(
                "Agent Card supportedInterfaces entries must be mappings",
                details={
                    "interface_index": index,
                    "reason_code": "WORKFLOW_PROTOCOL_A2A_AGENT_CARD_INVALID",
                },
            )
        interface_dict = dict(interface)
        binding = interface_dict.get("protocolBinding")
        version = interface_dict.get("protocolVersion")
        _binding_cf = binding.casefold() if isinstance(binding, str) else binding
        _transport_cf = interface_dict.get("transport")
        _transport_cf = _transport_cf.casefold() if isinstance(_transport_cf, str) else _transport_cf
        has_grpc_marker = (
            _binding_cf in _GRPC_BINDINGS
            or _transport_cf == "grpc"
        )
        # A gRPC interface at the required version (or the only interface) is
        # rejected. A gRPC interface at an *older* version alongside a valid
        # non-gRPC interface is intentionally skipped — it is not selected.
        if has_grpc_marker and (version == required_version or len(interfaces) == 1):
            raise _workflow_protocol_error(
                "gRPC transport is not supported for governed A2A in v0.9.0",
                reason_code="WORKFLOW_PROTOCOL_GRPC_UNSUPPORTED",
                details={"interface_index": index},
            )

        if version == required_version:
            version_match_seen = True
            if binding in allowed_bindings:
                return card, interface_dict

    if not version_match_seen:
        raise _workflow_protocol_error(
            "A2A compatibility must be proven from supportedInterfaces[].protocolVersion",
            reason_code="WORKFLOW_PROTOCOL_A2A_COMPATIBILITY_REQUIRED",
            details={"required_protocol_version": required_version},
        )

    raise _workflow_protocol_error(
        "A2A Agent Card has no supportedInterfaces[] entry with an allowed protocolBinding",
        reason_code="WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED",
        details={"allowed_protocol_bindings": list(allowed_bindings)},
    )


def _validate_task_state(state: Any, *, label: str) -> str:
    if not isinstance(state, str):
        raise _workflow_protocol_error(
            f"{label} must be one of the normative TASK_STATE_* values",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_INVALID",
            details={"task_state": state},
        )
    normalized = _JSON_TO_TASK_STATE.get(state, state)
    if normalized not in _TASK_STATES:
        raise _workflow_protocol_error(
            f"{label} must be one of the normative TASK_STATE_* values",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_INVALID",
            details={"task_state": state},
        )
    if normalized == "TASK_STATE_UNSPECIFIED":
        logger.warning("A2A task state TASK_STATE_UNSPECIFIED received")
    return normalized


def _validate_task_envelope(
    task: Mapping[str, Any] | Any | None,
    *,
    require_task_state: bool = True,
) -> dict[str, Any] | None:
    if task is None and not require_task_state:
        return None
    if task is None:
        raise _workflow_protocol_error(
            "A2A task_envelope is required by policy",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
        )

    try:
        task_map = _to_mapping(task, label="task_envelope")
    except InvocationValidationError as err:
        raise _workflow_protocol_error(
            "A2A task_envelope must be a mapping",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
            details={"type": type(task).__name__},
        ) from err

    status = task_map.get("status")
    if not isinstance(status, MappingABC):
        raise _workflow_protocol_error(
            "A2A task_envelope.status must be a mapping",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
        )
    if "state" not in status:
        raise _workflow_protocol_error(
            "A2A task_envelope.status.state is required",
            reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
        )
    normalized_state = _validate_task_state(
        status.get("state"), label="task_envelope.status.state"
    )
    if status.get("state") != normalized_state:
        task_map = dict(task_map)
        task_map["status"] = {**status, "state": normalized_state}
    return task_map


def _task_summary(task: Mapping[str, Any] | None) -> dict[str, Any]:
    if task is None:
        return {
            "task_id": None,
            "context_id": None,
            "task_state": None,
            "terminal": False,
            "artifact_count": 0,
            "history_count": 0,
        }

    status = task.get("status")
    state = status.get("state") if isinstance(status, MappingABC) else None
    artifacts = task.get("artifacts")
    history = task.get("history")
    task_id = task.get("id")
    context_id = task.get("contextId")

    return {
        "task_id": task_id if _is_scalar(task_id) else None,
        "context_id": context_id if _is_scalar(context_id) else None,
        "task_state": state,
        "terminal": state in _TERMINAL_TASK_STATES,
        "artifact_count": len(artifacts) if isinstance(artifacts, list) else 0,
        "history_count": len(history) if isinstance(history, list) else 0,
    }


def _validate_task_updates(
    task_updates: Sequence[Mapping[str, Any] | Any] | None,
) -> dict[str, Any]:
    if task_updates is None:
        return {
            "status_update_count": 0,
            "artifact_update_count": 0,
            "latest_task_state": None,
        }
    if isinstance(task_updates, (str, bytes)) or not isinstance(task_updates, SequenceABC):
        raise InvocationValidationError(
            "task_updates must be a sequence of mappings",
            details={"type": type(task_updates).__name__},
        )

    status_update_count = 0
    artifact_update_count = 0
    latest_task_state: str | None = None

    for index, update in enumerate(task_updates):
        update_map = _to_mapping(update, label=f"task_updates[{index}]")
        status = update_map.get("status")
        if "status" in update_map:
            if not isinstance(status, MappingABC):
                raise _workflow_protocol_error(
                    "A2A task update status must be a mapping",
                    reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
                    details={"update_index": index},
                )
            if "state" not in status:
                raise _workflow_protocol_error(
                    "A2A task update status.state is required",
                    reason_code="WORKFLOW_PROTOCOL_A2A_TASK_STATE_REQUIRED",
                    details={"update_index": index},
                )
            raw_state = _validate_task_state(
                status.get("state"),
                label=f"task_updates[{index}].status.state",
            )
            if index < _MAX_TASK_UPDATE_SUMMARIES:
                latest_task_state = raw_state
                status_update_count += 1

        if index < _MAX_TASK_UPDATE_SUMMARIES:
            if "artifact" in update_map:
                artifact_update_count += 1
            elif "artifacts" in update_map:
                artifacts = update_map.get("artifacts")
                artifact_update_count += len(artifacts) if isinstance(artifacts, list) else 1

    return {
        "status_update_count": status_update_count,
        "artifact_update_count": artifact_update_count,
        "latest_task_state": latest_task_state,
    }


@dataclass(frozen=True)
class A2AParticipantBinding:
    """Binds an A2A Agent Card name to an AEGIS participant and role."""

    participant_id: str
    agent_name: str
    role: str


@dataclass(frozen=True)
class A2APreparedStep:
    """Returned by ``prepare_step()``. Pass to ``complete_step()``."""

    _session_result: Any = field(repr=False)
    _adapter_step_key: str = field(repr=False)
    _session: Any = field(repr=False)


class A2AAdapter:
    """AEGIS governance adapter for host-owned A2A interactions."""

    def prepare_step(
        self,
        session: "GovernanceSession",
        invocation: dict[str, Any],
        *,
        binding: A2AParticipantBinding,
        agent_card: Mapping[str, Any] | Any,
        request_metadata: Mapping[str, Any] | None = None,
        step_id: str | None = None,
    ) -> A2APreparedStep:
        self._validate_binding(binding)
        constraints = _a2a_constraints(session)
        card, selected = _validate_agent_card(agent_card, constraints)

        if binding.agent_name != card["name"]:
            raise _workflow_protocol_error(
                "A2A binding.agent_name must match Agent Card name",
                reason_code="WORKFLOW_PROTOCOL_A2A_AGENT_NAME_MISMATCH",
                details={
                    "binding_agent_name": binding.agent_name,
                    "agent_card_name": card["name"],
                },
            )

        invocation_role = invocation.get("role")
        if binding.role != invocation_role:
            raise WorkflowParticipantMismatchError(
                "A2A binding.role must match invocation['role']",
                details={
                    "binding_role": binding.role,
                    "invocation_role": invocation_role,
                    "reason_code": "WORKFLOW_PARTICIPANT_ROLE_MISMATCH",
                },
            )

        participant = session.participant_for(binding.participant_id)
        if participant:
            allowed_roles = participant.get("roles")
            if allowed_roles and binding.role not in allowed_roles:
                raise WorkflowParticipantMismatchError(
                    f"binding.role={binding.role!r} not in participant "
                    f"{binding.participant_id!r} allowed roles: {allowed_roles}",
                    details={
                        "session_id": session.session_id,
                        "participant_id": binding.participant_id,
                        "binding_role": binding.role,
                        "allowed_roles": allowed_roles,
                        "reason_code": "WORKFLOW_PARTICIPANT_ROLE_MISMATCH",
                    },
                )

        ctx_value = invocation.get("context")
        if ctx_value is None:
            ctx_raw = {}
        elif isinstance(ctx_value, MappingABC):
            ctx_raw = ctx_value
        else:
            raise InvocationValidationError(
                "invocation context must be a mapping",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )
        proto_value = ctx_raw.get("protocol_evidence")
        if proto_value is None:
            proto_raw = {}
        elif isinstance(proto_value, MappingABC):
            proto_raw = proto_value
        else:
            raise InvocationValidationError(
                "invocation context['protocol_evidence'] must be a mapping",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )

        adapter_step_key = str(uuid.uuid4())
        a2a_evidence = {
            "adapter_family": "a2a",
            "adapter_version": _ADAPTER_VERSION,
            "adapter_step_key": adapter_step_key,
            "participant_id": binding.participant_id,
            "agent_name": binding.agent_name,
            "agent_card_version": card.get("version")
            if _is_scalar(card.get("version")) else None,
            "supportedInterfaces": _summarize_interfaces(card),
            "selected_protocol_binding": selected["protocolBinding"],
            "selected_protocol_version": selected["protocolVersion"],
            "capabilities": _summarize_capabilities(card.get("capabilities")),
            "skills": _summarize_skills(card),
            "request_metadata": _redacted_request_metadata(request_metadata),
        }

        existing_protocol = invocation.get("protocol") or ctx_raw.get("protocol")
        if existing_protocol is not None and existing_protocol != "a2a":
            raise WorkflowUnsupportedBindingError(
                f"invocation declares protocol={existing_protocol!r}; "
                "A2AAdapter cannot enrich a non-A2A invocation",
                details={
                    "existing_protocol": existing_protocol,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )

        enriched = dict(invocation)
        ctx = dict(ctx_raw)
        proto = dict(proto_raw)
        enriched["protocol"] = "a2a"
        ctx["protocol"] = "a2a"
        proto["a2a"] = a2a_evidence
        ctx["protocol_evidence"] = proto
        enriched["context"] = ctx

        session_result = session.enforce_step_pre_call(
            enriched,
            step_id=step_id,
            participant_id=binding.participant_id,
        )

        try:
            session.register_adapter_step_state(
                session_result,
                {
                    "adapter": "a2a",
                    "adapter_version": _ADAPTER_VERSION,
                    "adapter_step_key": adapter_step_key,
                    "participant_id": binding.participant_id,
                    "agent_name": binding.agent_name,
                    "protocol_version": selected["protocolVersion"],
                    "protocol_binding": selected["protocolBinding"],
                    "require_task_state": constraints["require_task_state"],
                },
            )
        except Exception:
            session.discard_adapter_step(session_result, rollback_authorization=True)
            raise

        return A2APreparedStep(
            _session_result=session_result,
            _adapter_step_key=adapter_step_key,
            _session=session,
        )

    def complete_step(
        self,
        prepared: A2APreparedStep,
        output: dict[str, Any],
        *,
        task_envelope: Mapping[str, Any] | Any | None = None,
        task_updates: Sequence[Mapping[str, Any] | Any] | None = None,
    ) -> Any:
        if not isinstance(prepared, A2APreparedStep):
            raise WorkflowSessionTokenInvalidError(
                "prepared must be an A2APreparedStep",
                details={"reason_code": "WORKFLOW_SESSION_TOKEN_INVALID"},
            )

        session = prepared._session
        session_result = prepared._session_result
        adapter_state = session.pop_adapter_step_state(session_result)
        if (
            adapter_state.get("adapter") != "a2a"
            or adapter_state.get("adapter_step_key") != prepared._adapter_step_key
        ):
            session.discard_adapter_step(session_result)
            raise WorkflowSessionTokenInvalidError(
                "No A2A adapter state is registered for this prepared step",
                details={
                    "session_id": getattr(session, "session_id", None),
                    "step_id": getattr(session_result, "step_id", None),
                    "reason_code": "WORKFLOW_SESSION_TOKEN_INVALID",
                },
            )

        try:
            task = _validate_task_envelope(
                task_envelope,
                require_task_state=adapter_state.get("require_task_state", True),
            )
            task_update_summary = _validate_task_updates(task_updates)
            metadata = {
                "adapter": "a2a",
                "adapter_version": adapter_state["adapter_version"],
                "adapter_step_key": adapter_state["adapter_step_key"],
                "participant_id": adapter_state["participant_id"],
                "agent_name": adapter_state["agent_name"],
                "protocol_version": adapter_state["protocol_version"],
                "protocol_binding": adapter_state["protocol_binding"],
                **_task_summary(task),
                "status_update_count": task_update_summary["status_update_count"],
                "artifact_update_count": task_update_summary["artifact_update_count"],
            }
            return session.enforce_step_post_call(
                session_result,
                output,
                step_metadata=metadata,
            )
        except Exception:
            session.discard_adapter_step(session_result)
            raise

    @staticmethod
    def _validate_binding(binding: A2AParticipantBinding) -> None:
        if not isinstance(binding, A2AParticipantBinding):
            raise WorkflowUnsupportedBindingError(
                "binding must be an A2AParticipantBinding",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )
        missing = [
            field_name
            for field_name in ("participant_id", "agent_name", "role")
            if not isinstance(getattr(binding, field_name), str)
            or not getattr(binding, field_name).strip()
        ]
        if missing:
            raise WorkflowUnsupportedBindingError(
                "A2AParticipantBinding fields must be non-empty strings",
                details={
                    "fields": missing,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )


__all__ = [
    "A2AAdapter",
    "A2AParticipantBinding",
    "A2APreparedStep",
]
