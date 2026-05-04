"""Bedrock trace adapter for AEGIS governance (source-only beta).

Not re-exported from the top-level ``aegis`` package.
No extra SDK dependency — the host supplies pre-parsed trace parts.

Usage::

    from aegis.bedrock_adapter import (
        BedrockTraceAdapter,
        BedrockParticipantBinding,
        BedrockPreparedStep,
    )

AEGIS owns: pre-call protocol validation, alias-backed identity enforcement,
trace-required enforcement, and additive workflow evidence.

The host continues to own: orchestration, Bedrock API calls, trace parsing,
retries, credentials, business state, and tool execution.
"""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis import (
    InvocationValidationError,
    WorkflowParticipantMismatchError,
    WorkflowProtocolViolationError,
    WorkflowUnsupportedBindingError,
)

if TYPE_CHECKING:
    from aegis._internal.session import GovernanceSession

logger = logging.getLogger(__name__)

_ADAPTER_VERSION = "0.9.0-beta"
_AGENT_ALIAS_ARN_RE = re.compile(
    r"^arn:aws(?:-[^:]+)?:bedrock:"
    r"(?P<region>[a-z0-9-]{1,20}):"
    r"(?P<account>[0-9]{12}):"
    r"agent-alias/"
    r"(?P<agent_id>[0-9A-Za-z]{10})/"
    r"(?P<alias_id>[0-9A-Za-z]{10})$"
)
_TRACE_UNION_KEYS = frozenset({
    "customOrchestrationTrace",
    "failureTrace",
    "guardrailTrace",
    "orchestrationTrace",
    "postProcessingTrace",
    "preProcessingTrace",
    "routingClassifierTrace",
})
_TRACE_ID_KEYS = frozenset({"traceId", "trace_id"})


def _is_alias_backed_reference(alias: Any) -> bool:
    """Return True for Bedrock agent alias ARN references."""
    if not isinstance(alias, str):
        return False
    return _AGENT_ALIAS_ARN_RE.fullmatch(alias) is not None


def _agent_alias_ids(alias: str) -> tuple[str, str] | None:
    """Return ``(agent_id, alias_id)`` for a valid Bedrock agent alias ARN."""
    match = _AGENT_ALIAS_ARN_RE.fullmatch(alias)
    if match is None:
        return None
    return match.group("agent_id"), match.group("alias_id")


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _walk_mappings(value: Any):
    """Yield dict nodes from a nested parsed Bedrock response."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_mappings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_mappings(child)


def _extract_trace_ids(value: Any) -> list[str]:
    trace_ids: list[str] = []
    for mapping in _walk_mappings(value):
        for key in _TRACE_ID_KEYS:
            trace_id = mapping.get(key)
            if isinstance(trace_id, str) and trace_id:
                trace_ids.append(trace_id)
    return _dedupe(trace_ids)


def _trace_part_matches_alias(part: dict[str, Any], collaborator_alias: str) -> bool:
    # Emitter identity is established exclusively via the TracePart envelope
    # fields agentId and agentAliasId. Alias ARNs inside trace content
    # (agentCollaboratorAliasArn, agentAliasArn in callerChain) identify
    # invocation targets or upstream forwarders — never the emitter.
    alias_ids = _agent_alias_ids(collaborator_alias)
    if alias_ids is None:
        return False
    agent_id, alias_id = alias_ids
    return part.get("agentId") == agent_id and part.get("agentAliasId") == alias_id


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BedrockParticipantBinding:
    """Binds a Bedrock collaborator alias to an AEGIS participant identity and role.

    ``collaborator_alias`` must be a Bedrock agent alias ARN
    (e.g. ``arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID12A/ALIASID12B``)
    — not a bare ``collaboratorName``. Name-only evidence is descriptive and
    insufficient for governed authorization.
    """

    participant_id: str
    collaborator_alias: str
    role: str


@dataclass(frozen=True)
class BedrockPreparedStep:
    """Returned by ``prepare_step()``. Pass to ``complete_step()``."""

    _session_result: Any = field(repr=False)
    _adapter_step_key: str = field(repr=False)
    _session: Any = field(repr=False)


# ---------------------------------------------------------------------------
# BedrockTraceAdapter
# ---------------------------------------------------------------------------

class BedrockTraceAdapter:
    """AEGIS governance adapter for AWS Bedrock trace evidence (source-only beta).

    AEGIS owns: pre-call protocol validation, alias-backed identity enforcement,
    trace-required enforcement, and additive workflow evidence.

    The host continues to own: orchestration, Bedrock API calls, trace parsing,
    retries, credentials, business state, and tool execution.
    """

    def prepare_step(
        self,
        session: "GovernanceSession",
        invocation: dict[str, Any],
        *,
        binding: BedrockParticipantBinding,
        step_id: str | None = None,
    ) -> BedrockPreparedStep:
        """Validate binding and evidence, inject context, call pre-call enforcement.

        :param session: Owning GovernanceSession.
        :param invocation: AEGIS invocation dict. If the host supplies
            ``context.protocol_evidence.bedrock.alias_backed``, it must not be
            ``False``; the adapter stamps ``alias_backed=True`` on the enriched
            invocation passed to pre-call enforcement.
        :param binding: Participant binding for the collaborator.
        :param step_id: Optional step ID; auto-generated when absent.
        :return: ``BedrockPreparedStep`` — pass to ``complete_step()``.
        :raises WorkflowUnsupportedBindingError: on binding validation failures.
        :raises WorkflowProtocolViolationError: on alias-backed identity failure.
        :raises InvocationValidationError: on malformed invocation evidence.
        """
        bedrock_constraints = session.protocol_constraints_for("bedrock")
        require_trace = bedrock_constraints.get("require_trace", False)
        require_alias_backed_identity = bedrock_constraints.get(
            "require_alias_backed_identity",
            bedrock_constraints.get("require_alias", True),
        )
        if require_alias_backed_identity is not True:
            raise WorkflowProtocolViolationError(
                "BedrockTraceAdapter requires alias-backed collaborator identity; "
                "require_alias_backed_identity cannot be disabled",
                details={
                    "protocol": "bedrock",
                    "reason_code": "WORKFLOW_PROTOCOL_ALIAS_BACKED_REQUIRED",
                },
            )

        # --- Extract and validate bedrock evidence ---
        ctx = invocation.get("context")
        if ctx is not None and not isinstance(ctx, dict):
            raise InvocationValidationError(
                "invocation['context'] must be a dict or absent",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )
        ctx = ctx or {}
        proto_evidence = ctx.get("protocol_evidence") or {}
        if not isinstance(proto_evidence, dict):
            raise InvocationValidationError(
                "invocation context['protocol_evidence'] must be a dict",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )
        bedrock_ev = proto_evidence.get("bedrock", {})

        if not isinstance(bedrock_ev, dict):
            raise InvocationValidationError(
                "invocation context['protocol_evidence']['bedrock'] must be a dict",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )

        if bedrock_ev.get("alias_backed") is False:
            raise WorkflowProtocolViolationError(
                "Bedrock evidence declares alias_backed=False; "
                "BedrockTraceAdapter requires alias-backed collaborator identity",
                details={
                    "protocol": "bedrock",
                    "participant_id": binding.participant_id,
                    "reason_code": "WORKFLOW_PROTOCOL_ALIAS_BACKED_REQUIRED",
                },
            )

        # --- Validate alias is a Bedrock agent alias ARN, not a bare name ---
        alias = binding.collaborator_alias
        if alias == binding.participant_id or not _is_alias_backed_reference(alias):
            raise WorkflowUnsupportedBindingError(
                "BedrockParticipantBinding.collaborator_alias must be a Bedrock agent alias ARN "
                "(arn:aws[-partition]:bedrock:<region>:<account>:agent-alias/<10>/<10>), "
                "not a bare collaboratorName",
                details={
                    "collaborator_alias": alias,
                    "participant_id": binding.participant_id,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )

        # --- Participant-role consistency check ---
        part = session.participant_for(binding.participant_id)
        if part:
            allowed_roles = part.get("roles")
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

        # --- Generate correlation key ---
        adapter_step_key = str(uuid.uuid4())

        # --- Enrich invocation with normalized evidence ---
        enriched = dict(invocation)
        enriched_ctx = dict(ctx)
        enriched_proto = dict(proto_evidence)
        enriched_bedrock_ev: dict[str, Any] = {
            k: v for k, v in bedrock_ev.items()
        }
        enriched_bedrock_ev.update({
            "adapter_version": _ADAPTER_VERSION,
            "collaborator_alias": binding.collaborator_alias,
            "participant_id": binding.participant_id,
            "adapter_step_key": adapter_step_key,
            "alias_backed": True,
        })
        enriched_proto["bedrock"] = enriched_bedrock_ev
        enriched_ctx["protocol_evidence"] = enriched_proto
        # Reject a conflicting top-level protocol; the adapter owns this seam.
        top_level_protocol = enriched.get("protocol")
        if top_level_protocol is not None and top_level_protocol != "bedrock":
            raise WorkflowProtocolViolationError(
                f"invocation['protocol']={top_level_protocol!r} conflicts with "
                "BedrockTraceAdapter; remove the top-level 'protocol' key or set it to 'bedrock'",
                details={
                    "protocol": top_level_protocol,
                    "participant_id": binding.participant_id,
                    "reason_code": "WORKFLOW_PROTOCOL_CONFLICT",
                },
            )
        enriched["protocol"] = "bedrock"
        enriched_ctx["protocol"] = "bedrock"
        enriched["context"] = enriched_ctx

        # binding.role is authoritative — reject explicit mismatches.
        explicit_role = enriched.get("role")
        if explicit_role is not None and explicit_role != binding.role:
            raise WorkflowParticipantMismatchError(
                f"invocation['role']={explicit_role!r} conflicts with "
                f"binding.role={binding.role!r}; "
                "BedrockParticipantBinding is the authoritative role source",
                details={
                    "invocation_role": explicit_role,
                    "binding_role": binding.role,
                    "participant_id": binding.participant_id,
                    "reason_code": "WORKFLOW_PARTICIPANT_ROLE_MISMATCH",
                },
            )
        enriched["role"] = binding.role

        # --- Pre-call enforcement ---
        session_result = session.enforce_step_pre_call(
            enriched,
            step_id=step_id,
            participant_id=binding.participant_id,
        )

        try:
            session.register_adapter_step_state(
                session_result,
                {
                    "adapter_step_key": adapter_step_key,
                    "require_trace": require_trace,
                    "collaborator_alias": binding.collaborator_alias,
                },
            )
        except Exception:
            session.discard_adapter_step(session_result, rollback_authorization=True)
            raise

        return BedrockPreparedStep(
            _session_result=session_result,
            _adapter_step_key=adapter_step_key,
            _session=session,
        )

    def complete_step(
        self,
        prepared: BedrockPreparedStep,
        *,
        output: dict[str, Any],
        trace_parts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Validate trace evidence and call enforce_step_post_call.

        :param prepared: Prepared step from ``prepare_step()``.
        :param output: AEGIS output dict.
        :param trace_parts: Optional list of host-supplied parsed Bedrock trace
            dicts. Required when ``require_trace=true`` in policy constraints.
        :return: Invocation PASS audit artifact.
        :raises WorkflowProtocolViolationError: if require_trace and no trace.
        """
        session = prepared._session
        session_result = prepared._session_result
        adapter_step_key = prepared._adapter_step_key

        # Peek before popping: if the key doesn't match, discard the pending
        # pre-call token before raising so the caller cannot use it to complete
        # the raw session token while bypassing Bedrock trace/alias checks.
        adapter_state = session.adapter_step_state(session_result)
        if (adapter_state or {}).get("adapter_step_key") != adapter_step_key:
            session.discard_adapter_step(session_result)
            raise WorkflowProtocolViolationError(
                "complete_step() called without valid adapter state: "
                "this BedrockPreparedStep has no registered Bedrock adapter state, "
                "was already completed, or was not produced by prepare_step()",
                details={
                    "session_id": session.session_id,
                    "step_id": session_result.step_id,
                    "protocol": "bedrock",
                    "adapter_step_key": adapter_step_key,
                    "reason_code": "WORKFLOW_PROTOCOL_ADAPTER_STATE_MISSING",
                },
            )
        adapter_state = session.pop_adapter_step_state(session_result)
        try:
            trace_summary = self._summarize_trace_parts(
                trace_parts,
                collaborator_alias=adapter_state.get("collaborator_alias"),
                session=session,
                session_result=session_result,
                adapter_step_key=adapter_step_key,
            )
            if (
                adapter_state.get("require_trace")
                and trace_summary["trace_parts_count"] == 0
            ):
                raise WorkflowProtocolViolationError(
                    "require_trace=true but no trace_parts were supplied to complete_step()",
                    details={
                        "session_id": session.session_id,
                        "step_id": session_result.step_id,
                        "protocol": "bedrock",
                        "adapter_step_key": adapter_step_key,
                        "reason_code": "WORKFLOW_PROTOCOL_TRACE_REQUIRED",
                    },
                )

            step_metadata = self._build_step_metadata(
                adapter_step_key=adapter_step_key,
                trace_summary=trace_summary,
                adapter_state=adapter_state,
            )

            return session.enforce_step_post_call(
                session_result,
                output,
                step_metadata=step_metadata,
            )
        except Exception:
            session.discard_adapter_step(session_result)
            raise

    def _summarize_trace_parts(
        self,
        trace_parts: list[dict[str, Any]] | None,
        *,
        collaborator_alias: str | None,
        session: "GovernanceSession",
        session_result: Any,
        adapter_step_key: str,
    ) -> dict[str, Any]:
        """Validate Bedrock TracePart shape and return safe summary fields."""
        if trace_parts is None:
            return {
                "trace_present": False,
                "trace_parts_count": 0,
                "trace_ids": [],
                "trace_alias_matched": False,
            }

        if not isinstance(trace_parts, list):
            raise InvocationValidationError(
                "trace_parts must be a list of parsed Bedrock TracePart dicts",
                details={
                    "session_id": session.session_id,
                    "step_id": session_result.step_id,
                    "protocol": "bedrock",
                    "adapter_step_key": adapter_step_key,
                    "reason_code": "WORKFLOW_PROTOCOL_TRACE_INVALID",
                },
            )

        trace_ids: list[str] = []
        alias_matched = False
        for index, part in enumerate(trace_parts):
            if not isinstance(part, dict):
                raise self._invalid_trace_part_error(
                    index,
                    "trace part must be a dict",
                    session=session,
                    session_result=session_result,
                    adapter_step_key=adapter_step_key,
                )

            trace = part.get("trace")
            if not isinstance(trace, dict):
                raise self._invalid_trace_part_error(
                    index,
                    "TracePart must contain a trace mapping",
                    session=session,
                    session_result=session_result,
                    adapter_step_key=adapter_step_key,
                )

            union_members = [
                key for key in _TRACE_UNION_KEYS if trace.get(key) is not None
            ]
            if len(union_members) != 1:
                raise self._invalid_trace_part_error(
                    index,
                    "TracePart.trace must contain exactly one Bedrock Trace union member",
                    session=session,
                    session_result=session_result,
                    adapter_step_key=adapter_step_key,
                )

            trace_member = trace[union_members[0]]
            if not isinstance(trace_member, dict):
                raise self._invalid_trace_part_error(
                    index,
                    "TracePart.trace union member must be a dict",
                    session=session,
                    session_result=session_result,
                    adapter_step_key=adapter_step_key,
                )

            if collaborator_alias and not _trace_part_matches_alias(part, collaborator_alias):
                raise WorkflowProtocolViolationError(
                    "Bedrock trace_parts do not correlate to the bound collaborator_alias",
                    details={
                        "session_id": session.session_id,
                        "step_id": session_result.step_id,
                        "protocol": "bedrock",
                        "adapter_step_key": adapter_step_key,
                        "collaborator_alias": collaborator_alias,
                        "trace_part_index": index,
                        "reason_code": "WORKFLOW_PROTOCOL_TRACE_ALIAS_MISMATCH",
                    },
                )

            trace_ids.extend(_extract_trace_ids(trace_member))
            alias_matched = True

        return {
            "trace_present": bool(trace_parts),
            "trace_parts_count": len(trace_parts),
            "trace_ids": _dedupe(trace_ids),
            "trace_alias_matched": alias_matched,
        }

    def _invalid_trace_part_error(
        self,
        index: int,
        reason: str,
        *,
        session: "GovernanceSession",
        session_result: Any,
        adapter_step_key: str,
    ) -> InvocationValidationError:
        return InvocationValidationError(
            f"trace_parts[{index}] is not a valid Bedrock TracePart: {reason}",
            details={
                "session_id": session.session_id,
                "step_id": session_result.step_id,
                "protocol": "bedrock",
                "adapter_step_key": adapter_step_key,
                "trace_part_index": index,
                "reason_code": "WORKFLOW_PROTOCOL_TRACE_INVALID",
            },
        )

    def _build_step_metadata(
        self,
        *,
        adapter_step_key: str,
        trace_summary: dict[str, Any],
        adapter_state: dict[str, Any],
    ) -> dict[str, Any]:
        """Build normalized evidence summary. No raw prompts, args, or outputs."""
        meta: dict[str, Any] = {
            "adapter": "bedrock_trace",
            "adapter_version": _ADAPTER_VERSION,
            "adapter_step_key": adapter_step_key,
            "collaborator_alias": adapter_state.get("collaborator_alias"),
            "trace_present": trace_summary["trace_present"],
            "trace_parts_count": trace_summary["trace_parts_count"],
            "trace_alias_matched": trace_summary["trace_alias_matched"],
        }

        trace_ids = trace_summary.get("trace_ids") or []
        if trace_ids:
            meta["trace_ids"] = trace_ids

        return meta


__all__ = [
    "BedrockTraceAdapter",
    "BedrockParticipantBinding",
    "BedrockPreparedStep",
]
