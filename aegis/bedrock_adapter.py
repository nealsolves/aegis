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
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis._internal.errors import (
    InvocationValidationError,
    WorkflowProtocolViolationError,
    WorkflowUnsupportedBindingError,
)

if TYPE_CHECKING:
    from aegis._internal.session import GovernanceSession

logger = logging.getLogger(__name__)

_ADAPTER_VERSION = "0.9.0-beta"


def _is_alias_backed_reference(alias: Any) -> bool:
    """Return True for Bedrock agent alias ARN references."""
    if not isinstance(alias, str):
        return False
    return alias.startswith("arn:aws:bedrock:")


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BedrockParticipantBinding:
    """Binds a Bedrock collaborator alias to an AEGIS participant identity and role.

    ``collaborator_alias`` must be a Bedrock agent alias ARN
    (e.g. ``arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID``)
    — not a bare ``collaboratorName``. Name-only evidence is descriptive and
    insufficient for governed authorization.
    """

    participant_id: str
    collaborator_alias: str  # e.g. "arn:aws:bedrock:us-east-1:123456789012:agent-alias/ID/ALIASID"
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
        :param invocation: AEGIS invocation dict. Must include
            ``context.protocol_evidence.bedrock`` with ``alias_backed=True``
            when the participant declares the ``bedrock`` protocol.
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
        ctx = invocation.get("context") or {}
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
                "(arn:aws:bedrock:...), not a bare collaboratorName",
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
                from aegis._internal.errors import WorkflowParticipantMismatchError
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
        enriched_ctx["protocol"] = "bedrock"
        enriched["context"] = enriched_ctx
        if not enriched.get("role"):
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

        adapter_state = session.pop_adapter_step_state(session_result)
        try:
            if adapter_state.get("require_trace") and not trace_parts:
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
                trace_parts=trace_parts or [],
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

    def _build_step_metadata(
        self,
        *,
        adapter_step_key: str,
        trace_parts: list[dict[str, Any]],
        adapter_state: dict[str, Any],
    ) -> dict[str, Any]:
        """Build normalized evidence summary. No raw prompts, args, or outputs."""
        meta: dict[str, Any] = {
            "adapter": "bedrock_trace",
            "adapter_version": _ADAPTER_VERSION,
            "adapter_step_key": adapter_step_key,
            "collaborator_alias": adapter_state.get("collaborator_alias"),
            "trace_present": bool(trace_parts),
            "trace_parts_count": len(trace_parts),
        }

        if trace_parts:
            trace_ids = [
                t.get("traceId") or t.get("trace_id")
                for t in trace_parts
                if t.get("traceId") or t.get("trace_id")
            ]
            meta["trace_ids"] = trace_ids

        return meta


__all__ = [
    "BedrockTraceAdapter",
    "BedrockParticipantBinding",
    "BedrockPreparedStep",
]
