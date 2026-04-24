"""OpenAI Agents SDK adapter for AEGIS governance (source-only beta).

Not re-exported from the top-level ``aegis`` package.
Requires ``aegis[openai-agents]``.

Usage::

    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsParticipantBinding,
        OpenAIAgentsPreparedStep,
        OpenAIAgentsPendingApproval,
        OpenAIAgentsTracingProcessor,
    )

AEGIS owns: pre-run protocol validation, binding validation, wrapped-tool
authorization, interruption checkpoint correlation, and additive workflow
evidence.  The host continues to own: orchestration, transport, retries,
credentials, business state, tool execution, and provider SDK usage.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis._internal.errors import (
    InvocationValidationError,
    WorkflowProtocolViolationError,
    WorkflowSessionTokenInvalidError,
    WorkflowUnsupportedBindingError,
)

if TYPE_CHECKING:
    from aegis._internal.session import GovernanceSession, SessionPreCallResult

logger = logging.getLogger(__name__)

_ADAPTER_VERSION = "0.9.0-beta"

# ---------------------------------------------------------------------------
# SDK import guard — lazy; base aegis import works without the extra
# ---------------------------------------------------------------------------

_SDK_AVAILABLE: bool = False
_SDK_IMPORT_ERROR: ImportError | None = None

try:
    import agents as _agents_sdk  # noqa: F401
    _SDK_AVAILABLE = True
except ImportError as _err:
    _SDK_IMPORT_ERROR = _err


def _require_sdk() -> None:
    """Fail-closed guard: raise ImportError when SDK extra is absent."""
    if not _SDK_AVAILABLE:
        raise ImportError(
            "The 'openai-agents' extra is required to use OpenAIAgentsAdapter. "
            "Install it with: pip install 'aegis[openai-agents]'"
        ) from _SDK_IMPORT_ERROR


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OpenAIAgentsParticipantBinding:
    """Binds a root Agent name to an AEGIS participant identity and role."""

    participant_id: str
    agent_name: str
    role: str


@dataclass(frozen=True)
class OpenAIAgentsPreparedStep:
    """Returned by ``prepare_step()``. Pass to ``complete_step()`` or ``pause_step()``."""

    wrapped_root_agent: Any
    run_config: Any
    _session_result: Any = field(repr=False)
    _adapter_step_key: str = field(repr=False)
    _session: Any = field(repr=False)


@dataclass(frozen=True)
class OpenAIAgentsPendingApproval:
    """Returned by ``pause_step()``. Pass to ``record_approval_decision()``."""

    run_state: Any
    checkpoint_id: str
    interruptions: list[Any]
    _prepared: Any = field(repr=False)


# ---------------------------------------------------------------------------
# Tracing processor
# ---------------------------------------------------------------------------

class OpenAIAgentsTracingProcessor:
    """AEGIS tracing processor registered globally with the OpenAI Agents SDK.

    Correlates SDK trace spans back to the adapter step via
    ``RunConfig.trace_metadata["_aegis_openai_agents"]["adapter_step_key"]``.
    Register once per process::

        from agents import add_trace_processor
        add_trace_processor(OpenAIAgentsTracingProcessor(adapter))
    """

    def __init__(self, adapter: "OpenAIAgentsAdapter | None" = None) -> None:
        self._adapter = adapter
        self._lock = threading.Lock()
        self._step_traces: dict[str, list[dict[str, Any]]] = {}

    # --- SDK TracingProcessor interface ---

    def on_trace_start(self, trace: Any) -> None:  # noqa: ARG002
        pass

    def on_trace_end(self, trace: Any) -> None:
        try:
            metadata = getattr(trace, "metadata", None) or {}
            if not isinstance(metadata, dict):
                return
            aegis_meta = metadata.get("_aegis_openai_agents")
            if not isinstance(aegis_meta, dict):
                return
            step_key = aegis_meta.get("adapter_step_key")
            if not step_key:
                return
            summary: dict[str, Any] = {
                "trace_id": getattr(trace, "trace_id", None),
                "group_id": getattr(trace, "group_id", None),
                "name": getattr(trace, "name", None),
                "ended_at": time.time(),
            }
            with self._lock:
                self._step_traces.setdefault(step_key, []).append(summary)
        except Exception:  # noqa: BLE001
            pass

    def on_span_start(self, span: Any) -> None:  # noqa: ARG002
        pass

    def on_span_end(self, span: Any) -> None:  # noqa: ARG002
        pass

    def force_flush(self) -> None:
        pass

    def shutdown(self) -> None:
        pass

    # --- AEGIS helpers ---

    def pop_trace_summary(self, adapter_step_key: str) -> list[dict[str, Any]]:
        with self._lock:
            return self._step_traces.pop(adapter_step_key, [])

    def get_trace_summary(self, adapter_step_key: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._step_traces.get(adapter_step_key, []))


# Global tracing processor singleton
_GLOBAL_TRACE_PROCESSOR: OpenAIAgentsTracingProcessor | None = None
_TRACE_PROCESSOR_LOCK = threading.Lock()


def _get_or_register_trace_processor(
    adapter: "OpenAIAgentsAdapter | None" = None,
) -> OpenAIAgentsTracingProcessor:
    """Get or create the global tracing processor, registering it with the SDK once."""
    global _GLOBAL_TRACE_PROCESSOR
    with _TRACE_PROCESSOR_LOCK:
        if _GLOBAL_TRACE_PROCESSOR is None:
            _GLOBAL_TRACE_PROCESSOR = OpenAIAgentsTracingProcessor(adapter)
            if _SDK_AVAILABLE:
                try:
                    from agents import add_trace_processor
                    add_trace_processor(_GLOBAL_TRACE_PROCESSOR)
                except (ImportError, AttributeError):
                    pass
        return _GLOBAL_TRACE_PROCESSOR


# ---------------------------------------------------------------------------
# Graph traversal and validation helpers
# ---------------------------------------------------------------------------

_UNSUPPORTED_AGENT_TYPES = frozenset({"RealtimeAgent", "SandboxAgent"})
_UNSUPPORTED_TOOL_TYPES = frozenset({
    "HostedMCPTool",
    "MCPTool",
    "WebSearchTool",
    "FileSearchTool",
    "CodeInterpreterTool",
    "ComputerTool",
    "DeferredTool",
    "ToolSearchTool",
})


def _is_agent_like(obj: Any) -> bool:
    return (
        not isinstance(obj, type)
        and hasattr(obj, "name")
        and hasattr(obj, "tools")
        and hasattr(obj, "handoffs")
    )


def _resolve_handoff_target(handoff: Any) -> Any | None:
    target = getattr(handoff, "target_agent", None)
    if target is not None and _is_agent_like(target):
        return target
    if _is_agent_like(handoff):
        return handoff
    return None


def _resolve_agent_as_tool_inner(tool: Any) -> Any | None:
    # Try _agent_instance (SDK v0.11+) first, then _inner_agent (older SDK)
    inner = getattr(tool, "_agent_instance", None)
    if inner is None:
        inner = getattr(tool, "_inner_agent", None)
    if inner is not None and _is_agent_like(inner):
        return inner
    return None


def _traverse_agent_graph(root: Any) -> list[Any]:
    """BFS traversal returning all reachable agent-like objects.

    Uses object identity (id()) to prevent infinite loops; this means two
    distinct agent objects with the same name both appear in the result so that
    the duplicate-name check in _validate_graph can detect them.
    """
    visited_ids: set[int] = set()
    result: list[Any] = []
    queue = [root]
    while queue:
        agent = queue.pop(0)
        agent_id = id(agent)
        if agent_id in visited_ids:
            continue
        visited_ids.add(agent_id)
        result.append(agent)
        for handoff in (getattr(agent, "handoffs", None) or []):
            target = _resolve_handoff_target(handoff)
            if target is not None and id(target) not in visited_ids:
                queue.append(target)
        for tool in (getattr(agent, "tools", None) or []):
            inner = _resolve_agent_as_tool_inner(tool)
            if inner is not None and id(inner) not in visited_ids:
                queue.append(inner)
    return result


def _validate_graph(
    root: Any,
    *,
    allow_hosted_tools: bool = False,
    allow_agent_as_tool: bool = True,
    require_unique_names: bool = True,
) -> None:
    """Validate agent graph for governed use. Raises on unsupported surfaces."""
    root_type = type(root).__name__
    if root_type in _UNSUPPORTED_AGENT_TYPES:
        raise WorkflowUnsupportedBindingError(
            f"Unsupported agent type {root_type!r}; governed runs do not support "
            "RealtimeAgent or SandboxAgent in v0.9.0",
            details={"agent_type": root_type, "reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
        )

    all_agents = _traverse_agent_graph(root)

    if require_unique_names:
        seen_names: set[str] = set()
        duplicates: list[str] = []
        for agent in all_agents:
            n = getattr(agent, "name", None) or ""
            if n in seen_names:
                duplicates.append(n)
            seen_names.add(n)
        if duplicates:
            raise WorkflowUnsupportedBindingError(
                f"Duplicate agent names in governed graph: {duplicates!r}; "
                "set require_unique_agent_names=false in openai_agents protocol constraints",
                details={
                    "duplicate_names": duplicates,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )

    for agent in all_agents:
        agent_type = type(agent).__name__
        if agent_type in _UNSUPPORTED_AGENT_TYPES:
            raise WorkflowUnsupportedBindingError(
                f"Unsupported agent type {agent_type!r} in governed graph",
                details={"agent_type": agent_type, "reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )
        if getattr(agent, "mcp_servers", None):
            raise WorkflowUnsupportedBindingError(
                f"Agent {getattr(agent, 'name', '?')!r} has mcp_servers which is "
                "not supported in governed mode",
                details={
                    "agent_name": getattr(agent, "name", None),
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )
        for tool in (getattr(agent, "tools", None) or []):
            tool_type = type(tool).__name__
            if tool_type in _UNSUPPORTED_TOOL_TYPES:
                if not allow_hosted_tools:
                    raise WorkflowUnsupportedBindingError(
                        f"Agent {getattr(agent, 'name', '?')!r} uses {tool_type!r} which "
                        "is rejected in governed mode; set allow_hosted_tools=true to override",
                        details={
                            "agent_name": getattr(agent, "name", None),
                            "tool_type": tool_type,
                            "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                        },
                    )
            inner = _resolve_agent_as_tool_inner(tool)
            if inner is not None and not allow_agent_as_tool:
                raise WorkflowUnsupportedBindingError(
                    f"Agent {getattr(agent, 'name', '?')!r} uses Agent.as_tool() which is "
                    "not allowed; set allow_agent_as_tool=true in openai_agents constraints",
                    details={
                        "agent_name": getattr(agent, "name", None),
                        "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                    },
                )


# ---------------------------------------------------------------------------
# Tool wrapping
# ---------------------------------------------------------------------------

def _make_tool_wrapper(
    tool: Any,
    *,
    session: "GovernanceSession",
    session_result: "SessionPreCallResult",
) -> Any:
    """Wrap a FunctionTool to intercept calls for AEGIS per-call authorization."""
    if not _SDK_AVAILABLE:
        return tool

    try:
        from agents.tool import FunctionTool
    except ImportError:
        try:
            from agents import FunctionTool
        except ImportError:
            return tool

    if not isinstance(tool, FunctionTool):
        return tool

    original_invoke = tool.on_invoke_tool

    async def _governed_invoke(ctx: Any, input_str: str) -> Any:
        session.authorize_step_tool_call(
            session_result,
            tool_name=tool.name,
            tool_call_id=str(uuid.uuid4()),
        )
        return await original_invoke(ctx, input_str)

    try:
        wrapped = dataclasses.replace(tool, on_invoke_tool=_governed_invoke)
    except (TypeError, ValueError):
        import copy as _copy
        wrapped = _copy.copy(tool)
        try:
            object.__setattr__(wrapped, "on_invoke_tool", _governed_invoke)
        except (AttributeError, TypeError):
            setattr(wrapped, "on_invoke_tool", _governed_invoke)
    return wrapped


# ---------------------------------------------------------------------------
# RunConfig builder
# ---------------------------------------------------------------------------

def _build_run_config(
    existing: Any,
    *,
    adapter_step_key: str,
    session: "GovernanceSession",
    require_trace: bool,
) -> Any:
    """Create or enrich a RunConfig with AEGIS correlation metadata."""
    if not _SDK_AVAILABLE:
        return existing

    try:
        from agents import RunConfig
    except ImportError:
        return existing

    if require_trace:
        try:
            from agents import is_tracing_enabled
            if not is_tracing_enabled():
                raise WorkflowProtocolViolationError(
                    "require_trace=true but SDK tracing is disabled; "
                    "enable tracing before the run",
                    details={
                        "protocol": "openai_agents",
                        "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                    },
                )
        except ImportError:
            pass

    aegis_meta: dict[str, Any] = {"adapter_step_key": adapter_step_key}

    if existing is None:
        return RunConfig(
            trace_metadata={"_aegis_openai_agents": aegis_meta},
            group_id=session.session_id,
        )

    merged_meta = dict(getattr(existing, "trace_metadata", None) or {})
    merged_meta["_aegis_openai_agents"] = aegis_meta
    group_id = getattr(existing, "group_id", None) or session.session_id

    if dataclasses.is_dataclass(existing):
        try:
            return dataclasses.replace(
                existing,
                trace_metadata=merged_meta,
                group_id=group_id,
            )
        except TypeError:
            pass

    return RunConfig(
        trace_metadata=merged_meta,
        group_id=group_id,
        workflow_name=getattr(existing, "workflow_name", None),
        trace_id=getattr(existing, "trace_id", None),
        model=getattr(existing, "model", None),
        model_provider=getattr(existing, "model_provider", None),
        model_settings=getattr(existing, "model_settings", None),
        trace_include_sensitive_data=getattr(existing, "trace_include_sensitive_data", True),
    )


# ---------------------------------------------------------------------------
# OpenAIAgentsAdapter
# ---------------------------------------------------------------------------

class OpenAIAgentsAdapter:
    """AEGIS governance adapter for the OpenAI Agents SDK (source-only beta).

    AEGIS owns: pre-run protocol validation, binding validation,
    wrapped-tool authorization, interruption checkpoint correlation,
    and additive workflow evidence.

    The host continues to own: orchestration, transport, retries, credentials,
    business state, tool execution, and provider SDK usage.
    """

    def __init__(
        self,
        *,
        trace_processor: OpenAIAgentsTracingProcessor | None = None,
    ) -> None:
        self._trace_processor = trace_processor

    def _get_trace_processor(self) -> OpenAIAgentsTracingProcessor | None:
        if self._trace_processor is not None:
            return self._trace_processor
        if _SDK_AVAILABLE:
            return _get_or_register_trace_processor(self)
        return None

    def bind_graph(
        self,
        agent: Any,
        binding: OpenAIAgentsParticipantBinding,
        *,
        protocol_constraints: dict[str, Any] | None = None,
    ) -> None:
        """Optional preflight validator. Validates graph and binding without side effects.

        Raises ``WorkflowUnsupportedBindingError`` on failure.
        """
        _require_sdk()
        c = protocol_constraints or {}
        _validate_graph(
            agent,
            allow_hosted_tools=c.get("allow_hosted_tools", False),
            allow_agent_as_tool=c.get("allow_agent_as_tool", True),
            require_unique_names=c.get("require_unique_agent_names", True),
        )
        agent_name = getattr(agent, "name", None)
        if agent_name and agent_name != binding.agent_name:
            raise WorkflowUnsupportedBindingError(
                f"Root agent name {agent_name!r} does not match "
                f"binding.agent_name {binding.agent_name!r}",
                details={
                    "agent_name": agent_name,
                    "binding_agent_name": binding.agent_name,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )

    def prepare_step(
        self,
        session: "GovernanceSession",
        invocation: dict[str, Any],
        *,
        binding: OpenAIAgentsParticipantBinding,
        run_config: Any = None,
        step_id: str | None = None,
    ) -> OpenAIAgentsPreparedStep:
        """Validate graph, clone agent, wrap tools, inject evidence, call pre-call.

        :param session: Owning GovernanceSession.
        :param invocation: AEGIS invocation dict.  Must contain
            ``context.protocol_evidence.openai_agents.root_agent``.
        :param binding: Participant binding for the root agent.
        :param run_config: Optional SDK RunConfig to enrich; a new one is
            created when absent.
        :param step_id: Optional step ID; auto-generated when absent.
        :return: ``OpenAIAgentsPreparedStep`` — pass to
            ``complete_step()`` or ``pause_step()``.
        :raises WorkflowUnsupportedBindingError: on graph or binding failures.
        :raises InvocationValidationError: on predeclared tool_calls.
        """
        _require_sdk()

        # --- Protocol constraints ---
        oa_constraints: dict[str, Any] = (
            (session._protocol_constraints or {}).get("openai_agents") or {}
        )
        allow_hosted_tools = oa_constraints.get("allow_hosted_tools", False)
        allow_agent_as_tool = oa_constraints.get("allow_agent_as_tool", True)
        require_unique_names = oa_constraints.get("require_unique_agent_names", True)
        require_trace = oa_constraints.get("require_trace", False)

        # --- Extract root agent from invocation evidence ---
        ctx = invocation.get("context") or {}
        proto_evidence = ctx.get("protocol_evidence") or {}
        openai_ev = proto_evidence.get("openai_agents") or {}
        root_agent = openai_ev.get("root_agent")

        if root_agent is None:
            raise InvocationValidationError(
                "invocation context['protocol_evidence']['openai_agents']['root_agent'] "
                "is required for prepare_step()",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )

        # --- Binding validation ---
        agent_name = getattr(root_agent, "name", None)
        if agent_name and agent_name != binding.agent_name:
            raise WorkflowUnsupportedBindingError(
                f"Root agent name {agent_name!r} disagrees with "
                f"binding.agent_name {binding.agent_name!r}",
                details={
                    "agent_name": agent_name,
                    "binding_agent_name": binding.agent_name,
                    "reason_code": "WORKFLOW_UNSUPPORTED_BINDING",
                },
            )

        # --- Participant-role consistency check ---
        if session._participants_by_id:
            part = session._participants_by_id.get(binding.participant_id)
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

        # --- Reject double-counting ---
        if invocation.get("tool_calls"):
            raise InvocationValidationError(
                "invocation.tool_calls must not be predeclared for adapter-managed tools; "
                "the adapter tracks tool calls dynamically via authorize_step_tool_call()",
                details={"reason_code": "WORKFLOW_UNSUPPORTED_BINDING"},
            )

        # --- Graph validation ---
        _validate_graph(
            root_agent,
            allow_hosted_tools=allow_hosted_tools,
            allow_agent_as_tool=allow_agent_as_tool,
            require_unique_names=require_unique_names,
        )

        # --- Clone agent graph ---
        try:
            cloned_root = root_agent.clone()
        except AttributeError:
            cloned_root = root_agent

        # --- Generate correlation key ---
        adapter_step_key = str(uuid.uuid4())

        # --- Enrich invocation with serializable evidence ---
        enriched = dict(invocation)
        enriched_ctx = dict(ctx)
        enriched_proto = dict(proto_evidence)
        oa_evidence: dict[str, Any] = {
            k: v for k, v in openai_ev.items() if k != "root_agent"
        }
        oa_evidence.update({
            "adapter_version": _ADAPTER_VERSION,
            "root_agent_name": binding.agent_name,
            "participant_id": binding.participant_id,
            "adapter_step_key": adapter_step_key,
        })
        enriched_proto["openai_agents"] = oa_evidence
        enriched_ctx["protocol_evidence"] = enriched_proto
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
            # --- Register adapter state for dynamic tool tracking ---
            session._adapter_step_states[session_result._token_id] = {
                "adapter_step_key": adapter_step_key,
                "dynamic_tool_calls_count": 0,
                "dynamic_tool_calls": [],
                "checkpoint_id": None,
                "require_trace": require_trace,
            }

            # --- Wrap tools on cloned graph ---
            self._wrap_all_tools(
                cloned_root,
                session=session,
                session_result=session_result,
            )

            # --- Build enriched RunConfig ---
            enriched_run_config = _build_run_config(
                run_config,
                adapter_step_key=adapter_step_key,
                session=session,
                require_trace=require_trace,
            )

            # --- Register global trace processor ---
            self._get_trace_processor()
        except Exception:
            session._discard_pending_step(
                session_result,
                rollback_authorization=True,
            )
            raise

        return OpenAIAgentsPreparedStep(
            wrapped_root_agent=cloned_root,
            run_config=enriched_run_config,
            _session_result=session_result,
            _adapter_step_key=adapter_step_key,
            _session=session,
        )

    def _wrap_all_tools(
        self,
        root: Any,
        *,
        session: "GovernanceSession",
        session_result: "SessionPreCallResult",
    ) -> None:
        """BFS through agent graph, wrapping FunctionTool instances."""
        for agent in _traverse_agent_graph(root):
            tools = getattr(agent, "tools", None) or []
            wrapped = [
                _make_tool_wrapper(t, session=session, session_result=session_result)
                for t in tools
            ]
            try:
                agent.tools = wrapped
            except (AttributeError, TypeError):
                logger.warning(
                    "OpenAIAgentsAdapter: could not replace tools on agent %r — "
                    "governed wrappers were not applied; tool budget enforcement "
                    "will not fire for this agent",
                    getattr(agent, "name", agent),
                )

    def pause_step(
        self,
        prepared: OpenAIAgentsPreparedStep,
        run_state: Any,
        interruptions: list[Any],
    ) -> OpenAIAgentsPendingApproval:
        """Mirror SDK interruptions into session.pause() and mint a checkpoint.

        :param prepared: Prepared step from ``prepare_step()``.
        :param run_state: SDK RunState from the interrupted run.
        :param interruptions: SDK interruptions list from the run result.
        :return: ``OpenAIAgentsPendingApproval`` — pass to
            ``record_approval_decision()``.
        """
        checkpoint_id = str(uuid.uuid4())
        reasons = [
            getattr(i, "type", type(i).__name__) for i in (interruptions or [])
        ]
        prepared._session.pause(
            approval_id=checkpoint_id,
            reason=f"OpenAI Agents SDK interruption: {reasons}",
        )

        token_id = prepared._session_result._token_id
        state = prepared._session._adapter_step_states.get(token_id)
        if state is not None:
            state["checkpoint_id"] = checkpoint_id

        return OpenAIAgentsPendingApproval(
            run_state=run_state,
            checkpoint_id=checkpoint_id,
            interruptions=list(interruptions or []),
            _prepared=prepared,
        )

    def record_approval_decision(
        self,
        pending: OpenAIAgentsPendingApproval,
        *,
        approve: bool,
        approver_id: str | None = None,
        approval_note: str | None = None,
        denial_reason: str | None = None,
    ) -> None:
        """Validate checkpoint correlation and approve or deny.

        :param pending: Pending approval from ``pause_step()``.
        :param approve: ``True`` to resume; ``False`` to deny.
        :raises WorkflowSessionTokenInvalidError: on checkpoint mismatch or
            stale state reuse.
        """
        session = pending._prepared._session
        token_id = pending._prepared._session_result._token_id

        adapter_state = session._adapter_step_states.get(token_id)
        if adapter_state is None:
            raise WorkflowSessionTokenInvalidError(
                "Adapter step state not found; the prepared step may have already "
                "been completed or the token was never registered",
                details={"checkpoint_id": pending.checkpoint_id},
            )

        stored_id = adapter_state.get("checkpoint_id")
        if stored_id != pending.checkpoint_id:
            raise WorkflowSessionTokenInvalidError(
                f"Checkpoint ID mismatch: stored {stored_id!r} != "
                f"provided {pending.checkpoint_id!r}; possible stale reuse",
                details={
                    "stored_checkpoint_id": stored_id,
                    "provided_checkpoint_id": pending.checkpoint_id,
                },
            )

        if approve:
            session.resume(
                approval_id=pending.checkpoint_id,
                approver_id=approver_id,
                approval_note=approval_note,
            )
        else:
            session.deny_approval(
                approval_id=pending.checkpoint_id,
                approver_id=approver_id,
                denial_reason=denial_reason,
            )

    def complete_step(
        self,
        prepared: OpenAIAgentsPreparedStep,
        run_result: Any,
        *,
        output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Normalize evidence, merge trace summary, call enforce_step_post_call.

        :param prepared: Prepared step from ``prepare_step()``.
        :param run_result: SDK ``RunResult`` or ``RunResultStreaming`` (after
            draining ``stream_events()``).
        :param output: AEGIS output dict; auto-built from run_result when absent.
        :return: Invocation PASS audit artifact.
        """
        session = prepared._session
        session_result = prepared._session_result
        adapter_step_key = prepared._adapter_step_key
        token_id = session_result._token_id

        adapter_state = session._adapter_step_states.pop(token_id, {})
        try:
            trace_processor = self._get_trace_processor()
            trace_summaries = (
                trace_processor.pop_trace_summary(adapter_step_key)
                if trace_processor else []
            )

            if adapter_state.get("require_trace") and not trace_summaries:
                raise WorkflowProtocolViolationError(
                    "require_trace=true but no SDK trace summary was captured for this step",
                    details={
                        "session_id": session.session_id,
                        "step_id": session_result.step_id,
                        "protocol": "openai_agents",
                        "adapter_step_key": adapter_step_key,
                        "reason_code": "WORKFLOW_PROTOCOL_TRACE_REQUIRED",
                    },
                )

            step_metadata = self._build_step_metadata(
                run_result,
                adapter_step_key=adapter_step_key,
                trace_summaries=trace_summaries,
                adapter_state=adapter_state,
            )

            if output is None:
                output = _extract_output(run_result)

            return session.enforce_step_post_call(
                session_result,
                output,
                step_metadata=step_metadata,
            )
        except Exception:
            session._discard_pending_step(session_result)
            raise

    def _build_step_metadata(
        self,
        run_result: Any,
        *,
        adapter_step_key: str,
        trace_summaries: list[dict[str, Any]],
        adapter_state: dict[str, Any],
    ) -> dict[str, Any]:
        """Build normalized evidence summary. No raw prompts, args, outputs, or blobs."""
        meta: dict[str, Any] = {
            "adapter": "openai_agents",
            "adapter_version": _ADAPTER_VERSION,
            "adapter_step_key": adapter_step_key,
        }

        if run_result is not None:
            last_agent = getattr(run_result, "last_agent", None)
            if last_agent is not None:
                meta["last_agent_name"] = getattr(last_agent, "name", None)

            raw_responses = getattr(run_result, "raw_responses", None) or []
            models_seen: set[str] = set()
            total_tokens = 0
            for resp in raw_responses:
                model = getattr(resp, "model", None)
                if model:
                    models_seen.add(str(model))
                usage = getattr(resp, "usage", None)
                if usage:
                    total_tokens += int(getattr(usage, "total_tokens", 0) or 0)
            meta["models_seen"] = sorted(models_seen)
            meta["total_tokens"] = total_tokens

            interruptions = getattr(run_result, "interruptions", None) or []
            meta["interruptions_count"] = len(interruptions)

            input_gr = getattr(run_result, "input_guardrail_results", None) or []
            output_gr = getattr(run_result, "output_guardrail_results", None) or []
            meta["guardrail_summary"] = {
                "input_guardrail_count": len(input_gr),
                "output_guardrail_count": len(output_gr),
            }

        meta["dynamic_tool_calls_count"] = adapter_state.get("dynamic_tool_calls_count", 0)
        meta["dynamic_tool_call_names"] = [
            tc.get("tool_name")
            for tc in (adapter_state.get("dynamic_tool_calls") or [])
        ]

        if trace_summaries:
            meta["trace_present"] = True
            meta["trace_ids"] = [
                t.get("trace_id") for t in trace_summaries if t.get("trace_id")
            ]
            meta["group_ids"] = [
                t.get("group_id") for t in trace_summaries if t.get("group_id")
            ]
        else:
            meta["trace_present"] = False

        return meta

    def wrap_function_tool(
        self,
        tool: Any,
        session: "GovernanceSession",
        session_result: "SessionPreCallResult",
    ) -> Any:
        """Wrap a ``function_tool`` for governed authorization. Advanced adapter helper."""
        _require_sdk()
        return _make_tool_wrapper(tool, session=session, session_result=session_result)

    def wrap_agent_as_tool(
        self,
        agent: Any,
        binding: OpenAIAgentsParticipantBinding,
        session: "GovernanceSession",
        session_result: "SessionPreCallResult",
    ) -> Any:
        """Wrap ``Agent.as_tool()`` for governed authorization. Advanced adapter helper."""
        _require_sdk()
        tool = agent.as_tool(
            tool_name=binding.agent_name,
            tool_description=f"Governed agent: {binding.agent_name}",
        )
        return _make_tool_wrapper(tool, session=session, session_result=session_result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_output(run_result: Any) -> dict[str, Any]:
    if run_result is None:
        return {"content": None}
    content = getattr(run_result, "output", None)
    if content is not None and not isinstance(content, str):
        try:
            content = str(content)
        except Exception:  # noqa: BLE001
            content = None
    return {"content": content}


__all__ = [
    "OpenAIAgentsAdapter",
    "OpenAIAgentsParticipantBinding",
    "OpenAIAgentsPendingApproval",
    "OpenAIAgentsPreparedStep",
    "OpenAIAgentsTracingProcessor",
]
