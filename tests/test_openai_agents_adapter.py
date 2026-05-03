"""
Unit tests for aegis.openai_agents_adapter.

Covers:
- Import guard behavior with and without the openai-agents extra
- Schema validation for openai_agents protocol_constraints
- Graph validation: duplicate names, unsupported surfaces, hosted tools,
  mcp_servers, realtime/sandbox agent rejection, Agent.as_tool() allow/deny
- Tool wrapping across nested Agent.as_tool() graphs and duplicate names
- Participant binding validation (name mismatch, role mismatch)
- Predeclared tool_calls double-count rejection
- Missing root_agent evidence rejection
- authorize_step_tool_call: budget enforcement and evidence recording
- Adapter cleanup on prepare_step / complete_step failures
- enforce_step_post_call step_metadata persistence
- pause_step / record_approval_decision: checkpoint matching and deny flows
- workflow trace and export step_metadata pass-through
- OpenAIAgentsTracingProcessor: on_trace_end correlation and pop_trace_summary
"""
from __future__ import annotations

import copy
import json
import sys
import types
import unittest.mock as mock
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import guard tests — must work WITHOUT openai-agents installed
# ---------------------------------------------------------------------------

def test_adapter_module_importable_without_sdk():
    """aegis.openai_agents_adapter must be importable even without openai-agents."""
    from aegis import openai_agents_adapter  # noqa: F401
    assert openai_agents_adapter is not None


def test_sdk_available_flag_reflects_installation():
    from aegis.openai_agents_adapter import _SDK_AVAILABLE
    # Flag must be a bool; value depends on whether openai-agents is installed
    assert isinstance(_SDK_AVAILABLE, bool)


def test_require_sdk_raises_without_sdk():
    import aegis.openai_agents_adapter as _mod
    with patch.object(_mod, "_SDK_AVAILABLE", False):
        with pytest.raises(ImportError, match="openai-agents"):
            _mod._require_sdk()


def test_dataclasses_importable_without_sdk():
    """Data classes must be importable without the SDK."""
    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsParticipantBinding,
        OpenAIAgentsPreparedStep,
        OpenAIAgentsPendingApproval,
        OpenAIAgentsTracingProcessor,
    )
    assert OpenAIAgentsAdapter is not None
    assert OpenAIAgentsParticipantBinding is not None
    assert OpenAIAgentsPreparedStep is not None
    assert OpenAIAgentsPendingApproval is not None
    assert OpenAIAgentsTracingProcessor is not None


def test_adapter_instantiable_without_sdk():
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter
    adapter = OpenAIAgentsAdapter()
    assert adapter is not None


def test_participant_binding_is_frozen():
    from aegis.openai_agents_adapter import OpenAIAgentsParticipantBinding
    b = OpenAIAgentsParticipantBinding(
        participant_id="p1", agent_name="AgentA", role="analyst"
    )
    with pytest.raises((AttributeError, TypeError)):
        b.participant_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Schema validation for openai_agents protocol_constraints
# ---------------------------------------------------------------------------

def test_policy_schema_accepts_openai_agents_constraints():
    import json
    import jsonschema
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "policy_dsl.schema.json"
    schema = json.loads(schema_path.read_text())
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "openai_agents": {
                    "require_trace": False,
                    "allow_hosted_tools": False,
                    "allow_agent_as_tool": True,
                    "require_unique_agent_names": True,
                }
            }
        },
    }
    jsonschema.validate(policy, schema)  # must not raise


def test_policy_schema_rejects_unknown_openai_agents_field():
    import json
    import jsonschema
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "policy_dsl.schema.json"
    schema = json.loads(schema_path.read_text())
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "openai_agents": {"unknown_field": True}
            }
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(policy, schema)


def test_policy_schema_accepts_partial_openai_agents_constraints():
    import json
    import jsonschema
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "policy_dsl.schema.json"
    schema = json.loads(schema_path.read_text())
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "openai_agents": {"require_trace": True}
            }
        },
    }
    jsonschema.validate(policy, schema)  # partial constraints are valid


# ---------------------------------------------------------------------------
# Graph validation helpers (testable without SDK via duck typing)
# ---------------------------------------------------------------------------

def _make_mock_agent(name: str, tools=None, handoffs=None, mcp_servers=None) -> MagicMock:
    agent = MagicMock(spec_set=False)
    agent.name = name
    agent.tools = tools or []
    agent.handoffs = handoffs or []
    if mcp_servers is not None:
        agent.mcp_servers = mcp_servers
    else:
        agent.mcp_servers = None
    return agent


def _make_mock_handoff(target_agent: Any) -> MagicMock:
    h = MagicMock()
    h.target_agent = target_agent
    return h


def _make_mock_function_tool(name: str) -> MagicMock:
    t = MagicMock()
    t.__class__.__name__ = "FunctionTool"
    type(t).__name__ = "FunctionTool"
    t.name = name
    return t


def _make_mock_hosted_tool(tool_type: str) -> MagicMock:
    t = MagicMock()
    t.__class__.__name__ = tool_type
    # Override type().__name__
    return t


class _FakeAgentType:
    def __init__(self, name: str, type_name: str, tools=None, handoffs=None,
                 mcp_servers=None):
        self.name = name
        self.tools = tools or []
        self.handoffs = handoffs or []
        self.mcp_servers = mcp_servers

    def __class_getitem__(cls, item):
        return cls


def _make_typed_agent(name: str, type_name: str, **kwargs) -> Any:
    """Create a fake agent whose type().__name__ returns type_name."""
    class _Agent:
        pass
    _Agent.__name__ = type_name
    obj = _Agent()
    obj.name = name
    obj.tools = kwargs.get("tools", [])
    obj.handoffs = kwargs.get("handoffs", [])
    obj.mcp_servers = kwargs.get("mcp_servers", None)
    return obj


# --- Patch _validate_graph to use pure-Python agent objects ---

def test_validate_graph_accepts_normal_agent():
    from aegis.openai_agents_adapter import _validate_graph
    agent = _make_typed_agent("AgentA", "Agent")
    _validate_graph(agent)  # should not raise


def test_validate_graph_rejects_realtime_agent():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    agent = _make_typed_agent("RT", "RealtimeAgent")
    with pytest.raises(WorkflowUnsupportedBindingError, match="RealtimeAgent"):
        _validate_graph(agent)


def test_validate_graph_rejects_sandbox_agent():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    agent = _make_typed_agent("SB", "SandboxAgent")
    with pytest.raises(WorkflowUnsupportedBindingError, match="SandboxAgent"):
        _validate_graph(agent)


def test_validate_graph_rejects_mcp_servers():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    agent = _make_typed_agent("AgentA", "Agent", mcp_servers=["server1"])
    with pytest.raises(WorkflowUnsupportedBindingError, match="mcp_servers"):
        _validate_graph(agent)


def test_validate_graph_rejects_duplicate_agent_names():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    child = _make_typed_agent("AgentA", "Agent")  # same name as root
    root = _make_typed_agent("AgentA", "Agent")

    class _Handoff:
        target_agent = child

    root.handoffs = [_Handoff()]
    with pytest.raises(WorkflowUnsupportedBindingError, match="Duplicate"):
        _validate_graph(root, require_unique_names=True)


def test_validate_graph_allows_duplicate_names_when_disabled():
    from aegis.openai_agents_adapter import _validate_graph
    child = _make_typed_agent("AgentA", "Agent")
    root = _make_typed_agent("AgentA", "Agent")

    class _Handoff:
        target_agent = child

    root.handoffs = [_Handoff()]
    _validate_graph(root, require_unique_names=False)  # should not raise


def test_validate_graph_rejects_hosted_tool_by_default():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    tool = _make_typed_agent("ws", "WebSearchTool")  # reuse helper for type name
    # Use a real FunctionTool-like with the right type name
    class _WebSearchTool:
        name = "web_search"
    _WebSearchTool.__name__ = "WebSearchTool"
    bad_tool = _WebSearchTool()

    root = _make_typed_agent("AgentA", "Agent", tools=[bad_tool])
    with pytest.raises(WorkflowUnsupportedBindingError, match="WebSearchTool"):
        _validate_graph(root, allow_hosted_tools=False)


def test_validate_graph_allows_hosted_tool_when_permitted():
    from aegis.openai_agents_adapter import _validate_graph

    class _WebSearchTool:
        name = "web_search"
    _WebSearchTool.__name__ = "WebSearchTool"
    tool = _WebSearchTool()
    root = _make_typed_agent("AgentA", "Agent", tools=[tool])
    _validate_graph(root, allow_hosted_tools=True)  # should not raise


def test_validate_graph_rejects_agent_as_tool_when_disabled():
    from aegis.openai_agents_adapter import _validate_graph
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    inner_agent = _make_typed_agent("SubAgent", "Agent")

    class _AgentAsTool:
        name = "sub_agent"
        _inner_agent = inner_agent
    _AgentAsTool.__name__ = "FunctionTool"

    tool = _AgentAsTool()
    root = _make_typed_agent("AgentA", "Agent", tools=[tool])
    with pytest.raises(WorkflowUnsupportedBindingError, match="Agent.as_tool"):
        _validate_graph(root, allow_agent_as_tool=False)


def test_wrap_all_tools_recurses_into_agent_as_tool_inner_agent():
    import aegis.openai_agents_adapter as _mod
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    class _Tool:
        def __init__(self, name: str, inner_agent: Any | None = None):
            self.name = name
            self._inner_agent = inner_agent

    class _Agent:
        def __init__(self, name: str, tools=None, handoffs=None):
            self.name = name
            self.tools = tools or []
            self.handoffs = handoffs or []

    inner = _Agent("Inner", tools=[_Tool("inner_func")])
    root = _Agent("Root", tools=[_Tool("sub_agent_tool", inner_agent=inner)])
    wrapped_names: list[str] = []

    with patch.object(
        _mod,
        "_make_tool_wrapper",
        side_effect=lambda tool, **kwargs: wrapped_names.append(tool.name) or f"wrapped:{tool.name}",
    ):
        OpenAIAgentsAdapter()._wrap_all_tools(
            root,
            session=MagicMock(),
            session_result=MagicMock(),
        )

    assert wrapped_names == ["sub_agent_tool", "inner_func"]
    assert root.tools == ["wrapped:sub_agent_tool"]
    assert inner.tools == ["wrapped:inner_func"]


def test_wrap_all_tools_uses_object_identity_for_duplicate_names():
    import aegis.openai_agents_adapter as _mod
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    class _Tool:
        def __init__(self, name: str):
            self.name = name

    class _Handoff:
        def __init__(self, target_agent: Any):
            self.target_agent = target_agent

    class _Agent:
        def __init__(self, name: str, tools=None, handoffs=None):
            self.name = name
            self.tools = tools or []
            self.handoffs = handoffs or []

    child = _Agent("Dup", tools=[_Tool("child_tool")])
    root = _Agent("Dup", tools=[_Tool("root_tool")], handoffs=[_Handoff(child)])
    wrapped_names: list[str] = []

    with patch.object(
        _mod,
        "_make_tool_wrapper",
        side_effect=lambda tool, **kwargs: wrapped_names.append(tool.name) or f"wrapped:{tool.name}",
    ):
        OpenAIAgentsAdapter()._wrap_all_tools(
            root,
            session=MagicMock(),
            session_result=MagicMock(),
        )

    assert wrapped_names == ["root_tool", "child_tool"]
    assert root.tools == ["wrapped:root_tool"]
    assert child.tools == ["wrapped:child_tool"]


def test_wrap_all_tools_raises_on_immutable_agent_tools():
    import aegis.openai_agents_adapter as _mod
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    class _Tool:
        name = "my_tool"

    class _FrozenAgent:
        name = "FrozenAgent"
        handoffs = []

        @property
        def tools(self):
            return [_Tool()]

        @tools.setter
        def tools(self, value):
            raise AttributeError("immutable")

    with pytest.raises(WorkflowUnsupportedBindingError, match="immutable tools"):
        OpenAIAgentsAdapter()._wrap_all_tools(
            _FrozenAgent(),
            session=MagicMock(),
            session_result=MagicMock(),
        )


def test_prepare_step_aborts_on_immutable_agent_tools(monkeypatch):
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    class _FunctionTool:
        pass

    class _Tool(_FunctionTool):
        name = "my_tool"
        on_invoke_tool = None

    class _FrozenAgent:
        name = "AgentA"
        handoffs = []

        @property
        def tools(self):
            return [_Tool()]

        @tools.setter
        def tools(self, value):
            raise AttributeError("immutable")

        def clone(self):
            return self

    import types as _types
    fake_agents = _types.ModuleType("agents")
    fake_agents.FunctionTool = _FunctionTool
    monkeypatch.setitem(sys.modules, "agents", fake_agents)

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": _FrozenAgent()}},
    }

    with a.open_session(policy_file=None) as session:
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            with pytest.raises(WorkflowUnsupportedBindingError, match="immutable tools"):
                adapter.prepare_step(
                    session,
                    invocation,
                    binding=OpenAIAgentsParticipantBinding("p1", "AgentA", "planner"),
                )

        assert session._pending_results == {}
        assert session._adapter_step_states == {}
        assert session._authorized_step_count == 0


def test_make_tool_wrapper_rejects_non_function_tool_when_sdk_available(monkeypatch):
    import aegis.openai_agents_adapter as _mod
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    class _FunctionTool:
        pass

    class _CustomTool:
        name = "custom_tool"

    fake_agents = types.ModuleType("agents")
    fake_agents.FunctionTool = _FunctionTool
    monkeypatch.setitem(sys.modules, "agents", fake_agents)

    with patch.object(_mod, "_SDK_AVAILABLE", True):
        with pytest.raises(
            WorkflowUnsupportedBindingError,
            match="cannot be governance-wrapped",
        ) as exc_info:
            _mod._make_tool_wrapper(
                _CustomTool(),
                session=MagicMock(),
                session_result=MagicMock(),
            )

    assert exc_info.value.details["tool_name"] == "custom_tool"
    assert exc_info.value.details["tool_type"] == "_CustomTool"
    assert exc_info.value.details["reason_code"] == "WORKFLOW_UNSUPPORTED_BINDING"


# ---------------------------------------------------------------------------
# Missing root_agent evidence rejection
# ---------------------------------------------------------------------------

def test_prepare_step_rejects_missing_root_agent():
    """prepare_step raises InvocationValidationError when root_agent is absent."""
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis._internal.errors import InvocationValidationError
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    binding = OpenAIAgentsParticipantBinding("p1", "AgentA", "planner")
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    # protocol_evidence present but root_agent missing
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {}},
    }

    with a.open_session(policy_file=None) as session:
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            with pytest.raises(InvocationValidationError, match="root_agent"):
                adapter.prepare_step(session, invocation, binding=binding)


def test_prepare_step_rejects_predeclared_tool_calls():
    """prepare_step raises InvocationValidationError when tool_calls are predeclared."""
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis._internal.errors import InvocationValidationError
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = _make_typed_agent("AgentA", "Agent")
    binding = OpenAIAgentsParticipantBinding("p1", "AgentA", "planner")
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["tool_calls"] = [{"id": "call-1", "name": "some_tool"}]
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            with pytest.raises(InvocationValidationError, match="tool_calls"):
                adapter.prepare_step(session, invocation, binding=binding)


def test_prepare_step_rejects_custom_tool_without_wrapper_hook(monkeypatch):
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    class _FunctionTool:
        pass

    class _CustomTool:
        name = "custom_tool"

    fake_agents = types.ModuleType("agents")
    fake_agents.FunctionTool = _FunctionTool
    monkeypatch.setitem(sys.modules, "agents", fake_agents)

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = _make_typed_agent("AgentA", "Agent", tools=[_CustomTool()])
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            with pytest.raises(
                WorkflowUnsupportedBindingError,
                match="cannot be governance-wrapped",
            ):
                adapter.prepare_step(
                    session,
                    invocation,
                    binding=OpenAIAgentsParticipantBinding("p1", "AgentA", "planner"),
                )

        assert session._pending_results == {}
        assert session._adapter_step_states == {}
        assert session._authorized_step_count == 0


def test_prepare_step_requires_sdk():
    """prepare_step fails fast when SDK is not installed."""
    import aegis.openai_agents_adapter as _mod
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    adapter = OpenAIAgentsAdapter()
    binding = OpenAIAgentsParticipantBinding("p1", "AgentA", "analyst")

    with patch.object(_mod, "_SDK_AVAILABLE", False):
        with pytest.raises(ImportError, match="openai-agents"):
            adapter.prepare_step(MagicMock(), {}, binding=binding)


def test_bind_graph_requires_sdk():
    import aegis.openai_agents_adapter as _mod
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding
    adapter = OpenAIAgentsAdapter()
    binding = OpenAIAgentsParticipantBinding("p1", "AgentA", "analyst")
    with patch.object(_mod, "_SDK_AVAILABLE", False):
        with pytest.raises(ImportError, match="openai-agents"):
            adapter.bind_graph(MagicMock(), binding)


def test_prepare_step_cleans_up_session_state_when_setup_fails():
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = _make_typed_agent("AgentA", "Agent")
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            with patch.object(_mod, "_build_run_config", side_effect=RuntimeError("boom")):
                with pytest.raises(RuntimeError, match="boom"):
                    adapter.prepare_step(
                        session,
                        invocation,
                        binding=OpenAIAgentsParticipantBinding("p1", "AgentA", "planner"),
                    )

        assert session._pending_results == {}
        assert session._adapter_step_states == {}
        assert session._authorized_step_count == 0
        assert len(session._consumed_token_ids) == 1


# ---------------------------------------------------------------------------
# authorize_step_tool_call — budget enforcement
# ---------------------------------------------------------------------------

POLICY_FILE = "tests/golden_replays/golden_policy_v1.yaml"

_BASE_INV = {
    "policy_file": POLICY_FILE,
    "model_provider": "openai",
    "model_identifier": "gpt-4o",
    "role": "planner",
    "input": {"messages": [{"role": "user", "content": "hi"}]},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


def _make_session(max_tool_calls=None):
    from aegis import AEGIS
    a = AEGIS()
    kwargs: dict[str, Any] = {}
    if max_tool_calls is not None:
        kwargs["metadata"] = {"max_total_tool_calls": max_tool_calls}
    return a.open_session(policy_file=None, metadata=kwargs.get("metadata"))


def test_authorize_step_tool_call_records_evidence():
    from aegis import AEGIS
    from aegis._internal.errors import WorkflowSessionTokenInvalidError

    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        session_result = session.enforce_step_pre_call(_BASE_INV)
        # Register fake adapter state
        session._adapter_step_states[session_result._token_id] = {
            "adapter_step_key": "test-key",
            "dynamic_tool_calls_count": 0,
            "dynamic_tool_calls": [],
            "checkpoint_id": None,
        }
        session.authorize_step_tool_call(
            session_result,
            tool_name="my_tool",
            tool_call_id="call-1",
        )
        state = session._adapter_step_states[session_result._token_id]
        assert state["dynamic_tool_calls_count"] == 1
        assert state["dynamic_tool_calls"][0]["tool_name"] == "my_tool"
        assert session._total_tool_calls_consumed == 1


def test_authorize_step_tool_call_increments_session_counter():
    from aegis import AEGIS
    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(_BASE_INV)
        session._adapter_step_states[r._token_id] = {
            "adapter_step_key": "k", "dynamic_tool_calls_count": 0,
            "dynamic_tool_calls": [], "checkpoint_id": None,
        }
        session.authorize_step_tool_call(r, tool_name="tool_a")
        session.authorize_step_tool_call(r, tool_name="tool_b")
        assert session._total_tool_calls_consumed == 2


def test_authorize_step_tool_call_enforces_allowed_tools():
    from aegis import AEGIS
    from aegis._internal.errors import ToolConstraintViolationError

    a = AEGIS()
    invocation = copy.deepcopy(_BASE_INV)
    invocation["policy_file"] = "tests/golden_replays/policy_with_tools.yaml"
    invocation["context"] = {"role_declared": True}

    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(invocation)
        session._adapter_step_states[r._token_id] = {
            "adapter_step_key": "k",
            "dynamic_tool_calls_count": 0,
            "dynamic_tool_calls": [],
            "checkpoint_id": None,
        }

        with pytest.raises(ToolConstraintViolationError, match="not in allowed_tools"):
            session.authorize_step_tool_call(r, tool_name="unlisted_tool")

        assert session._total_tool_calls_consumed == 0
        assert session._adapter_step_states[r._token_id]["dynamic_tool_calls"] == []


def test_authorize_step_tool_call_enforces_per_tool_max_calls():
    from aegis import AEGIS
    from aegis._internal.errors import ToolConstraintViolationError

    a = AEGIS()
    invocation = copy.deepcopy(_BASE_INV)
    invocation["policy_file"] = "tests/golden_replays/policy_with_tools.yaml"
    invocation["context"] = {"role_declared": True}

    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(invocation)
        session._adapter_step_states[r._token_id] = {
            "adapter_step_key": "k",
            "dynamic_tool_calls_count": 0,
            "dynamic_tool_calls": [],
            "checkpoint_id": None,
        }

        session.authorize_step_tool_call(r, tool_name="search_knowledge_base")
        session.authorize_step_tool_call(r, tool_name="search_knowledge_base")
        with pytest.raises(ToolConstraintViolationError, match="max is 2"):
            session.authorize_step_tool_call(r, tool_name="search_knowledge_base")

        state = session._adapter_step_states[r._token_id]
        assert session._total_tool_calls_consumed == 2
        assert state["dynamic_tool_calls_count"] == 2
        assert [tc["name"] for tc in state["dynamic_tool_calls"]] == [
            "search_knowledge_base",
            "search_knowledge_base",
        ]


def test_authorize_step_tool_call_rejects_unregistered_token():
    from aegis import AEGIS
    from aegis._internal.session import SessionPreCallResult
    from aegis._internal.errors import WorkflowSessionTokenInvalidError

    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        fake = SessionPreCallResult(
            session_id=session.session_id,
            step_id="step-x",
            participant_id=None,
            _token_id="not-registered",
        )
        with pytest.raises(WorkflowSessionTokenInvalidError, match="not registered"):
            session.authorize_step_tool_call(fake, tool_name="tool")


# ---------------------------------------------------------------------------
# enforce_step_post_call step_metadata persistence
# ---------------------------------------------------------------------------

def test_step_metadata_stored_in_step_record():
    from aegis import AEGIS
    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(_BASE_INV)
        meta = {"adapter": "openai_agents", "total_tokens": 42}
        session.enforce_step_post_call(r, {"result": "ok", "confidence": 0.9}, step_metadata=meta)
        assert session._steps[0]["metadata"] == meta


def test_step_without_metadata_has_no_metadata_key():
    from aegis import AEGIS
    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(_BASE_INV)
        session.enforce_step_post_call(r, {"result": "ok", "confidence": 0.9})
        assert "metadata" not in session._steps[0]


def test_step_metadata_none_not_stored():
    from aegis import AEGIS
    a = AEGIS()
    with a.open_session(policy_file=None) as session:
        r = session.enforce_step_pre_call(_BASE_INV)
        session.enforce_step_post_call(r, {"result": "ok", "confidence": 0.9}, step_metadata=None)
        assert "metadata" not in session._steps[0]


# ---------------------------------------------------------------------------
# workflow trace step_metadata pass-through
# ---------------------------------------------------------------------------

def _make_workflow_artifact_with_metadata(step_metadata: dict | None) -> dict:
    step: dict[str, Any] = {
        "step_id": "s1",
        "participant_id": None,
        "invocation_artifact_checksum": "abc123",
    }
    if step_metadata is not None:
        step["metadata"] = step_metadata
    return {
        "workflow_schema_version": "0.9.0",
        "artifact_type": "workflow",
        "session_id": "sess-1",
        "policy_file": None,
        "status": "COMPLETED",
        "started_at": 1000,
        "finalized_at": 2000,
        "steps": [step],
        "invocation_audit_checksums": ["abc123"],
        "failure_summary": None,
        "approval_checkpoints": [],
        "validator_hook_evidence": [],
        "metadata": {},
    }


def test_workflow_trace_includes_step_metadata():
    from aegis._internal.workflow_trace import reconstruct_trace
    meta = {"adapter": "openai_agents", "total_tokens": 99}
    wa = _make_workflow_artifact_with_metadata(meta)
    inv = {
        "enforcement_result": "pass",
        "model_provider": "openai",
        "model_identifier": "gpt-4o",
        "role": "analyst",
        "risk_score": 0.1,
        "failures": [],
        "timestamp": 1000,
    }
    inv_checksum = "abc123"

    trace = reconstruct_trace(wa, [inv])
    step_entry = trace["steps"][0]
    assert step_entry.get("metadata") == meta


def test_workflow_trace_excludes_metadata_when_absent():
    from aegis._internal.workflow_trace import reconstruct_trace
    wa = _make_workflow_artifact_with_metadata(None)
    inv = {
        "enforcement_result": "pass", "model_provider": "openai",
        "model_identifier": "gpt-4o", "role": "analyst",
        "risk_score": 0.1, "failures": [], "timestamp": 1000,
    }
    trace = reconstruct_trace(wa, [inv])
    step_entry = trace["steps"][0]
    assert "metadata" not in step_entry


# ---------------------------------------------------------------------------
# workflow export step_metadata pass-through
# ---------------------------------------------------------------------------

def test_workflow_export_audit_includes_step_metadata():
    from aegis._internal.workflow_export import export_workflow
    meta = {"adapter": "openai_agents", "dynamic_tool_calls_count": 2}
    wa = _make_workflow_artifact_with_metadata(meta)
    inv_artifact = {
        "enforcement_result": "pass",
        "model_provider": "openai",
        "model_identifier": "gpt-4o",
        "role": "analyst",
        "risk_score": 0.1,
        "failures": [],
        "timestamp": 1000,
        "input_checksum": "x",
        "output_checksum": "y",
    }
    result = export_workflow([wa], [inv_artifact], mode="audit")
    step = result["sessions"][0]["steps"][0]
    assert step.get("metadata") == meta


def test_workflow_export_audit_no_metadata_when_absent():
    from aegis._internal.workflow_export import export_workflow
    wa = _make_workflow_artifact_with_metadata(None)
    inv_artifact = {
        "enforcement_result": "pass", "model_provider": "openai",
        "model_identifier": "gpt-4o", "role": "analyst",
        "risk_score": 0.1, "failures": [], "timestamp": 1000,
        "input_checksum": "x", "output_checksum": "y",
    }
    result = export_workflow([wa], [inv_artifact], mode="audit")
    step = result["sessions"][0]["steps"][0]
    assert "metadata" not in step


def test_workflow_export_operator_includes_step_metadata():
    from aegis._internal.workflow_export import export_workflow
    meta = {"adapter": "openai_agents", "trace_present": True}
    wa = _make_workflow_artifact_with_metadata(meta)
    inv_artifact = {
        "enforcement_result": "pass", "model_provider": "openai",
        "model_identifier": "gpt-4o", "role": "analyst",
        "risk_score": 0.1, "failures": [], "timestamp": 1000,
        "input_checksum": "x", "output_checksum": "y",
    }
    result = export_workflow([wa], [inv_artifact], mode="operator")
    step = result["sessions"][0]["steps"][0]
    # operator mode spreads step dict so metadata comes through
    assert step.get("metadata") == meta


# ---------------------------------------------------------------------------
# OpenAIAgentsTracingProcessor tests
# ---------------------------------------------------------------------------

def test_tracing_processor_on_trace_end_no_aegis_meta():
    """Trace without _aegis_openai_agents metadata is silently ignored."""
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor
    p = OpenAIAgentsTracingProcessor()
    trace = MagicMock()
    trace.metadata = {"other": "data"}
    p.on_trace_end(trace)  # should not raise
    assert p.get_trace_summary("any-key") == []


def test_tracing_processor_on_trace_end_captures_summary():
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor
    p = OpenAIAgentsTracingProcessor()
    trace = MagicMock()
    trace.metadata = {"_aegis_openai_agents": {"adapter_step_key": "k1"}}
    trace.trace_id = "trace-abc"
    trace.group_id = "group-xyz"
    trace.name = "my-workflow"
    p.on_trace_end(trace)
    summaries = p.get_trace_summary("k1")
    assert len(summaries) == 1
    assert summaries[0]["trace_id"] == "trace-abc"
    assert summaries[0]["group_id"] == "group-xyz"


def test_tracing_processor_pop_trace_summary_clears():
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor
    p = OpenAIAgentsTracingProcessor()
    trace = MagicMock()
    trace.metadata = {"_aegis_openai_agents": {"adapter_step_key": "k2"}}
    trace.trace_id = "t1"
    trace.group_id = None
    trace.name = None
    p.on_trace_end(trace)
    assert len(p.pop_trace_summary("k2")) == 1
    assert p.get_trace_summary("k2") == []


def test_tracing_processor_handles_missing_adapter_step_key():
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor
    p = OpenAIAgentsTracingProcessor()
    trace = MagicMock()
    trace.metadata = {"_aegis_openai_agents": {}}  # no adapter_step_key
    p.on_trace_end(trace)
    assert p.get_trace_summary("") == []


def test_tracing_processor_handles_exception_gracefully():
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor
    p = OpenAIAgentsTracingProcessor()
    trace = MagicMock()
    trace.metadata = MagicMock(side_effect=RuntimeError("boom"))
    p.on_trace_end(trace)  # must not raise; exception swallowed


# ---------------------------------------------------------------------------
# pause_step / record_approval_decision checkpoint correlation
# ---------------------------------------------------------------------------

def _make_prepared_step(session: Any, token_id: str, adapter_step_key: str) -> Any:
    from aegis.openai_agents_adapter import OpenAIAgentsPreparedStep
    from aegis._internal.session import SessionPreCallResult

    session_result = SessionPreCallResult(
        session_id=session.session_id,
        step_id="step-test",
        participant_id=None,
        _token_id=token_id,
    )
    session._adapter_step_states[token_id] = {
        "adapter_step_key": adapter_step_key,
        "dynamic_tool_calls_count": 0,
        "dynamic_tool_calls": [],
        "checkpoint_id": None,
    }
    return OpenAIAgentsPreparedStep(
        wrapped_root_agent=MagicMock(),
        run_config=MagicMock(),
        _session_result=session_result,
        _adapter_step_key=adapter_step_key,
        _session=session,
    )


def test_pause_step_sets_checkpoint_id():
    from aegis import AEGIS
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    with a.open_session(policy_file=None) as session:
        prepared = _make_prepared_step(session, "tok-1", "step-key-1")
        pending = adapter.pause_step(prepared, MagicMock(), [])
        assert pending.checkpoint_id != ""
        assert session.state == "PAUSED"
        state = session._adapter_step_states.get("tok-1")
        assert state["checkpoint_id"] == pending.checkpoint_id


def test_record_approval_decision_approve_resumes_session():
    from aegis import AEGIS
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    with a.open_session(policy_file=None) as session:
        prepared = _make_prepared_step(session, "tok-2", "step-key-2")
        pending = adapter.pause_step(prepared, MagicMock(), [])
        adapter.record_approval_decision(pending, approve=True, approver_id="alice")
        assert session.state == "OPEN"


def test_record_approval_decision_deny_leaves_paused():
    from aegis import AEGIS
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    with a.open_session(policy_file=None) as session:
        prepared = _make_prepared_step(session, "tok-3", "step-key-3")
        pending = adapter.pause_step(prepared, MagicMock(), [])
        adapter.record_approval_decision(
            pending, approve=False, denial_reason="not approved"
        )
        assert session.state == "PAUSED"


def test_record_approval_decision_rejects_checkpoint_mismatch():
    from aegis import AEGIS
    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsPendingApproval,
        OpenAIAgentsPreparedStep,
    )
    from aegis._internal.errors import WorkflowSessionTokenInvalidError

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    with a.open_session(policy_file=None) as session:
        prepared = _make_prepared_step(session, "tok-4", "step-key-4")
        pending = adapter.pause_step(prepared, MagicMock(), [])
        # Tamper with checkpoint_id
        tampered = OpenAIAgentsPendingApproval(
            run_state=pending.run_state,
            checkpoint_id="wrong-id",
            interruptions=[],
            _prepared=prepared,
        )
        with pytest.raises(WorkflowSessionTokenInvalidError, match="mismatch"):
            adapter.record_approval_decision(tampered, approve=True)


def test_record_approval_decision_rejects_missing_adapter_state():
    from aegis import AEGIS
    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsPendingApproval,
        OpenAIAgentsPreparedStep,
    )
    from aegis._internal.errors import WorkflowSessionTokenInvalidError

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    with a.open_session(policy_file=None) as session:
        prepared = _make_prepared_step(session, "tok-5", "step-key-5")
        pending = adapter.pause_step(prepared, MagicMock(), [])
        # Remove adapter state to simulate stale reuse
        session._adapter_step_states.pop("tok-5", None)
        with pytest.raises(WorkflowSessionTokenInvalidError, match="not found"):
            adapter.record_approval_decision(pending, approve=True)


# ---------------------------------------------------------------------------
# require_trace fail-closed behavior
# ---------------------------------------------------------------------------

def test_complete_step_requires_trace_summary_when_policy_demands_it():
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsParticipantBinding,
        OpenAIAgentsTracingProcessor,
    )
    from aegis._internal.errors import InvocationValidationError, WorkflowProtocolViolationError

    a = AEGIS()
    adapter = OpenAIAgentsAdapter(trace_processor=OpenAIAgentsTracingProcessor())
    root_agent = _make_typed_agent("AgentA", "Agent")
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        session._protocol_constraints = {"openai_agents": {"require_trace": True}}
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            prepared = adapter.prepare_step(
                session,
                invocation,
                binding=OpenAIAgentsParticipantBinding("p1", "AgentA", "planner"),
            )

            with pytest.raises(WorkflowProtocolViolationError, match="require_trace=true"):
                adapter.complete_step(
                    prepared,
                    run_result=None,
                    output={"result": "ok", "confidence": 0.9},
                )

        token = prepared._session_result
        assert token._consumed is True
        assert token._token_id not in session._pending_results
        assert token._token_id not in session._adapter_step_states
        with pytest.raises(InvocationValidationError, match="Token already consumed"):
            session.enforce_step_post_call(token, {"result": "ok", "confidence": 0.9})


def test_complete_step_allows_required_trace_when_summary_present():
    import aegis.openai_agents_adapter as _mod
    from aegis import AEGIS
    from aegis.openai_agents_adapter import (
        OpenAIAgentsAdapter,
        OpenAIAgentsParticipantBinding,
        OpenAIAgentsTracingProcessor,
    )

    a = AEGIS()
    trace_processor = OpenAIAgentsTracingProcessor()
    adapter = OpenAIAgentsAdapter(trace_processor=trace_processor)
    root_agent = _make_typed_agent("AgentA", "Agent")
    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        session._protocol_constraints = {"openai_agents": {"require_trace": True}}
        with patch.object(_mod, "_SDK_AVAILABLE", True):
            prepared = adapter.prepare_step(
                session,
                invocation,
                binding=OpenAIAgentsParticipantBinding("p1", "AgentA", "planner"),
            )
            trace = MagicMock()
            trace.metadata = {
                "_aegis_openai_agents": {"adapter_step_key": prepared._adapter_step_key}
            }
            trace.trace_id = "trace-1"
            trace.group_id = "group-1"
            trace.name = "workflow"
            trace_processor.on_trace_end(trace)

            artifact = adapter.complete_step(
                prepared,
                run_result=None,
                output={"result": "ok", "confidence": 0.9},
            )

        assert artifact["enforcement_result"] == "PASS"
        assert session._steps[0]["metadata"]["trace_present"] is True
        assert session._steps[0]["metadata"]["trace_ids"] == ["trace-1"]


# ---------------------------------------------------------------------------
# _build_step_metadata tests
# ---------------------------------------------------------------------------

def test_build_step_metadata_trace_absent():
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter
    adapter = OpenAIAgentsAdapter()
    meta = adapter._build_step_metadata(
        None,
        adapter_step_key="k",
        trace_summaries=[],
        adapter_state={"dynamic_tool_calls_count": 0, "dynamic_tool_calls": []},
    )
    assert meta["trace_present"] is False
    assert meta["adapter"] == "openai_agents"


def test_build_step_metadata_trace_present():
    from aegis.openai_agents_adapter import OpenAIAgentsAdapter
    adapter = OpenAIAgentsAdapter()
    meta = adapter._build_step_metadata(
        None,
        adapter_step_key="k",
        trace_summaries=[{"trace_id": "t1", "group_id": "g1"}],
        adapter_state={"dynamic_tool_calls_count": 3, "dynamic_tool_calls": [
            {"tool_name": "tool_a"}, {"tool_name": "tool_b"}, {"tool_name": "tool_a"},
        ]},
    )
    assert meta["trace_present"] is True
    assert "t1" in meta["trace_ids"]
    assert meta["dynamic_tool_calls_count"] == 3
    assert "tool_a" in meta["dynamic_tool_call_names"]
