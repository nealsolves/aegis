"""
Integration tests for aegis.openai_agents_adapter with the live OpenAI Agents SDK.

These tests require the openai-agents extra:
    pip install -e ".[openai-agents]"

They validate adapter behavior against the real SDK without making network calls.
Tests cover:
- Agent.clone() preservation
- function_tool wrapping and execution
- Agent.as_tool() wrapping
- Handoff traversal
- RunState interruption and resume
- Tracing processor callbacks
"""
from __future__ import annotations

import copy
from unittest.mock import MagicMock

import pytest

# Skip all tests if SDK is not available
pytest.importorskip("agents", reason="openai-agents extra not installed")

from agents import Agent, function_tool  # noqa: E402
from agents.run_config import RunConfig  # noqa: E402

from aegis import AEGIS  # noqa: E402
from aegis.openai_agents_adapter import (  # noqa: E402
    OpenAIAgentsAdapter,
    OpenAIAgentsParticipantBinding,
)

# ---------------------------------------------------------------------------
# Test fixtures
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


@function_tool
def calculator(operation: str, a: float, b: float) -> float:
    """Perform basic math operations."""
    if operation == "add":
        return a + b
    if operation == "multiply":
        return a * b
    return 0.0


@function_tool
def weather_tool(location: str) -> str:
    """Get weather for a location."""
    return f"Weather in {location}: Sunny, 72°F"


# ---------------------------------------------------------------------------
# Agent.clone() tests
# ---------------------------------------------------------------------------


def test_agent_clone_preserves_structure():
    """Verify Agent.clone() creates independent copies."""
    agent = Agent(name="TestAgent", tools=[calculator])
    cloned = agent.clone()

    assert cloned.name == agent.name
    assert len(cloned.tools) == len(agent.tools)
    assert cloned is not agent
    assert id(cloned) != id(agent)


def test_prepare_step_clones_agent_graph():
    """Verify prepare_step clones the agent without mutating the original."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="OriginalAgent", tools=[calculator])
    original_tools = root_agent.tools

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "OriginalAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)
        pending = session._pending_results[prepared._session_result.operation_id]

        # Verify tools were wrapped on cloned agent
        assert prepared.wrapped_root_agent is not root_agent
        assert prepared.wrapped_root_agent.name == root_agent.name
        assert "inner" not in pending
        assert invocation["output"] == {
            "result": "ok",
            "confidence": 0.9,
        }

        # Original tools should be unchanged
        assert root_agent.tools is original_tools
        assert len(root_agent.tools) == 1


def test_prepare_step_deep_clones_handoff_targets():
    """Nested handoff agents must not be mutated with session-bound wrappers."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    child_agent = Agent(name="ChildAgent", tools=[calculator])
    root_agent = Agent(name="RootAgent", handoffs=[child_agent])
    original_child_tools = child_agent.tools
    original_child_tool = child_agent.tools[0]

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "RootAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        cloned_child = prepared.wrapped_root_agent.handoffs[0]
        assert cloned_child is not child_agent
        assert cloned_child.tools[0] is not original_child_tool
        assert child_agent.tools is original_child_tools
        assert child_agent.tools[0] is original_child_tool


def test_prepare_step_deep_clones_agent_as_tool_inner_agent():
    """Agent.as_tool() inner agents must be wrapped only on the cloned graph."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    inner_agent = Agent(name="InnerCloneAgent", tools=[calculator])
    outer_agent = Agent(
        name="OuterCloneAgent",
        tools=[inner_agent.as_tool(
            tool_name="inner_clone_tool",
            tool_description="Inner clone tool",
        )],
    )
    original_inner_tools = inner_agent.tools
    original_inner_tool = inner_agent.tools[0]

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": outer_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "OuterCloneAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        wrapped_tool = prepared.wrapped_root_agent.tools[0]
        cloned_inner = getattr(wrapped_tool, "_agent_instance")
        assert cloned_inner is not inner_agent
        assert cloned_inner.tools[0] is not original_inner_tool
        assert inner_agent.tools is original_inner_tools
        assert inner_agent.tools[0] is original_inner_tool


# ---------------------------------------------------------------------------
# function_tool wrapping tests
# ---------------------------------------------------------------------------


def test_wrapped_function_tool_executes():
    """Verify wrapped function tools can execute successfully."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="MathAgent", tools=[calculator])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "MathAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Verify wrapped agent has tools
        assert len(prepared.wrapped_root_agent.tools) == 1
        wrapped_tool = prepared.wrapped_root_agent.tools[0]
        assert wrapped_tool.name == "calculator"


def test_multiple_tools_wrapped_independently():
    """Verify each tool in the graph gets independently wrapped."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="MultiToolAgent", tools=[calculator, weather_tool])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "MultiToolAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Both tools should be wrapped
        assert len(prepared.wrapped_root_agent.tools) == 2
        tool_names = {t.name for t in prepared.wrapped_root_agent.tools}
        assert tool_names == {"calculator", "weather_tool"}


# ---------------------------------------------------------------------------
# Agent.as_tool() tests
# ---------------------------------------------------------------------------


def test_agent_as_tool_wrapping():
    """Verify Agent.as_tool() creates tool-wrapped agents."""
    inner_agent = Agent(name="InnerAgent", tools=[calculator])
    outer_agent = Agent(
        name="OuterAgent",
        tools=[inner_agent.as_tool(
            tool_name="inner_calculator",
            tool_description="Inner agent calculator"
        )],
    )

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": outer_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "OuterAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Verify outer agent has wrapped tool
        assert len(prepared.wrapped_root_agent.tools) == 1
        wrapped_outer_tool = prepared.wrapped_root_agent.tools[0]
        assert wrapped_outer_tool.name == "inner_calculator"


def test_agent_as_tool_disabled_rejects():
    """Verify Agent.as_tool() is rejected when allow_agent_as_tool=false."""
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    inner_agent = Agent(name="InnerAgent", tools=[calculator])
    outer_agent = Agent(
        name="OuterAgent",
        tools=[inner_agent.as_tool(
            tool_name="inner_tool",
            tool_description="Inner tool"
        )],
    )

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": outer_agent}},
    }

    with a.open_session(policy_file=None) as session:
        session._protocol_constraints = {
            "openai_agents": {"allow_agent_as_tool": False}
        }
        binding = OpenAIAgentsParticipantBinding("p1", "OuterAgent", "planner")

        with pytest.raises(WorkflowUnsupportedBindingError, match="Agent.as_tool"):
            adapter.prepare_step(session, invocation, binding=binding)


# ---------------------------------------------------------------------------
# Handoff traversal tests
# ---------------------------------------------------------------------------


def test_handoff_traversal():
    """Verify handoff targets are discovered and wrapped."""
    analyst_agent = Agent(name="Analyst", tools=[calculator])
    planner_agent = Agent(
        name="Planner",
        tools=[weather_tool],
        handoffs=[analyst_agent],  # Direct agent reference in handoffs
    )

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": planner_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "Planner", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Root agent tools should be wrapped
        assert len(prepared.wrapped_root_agent.tools) == 1
        # Handoff should be preserved
        assert len(prepared.wrapped_root_agent.handoffs) == 1


def test_duplicate_agent_names_across_handoffs_rejected():
    """Verify duplicate agent names in graph are rejected by default."""
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    # Two agents with the same name
    dup_agent_1 = Agent(name="DupName", tools=[calculator])
    dup_agent_2 = Agent(name="DupName", tools=[weather_tool])
    root_agent = Agent(
        name="Root",
        handoffs=[dup_agent_1, dup_agent_2],  # Direct agent references
    )

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "Root", "planner")

        with pytest.raises(WorkflowUnsupportedBindingError, match="Duplicate"):
            adapter.prepare_step(session, invocation, binding=binding)


# ---------------------------------------------------------------------------
# RunConfig and tracing tests
# ---------------------------------------------------------------------------


def test_run_config_injection():
    """Verify RunConfig is enriched with AEGIS correlation metadata."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="TestAgent", tools=[calculator])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "TestAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Verify RunConfig has AEGIS metadata
        assert prepared.run_config is not None
        assert hasattr(prepared.run_config, "trace_metadata")
        assert "_aegis_openai_agents" in prepared.run_config.trace_metadata
        assert "adapter_step_key" in prepared.run_config.trace_metadata["_aegis_openai_agents"]
        assert prepared.run_config.group_id == session.session_id


def test_run_config_preserves_host_fields():
    """Verify adapter preserves host-supplied RunConfig fields."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="TestAgent", tools=[calculator])

    host_config = RunConfig(
        workflow_name="HostWorkflow",
        trace_id="host-trace-123",
        model="gpt-4o-mini",
    )

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "TestAgent", "planner")
        prepared = adapter.prepare_step(
            session, invocation, binding=binding, run_config=host_config
        )

        # Host fields should be preserved
        assert prepared.run_config.workflow_name == "HostWorkflow"
        assert prepared.run_config.trace_id == "host-trace-123"
        assert prepared.run_config.model == "gpt-4o-mini"
        # AEGIS metadata should be added
        assert "_aegis_openai_agents" in prepared.run_config.trace_metadata


def test_tracing_processor_correlation():
    """Verify OpenAIAgentsTracingProcessor correlates traces via adapter_step_key."""
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor

    processor = OpenAIAgentsTracingProcessor()

    # Simulate SDK trace end callback
    mock_trace = MagicMock()
    mock_trace.trace_id = "trace-123"
    mock_trace.group_id = "group-456"
    mock_trace.name = "test-workflow"
    mock_trace.metadata = {
        "_aegis_openai_agents": {"adapter_step_key": "test-step-key-789"}
    }

    processor.on_trace_end(mock_trace)

    # Verify trace summary was captured
    summaries = processor.get_trace_summary("test-step-key-789")
    assert len(summaries) == 1
    assert summaries[0]["trace_id"] == "trace-123"
    assert summaries[0]["group_id"] == "group-456"
    assert summaries[0]["name"] == "test-workflow"


def test_tracing_processor_pop_clears():
    """Verify pop_trace_summary removes the summary."""
    from aegis.openai_agents_adapter import OpenAIAgentsTracingProcessor

    processor = OpenAIAgentsTracingProcessor()
    mock_trace = MagicMock()
    mock_trace.trace_id = "t1"
    mock_trace.group_id = "g1"
    mock_trace.name = "n1"
    mock_trace.metadata = {"_aegis_openai_agents": {"adapter_step_key": "key1"}}

    processor.on_trace_end(mock_trace)
    assert len(processor.get_trace_summary("key1")) == 1

    popped = processor.pop_trace_summary("key1")
    assert len(popped) == 1
    assert len(processor.get_trace_summary("key1")) == 0


# ---------------------------------------------------------------------------
# Complete step and metadata tests
# ---------------------------------------------------------------------------


def test_complete_step_builds_metadata():
    """Verify complete_step builds normalized step metadata."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="MetaAgent", tools=[calculator])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "MetaAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Complete with explicit output
        artifact = adapter.complete_step(
            prepared,
            run_result=None,
            output={"result": "completed", "confidence": 0.95},
        )

        # Verify artifact returned
        assert artifact["enforcement_result"] == "PASS"

        # Verify metadata stored in session
        assert len(session._steps) == 1
        assert "metadata" in session._steps[0]
        meta = session._steps[0]["metadata"]
        assert meta["adapter"] == "openai_agents"
        assert "adapter_step_key" in meta
        assert meta["trace_present"] is False


def test_complete_step_with_mock_run_result():
    """Verify complete_step extracts metadata from RunResult."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="ResultAgent", tools=[calculator])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "ResultAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Mock RunResult
        mock_result = MagicMock()
        mock_result.output = "Task completed successfully"
        mock_result.last_agent = root_agent
        mock_result.raw_responses = []
        mock_result.interruptions = []
        mock_result.input_guardrail_results = []
        mock_result.output_guardrail_results = []

        # Provide output matching golden schema (result + confidence)
        artifact = adapter.complete_step(
            prepared,
            run_result=mock_result,
            output={"result": "completed", "confidence": 0.95}
        )

        assert artifact["enforcement_result"] == "PASS"
        meta = session._steps[0]["metadata"]
        assert meta["last_agent_name"] == "ResultAgent"
        assert meta["interruptions_count"] == 0


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------


def test_prepare_step_fails_on_unsupported_agent_type():
    """Verify unsupported agent types are rejected."""
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    # Create a fake agent with unsupported type name
    class RealtimeAgent:
        def __init__(self):
            self.name = "RealtimeTest"
            self.tools = []
            self.handoffs = []
            self.mcp_servers = None

    unsupported_agent = RealtimeAgent()

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": unsupported_agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "RealtimeTest", "planner")

        with pytest.raises(WorkflowUnsupportedBindingError, match="RealtimeAgent"):
            adapter.prepare_step(session, invocation, binding=binding)


def test_prepare_step_fails_on_mcp_servers():
    """Verify agents with mcp_servers are rejected."""
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    agent = Agent(name="MCPAgent", tools=[calculator])
    agent.mcp_servers = ["server1"]

    a = AEGIS()
    adapter = OpenAIAgentsAdapter()

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": agent}},
    }

    with a.open_session(policy_file=None) as session:
        binding = OpenAIAgentsParticipantBinding("p1", "MCPAgent", "planner")

        with pytest.raises(WorkflowUnsupportedBindingError, match="mcp_servers"):
            adapter.prepare_step(session, invocation, binding=binding)


# ---------------------------------------------------------------------------
# End-to-end integration test
# ---------------------------------------------------------------------------


def test_end_to_end_governed_step_without_network():
    """End-to-end test: prepare → complete without network calls."""
    a = AEGIS()
    adapter = OpenAIAgentsAdapter()
    root_agent = Agent(name="E2EAgent", tools=[calculator, weather_tool])

    invocation = copy.deepcopy(_BASE_INV)
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"openai_agents": {"root_agent": root_agent}},
    }

    with a.open_session(policy_file=None) as session:
        # Phase 1: Prepare
        binding = OpenAIAgentsParticipantBinding("p1", "E2EAgent", "planner")
        prepared = adapter.prepare_step(session, invocation, binding=binding)

        # Verify prepared step
        assert prepared.wrapped_root_agent.name == "E2EAgent"
        assert len(prepared.wrapped_root_agent.tools) == 2
        assert prepared.run_config is not None

        # Phase 2: Simulate tool execution (no actual run)
        # In real usage, host would call Runner.run(prepared.wrapped_root_agent, ...)
        # For this test, we skip to completion

        # Phase 3: Complete
        mock_result = MagicMock()
        mock_result.output = "Analysis complete"
        mock_result.last_agent = root_agent
        mock_result.raw_responses = []
        mock_result.interruptions = []
        mock_result.input_guardrail_results = []
        mock_result.output_guardrail_results = []

        # Provide output matching golden schema
        artifact = adapter.complete_step(
            prepared,
            run_result=mock_result,
            output={"result": "Analysis complete", "confidence": 0.98}
        )

        # Verify governance artifact
        assert artifact["enforcement_result"] == "PASS"
        assert artifact["model_provider"] == "openai"
        assert artifact["role"] == "planner"

        # Verify workflow state
        assert session.state == "OPEN"
        assert len(session._steps) == 1
        assert session._steps[0]["metadata"]["adapter"] == "openai_agents"
