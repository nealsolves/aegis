"""PR-11 optional adapter boundary tests."""
from __future__ import annotations

import importlib

import pytest

import aegis
from aegis import (
    AEGIS,
    WorkflowProtocolViolationError,
    WorkflowUnsupportedBindingError,
)


def test_optional_adapter_modules_import_without_external_sdks():
    modules = [
        "aegis.bedrock_adapter",
        "aegis.a2a_adapter",
        "aegis.openai_agents_adapter",
    ]
    for name in modules:
        assert importlib.import_module(name) is not None


def test_optional_adapter_classes_are_not_top_level_exports():
    for name in [
        "BedrockTraceAdapter",
        "BedrockParticipantBinding",
        "A2AAdapter",
        "A2AParticipantBinding",
        "OpenAIAgentsAdapter",
        "OpenAIAgentsParticipantBinding",
    ]:
        assert not hasattr(aegis, name)
        assert name not in aegis.__all__


def test_bedrock_alias_backed_identity_is_required_for_governed_binding():
    from aegis.bedrock_adapter import BedrockParticipantBinding, BedrockTraceAdapter

    adapter = BedrockTraceAdapter()
    with AEGIS().open_session() as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias="CollaboratorNameOnly",
            role="planner",
        )
        with pytest.raises(WorkflowUnsupportedBindingError):
            adapter.prepare_step(
                session,
                {
                    "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
                    "model_provider": "bedrock",
                    "model_identifier": "anthropic.claude",
                    "role": "planner",
                    "input": {"messages": []},
                    "context": {"role_declared": True, "schema_exists": True},
                },
                binding=binding,
            )


def test_a2a_rejects_grpc_and_confusable_grpc_bindings():
    from aegis.a2a_adapter import _validate_agent_card

    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    for binding in ["GRPC", "grpc", "ɡrpc"]:
        card = {
            "name": "RemotePlanner",
            "supportedInterfaces": [
                {"protocolBinding": binding, "protocolVersion": "1.0"}
            ],
        }
        with pytest.raises(WorkflowProtocolViolationError):
            _validate_agent_card(card, constraints)


def test_a2a_rejects_task_state_shorthand_and_redacts_raw_payload():
    from aegis.a2a_adapter import _validate_task_envelope, _task_summary

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_envelope({"status": {"state": "done"}}, require_task_state=True)

    summary = _task_summary({
        "id": "task-1",
        "status": {"state": "TASK_STATE_COMPLETED"},
        "history": [{"message": "raw prompt"}],
        "artifacts": [{"artifactId": "artifact-1", "bytes": "raw"}],
    })
    serialized = str(summary)
    assert "raw prompt" not in serialized
    assert "bytes" not in serialized
    assert summary["artifact_count"] == 1


def test_openai_agents_import_guard_is_actionable_without_sdk():
    import aegis.openai_agents_adapter as module

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(module, "_SDK_AVAILABLE", False)
        with pytest.raises(
            ImportError,
            match="aegis-ai-governance\\[openai-agents\\]",
        ):
            module._require_sdk()


def test_openai_agents_duplicate_names_and_hosted_tools_fail_closed():
    from aegis.openai_agents_adapter import _validate_graph

    class Agent:
        def __init__(self, name, tools=None, handoffs=None, mcp_servers=None):
            self.name = name
            self.tools = tools or []
            self.handoffs = handoffs or []
            self.mcp_servers = mcp_servers

    class Handoff:
        def __init__(self, target_agent):
            self.target_agent = target_agent

    class WebSearchTool:
        name = "web_search"

    root = Agent("A", handoffs=[Handoff(Agent("A"))])
    with pytest.raises(WorkflowUnsupportedBindingError):
        _validate_graph(root, require_unique_names=True)

    with pytest.raises(WorkflowUnsupportedBindingError):
        _validate_graph(Agent("B", tools=[WebSearchTool()]), allow_hosted_tools=False)
