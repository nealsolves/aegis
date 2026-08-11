"""Deterministic, network-free runs through AEGIS public adapter seams."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from agents import Agent

from aegis import AIGCError
from aegis.a2a_adapter import A2AAdapter, A2AParticipantBinding
from aegis.bedrock_adapter import (
    BedrockParticipantBinding,
    BedrockTraceAdapter,
)
from aegis.openai_agents_adapter import (
    OpenAIAgentsAdapter,
    OpenAIAgentsParticipantBinding,
)

from demo_contract import AdapterRunResponse, DemoError, demo_source
from demo_errors import public_demo_error
from demo_fixtures import AdapterFixture, get_adapter_fixture
from demo_runtime import demo_aegis


POLICY_DIR = Path(__file__).resolve().parent / "demo_policies"
POLICY_REF = "integration_adapters.yaml"
BEDROCK_ALIAS = (
    "arn:aws:bedrock:us-east-1:123456789012:"
    "agent-alias/AGENTID12A/ALIASID12B"
)


def _invocation(adapter_id: str) -> dict[str, Any]:
    return {
        "policy_file": POLICY_REF,
        "model_provider": adapter_id,
        "model_identifier": "deterministic-adapter-fixture-v1",
        "role": "planner",
        "input": {"prompt": "Record the fixed demonstration plan."},
        "context": {"deterministic_fixture": True},
    }


def _reason_code(exc: AIGCError) -> str:
    details = exc.details
    if isinstance(details, dict):
        reason_code = details.get("reason_code")
        if isinstance(reason_code, str):
            return reason_code
    return exc.code


def _run_bedrock(session: Any, fixture: AdapterFixture) -> dict[str, Any]:
    adapter = BedrockTraceAdapter()
    prepared = adapter.prepare_step(
        session,
        _invocation("bedrock"),
        binding=BedrockParticipantBinding(
            participant_id="bedrock-demo-planner",
            collaborator_alias=BEDROCK_ALIAS,
            role="planner",
        ),
    )
    return adapter.complete_step(
        prepared,
        output=deepcopy(fixture.output),
        trace_parts=deepcopy(fixture.provider_input["trace_parts"]),
    )


def _run_openai_agents(
    session: Any,
    fixture: AdapterFixture,
) -> dict[str, Any]:
    graph = fixture.provider_input["agent"]
    root_agent = Agent(name=graph["name"], tools=[])
    invocation = _invocation("openai_agents")
    invocation["protocol"] = "openai_agents"
    invocation["context"] = {
        **invocation["context"],
        "protocol_evidence": {
            "openai_agents": {
                "root_agent": root_agent,
            },
        },
    }
    if "tool_calls" in fixture.provider_input:
        invocation["tool_calls"] = deepcopy(
            fixture.provider_input["tool_calls"]
        )

    adapter = OpenAIAgentsAdapter()
    prepared = adapter.prepare_step(
        session,
        invocation,
        binding=OpenAIAgentsParticipantBinding(
            participant_id="openai-agents-demo-planner",
            agent_name="DemoPlanner",
            role="planner",
        ),
    )
    run_result = SimpleNamespace(
        last_agent=prepared.wrapped_root_agent,
        raw_responses=[],
        interruptions=[],
        input_guardrail_results=[],
        output_guardrail_results=[],
    )
    return adapter.complete_step(
        prepared,
        run_result,
        output=deepcopy(fixture.output),
    )


def _run_a2a(session: Any, fixture: AdapterFixture) -> dict[str, Any]:
    adapter = A2AAdapter()
    prepared = adapter.prepare_step(
        session,
        _invocation("a2a"),
        binding=A2AParticipantBinding(
            participant_id="a2a-demo-planner",
            agent_name="DemoRemotePlanner",
            role="planner",
        ),
        agent_card=deepcopy(fixture.provider_input["agent_card"]),
    )
    return adapter.complete_step(
        prepared,
        deepcopy(fixture.output),
        task_envelope=deepcopy(
            fixture.provider_input["task_envelope"],
        ),
    )


ADAPTER_RUNNERS: dict[
    str,
    Callable[[Any, AdapterFixture], dict[str, Any]],
] = {
    "bedrock": _run_bedrock,
    "openai_agents": _run_openai_agents,
    "a2a": _run_a2a,
}


def _positive_response(
    fixture: AdapterFixture,
    artifact: dict[str, Any],
    workflow_artifact: dict[str, Any],
) -> AdapterRunResponse:
    normalized_evidence = workflow_artifact["steps"][0]["metadata"]
    return AdapterRunResponse(
        adapter_id=fixture.adapter_id,
        fixture_id=fixture.fixture_id,
        provider_input=deepcopy(fixture.provider_input),
        normalized_evidence=normalized_evidence,
        decision="PASS",
        artifact=artifact,
        workflow_artifact=workflow_artifact,
        error=None,
        source=demo_source(),
    )


def _negative_response(
    fixture: AdapterFixture,
    exc: AIGCError,
    workflow_artifact: dict[str, Any],
) -> AdapterRunResponse:
    reason_code = _reason_code(exc)
    if reason_code != fixture.expected_reason_code:
        raise exc
    return AdapterRunResponse(
        adapter_id=fixture.adapter_id,
        fixture_id=fixture.fixture_id,
        provider_input=deepcopy(fixture.provider_input),
        normalized_evidence={"reason_code": reason_code},
        decision="FAIL",
        artifact=exc.audit_artifact,
        workflow_artifact=workflow_artifact,
        error=DemoError(**public_demo_error(reason_code)),
        source=demo_source(),
    )


def run_adapter(adapter_id: str, fixture_id: str) -> AdapterRunResponse:
    fixture = get_adapter_fixture(adapter_id, fixture_id)
    runner = ADAPTER_RUNNERS[adapter_id]
    session = demo_aegis(POLICY_DIR).open_session(policy_file=POLICY_REF)

    if fixture.expected_reason_code is not None:
        try:
            with session:
                runner(session, fixture)
        except AIGCError as exc:
            workflow_artifact = session.workflow_artifact
            if workflow_artifact is None:
                raise
            return _negative_response(
                fixture,
                exc,
                workflow_artifact,
            )
        raise RuntimeError(
            "Typed-negative adapter fixture unexpectedly completed",
        )

    with session:
        artifact = runner(session, fixture)
        session.complete()

    workflow_artifact = session.workflow_artifact
    if workflow_artifact is None:
        raise RuntimeError("AEGIS did not emit a workflow artifact")
    return _positive_response(
        fixture,
        artifact,
        workflow_artifact,
    )
