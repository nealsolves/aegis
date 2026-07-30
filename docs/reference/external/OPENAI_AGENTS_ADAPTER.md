# OpenAI Agents SDK Adapter — AEGIS v0.9.0 Beta

> **Status:** Included in the `aegis-ai-governance==0.9.0b1` public beta.
> Not re-exported from the top-level `aegis` package.
> Requires `pip install "aegis-ai-governance[openai-agents]"`.
> This is an advanced follow-on surface per the [first-adopter docs order](../WORKFLOW_QUICKSTART.md).

## Overview

`aegis.openai_agents_adapter` provides AEGIS governance for runs that use the
[OpenAI Agents SDK](https://openai.github.io/openai-agents-python/).

**AEGIS owns:** pre-run protocol validation, binding validation,
wrapped-tool authorization, interruption checkpoint correlation, and additive
workflow evidence.

**The host continues to own:** orchestration, transport, retries, credentials,
business state, tool execution, and provider SDK usage.

## Installation

```bash
pip install "aegis-ai-governance[openai-agents]"
```

## Public Surface

```python
from aegis.openai_agents_adapter import (
    OpenAIAgentsAdapter,
    OpenAIAgentsParticipantBinding,
    OpenAIAgentsPreparedStep,
    OpenAIAgentsPendingApproval,
    OpenAIAgentsTracingProcessor,
)
```

### `OpenAIAgentsParticipantBinding`

Binds a root agent name to an AEGIS participant identity and role.

| Field | Type | Description |
|-------|------|-------------|
| `participant_id` | `str` | Must match a participant declared in the workflow policy |
| `agent_name` | `str` | Must match `Agent.name` of the root agent |
| `role` | `str` | AEGIS role for the invocation |

### `OpenAIAgentsAdapter`

```python
adapter = OpenAIAgentsAdapter()
```

#### `bind_graph(agent, binding, *, protocol_constraints=None)`

Optional preflight validator. Validates the agent graph and binding without
modifying the session or agent objects. Raises
`WorkflowUnsupportedBindingError` on failure.

#### `prepare_step(session, invocation, *, binding, run_config=None, step_id=None)`

Validates the graph, clones the agent graph, wraps supported tools, injects
`protocol_evidence.openai_agents`, calls `session.enforce_step_pre_call`, and
returns an `OpenAIAgentsPreparedStep`.

The invocation dict must include:
```python
invocation["context"]["protocol_evidence"]["openai_agents"]["root_agent"] = my_agent
```

Returns `OpenAIAgentsPreparedStep` with:
- `wrapped_root_agent` — cloned, governed root agent (pass to `Runner.run`)
- `run_config` — enriched `RunConfig` with AEGIS correlation metadata

#### `pause_step(prepared, run_state, interruptions)`

Call when a run returns interruptions. Mirrors them into
`session.pause(...)`, mints an AEGIS checkpoint, and returns
`OpenAIAgentsPendingApproval`.

#### `record_approval_decision(pending, *, approve, approver_id=None, approval_note=None, denial_reason=None)`

Call to approve or deny a pending interruption checkpoint.

- `approve=True` → calls `session.resume(...)`
- `approve=False` → calls `session.deny_approval(...)`

Raises `WorkflowSessionTokenInvalidError` on checkpoint mismatch or stale reuse.

#### `complete_step(prepared, run_result, *, output=None)`

Normalizes result evidence, merges trace summary, and calls
`session.enforce_step_post_call(step_metadata=...)`. Returns the invocation
PASS audit artifact.

### `OpenAIAgentsTracingProcessor`

Implements the SDK `TracingProcessor` interface. Registered globally once per
process via `add_trace_processor`. Correlates trace spans back to
`adapter_step_key` via `RunConfig.trace_metadata["_aegis_openai_agents"]`.

## Minimal Usage Example

```python
import asyncio
from aegis import AEGIS
from aegis.openai_agents_adapter import OpenAIAgentsAdapter, OpenAIAgentsParticipantBinding

# Requires openai-agents to be installed
from agents import Agent, Runner, function_tool

@function_tool
def get_weather(city: str) -> str:
    return f"Sunny in {city}"

agent = Agent(name="WeatherAgent", tools=[get_weather])
adapter = OpenAIAgentsAdapter()
binding = OpenAIAgentsParticipantBinding(
    participant_id="weather-agent",
    agent_name="WeatherAgent",
    role="analyst",
)

aegis = AEGIS()

async def run():
    with aegis.open_session(policy_file="policies/my_policy.yaml") as session:
        invocation = {
            "model_provider": "openai",
            "model_identifier": "gpt-4o",
            "role": "analyst",
            "input": {"messages": [{"role": "user", "content": "Weather in NYC?"}]},
            "output": {},
            "protocol": "openai_agents",
            "context": {
                "protocol_evidence": {
                    "openai_agents": {"root_agent": agent}
                }
            },
        }
        prepared = adapter.prepare_step(session, invocation, binding=binding)
        result = await Runner.run(
            prepared.wrapped_root_agent,
            "What's the weather in NYC?",
            run_config=prepared.run_config,
        )
        adapter.complete_step(prepared, result)
        session.complete()

asyncio.run(run())
```

`prepare_step(...)` accepts the broader host invocation shape shown above for
adapter compatibility. If `output` is present, it must be a JSON-serializable
object; the adapter validates it without mutating the caller's mapping, then
constructs a detached Phase A projection with `output` omitted. Actual provider
output enters governance only through `complete_step(...)` (Phase B). Direct
`enforce_pre_call(...)` and `GovernanceSession.enforce_step_pre_call(...)`
invocations must omit `output`.

## Protocol Constraints

Add to your workflow policy under `workflow.protocol_constraints.openai_agents`:

```yaml
workflow:
  protocol_constraints:
    openai_agents:
      require_trace: false          # default: false
      allow_hosted_tools: false     # default: false — hosted tools are not governance-wrapped
      allow_agent_as_tool: true     # default: true
      require_unique_agent_names: true  # default: true
```

## Human-in-the-Loop (Interruptions)

```python
result = await Runner.run(prepared.wrapped_root_agent, input,
                          run_config=prepared.run_config)

if result.interruptions:
    pending = adapter.pause_step(prepared, result.interrupted_state, result.interruptions)
    # ... human decision ...
    adapter.record_approval_decision(pending, approve=True, approver_id="alice")
    # record_approval_decision already called session.resume() — do not call it again
    # resume run with same prepared step
    final = await Runner.run(
        prepared.wrapped_root_agent, input,
        run_config=prepared.run_config,
        state=pending.run_state,
    )
    adapter.complete_step(prepared, final)
```

## Rejected Surfaces

The following surfaces are rejected in governed mode:

| Surface | Reason |
|---------|--------|
| `RealtimeAgent`, `SandboxAgent` | Not supported in v0.9.0 |
| `mcp_servers` on any agent | Not supported in governed mode |
| `WebSearchTool`, `FileSearchTool`, `CodeInterpreterTool`, `ComputerTool` | Hosted tools are not governance-wrapped |
| `HostedMCPTool`, `MCPTool` | Hosted MCP (not supported) |
| Non-`FunctionTool` custom tool classes | No verified pre-execution wrapper hook |
| Predeclared `tool_calls` in invocation | Adapter tracks tool calls dynamically |
| Duplicate agent names (across root + handoffs + nested) | Set `require_unique_agent_names=false` to override |

## GovernanceSession Seams

Two new methods were added to `GovernanceSession` for adapter use:

### `authorize_step_tool_call(session_result, *, tool_name, tool_call_id=None)`

Called by the adapter for each intercepted tool call. Enforces the session
tool-call budget, policy `tools.allowed_tools` / per-tool `max_calls`, and
records summary evidence.

### `enforce_step_post_call(session_result, output, *, step_metadata=None)`

Extended to accept an optional `step_metadata` dict, which is stored under
`steps[i]["metadata"]` in the workflow artifact. Existing step keys are
unchanged. Workflow artifacts without adapter metadata are not affected.
