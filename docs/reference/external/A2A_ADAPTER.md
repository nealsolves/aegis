# A2A Adapter

> **Status:** Included in the `aegis-ai-governance==0.9.0b1` public beta.
> Import from `aegis.a2a_adapter`; it is not re-exported from top-level
> `aegis`.

`A2AAdapter` is an optional adapter for host-owned A2A interactions. It
validates Agent Card compatibility before a governed step and validates A2A
task-state evidence before completing the step.

AEGIS does not become an A2A client, server, proxy, gateway, task store, retry
loop, streaming runtime, credential manager, or remote agent host.

| Host owns | AEGIS owns |
|---|---|
| Agent Card discovery and caching | Policy loading and workflow constraints |
| A2A clients, transports, auth, retries, streaming, and polling | Pre-call Agent Card evidence validation |
| Remote task execution and business state | Post-call task-envelope validation |
| Raw messages, artifacts, histories, and credentials | Redacted additive workflow metadata |

## Import

```python
from aegis import AEGIS
from aegis.a2a_adapter import A2AAdapter, A2AParticipantBinding
```

The base `aegis` install does not require `a2a-sdk`, `google.protobuf`, or any
A2A transport package. Hosts may use an A2A SDK on their side and pass
dictionaries or supported model objects into the adapter.

## Policy

```yaml
policy_version: "1.0"
roles:
  - planner
workflow:
  protocol_constraints:
    a2a:
      protocol_version: "1.0"
      allowed_protocol_bindings:
        - JSONRPC
        - HTTP+JSON
      require_task_state: true
```

Defaults are `protocol_version: "1.0"`,
`allowed_protocol_bindings: ["JSONRPC", "HTTP+JSON"]`, and
`require_task_state: true`.

## Fixture-Style Usage

```python
agent_card = {
    "name": "RemotePlanner",
    "version": "1.0.0",
    "capabilities": {"streaming": True},
    "supportedInterfaces": [
        {
            "url": "https://example.test/a2a",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "skills": [{"id": "plan", "name": "Plan", "tags": ["planning"]}],
}

task = {
    "id": "task-1",
    "contextId": "ctx-1",
    "status": {"state": "TASK_STATE_COMPLETED"},
    "artifacts": [{"artifactId": "artifact-1"}],
    "history": [],
}

invocation = {
    "policy_file": "policy.yaml",
    "model_provider": "a2a",
    "model_identifier": "remote-agent-card",
    "role": "planner",
    "input": {"messages": [{"role": "user", "content": "Draft a plan"}]},
    "context": {"role_declared": True, "schema_exists": True},
}

adapter = A2AAdapter()
binding = A2AParticipantBinding(
    participant_id="remote-planner",
    agent_name="RemotePlanner",
    role="planner",
)

with AEGIS().open_session(policy_file="policy.yaml") as session:
    prepared = adapter.prepare_step(
        session,
        invocation,
        binding=binding,
        agent_card=agent_card,
        request_metadata={"tenant": "acme"},
    )

    # The host sends the A2A request and receives or polls the task.
    output = {"result": "ok", "confidence": 0.9}

    adapter.complete_step(
        prepared,
        output,
        task_envelope=task,
        task_updates=[
            {"status": {"state": "TASK_STATE_WORKING"}},
            {"artifact": {"artifactId": "artifact-1"}},
        ],
    )
    session.complete()
```

`prepare_step(...)` enriches the invocation with
`context.protocol_evidence.a2a`, then calls
`GovernanceSession.enforce_step_pre_call(...)`. A broader host invocation may
contain a JSON-serializable `output` object; the adapter validates it without
mutating the caller and omits it from the detached Phase A projection. Actual
output enters only through `complete_step(...)`, while direct session pre-call
invocations must omit it. `complete_step(...)` validates the host-supplied task
evidence and stores only a redacted summary in workflow step metadata.

Compatibility `output` validation is bounded to 1 MiB of compact UTF-8 JSON,
10,000 value nodes, and nesting depth 64. Object keys must be strings and count
toward the byte limit; the root plus object values and array elements count as
nodes, with the root at depth one.

## Strict Validation

Compatibility is checked from `supportedInterfaces[].protocolVersion`, not from
the descriptive Agent Card `version` field.

Accepted protocol bindings for v0.9.0 are `JSONRPC` and `HTTP+JSON`. gRPC
evidence is rejected even if a host SDK supports it.

Task states must be normative A2A wire values:

- `TASK_STATE_UNSPECIFIED`
- `TASK_STATE_SUBMITTED`
- `TASK_STATE_WORKING`
- `TASK_STATE_COMPLETED`
- `TASK_STATE_FAILED`
- `TASK_STATE_CANCELED`
- `TASK_STATE_INPUT_REQUIRED`
- `TASK_STATE_REJECTED`
- `TASK_STATE_AUTH_REQUIRED`

Only `TASK_STATE_COMPLETED`, `TASK_STATE_FAILED`, `TASK_STATE_CANCELED`, and
`TASK_STATE_REJECTED` are treated as terminal in adapter metadata.

## Failure Examples

Non-spec task states fail:

```python
adapter.complete_step(
    prepared,
    output,
    task_envelope={"status": {"state": "done"}},
)
```

The double-L spelling fails:

```python
adapter.complete_step(
    prepared,
    output,
    task_envelope={"status": {"state": "TASK_STATE_CANCELLED"}},
)
```

gRPC evidence fails:

```python
agent_card = {
    "name": "RemotePlanner",
    "supportedInterfaces": [
        {"protocolBinding": "GRPC", "protocolVersion": "1.0"}
    ],
}
```

`AgentCard.version` alone is not compatibility proof:

```python
agent_card = {
    "name": "RemotePlanner",
    "version": "1.0.0",
    "supportedInterfaces": [
        {"protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
    ],
}
```
