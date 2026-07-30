# Bedrock Adapter

> **Status:** Included in the `aegis-ai-governance==0.9.0b1` public beta.
> Import from `aegis.bedrock_adapter`; it is not re-exported from top-level
> `aegis` and adds no Bedrock SDK dependency.

`BedrockTraceAdapter` governs host-owned Bedrock interactions using an
alias-backed participant binding and host-supplied, parsed trace evidence. It
does not create a provider client or call a service.

## Ownership boundary

| The host owns | AEGIS owns |
| --- | --- |
| Bedrock client and API calls | Policy and workflow constraint enforcement |
| Credentials, authentication, networking, TLS, retries, and timeouts | Agent alias ARN and participant-role validation |
| Orchestration, model/tool execution, and business state | `require_trace` and `require_alias_backed_identity` enforcement |
| Parsing provider responses into trace-part dictionaries | Safe trace correlation and additive workflow evidence |
| Persistence and retention outside governance artifacts | Single-use prepared-step state and replay rejection |

## Import

```python
from aegis import AEGIS
from aegis.bedrock_adapter import (
    BedrockParticipantBinding,
    BedrockPreparedStep,
    BedrockTraceAdapter,
)
```

`BedrockPreparedStep` is returned by `prepare_step(...)`; applications normally
do not instantiate it.

## Policy

```yaml
policy_version: "1.0"
roles:
  - planner
workflow:
  participants:
    - id: research-collaborator
      roles: [planner]
      protocols: [bedrock]
  protocol_constraints:
    bedrock:
      require_trace: true
      require_alias_backed_identity: true
```

`require_trace` defaults to `false`.
`require_alias_backed_identity` is always `true` and cannot be disabled. The
deprecated compatibility spelling `require_alias: true` is accepted, but new
policies should use the full field name.

## Prepare and complete a step

The binding must use a Bedrock agent alias ARN, not a descriptive
`collaboratorName`:

```python
binding = BedrockParticipantBinding(
    participant_id="research-collaborator",
    collaborator_alias=(
        "arn:aws:bedrock:us-east-1:123456789012:"
        "agent-alias/AGENTID12A/ALIASID12B"
    ),
    role="planner",
)

invocation = {
    "policy_file": "policy.yaml",
    "model_provider": "bedrock",
    "model_identifier": "host-selected-model",
    "role": "planner",
    "input": {"query": "Draft a sourced plan"},
    "context": {"role_declared": True, "schema_exists": True},
}

adapter = BedrockTraceAdapter()
with AEGIS().open_session(policy_file="policy.yaml") as session:
    prepared = adapter.prepare_step(
        session,
        invocation,
        binding=binding,
        step_id="draft",
    )

    # Host-owned provider call and response parsing happen here.
    output = {"result": "draft", "confidence": 0.9}
    trace_parts = [
        {
            "agentId": "AGENTID12A",
            "agentAliasId": "ALIASID12B",
            "trace": {
                "orchestrationTrace": {
                    "invocationInput": {"traceId": "trace-001"}
                }
            },
        }
    ]

    adapter.complete_step(
        prepared,
        output=output,
        trace_parts=trace_parts,
    )
    session.complete()
```

`prepare_step(...)` stamps normalized `protocol_evidence.bedrock`, makes the
binding role authoritative, calls the owning
`GovernanceSession.enforce_step_pre_call(...)`, and registers adapter state.
For compatibility it may receive a broader host invocation containing a
JSON-serializable `output` object. It validates that field without mutating the
caller, then omits it from a detached Phase A projection. Actual output is
accepted only by `complete_step(...)`; direct session pre-call invocations must
omit `output`.

Compatibility `output` validation is bounded to 1 MiB of compact UTF-8 JSON,
10,000 value nodes, and nesting depth 64. Object keys must be strings and count
toward the byte limit; the root plus object values and array elements count as
nodes, with the root at depth one.

`complete_step(...)` validates every supplied parsed trace part, correlates the
emitter's `agentId` and `agentAliasId` to the bound alias, enforces
`require_trace`, and completes the step through the owning session.

## Evidence and redaction

Workflow step metadata contains only the adapter name/version, correlation key,
bound collaborator alias, trace presence/count, alias-match result, and
deduplicated trace IDs. Raw trace trees, prompts, tool arguments, credentials,
and model outputs are not copied into adapter metadata.

The invocation audit artifact remains separate from the workflow artifact.
`complete_step(...)` returns the invocation PASS artifact; completing or
finalizing the session emits the workflow evidence.

## Replay and failure behavior

A `BedrockPreparedStep` is single-use and bound to its originating session and
adapter state. A second completion, missing state, mismatched correlation key,
or failed completion discards the pending token; callers must run
`prepare_step(...)` again.

Representative fail-closed cases:

- a bare collaborator name or malformed agent alias ARN
- a role that conflicts with `BedrockParticipantBinding`
- a conflicting top-level protocol
- `alias_backed: false`
- missing or empty trace parts when `require_trace: true`
- malformed trace union content
- a trace emitted by a different agent/alias
- a mixed trace list where any item does not match the binding

These raise typed invocation, participant, binding, or protocol errors before
the workflow step can be accepted.
