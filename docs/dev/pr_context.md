# PR Context — `v0.9.0` PR-10b A2A Adapter

Date: 2026-05-04
Status: Implemented locally
Active branch: `feat/v0.9-10-a2a-adapter`

---

## Branch Sequence

Do NOT open or merge a PR from `origin/develop` -> `origin/main` until
`v0.9.0` is formally declared a GO.

PR-07 is the mandatory stop-ship checkpoint. If the golden path fails there,
no further public-surface work proceeds until the default path is repaired.

| PR | Branch | Goal |
|----|--------|------|
| PR-01 | `feat/v0.9-01-source-of-truth` | Canonical plan, release packet, and CI truth checks |
| PR-02 | `feat/v0.9-02-contract-freeze` | Freeze session lifecycle, `SessionPreCallResult`, and artifact separation |
| PR-03 | `feat/v0.9-03-golden-path-contract` | Freeze CLI shape, starter profiles, public-import rules, and docs order |
| PR-04 | `feat/v0.9-04-minimal-session-flow` | Land the smallest real governed local workflow path |
| PR-05 | `feat/v0.9-05-starters-and-migration` | Ship starters, thin presets, and migration helpers |
| PR-06 | `feat/v0.9-06-doctor-and-lint` | Ship `workflow doctor`, `workflow lint`, and stable reason codes |
| PR-07 | `feat/v0.9-07-beta-proof` | Mandatory stop-ship checkpoint for quickstart, demo, and failure-and-fix proof |
| PR-08 | `feat/v0.9-08-engine-hardening` | Harden workflow sequencing, approvals, budgets, and validator hooks |
| PR-09 | `feat/v0.9-09-exports-and-ops` | Ship trace, export, and operator polish |
| PR-10a | `feat/v0.9-10-bedrock-adapter` | Add optional Bedrock adapter with alias-backed identity binding |
| PR-10b | `feat/v0.9-10-a2a-adapter` | Add optional A2A adapter with strict wire-contract validation |
| PR-10c | `feat/v0.9-10-openai-agents-adapter` | Add optional OpenAI Agents SDK adapter with governed binding and fail-closed unsupported-surface rules |
| PR-10d | `feat/v0.9-10d-research-safety-addendum` | Add research-informed lint, doctor, export, safety-smoke, and adapter-fixture hardening |
| PR-11 | `feat/v0.9-11-beta-freeze` -> `release/v0.9.0` | Freeze the beta and start the final release sequence only after all gates pass |

---

## Current State

- PR-01 through PR-09 are complete on `develop`.
- The source-only `v0.9.0` beta path currently ships:
  - `AEGIS.open_session(...)`
  - `GovernanceSession`
  - `SessionPreCallResult`
  - `aegis workflow init`
  - `aegis policy init`
  - `aegis workflow lint`
  - `aegis workflow doctor`
  - `aegis workflow trace`
  - `aegis workflow export`
- The default adopter path succeeds without Bedrock, A2A, or the OpenAI Agents SDK.
- `ValidatorHook` is implemented as an internal engine capability in PR-08. It is not a public beta surface.
- PR-10a has not started.
- PR-10b is implemented locally on `feat/v0.9-10-a2a-adapter`.
- PR-10c is complete on local `develop` and is pending merge to `origin/develop` via PR.
- PR-10d is implemented locally as pre-freeze safety hardening before PR-11.

---

## Boundaries

- Workflow adoption is always instance-scoped through `AEGIS.open_session(...)`.
- Invocation artifacts remain separate from workflow/session artifacts.
- Public examples, docs, starters, presets, and demo code must use public
  `aegis` imports only and must not import from `aegis._internal`.
- `aegis workflow trace` and `aegis workflow export` shipped in PR-09.
- `OpenAIAgentsAdapter` is a source-only beta surface behind the optional
  `aegis[openai-agents]` extra. It is not re-exported from the top-level
  `aegis` package.
- `A2AAdapter` is a source-only beta surface under `aegis.a2a_adapter`. It is
  not re-exported from the top-level `aegis` package and does not require
  `a2a-sdk`.
- `BedrockTraceAdapter` remains a planned follow-on adapter surface until the
  PR-10a release-truth gate is closed.
- `AgentIdentity` and `AgentCapabilityManifest` remain out-of-scope for v0.9.0.

---

## PR-10b Goal

PR-10b adds an optional source-only A2A governance adapter for host-owned A2A
interactions:

- `A2AAdapter`
- `A2AParticipantBinding`
- `A2APreparedStep`
- strict `workflow.protocol_constraints.a2a` schema
- runtime A2A protocol-boundary hardening in `GovernanceSession`
- normative `TASK_STATE_*` validation
- redacted A2A workflow step metadata
- fixture-only tests and advanced host-owned usage docs

It must not add an A2A client, server, proxy, gateway, transport runtime, task
store, streaming runtime, retry loop, credential manager, remote agent host, or
new required dependency.

---

## In Scope

- `aegis/_internal/session.py`
- `aegis/a2a_adapter.py`
- `schemas/policy_dsl.schema.json`
- `aegis/schemas/policy_dsl.schema.json`
- `tests/test_a2a_adapter.py`
- `docs/reference/external/A2A_ADAPTER.md`
- release-truth and external adapter documentation updates

---

## Out of Scope

- PR-10a Bedrock implementation
- PR-10c OpenAI Agents SDK implementation
- PR-10d research-safety addendum work
- PR-11 beta freeze
- A2A transport, auth, retries, streaming, polling, task execution, or task storage
- gRPC support for governed v0.9.0 A2A normalization
- new required package dependencies

---

## Exit Criteria

- `A2AAdapter` exists under `aegis.a2a_adapter` and is not re-exported from top-level `aegis`.
- Base import succeeds without `a2a-sdk`.
- A2A policy schema is strict in root and packaged schema copies.
- Compatibility is validated from `supportedInterfaces[].protocolVersion`.
- `JSONRPC` and `HTTP+JSON` are the only accepted governed bindings.
- gRPC evidence fails closed in adapter and direct session checks.
- Normative `TASK_STATE_*` values pass and shorthand or misspelled values fail.
- Step metadata contains redacted A2A summaries and no raw task payloads.
- The implementation preserves the AEGIS ownership boundary: host owns execution; AEGIS governs and emits evidence.
- The default local adopter path remains unchanged and optional adapters stay optional.

---

## PR-10b Outcomes

Ships:

- `A2AAdapter` — governed binding for host-owned A2A interactions
- `A2AParticipantBinding` and `A2APreparedStep`
- strict `workflow.protocol_constraints.a2a` schema with `protocol_version`, `allowed_protocol_bindings`, and `require_task_state`
- direct `GovernanceSession` A2A protocol checks for callers that bypass the adapter
- gRPC rejection with typed workflow protocol violations
- normative `TASK_STATE_*` acceptance and shorthand/misspelling rejection
- redacted workflow step metadata for task ID, context ID, state, terminal flag, artifact/history counts, and update counts
- fixture-only adapter tests in `tests/test_a2a_adapter.py`
- reference doc at `docs/reference/external/A2A_ADAPTER.md`
- no required A2A SDK, protobuf, transport, or gRPC dependency

---

## PR-10c Outcomes

PR-10c is complete on local `develop` and is pending merge to `origin/develop` via PR.

Ships:

- `OpenAIAgentsAdapter` — governed binding for `openai-agents`, fail-closed unsupported-surface rules
- `OpenAIAgentsParticipantBinding`, `OpenAIAgentsPreparedStep`, `OpenAIAgentsPendingApproval`, `OpenAIAgentsTracingProcessor`
- `GovernanceSession.authorize_step_tool_call` — real-time tool-call budget enforcement and evidence recording
- `GovernanceSession.enforce_step_post_call` extended with `step_metadata` param
- `workflow.protocol_constraints.openai_agents` in policy DSL schema
- `step_metadata` pass-through in `workflow trace` and `workflow export`
- Reference doc at `docs/reference/external/OPENAI_AGENTS_ADAPTER.md`
- optional OpenAI Agents SDK extra (`aegis[openai-agents]`)

P1 issues resolved:

- `_make_tool_wrapper` rejects non-`FunctionTool` types with `WorkflowUnsupportedBindingError`
- `_wrap_all_tools` raises and aborts `prepare_step` when `agent.tools` is immutable
- `authorize_step_tool_call` raises `InvocationValidationError` when adapter state is absent (B1 defense-in-depth)
- `_authorized_step_count` counts Phase-A authorizations only, not Phase-B completions (B4 semantics documented)

---

## Next PRs

Current execution note:

- PR-10b is implemented locally and ready for the PR-10b verification gate.
- PR-10c is complete on local `develop` and is being merged to `origin/develop` via PR.
- PR-10a remains not started.
- Deferred PR-10d adapter gate: Bedrock alias-backed participant identity tests remain blocked until PR-10a surfaces are present.
- PR-10d A2A capability and protocol mismatch gate is now covered by PR-10b fixtures.
- PR-11 follows after PR-10d gates and any required adapter sequencing decisions are satisfied.
