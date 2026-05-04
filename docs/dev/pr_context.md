# PR Context — `v0.9.0` PR-10d Research Safety Addendum

Date: 2026-05-03
Status: Implemented locally
Active branch: `feat/v0.9-10d-research-safety-addendum`

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
- PR-10a and PR-10b have not started.
- PR-10c is complete on local `develop` and is pending merge to `origin/develop` via PR; PR-10c source surfaces are absent from this branch.
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
- `BedrockTraceAdapter` and `A2AAdapter` remain planned follow-on adapter
  surfaces; their protocol evidence checks exist in the workflow runtime, but
  no public adapter modules or extras ship until PR-10a/10b.
- `AgentIdentity` and `AgentCapabilityManifest` remain out-of-scope for v0.9.0.

---

## PR-10d Goal

PR-10d converts recent agent-safety research into bounded hardening of the existing beta surfaces:

- graph/topology lint rules
- bounded witness traces
- temporal-check approximations using existing DSL fields
- source and memory provenance warnings
- workflow doctor remediation mapping
- workflow export governance rationale metadata
- fixture-only adapter capability/trust tests for adapter surfaces present in the branch
- internal multi-aspect `ValidatorHook` example
- starter safety smoke tests

It must not add a new runtime, new transport layer, MCP governance proxy, streaming governance handle, memory governance subsystem, public LLM-as-judge engine, or new required dependency.

---

## In Scope

- `aegis/_internal/workflow_lint.py`
- `aegis/_internal/workflow_doctor.py`
- `aegis/_internal/workflow_export.py`
- `aegis/_internal/session.py`
- `aegis/_internal/starter_templates.py`
- focused PR-10d lint, doctor, export, safety-smoke, and internal ValidatorHook tests
- release-truth and reference documentation updates

---

## Out of Scope

- PR-10a Bedrock implementation
- PR-10b A2A implementation
- PR-10c OpenAI Agents SDK implementation
- PR-11 beta freeze
- public `ValidatorHook` promotion
- full memory governance
- streaming governance
- MCP governance proxy
- formal model checking
- new required package dependencies

---

## Exit Criteria

- Graph/topology lint uses existing workflow DSL fields only and emits bounded `details` and `witness_trace`.
- Lint findings keep stable keys and do not include `severity` or `next_action`.
- Doctor maps every new lint and doctor-only code to severity and remediation guidance.
- `WORKFLOW_SOURCE_PROVENANCE_WARNING` is doctor-only and non-blocking by default.
- Workflow export projects redacted governance rationale from `steps[i].metadata.governance` and preserves integrity metadata.
- Internal multi-aspect `ValidatorHook` examples remain tests only and are not public beta guidance.
- The implementation preserves the AEGIS ownership boundary: host owns execution; AEGIS governs and emits evidence.
- The default local adopter path remains unchanged and optional adapters stay optional.

---

## PR-10c Outcomes

PR-10c is complete on local `develop` and is pending merge to `origin/develop` via PR. Source surfaces are absent from this branch.

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

- PR-10c is complete on local `develop` and is being merged to `origin/develop` via PR; source surfaces absent from this branch.
- PR-10a and PR-10b remain not started.
- Deferred PR-10d adapter gate: Bedrock alias-backed participant identity tests remain blocked until PR-10a surfaces are present.
- Deferred PR-10d adapter gate: A2A capability and protocol mismatch tests remain blocked until PR-10b surfaces are present.
- Deferred PR-10d adapter gate: OpenAI Agents SDK capability mismatch, side-effecting tool, and unsupported dynamic-tool tests remain blocked until PR-10c source surfaces are present on this target branch.
- PR-11 follows after PR-10d gates and any required adapter sequencing decisions are satisfied.
