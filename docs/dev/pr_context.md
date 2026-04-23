# PR Context — `v0.9.0` PR-10c openai-agents-adapter

Date: 2026-04-23
Status: `feat/v0.9-10-openai-agents-adapter` contains PR-01 through PR-10c
Active branch: `feat/v0.9-10-openai-agents-adapter`

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
| PR-11 | `feat/v0.9-11-beta-freeze` -> `release/v0.9.0` | Freeze the beta and start the final release sequence only after all gates pass |

---

## Current State

- PR-01 through PR-10c are complete on local `develop`.
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
  - `BedrockTraceAdapter` (optional, `aegis[bedrock]`)
  - `A2AAdapter` (optional, `aegis[a2a]`)
  - `OpenAIAgentsAdapter` (optional, `aegis[openai-agents]`)
- The default adopter path succeeds without Bedrock, A2A, or the OpenAI Agents SDK.
- `ValidatorHook` is implemented as an internal engine capability in PR-08. It
  is not a public beta surface.

## Beta Contract Notes

- Workflow adoption is always instance-scoped through `AEGIS.open_session(...)`.
- Invocation artifacts remain separate from workflow/session artifacts.
- Public examples, docs, starters, presets, and demo code must use public
  `aegis` imports only and must not import from `aegis._internal`.
- `aegis workflow trace` and `aegis workflow export` shipped in PR-09.
- `BedrockTraceAdapter`, `A2AAdapter`, and `OpenAIAgentsAdapter` are source-only
  beta surfaces behind optional extras (`aegis[bedrock]`, `aegis[a2a]`,
  `aegis[openai-agents]`). They are not re-exported from the top-level `aegis`
  package.
- `AgentIdentity` and `AgentCapabilityManifest` remain out-of-scope for v0.9.0.

## Verified PR-07 / PR-08 Outcomes

- The regulated failure-and-fix proof now breaks the generated
  `workflow_example.py`, runs that same broken starter, diagnoses that same
  directory with `aegis workflow doctor`, restores the same file, and reruns the
  same starter to `COMPLETED`.
- Demo failure diagnosis now uses a real generated starter directory instead of
  fabricating a diagnostic-only directory.
- Workflow-step exceptions raised from public session methods are re-exported
  from `aegis` and `aegis.errors`.
- Session post-call attempts now clean up session tokens deterministically on
  failure instead of leaving dead pending tokens behind.

## PR-09 Outcomes

PR-09 shipped:

- `aegis workflow trace` — timeline reconstruction from workflow and invocation artifacts
- `aegis workflow export` — operator and audit export modes
- operator-facing visibility and portability polish

## PR-10a Outcomes

PR-10a shipped:

- `BedrockTraceAdapter` — alias-backed identity, fail-closed on missing trace
- optional Bedrock adapter (`aegis[bedrock]`)

## PR-10b Outcomes

PR-10b shipped:

- `A2AAdapter` — strict `TASK_STATE_*` validation, gRPC rejection
- optional A2A adapter (`aegis[a2a]`)

## PR-10c Outcomes

PR-10c shipped:

- `OpenAIAgentsAdapter` — governed binding for `openai-agents`, fail-closed unsupported-surface rules
- `OpenAIAgentsParticipantBinding`, `OpenAIAgentsPreparedStep`, `OpenAIAgentsPendingApproval`, `OpenAIAgentsTracingProcessor`
- `GovernanceSession.authorize_step_tool_call` — real-time tool-call budget enforcement and evidence recording
- `GovernanceSession.enforce_step_post_call` extended with `step_metadata` param
- `workflow.protocol_constraints.openai_agents` in policy DSL schema
- `step_metadata` pass-through in `workflow trace` and `workflow export`
- Reference doc at `docs/reference/external/OPENAI_AGENTS_ADAPTER.md`
- optional OpenAI Agents SDK extra (`aegis[openai-agents]`)

## Next PR

PR-11 (`feat/v0.9-11-beta-freeze` → `release/v0.9.0`) is the final step:

- Public API snapshot tests
- Full CI matrix
- All stop-ship gates
- Triggers `origin/main` PR
