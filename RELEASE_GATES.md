# Release Gates

This file tracks the release gates for the `v0.9.0` beta train.

Do NOT open or merge a PR from `origin/develop` -> `origin/main` until
`v0.9.0` is formally declared a GO.

PR-07 is the mandatory stop-ship checkpoint. If the golden path fails there,
no further public-surface work proceeds until the default path is repaired.

---

## `v0.9.0` Branch Map

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

## PR-01 — Source-of-Truth Gate

- [x] one canonical implementation plan is active
- [x] stale plan variants are marked superseded or historical
- [x] `CLAUDE.md`, `docs/dev/pr_context.md`, `implementation_status.md`, and this file share one PR/branch map
- [x] CI truth checks fail on release-packet drift

## PR-03 — Golden-Path Contract Freeze Gate

- [x] the beta CLI inventory is frozen as `aegis policy init`, `aegis workflow init`, `aegis workflow lint`, and `aegis workflow doctor`
- [x] scaffold profiles are frozen as `minimal`, `standard`, and `regulated-high-assurance`
- [x] starter coverage is frozen as local multi-step review, approval checkpoint, source required, and tool budget
- [x] public-import boundary rules are frozen across docs, starters, presets, and demo code
- [x] first-adopter docs order is frozen

## PR-06 — Doctor And Lint Gate

- [x] `aegis workflow lint` covers schema, transition references, unsupported bindings, budgets, starter integrity, and public-import safety
- [x] `aegis workflow doctor` covers policy, starter, workflow-artifact, and audit-artifact diagnosis
- [x] stable first-user reason codes and next actions exist for common failures

## PR-07 — Beta Proof Gate

- [x] clean-environment docs-to-working-app validation exists
- [x] minimal starter reaches `COMPLETED`
- [x] standard starter reaches `COMPLETED`
- [x] at least one intentional failure-and-fix path is validated end to end
- [x] the broken asset diagnosed by `workflow doctor` is the same generated starter that was broken and later rerun
- [x] demo failure diagnosis uses the real broken starter directory rather than synthetic backend fixtures
- [x] the default adopter path succeeds without Bedrock, A2A, or the OpenAI Agents SDK
- [x] no maintained public docs, demos, or starters import `aegis._internal`

## PR-08 — Engine Hardening Gate

- [x] restrictive composition rejects widening workflow merges
- [x] approvals, budgets, transitions, handoffs, participants, roles, and protocol constraints behave deterministically
- [x] validator hooks are wired internally through ordinary session creation and remain internal-only in the beta contract
- [x] workflow-step exceptions raised by public session methods are catchable through `aegis` and `aegis.errors`
- [x] failed Phase B attempts clean up session tokens deterministically

## PR-09 — Exports and Ops Gate

- [x] `aegis workflow trace` — timeline reconstruction from workflow and invocation artifacts
- [x] `aegis workflow export` — operator and audit export modes with checksum integrity reporting
- [x] operator-facing export portability and timeline reconstruction

## PR-10b — A2A Adapter Gate

- [x] `A2AAdapter` is optional, source-only, and importable without `a2a-sdk`
- [x] no `A2AAdapter`, `A2AParticipantBinding`, or `A2APreparedStep` top-level `aegis` re-export is added
- [x] `workflow.protocol_constraints.a2a` is strict in root and packaged schemas
- [x] Agent Card compatibility is validated from `supportedInterfaces[].protocolVersion`
- [x] only `JSONRPC` and `HTTP+JSON` are accepted governed protocol bindings
- [x] gRPC evidence rejects through adapter and direct session protocol-boundary checks
- [x] normative `TASK_STATE_*` values pass and shorthand or misspelled values fail
- [x] workflow step metadata stores redacted A2A summaries without raw task payloads
- [x] `docs/reference/external/A2A_ADAPTER.md` advanced recipe ships
- [x] default local adopter path remains unchanged and green without A2A dependencies

## PR-10c — OpenAI Agents Adapter Gate

- [x] `OpenAIAgentsAdapter` is optional, fail-closed, and ships behind the `aegis[openai-agents]` extra
- [x] the default local adopter path is unchanged and green without `openai-agents` installed
- [x] participant binding, duplicate-name rejection, and trace-required enforcement are tested with fixtures only
- [x] `GovernanceSession.authorize_step_tool_call` enforces tool budgets and allowlists in real time
- [x] adapter state must be registered before tool authorization — absent state raises `InvocationValidationError`
- [x] `_authorized_step_count` counts Phase-A authorizations; Phase-B failure does not roll it back
- [x] unsupported surfaces reject explicitly with typed `WorkflowUnsupportedBindingError`
- [x] function-tool and `Agent.as_tool(...)` wrapper governance tests pass
- [x] import-guard tests confirm `openai-agents` is not a required base dependency
- [x] `docs/reference/external/OPENAI_AGENTS_ADAPTER.md` advanced recipe ships

## PR-10d — Research Safety Addendum Gate

PR-10d is a bounded post-adapter hardening addendum. It must improve the existing beta surfaces without reopening product scope.

- [x] graph/topology lint rules are deterministic and test-backed
- [x] every new lint finding has a stable code, plain-English explanation, and bounded evidence where applicable
- [x] lint findings do not include `severity` or `next_action`; doctor owns remediation
- [x] witness traces are bounded and useful for invalid path diagnosis
- [x] `workflow doctor` maps new lint and doctor-only findings to remediation guidance
- [x] `WORKFLOW_SOURCE_PROVENANCE_WARNING` is doctor-only and non-blocking by default
- [x] `workflow export` includes backward-compatible governance rationale metadata
- [x] starter and workflow safety smoke tests pass without external dependencies
- [x] A2A adapter-specific gates are covered by PR-10b fixtures; unavailable adapter surfaces remain documented as deferred when source surfaces are absent
- [x] no public example imports from `aegis._internal`
- [x] no new required runtime dependency is introduced
- [x] default local adopter path remains unchanged and green
- [x] base package smoke still passes

PR-10d Bedrock adapter gate: Bedrock alias-backed participant identity tests
are covered where PR-10a source surfaces are present.

PR-10d A2A adapter gate: A2A capability and protocol mismatch tests are now
covered by PR-10b fixtures.

PR-10d OpenAI Agents adapter gate: capability mismatch, side-effecting tool,
and unsupported dynamic-tool tests are covered where PR-10c source surfaces are
present.

## Deferred To PR-10 And Later

- [x] PR-10a optional Bedrock adapter track — source present locally
- [x] PR-10b optional A2A adapter track — source present locally
- [x] PR-10c optional OpenAI Agents SDK adapter track — source present locally
- [x] research-informed PR-10d safety hardening addendum — source present locally

---

## Beta Stop-Ship Gate

`v0.9.0` beta readiness is blocked until all of the following are true:

- [x] clean-environment docs-to-working-app success exists for the default path
- [x] quickstart completes within the `15` minute target budget
- [x] at least two public-import-only starter examples reach PASS
- [x] at least one failure-and-fix path is validated end to end
- [x] `workflow doctor` and `workflow lint` explain that failure clearly
- [x] no internal-code reading is required
- [x] no advanced manifest authoring is mandatory on the default path
- [x] workflow or invocation evidence visibility exists on the default path
- [x] the default adopter path succeeds without Bedrock, A2A, or the OpenAI Agents SDK

## `v0.9.0` Beta Release Gate

`v0.9.0` beta ships only if all of the following are true:

- [ ] PR-01 through PR-10d work is merged to `origin/develop`
- [x] the golden-path contract is frozen before later public-surface expansion
- [x] quickstart, starters, migration, diagnostics, beta proof, and engine hardening are test-backed on local `develop`
- [x] PR-09 operator polish lands
- [ ] optional adapter work lands
- [ ] PR-10d research-informed safety hardening lands
- [ ] `feat/v0.9-11-beta-freeze` lands
- [ ] `release/v0.9.0` is cut from the PR-11 result
- [ ] only then is the `origin/develop` -> `origin/main` PR opened
