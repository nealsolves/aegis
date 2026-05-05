# Implementation Status

**Target Version:** `0.9.0` Beta
**Baseline Version:** `0.3.3`
**Active Branch:** `feat/v0.9-10-a2a-adapter`
**Last Updated:** 2026-05-04

---

## Overall Progress

- PR-01 through PR-09 are complete.
- PR-10a has not started.
- PR-10b is implemented locally on `feat/v0.9-10-a2a-adapter`.
- PR-10c is complete on local `develop` and is pending merge to `origin/develop` via PR.
- PR-10d is implemented locally as a bounded research-informed safety addendum before PR-11.
- PR-11 has not started.

| Track | Status | Notes |
|-------|--------|-------|
| Source of truth | complete | Canonical docs, release packet, and parity checks are aligned |
| Contract freeze | complete | Lifecycle, artifact separation, and instance-scoped workflow entry are frozen |
| Golden-path contract | complete | Beta CLI inventory, starter profiles, docs order, and public-import rules are frozen |
| Minimal session flow | complete | `GovernanceSession`, `AEGIS.open_session(...)`, and `SessionPreCallResult` ship on `develop` |
| Starters and migration | complete | `aegis workflow init`, `aegis policy init`, starter scaffolds, presets, and migration docs ship |
| Diagnostics | complete | `aegis workflow lint` and `aegis workflow doctor` ship with stable first-user codes |
| Beta proof | complete | Clean-env proof, real failure/diagnosis/fix/rerun flow, and demo parity are in place |
| Engine hardening | complete | Budgets, transitions, protocol constraints, approvals, handoffs, and internal validator hooks are hardened |
| Exports and ops | complete | `aegis workflow trace` and `aegis workflow export` ship on `develop` |
| Optional adapters | partial | PR-10b implemented locally; PR-10a not started; PR-10c complete on local `develop`, pending `origin/develop` merge |
| Research safety addendum | implemented locally | PR-10d adds graph/topology lint, doctor remediation, export rationale, and safety smoke tests |
| Beta freeze | not started | Begins in PR-11 |

---

## Release Rules

- Do NOT open or merge a PR from `origin/develop` -> `origin/main` until
  `v0.9.0` is formally declared a GO.
- PR-07 is the mandatory stop-ship checkpoint. If the golden path fails there,
  no further public-surface work proceeds until the default path is repaired.
- The default adopter path must succeed without Bedrock, A2A, or the OpenAI Agents SDK.
- PR-10d must not introduce a new runtime, transport proxy, MCP gateway, streaming runtime, memory manager, or new required dependency.

---

## PR Status

| PR | Branch | Status | Notes |
|----|--------|--------|-------|
| PR-01 | `feat/v0.9-01-source-of-truth` | complete | Canonical plan, release packet, supersession banners, and CI truth checks |
| PR-02 | `feat/v0.9-02-contract-freeze` | complete | Freeze lifecycle, `SessionPreCallResult`, `AEGIS.open_session(...)`, and evidence separation |
| PR-03 | `feat/v0.9-03-golden-path-contract` | complete | Freeze beta CLI shape, starter profiles, public-import rules, docs order, and first-user reason codes |
| PR-04 | `feat/v0.9-04-minimal-session-flow` | complete | Smallest real governed local workflow path |
| PR-05 | `feat/v0.9-05-starters-and-migration` | complete | Starters, thin presets, and migration helpers |
| PR-06 | `feat/v0.9-06-doctor-and-lint` | complete | Diagnostics: lint, doctor, stable reason codes |
| PR-07 | `feat/v0.9-07-beta-proof` | complete | Mandatory stop-ship proof for quickstart, diagnosis, fix, rerun, and demo parity |
| PR-08 | `feat/v0.9-08-engine-hardening` | complete | Sequencing, approvals, budgets, transitions, handoffs, protocol rules, and internal validator hooks |
| PR-09 | `feat/v0.9-09-exports-and-ops` | complete | Trace, export, and operator polish |
| PR-10a | `feat/v0.9-10-bedrock-adapter` | not started | Optional Bedrock adapter with alias-backed identity rules |
| PR-10b | `feat/v0.9-10-a2a-adapter` | implemented locally | Optional A2A adapter with strict wire-contract rules |
| PR-10c | `feat/v0.9-10-openai-agents-adapter` | complete | Optional OpenAI Agents SDK adapter ships on local `develop`; pending merge to `origin/develop` via PR |
| PR-10d | `feat/v0.9-10d-research-safety-addendum` | implemented locally | Research-informed lint, doctor, export, safety smoke, and adapter-fixture hardening |
| PR-11 | `feat/v0.9-11-beta-freeze` -> `release/v0.9.0` | not started | Public API freeze, beta gate verification, and release cut |

---

## PR-05 Deliverables

- [x] `aegis workflow init`
- [x] `aegis policy init`
- [x] `minimal`, `standard`, and `regulated-high-assurance` starter scaffolds
- [x] thin presets exposed through `aegis.presets`
- [x] invocation-only migration guidance and smoke coverage
- [x] public-import-only starter and example coverage

## PR-07 Deliverables

- [x] `docs/reference/WORKFLOW_QUICKSTART.md` covers minimal starter to `COMPLETED`
- [x] `docs/reference/TROUBLESHOOTING.md` covers doctor/lint usage and the regulated failure-and-fix flow
- [x] `docs/reference/WORKFLOW_CLI.md` documents policy init, workflow init, workflow lint, and workflow doctor only
- [x] `docs/reference/STARTER_INDEX.md`, `docs/reference/STARTER_RECIPES.md`, `docs/reference/SUPPORTED_ENVIRONMENTS.md`, and `docs/reference/OPERATIONS_RUNBOOK.md` ship as first-adopter docs
- [x] `tests/test_pr07_beta_proof.py` validates minimal PASS, standard PASS, broken regulated starter, doctor diagnosis, fix-in-place, and rerun
- [x] `scripts/validate_v090_beta_proof.py` validates the same clean-env journey in a fresh venv
- [x] demo workflow routes and the React lab follow the same failure-and-fix story
- [x] no maintained public docs, demos, or starters import `aegis._internal`

## PR-08 Deliverables

- [x] ordered sequence, transition, role, participant, handoff, and protocol enforcement
- [x] `max_steps` and `max_total_tool_calls` enforcement
- [x] auditable approval checkpoints
- [x] restrictive workflow composition checks
- [x] internal validator-hook wiring through ordinary session creation
- [x] public re-exports for workflow-step exceptions raised by public methods
- [x] deterministic session token cleanup on failed Phase B attempts

## PR-10c Deliverables

- [x] `OpenAIAgentsAdapter` public surface with optional `openai-agents` extra guard
- [x] `OpenAIAgentsTracingProcessor` for optional SDK trace correlation
- [x] `openai_agents` protocol constraint support in policy DSL
- [x] participant binding, duplicate-name rejection, and trace-required enforcement
- [x] dynamic tool-governance seam: `authorize_step_tool_call` on `GovernanceSession`
- [x] adapter-managed wrappers for function tools and `Agent.as_tool(...)`
- [x] fail-closed unsupported-surface rejection with typed protocol violations
- [x] interruption pause/resume bridge via `_discard_pending_step`
- [x] adapter state must be registered before tool authorization (B1 defense-in-depth)
- [x] `_authorized_step_count` counts Phase-A authorizations, not Phase-B completions (B4 semantics)
- [x] fixture-only adapter tests, import-guard tests, and governance tests ship in `tests/test_openai_agents_adapter.py`
- [x] `docs/reference/external/OPENAI_AGENTS_ADAPTER.md` advanced recipe
- [x] default local adopter path unchanged and green without `openai-agents` installed

## PR-10b Deliverables

- [x] `A2AAdapter` public submodule with no top-level `aegis` re-export
- [x] no required `a2a-sdk`, protobuf, or transport dependency
- [x] strict `workflow.protocol_constraints.a2a` policy schema in root and packaged schemas
- [x] runtime A2A protocol checks use `supportedInterfaces[].protocolVersion`
- [x] `JSONRPC` and `HTTP+JSON` are the only accepted governed bindings
- [x] gRPC evidence rejects with typed workflow protocol violations
- [x] normative `TASK_STATE_*` values are accepted and shorthand/misspelled states reject
- [x] workflow step metadata stores redacted A2A summaries only
- [x] fixture-only tests ship in `tests/test_a2a_adapter.py`
- [x] `docs/reference/external/A2A_ADAPTER.md` advanced recipe
- [x] default local adopter path remains unchanged and green without A2A dependencies

## PR-10d Deliverables

- [x] graph/topology lint rules with bounded witness traces
- [x] temporal-check approximations use existing DSL fields and starter metadata only
- [x] source and memory provenance warnings live in doctor without adding full memory governance
- [x] backward-compatible workflow export governance rationale metadata
- [x] A2A adapter-informed fixture gates are covered by PR-10b tests; unavailable adapter surfaces remain deferred until their source surfaces are present
- [x] internal multi-aspect `ValidatorHook` example without public promotion
- [x] starter and workflow safety smoke tests with no external services
- [x] release docs confirm PR-10d does not change the default local adopter path

Deferred PR-10d adapter gate: Bedrock alias-backed participant identity tests
remain blocked until PR-10a surfaces are present.

PR-10d A2A adapter gate: A2A capability and protocol mismatch tests are now
covered by PR-10b fixtures.

PR-10d OpenAI Agents adapter gate: capability mismatch, side-effecting tool,
and unsupported dynamic-tool tests are covered where PR-10c source surfaces are
present.
