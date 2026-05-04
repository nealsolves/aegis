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
- PR-10a and PR-10b source surfaces are absent from this branch.
- PR-10c OpenAI Agents source surfaces are absent from this branch.
- PR-10d is implemented locally as pre-freeze safety hardening before PR-11.

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

## Next PRs

Current execution note:

- Deferred PR-10d adapter gate: Bedrock alias-backed participant identity tests remain blocked until PR-10a surfaces are present.
- Deferred PR-10d adapter gate: A2A capability and protocol mismatch tests remain blocked until PR-10b surfaces are present.
- Deferred PR-10d adapter gate: OpenAI Agents SDK capability mismatch, side-effecting tool, and unsupported dynamic-tool tests remain blocked until PR-10c source surfaces are present on this target branch.
- PR-11 follows after PR-10d gates and any required adapter sequencing decisions are satisfied.
