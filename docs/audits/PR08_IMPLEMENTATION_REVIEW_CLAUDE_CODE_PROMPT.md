# Claude Code Prompt: PR-08 Implementation Review

Use the prompt below as-is with Claude Code when you want a findings-first
review of the PR-08 implementation, with the review written to
`docs/audits` as Markdown.

```text
Review the PR-08 implementation in the local AIGC repository.

Repository root:
/Users/neal/Documents/_Shenanigans/_myProjects/aegis

Base branch:
develop

Review branch:
feat/v0.9-08-engine-hardening

Primary deliverable:
- Create a Markdown review report in:
  /Users/neal/Documents/_Shenanigans/_myProjects/aegis/docs/audits
- Name the file using the local system date:
  YYYY-MM-DD-pr08-implementation-code-review.md
- Overwrite that file if it already exists.
- The Markdown report is the main deliverable.
- Do not make source-code, test, schema, or documentation edits as part of this task.
  Only create or update the audit report unless a separate instruction explicitly asks for fixes.

Review objective:
- Determine whether PR-08 meets its intended scope and is safe to merge into `develop`.
- Prioritize correctness bugs, fail-open behavior, governance regressions, public-contract drift,
  race conditions, and missing or weak tests.
- Use executable evidence and direct code inspection, not plan text alone.

Canonical review sources:
- docs/dev/pr_context.md
- RELEASE_GATES.md
- docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md
- implementation_status.md
- CLAUDE.md
- docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md
- docs/architecture/ARCHITECTURAL_INVARIANTS.md
- docs/architecture/ENFORCEMENT_PIPELINE.md
- docs/PUBLIC_INTEGRATION_CONTRACT.md

Expected PR-08 scope:
- enforce ordered sequence, allowed transitions, participants, roles, handoffs,
  protocol constraints, approvals, `max_steps`, and `max_total_tool_calls`
- freeze restrictive composition behavior and reject widening merges
- add deterministic workflow failure reasons aligned with `workflow doctor`
- add auditable approval checkpoints with pause and resume semantics
- add typed `ValidatorHook` contracts with timeout, bounded retry,
  stale-result handling, and provenance

Changed files to prioritize:
- aegis/_internal/session.py
- aegis/_internal/policy_loader.py
- aegis/_internal/errors.py
- aegis/_internal/validator_hook.py
- aegis/_internal/workflow_doctor.py
- aegis/schemas/policy_dsl.schema.json
- schemas/policy_dsl.schema.json
- aegis/schemas/workflow_artifact.schema.json
- tests/test_engine_hardening.py
- tests/test_approval_checkpoints.py
- tests/test_budget_accounting.py
- tests/test_validator_hook.py
- tests/test_sequence_enforcement.py
- tests/test_transition_enforcement.py
- tests/test_participant_enforcement.py
- tests/test_handoff_enforcement.py
- tests/test_protocol_enforcement.py
- tests/test_escalation_enforcement.py
- tests/test_workflow_doctor.py
- tests/test_v090_contract_freeze.py
- tests/test_session_core.py
- tests/test_workflow_lint.py

Recent fixes that require explicit verification:
- escalation re-fire after approval
- composition weakening via `replace`
- `require_approval_for_roles` narrowing
- per-hook independent deadline envelopes
- fail-closed normalization for unknown hook decisions
- `complete()` blocked when checkpoints are pending or denied

Operating rules:
- Compare `develop...feat/v0.9-08-engine-hardening`.
- Treat docs as claims to verify, not truth by assertion.
- Keep the review findings-first. Do not lead with a broad summary.
- Cite exact file paths and line numbers for every confirmed issue.
- Distinguish clearly between:
  - confirmed defects
  - plausible risks
  - missing coverage
- Ignore tracking-doc edits unless they reveal contract drift, bad release gating,
  or a public-surface inconsistency.
- Preserve the public-boundary rule: PR-08 may add internal `ValidatorHook` support,
  but it must not silently expand the public API surface.
- If no confirmed defects are found, say that explicitly and still document residual risks and test gaps.

Execution sequence:

Phase 1: Establish the audit baseline
- Confirm branch state and working tree status.
- Capture the exact `develop` and `feat/v0.9-08-engine-hardening` HEAD SHAs.
- Summarize commit history and changed-file scope for `develop...feat/v0.9-08-engine-hardening`.

Phase 2: Read the release contract
- Read the PR-08 sections in the plan, release gates, and PR context.
- Extract the actual acceptance criteria and non-goals before judging implementation.

Phase 3: Inspect the implementation
- Review the session runtime, policy loading, error taxonomy, validator-hook contract,
  artifact schema, and workflow doctor mapping.
- Confirm whether the implementation is fail-closed, deterministic, and coherent
  across schema, runtime, tests, and contract-freeze coverage.

Phase 4: Validate key behavior
- Run targeted tests that directly exercise PR-08 behavior.
- If a full targeted bundle is too slow or noisy, run the strongest focused subset
  and document exactly what you did and did not run.
- Do not claim tests passed unless you actually ran them.

Phase 5: Write the report
- Write the final review to the Markdown file in `docs/audits`.
- The file must be complete enough to stand alone without the chat transcript.

Minimum commands to run:
- `git status -sb`
- `git rev-parse develop`
- `git rev-parse feat/v0.9-08-engine-hardening`
- `git log --oneline develop..feat/v0.9-08-engine-hardening`
- `git diff --stat develop...feat/v0.9-08-engine-hardening`
- `git diff --name-only develop...feat/v0.9-08-engine-hardening`
- `git diff develop...feat/v0.9-08-engine-hardening -- aegis/_internal/session.py aegis/_internal/policy_loader.py aegis/_internal/errors.py aegis/_internal/validator_hook.py aegis/_internal/workflow_doctor.py`
- `pytest -q tests/test_engine_hardening.py tests/test_approval_checkpoints.py tests/test_budget_accounting.py tests/test_validator_hook.py tests/test_sequence_enforcement.py tests/test_transition_enforcement.py tests/test_participant_enforcement.py tests/test_handoff_enforcement.py tests/test_protocol_enforcement.py tests/test_escalation_enforcement.py tests/test_workflow_doctor.py tests/test_v090_contract_freeze.py tests/test_session_core.py tests/test_workflow_lint.py`

Specific review checklist:

1. Policy, schema, and composition hardening
- Verify both policy schema copies stay in sync.
- Verify new workflow DSL fields are accepted and unknown workflow fields are still rejected.
- Verify child policies cannot widen:
  - `max_steps`
  - `max_total_tool_calls`
  - participants
  - participant roles and protocols
  - participant `manifest_ref`
  - `required_sequence`
  - `allowed_transitions`
  - `allowed_agent_roles`
  - `handoffs`
  - escalation thresholds
  - `protocol_constraints`
- Verify `intersect`, `union`, and especially `replace` cannot hide a weakening attempt.
- Verify omission of child fields cannot silently drop a base restriction.

2. Session runtime enforcement
- Verify workflow constraints are loaded once at session init from the effective policy.
- Verify authorization checks happen before state mutation.
- Verify rejected pre-calls do not advance counters, sequence position,
  handoff state, escalation state, or transition state.
- Verify `max_steps` enforcement is pre-call and authorized-step counters only
  increment after all checks pass.
- Verify `max_total_tool_calls` is checked pre-call and reconciled post-call
  without double counting or silent drift.
- Verify sequence enforcement uses completed steps, not attempted steps.
- Verify transition enforcement uses the last completed step.
- Verify participant, role, protocol, and handoff checks are fail-closed when declared.
- Verify escalation pauses before failure, creates evidence, and does not immediately
  re-fire after a correct resume.
- Verify pending or denied checkpoints block `complete()`.
- Verify wrong `approval_id` cannot silently approve the wrong checkpoint.
- Verify finalization preserves artifact integrity and evidence on pass, fail, pause, and cancel.

3. Validator-hook contract
- Verify `ValidatorHook` remains internal-only.
- Verify `AIGC.open_session()` does not expose `validator_hooks` as a public parameter.
- Verify envelope and result dataclasses are immutable and typed.
- Verify each hook gets its own deadline window.
- Verify only `execution_failure` is retry-eligible.
- Verify `deny`, `timeout`, and `review_required` fail closed.
- Verify unknown decisions normalize safely.
- Verify stale, late, or wrong-attempt results are treated as non-authoritative.
- Verify hook evidence is recorded with enough provenance to audit later.
- Look for thread-safety or race issues where stale hook results could still affect session state.

4. Diagnostics and contract freeze
- Verify engine failures remain diagnosable through `workflow doctor`.
- Verify PR-08 behavior does not silently expand the frozen first-user reason-code contract.
- Explicitly verify `WORKFLOW_STEP_BUDGET_EXCEEDED` and `WORKFLOW_HOOK_DENIED`
  do not leak into frozen public reason-code lists where they are not supposed to.
- Verify workflow artifact schema additions are emitted consistently:
  - `approval_checkpoints`
  - `validator_hook_evidence`

5. Test quality
- Review whether the tests prove behavior rather than merely matching implementation details.
- Call out missing tests for:
  - rejected pre-call leaving counters untouched
  - post-call budget overrun reconciliation
  - composition weakening hidden by merge strategy
  - escalation resume loops
  - wrong `approval_id`
  - denied checkpoint behavior
  - same-participant and null-participant handoffs
  - protocol-family weakening or removal
  - hook timeout, retry, and stale-result races
  - public-surface freeze around `ValidatorHook`

Required report structure:

# PR-08 Implementation Code Review

- Audit date
- Repository root
- Base branch and commit
- Review branch and commit
- Scope reviewed
- Commands run

## Findings

List confirmed issues first, sorted by severity.

Use one subsection per finding in this format:

### F-XX — <Severity> — <Short title>
- Location: `path:line`
- Issue:
- Why it matters:
- Evidence:
- Recommended fix:
- Verification gap or confirming test:

If there are no confirmed defects, write:
`No confirmed defects found.`

## Open Questions / Assumptions

## Residual Test Gaps

## Merge Verdict
- `Ready`
- `Ready with fixes`
- `Not ready`

Final chat response requirements:
- Start with the full path to the Markdown report you created.
- Then give a short summary of the highest-severity findings.
- Then state what commands and tests you ran.
- Do not paste the full report into chat.
```
