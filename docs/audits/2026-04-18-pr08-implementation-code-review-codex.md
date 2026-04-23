# PR-08 Implementation Code Review

- Audit date: 2026-04-18
- Repository root: `/Users/neal/Documents/_Shenanigans/_myProjects/aigc`
- Base branch and commit: `develop` @ `1b76ff69bf9b15df0f626535de7e7dbf7ed2782e`
- Review branch and commit: `feat/v0.9-08-engine-hardening` @ `9f767f13117fd0b1d56e274337abfb90af9cca11`
- Scope reviewed: `develop...feat/v0.9-08-engine-hardening` with focus on workflow runtime enforcement, restrictive composition, validator-hook behavior, workflow-doctor mappings, schema changes, and the targeted PR-08 tests. I also verified that `aigc/schemas/policy_dsl.schema.json` and `schemas/policy_dsl.schema.json` are byte-identical.
- Commands run:
  - `git status -sb`
  - `git rev-parse develop`
  - `git rev-parse feat/v0.9-08-engine-hardening`
  - `git log --oneline develop..feat/v0.9-08-engine-hardening`
  - `git diff --stat develop...feat/v0.9-08-engine-hardening`
  - `git diff --name-only develop...feat/v0.9-08-engine-hardening`
  - `git diff develop...feat/v0.9-08-engine-hardening -- aigc/_internal/session.py aigc/_internal/policy_loader.py aigc/_internal/errors.py aigc/_internal/validator_hook.py aigc/_internal/workflow_doctor.py`
  - `rg -n "PR-08|engine hardening|validator hook|approval checkpoint|max_steps|max_total_tool_calls|required_sequence|allowed_transitions|participants|handoffs|protocol_constraints|workflow doctor" docs/dev/pr_context.md RELEASE_GATES.md "docs/plans/AIGC V0.9.0 IMPLEMENTATION_PLAN.md" implementation_status.md CLAUDE.md docs/architecture/AIGC_HIGH_LEVEL_DESIGN.md docs/architecture/ARCHITECTURAL_INVARIANTS.md docs/architecture/ENFORCEMENT_PIPELINE.md docs/PUBLIC_INTEGRATION_CONTRACT.md`
  - `diff -u aigc/schemas/policy_dsl.schema.json schemas/policy_dsl.schema.json`
  - `pytest -q tests/test_engine_hardening.py tests/test_approval_checkpoints.py tests/test_budget_accounting.py tests/test_validator_hook.py tests/test_sequence_enforcement.py tests/test_transition_enforcement.py tests/test_participant_enforcement.py tests/test_handoff_enforcement.py tests/test_protocol_enforcement.py tests/test_escalation_enforcement.py tests/test_workflow_doctor.py tests/test_v090_contract_freeze.py tests/test_session_core.py tests/test_workflow_lint.py`
  - `PYTHONPATH=/Users/neal/Documents/_Shenanigans/_myProjects/aigc/.worktrees/feat-v0.9-08-engine-hardening pytest -q tests/test_engine_hardening.py tests/test_approval_checkpoints.py tests/test_budget_accounting.py tests/test_validator_hook.py tests/test_sequence_enforcement.py tests/test_transition_enforcement.py tests/test_participant_enforcement.py tests/test_handoff_enforcement.py tests/test_protocol_enforcement.py tests/test_escalation_enforcement.py tests/test_workflow_doctor.py tests/test_v090_contract_freeze.py tests/test_session_core.py tests/test_workflow_lint.py`
  - `python -c "import inspect, aigc; print('open_session', inspect.signature(aigc.AIGC.open_session)); print('GovernanceSession', inspect.signature(aigc.GovernanceSession))"`
  - Reproduction snippets for denied-checkpoint resume bypass, unknown-hook fail-open, and `required_sequence` reorder under `replace`

## Findings

### F-01 — High — Unknown validator-hook decisions fail open instead of blocking the step
- Location: `aigc/_internal/validator_hook.py:185`, `aigc/_internal/session.py:881`, `tests/test_validator_hook.py:445`
- Issue: `_call_hook_once()` normalizes an unrecognized hook decision to `execution_failure`, and `GovernanceSession.enforce_step_pre_call()` only blocks `deny`, `timeout`, and `review_required`. The normalized invalid decision therefore falls through the "safe to continue" path and the step completes.
- Why it matters: The PR-08 contract is explicitly fail-closed around validator hooks. A malformed or unexpected hook response is non-authoritative and should not permit governed work to proceed.
- Evidence: `validator_hook.py` returns `ValidatorHookResult(decision=VALIDATOR_EXECUTION_FAILURE, reason_code="HOOK_INVALID_DECISION", ...)` for unknown decisions at lines 185-195. `session.py` only raises `WorkflowHookDeniedError` for `{deny, timeout, review_required}` at lines 881-895, then allows the step to continue at lines 896-909. Executable reproduction on the review branch completed the workflow successfully and printed `COMPLETED execution_failure HOOK_INVALID_DECISION`.
- Recommended fix: Treat unknown decisions as fail-closed at the session boundary, or normalize them directly to a fail-closed decision that raises `WorkflowHookDeniedError`.
- Verification gap or confirming test: `tests/test_validator_hook.py:445-477` currently asserts the opposite behavior and therefore locks in the fail-open path.

### F-02 — High — Denied approval checkpoints can be bypassed by calling `resume()`
- Location: `aigc/_internal/session.py:343`, `aigc/_internal/session.py:280`
- Issue: `resume()` transitions the session to `OPEN` before it confirms that a pending checkpoint exists. If the latest checkpoint was denied, the loop at lines 344-363 finds no pending record and returns without error, leaving the session open. `_assert_accepting_new_step()` then authorizes more work because it only checks for `state == OPEN`.
- Why it matters: Denied approvals are supposed to be fail-closed. This path reopens the session after denial and allows additional governed steps to run before `complete()` eventually rejects the unresolved checkpoint.
- Evidence: After `pause(approval_id='chk-denied')` and `deny_approval(denial_reason='Denied')`, the review-branch reproduction printed `after_deny PAUSED denied`, then `after_resume OPEN`, then successfully authorized another step (`authorized_step <uuid>`).
- Recommended fix: Make `resume()` verify that a matching pending checkpoint exists before changing state, and reject resume attempts when the session has only denied or already-approved checkpoints.
- Verification gap or confirming test: `tests/test_approval_checkpoints.py:200-247` checks `complete()` and `cancel()` after denial, but it never attempts `resume()` after denial or after a no-pending state.

### F-03 — Medium — Restrictive composition misses `required_sequence` reordering under `replace`
- Location: `aigc/_internal/policy_loader.py:379`
- Issue: `_validate_composition_restriction()` compares `required_sequence` with set arithmetic. That catches added step IDs, but it does not catch a child policy that keeps the same step IDs and changes their order. Under `composition_strategy: replace`, the reordered sequence becomes the effective policy.
- Why it matters: `required_sequence` is order-bearing governance data. Reordering the same step IDs changes the allowed workflow without being a valid narrowing.
- Evidence: The validation logic at lines 380-387 converts both sequences to sets and only checks for added IDs. Executable reproduction with a temporary base policy `['draft', 'review']` and child `replace` policy `['review', 'draft']` loaded successfully and returned `['review', 'draft']`.
- Recommended fix: Validate `required_sequence` as an ordered subsequence of the base sequence, not as an unordered set.
- Verification gap or confirming test: `tests/test_engine_hardening.py:382-433` covers additive widening and a `max_steps` drop via `replace`, but it does not cover same-ID reordering of `required_sequence`.

### F-04 — Medium — `validator_hooks` leaks through the public `GovernanceSession` constructor
- Location: `aigc/_internal/session.py:134`, `aigc/session.py:3`, `aigc/__init__.py:40`, `docs/PUBLIC_INTEGRATION_CONTRACT.md:28`
- Issue: `AIGC.open_session()` correctly omits `validator_hooks`, but the publicly exported `aigc.GovernanceSession` constructor still accepts `validator_hooks: list[Any] | None = None`.
- Why it matters: The public contract says `ValidatorHook` remains planned-only and must not ship through public package exports or instance API yet. Exposing hook injection on a public constructor is public-surface drift even though the factory method stays clean.
- Evidence: `aigc/session.py` and `aigc/__init__.py` re-export `GovernanceSession` publicly, and `inspect.signature(aigc.GovernanceSession)` on the review branch prints `(aigc, session_id, policy_file, metadata, validator_hooks=None)`. The same command shows `AIGC.open_session(...)` does not expose the parameter.
- Recommended fix: Remove `validator_hooks` from the public constructor surface, or make direct construction internal-only while keeping hook wiring entirely behind non-public APIs.
- Verification gap or confirming test: `tests/test_validator_hook.py:24-31` only checks `AIGC.open_session()` and never inspects the public `aigc.GovernanceSession` signature.

## Open Questions / Assumptions

- I treated the prompt’s explicit PR-08 fix requirement "fail-closed normalization for unknown hook decisions" as authoritative. The canonical docs describe validator hooks as fail-closed but do not spell out invalid-decision normalization in the same detail.
- I treated the exported `aigc.GovernanceSession` constructor as public API because it is re-exported from `aigc` and documented as a public workflow primitive, even though the preferred entrypoint is `AIGC.open_session()`.
- I did not find evidence that the frozen first-user reason-code lists now include `WORKFLOW_STEP_BUDGET_EXCEEDED` or `WORKFLOW_HOOK_DENIED`; the branch-specific freeze tests passed once the review worktree was on `PYTHONPATH`.

## Residual Test Gaps

- No test asserts that rejected pre-call checks leave `_authorized_step_count`, `_total_tool_calls_consumed`, `_sequence_position`, and handoff/escalation tracking untouched.
- No test exercises post-call tool-budget reconciliation or accounting when a step is authorized but `enforce_step_post_call()` fails.
- No composition test covers same-ID `required_sequence` reordering or similar merge-strategy weakening that is hidden unless order is checked explicitly.
- No approval-checkpoint test covers `resume()` after a denied checkpoint or after there is no pending checkpoint.
- No public-surface freeze test inspects the exported `aigc.GovernanceSession` constructor for `validator_hooks`.
- The validator-hook timeout/stale-result tests are single-threaded and synthetic; there is no race-oriented test for late background hook completion after timeout.
- `tests/test_workflow_doctor.py:482-607` injects rich `failure_summary` details directly into artifacts, but there is no end-to-end runtime test proving the session runtime actually emits those fields for doctor to consume.

## Merge Verdict

- `Not ready`
