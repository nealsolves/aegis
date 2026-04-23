# PR-08 Implementation Code Review

- Audit date: 2026-04-18
- Repository root: /Users/neal/Documents/_Shenanigans/_myProjects/aigc
- Base branch: develop (SHA: 1b76ff69bf9b15df0f626535de7e7dbf7ed2782e)
- Review branch: feat/v0.9-08-engine-hardening (SHA: 9f767f13117fd0b1d56e274337abfb90af9cca11)
- Scope reviewed: aigc/_internal/session.py, aigc/_internal/policy_loader.py, aigc/_internal/errors.py, aigc/_internal/validator_hook.py, aigc/_internal/workflow_doctor.py, aigc/schemas/policy_dsl.schema.json, schemas/policy_dsl.schema.json, aigc/schemas/workflow_artifact.schema.json, implementation_status.md, RELEASE_GATES.md, all new test files listed under Changed files
- Commands run:
  - `git -C ... status -sb`
  - `git -C ... rev-parse develop`
  - `git -C ... rev-parse feat/v0.9-08-engine-hardening`
  - `git -C ... log --oneline develop..feat/v0.9-08-engine-hardening`
  - `git -C ... diff --stat develop...feat/v0.9-08-engine-hardening`
  - `git -C ... diff --name-only develop...feat/v0.9-08-engine-hardening`
  - `git -C ... diff develop...feat/v0.9-08-engine-hardening -- aigc/_internal/session.py aigc/_internal/policy_loader.py aigc/_internal/errors.py aigc/_internal/validator_hook.py aigc/_internal/workflow_doctor.py`
  - `git -C ... diff develop...feat/v0.9-08-engine-hardening -- aigc/schemas/policy_dsl.schema.json schemas/policy_dsl.schema.json aigc/schemas/workflow_artifact.schema.json`
  - `diff aigc/schemas/policy_dsl.schema.json schemas/policy_dsl.schema.json`
  - `cd .worktrees/feat-v0.9-08-engine-hardening && python -m pytest -q tests/test_engine_hardening.py tests/test_approval_checkpoints.py tests/test_budget_accounting.py tests/test_validator_hook.py tests/test_sequence_enforcement.py tests/test_transition_enforcement.py tests/test_participant_enforcement.py tests/test_handoff_enforcement.py tests/test_protocol_enforcement.py tests/test_escalation_enforcement.py tests/test_workflow_doctor.py tests/test_v090_contract_freeze.py tests/test_session_core.py tests/test_workflow_lint.py`
  - `cd .worktrees/feat-v0.9-08-engine-hardening && python -m pytest -q`
  - `cd .worktrees/feat-v0.9-08-engine-hardening && flake8 aigc`
  - `cd .worktrees/feat-v0.9-08-engine-hardening && flake8 aigc/_internal/session.py aigc/_internal/policy_loader.py aigc/_internal/errors.py aigc/_internal/validator_hook.py aigc/_internal/workflow_doctor.py`

---

## Test Run Results

**Targeted PR-08 test suite:** 225 passed in 1.77s. Zero failures, zero errors.

**Full suite:** 1359 passed, 11 warnings in 10.43s. Zero failures, zero errors.

**Flake8 on aigc/:**

```
EXIT CODE 1

aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowParticipantMismatchError' imported but unused
aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowSequenceViolationError' imported but unused
aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowTransitionDeniedError' imported but unused
aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowRoleViolationError' imported but unused
aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowProtocolViolationError' imported but unused
aigc/_internal/workflow_doctor.py:29:1: F401 'aigc._internal.errors.WorkflowHandoffDeniedError' imported but unused
```

`flake8 aigc` is a mandatory CI step in `.github/workflows/sdk_ci.yml:68` and `.github/workflows/release.yml:38`. These violations block CI.

---

## Findings

### F-01 — High — flake8 F401 violations in workflow_doctor.py block CI

- Location: `aigc/_internal/workflow_doctor.py:29-38`
- Issue: Six exception classes are imported by object reference but are used only as strings in `_INVALID_TRANSITION_EXCEPTION_TYPES` (a `frozenset` of class-name strings, not class objects). The imports are never consumed by the runtime.
- Why it matters: `flake8 aigc` runs as a mandatory CI step in both `sdk_ci.yml` and `release.yml`. This PR will not pass CI as submitted.
- Evidence: Running `flake8 aigc/_internal/workflow_doctor.py` in the worktree returns exit code 1 with six F401 errors. The frozenset at lines 406-414 stores bare strings: `"WorkflowParticipantMismatchError"`, `"WorkflowSequenceViolationError"`, etc. — not the imported class objects.
- Recommended fix: Remove the six unused imports. The exception matching logic at line 452 (`exc_type in _INVALID_TRANSITION_EXCEPTION_TYPES`) compares a string from the artifact against string literals, so the import objects are never needed.
- Verification gap: No test asserts that `flake8 aigc` passes (tests import from `aigc._internal` directly and pass regardless). The CI step would catch this on push.

---

### F-02 — Medium — Doctor never emits WORKFLOW_STEP_BUDGET_EXCEEDED or WORKFLOW_HOOK_DENIED codes from artifact diagnosis

- Location: `aigc/_internal/workflow_doctor.py:447-479`
- Issue: `_NEXT_ACTIONS` contains entries for `WORKFLOW_STEP_BUDGET_EXCEEDED` (line 78) and `WORKFLOW_HOOK_DENIED` (line 83), implying the doctor should emit these codes. However, `diagnose_workflow_artifact()` only branches on `is_invalid_transition` (which covers `_INVALID_TRANSITION_EXCEPTION_TYPES`) or falls through to `POLICY_LOAD_ERROR`. `WorkflowStepBudgetExceededError` and `WorkflowHookDeniedError` are not in `_INVALID_TRANSITION_EXCEPTION_TYPES` and the function contains no dedicated branch for them. A session that fails with either of these errors produces a `POLICY_LOAD_ERROR` doctor finding instead of the more specific code.
- Why it matters: The `_NEXT_ACTIONS` entries for these two codes are dead. A user experiencing a step-budget failure or hook denial who runs `workflow doctor` on the resulting artifact receives a generic `POLICY_LOAD_ERROR` finding with generic guidance, not the targeted remediation text that was written for these scenarios. This partially defeats the stated goal of "add deterministic workflow failure reasons aligned with `workflow doctor`."
- Evidence: `grep "WORKFLOW_STEP_BUDGET\|WORKFLOW_HOOK_DENIED" aigc/_internal/workflow_doctor.py` returns only lines 78 and 83 (the `_NEXT_ACTIONS` entries). No call-site emits either code. No test in `test_workflow_doctor.py` covers `WorkflowStepBudgetExceededError` or `WorkflowHookDeniedError` artifact diagnosis.
- Recommended fix: Add `"WorkflowStepBudgetExceededError"` and `"WorkflowHookDeniedError"` to a new lookup dict (similar to `_INVALID_TRANSITION_EXCEPTION_TYPES`) that maps exception type names to their emitted reason codes. Alternatively, add explicit branches in `diagnose_workflow_artifact()` that check `exc_type in {"WorkflowStepBudgetExceededError"}` and emit `WORKFLOW_STEP_BUDGET_EXCEEDED`, and similarly for hook denied.
- Verification gap: No test covers this path. Add tests for failed artifacts carrying `WorkflowStepBudgetExceededError` and `WorkflowHookDeniedError` in `failure_summary.exception_type`.

---

### F-03 — Low — resume() on a session with only denied checkpoints silently transitions to OPEN

- Location: `aigc/_internal/session.py:344-364`
- Issue: `resume()` calls `self._transition(STATE_OPEN)` at line 344 before scanning `_approval_records` for a pending checkpoint. If all checkpoints are in "denied" status (after `deny_approval()`), the for-loop finds nothing and exits without updating any record. The session transitions from PAUSED to OPEN with a denied checkpoint still present. A subsequent `complete()` call correctly raises because `rec["status"] != "approved"` for the denied record. However, the intermediate state (OPEN + denied checkpoint) is semantically inconsistent and could confuse host code that checks `session.state` before deciding whether to proceed.
- Why it matters: The error is not silent in the sense that `complete()` still enforces the guard. But an OPEN session that cannot be completed is an unexpected state from the caller's perspective. A caller that calls `resume()` after denial expecting a no-op or error receives a silent OPEN transition instead.
- Evidence: No test covers `resume()` after `deny_approval()`. `test_denied_checkpoint_keeps_session_paused` (line 227 in `test_approval_checkpoints.py`) only calls `cancel()` after denial, not `resume()`. The state diagram at `_VALID_TRANSITIONS` (line 53 in `session.py`) permits PAUSED → OPEN, so no transition error fires.
- Recommended fix: Before calling `_transition(STATE_OPEN)`, check that at least one pending checkpoint exists and raise `SessionStateError` if not (when `_approval_records` is non-empty and all are resolved). Alternatively, document in the docstring that `resume()` on a fully-denied session is caller error and that `cancel()` is the correct path.
- Verification gap: Add a test for `resume()` called on a session with only denied checkpoints.

---

### F-04 — Low — Post-call tool-budget reconciliation guard is unreachable in current architecture

- Location: `aigc/_internal/session.py:981-995`
- Issue: The post-call guard (`if self._total_tool_calls_consumed > self._max_total_tool_calls`) runs after `_total_tool_calls_consumed += entry["tool_calls_count"]` at line 979. The pre-call guard (lines 822-838) uses `_projected_total = self._total_tool_calls_consumed + _tool_calls_this_step` and raises if `_projected_total > max`. If pre-call passes, `_projected_total <= max`. Post-call adds the same count (`entry["tool_calls_count"]` equals `_tool_calls_this_step`), so `_total_tool_calls_consumed` becomes exactly `_projected_total` which is `<= max`. The post-call check `> max` cannot fire.
- Why it matters: The guard creates the impression of a two-phase reconciliation that does not exist in practice. Any future refactor that changes which phase increments the counter risks breaking one side while the other appears to protect. The comment "Budget post-call reconciliation — check if actual consumption exceeds budget" implies this is an active check, but it is structurally dead.
- Evidence: No test triggers this path. `test_tool_call_budget_check_happens_at_pre_call` (line 127 in `test_budget_accounting.py`) tests only that the pre-call path fires. The post-call reconciliation path has no corresponding test.
- Recommended fix: Either remove the post-call guard and add a comment explaining it is enforced entirely at pre-call time, or add a design note explaining when the post-call path would be needed (e.g., if post-call tool-call counts could differ from pre-call declaration). If the intent is to reconcile against actual tool output, the counting mechanism needs to change to read from the output artifact rather than the invocation, which would require a deliberate design decision.
- Verification gap: No test for the post-call reconciliation path. If this guard is intended to be active, add a test that exercises it.

---

### F-05 — Low — Warning branch in hook dispatch loop is dead code

- Location: `aigc/_internal/session.py:900-908`
- Issue: The warning block at lines 900-908 fires when `_result.decision not in {VALIDATOR_ALLOW, VALIDATOR_WARN, VALIDATOR_EXECUTION_FAILURE}`. After the fail-closed check at lines 885-899 raises on `DENY`, `TIMEOUT`, and `REVIEW_REQUIRED`, only `ALLOW`, `WARN`, and `EXECUTION_FAILURE` can remain. All other decisions are normalized to `EXECUTION_FAILURE` by `_call_hook_once` before returning. The intersection of "not in _non_warning" and "not already raised" is empty.

  Verified empirically:
  ```python
  deny_set = {DENY, TIMEOUT, REVIEW_REQUIRED}
  non_warn = {ALLOW, WARN, EXECUTION_FAILURE}
  all_known = {ALLOW, DENY, WARN, REVIEW_REQUIRED, EXECUTION_FAILURE, TIMEOUT}
  residual = all_known - deny_set - non_warn  # empty set
  ```

- Why it matters: Dead warning code does not affect correctness. However, it gives the false impression that `_invoke_hook` can return a decision that is neither fail-closed nor in the warning-safe set, which misleads future maintainers.
- Recommended fix: Remove lines 900-908. If a fallback warning is desired for future extensibility, add a comment explaining the invariant.
- Verification gap: None needed — this is a maintenance clarity issue.

---

### F-06 — Low — implementation_status.md partially stale in the PR branch

- Location: `implementation_status.md:12-25` and `implementation_status.md:73`
- Issue: The `b504b7c` commit marks PR-08 as "complete" but does not update the `Active Branch` header (still shows `feat/v0.9-07-beta-proof`) or the `Last Updated` date (still shows `2026-04-17`). PR-07 remains "in progress" in the tracking table even though it merged to develop before this branch was cut.
- Why it matters: `CLAUDE.md` and the CI truth-check scripts (`scripts/check_doc_parity.py`) cross-reference these files. If the CI parity check includes `Active Branch` or PR status comparisons, this inconsistency could cause a downstream failure. Review `scripts/check_doc_parity.py` before merging to confirm whether these fields are checked.
- Recommended fix: Update `implementation_status.md`: set `Active Branch` to `feat/v0.9-08-engine-hardening`, set `Last Updated` to `2026-04-18`, and update PR-07 status from "in progress" to "complete".
- Verification gap: The existing `test_v090_contract_freeze.py::test_v090_pr05_contract_truth_passes_for_repo` calls `check_v090_pr05_contract()`, which did pass. Confirm the check script does not read `Active Branch` or per-PR status fields.

---

## Open Questions / Assumptions

**OQ-1 — Protocol enforcement scope boundary**

`aigc/_internal/session.py` contains protocol-family-specific runtime checks for `bedrock` (alias-backed identity requirement) and `a2a` (gRPC rejection, `supportedInterfaces` version check) embedded directly at lines 697-735. CLAUDE.md designates `BedrockTraceAdapter` and `A2AAdapter` as reserved for PR-10a/10b. The plan text for PR-08 ("enforce protocol constraints") does explicitly include this scope. The distinction is: the PR-08 code enforces protocol *evidence requirements* declared in the policy's `protocol_constraints` block (a governance concern), while PR-10 adapters normalize *external provider payloads* (a transport concern). This scope placement is correct per the implementation plan but should be confirmed by the author, since inline protocol-family checks in session.py could create maintenance coupling before the adapters land.

**OQ-2 — EXECUTION_FAILURE is warning-path, not fail-closed**

After all `max_retries` are exhausted on `EXECUTION_FAILURE`, the hook result is treated as non-blocking (warning path, step proceeds). This is the implemented and tested behavior. The review checklist asks to "verify `deny`, `timeout`, and `review_required` fail closed" — all three do fail closed. But it also says "verify unknown decisions normalize safely" — they normalize to `EXECUTION_FAILURE` which is the warning path, not fail-closed. This is consistent with the docstring in `ValidatorHook` which says "return EXECUTION_FAILURE instead" of raising. The assumption here is that exhausted-retry hook failures should allow the step to proceed with a warning rather than blocking it. Operators deploying hooks with `max_retries=0` (the default) should be aware that a single `EXECUTION_FAILURE` does not block the step.

**OQ-3 — Bedrock/A2A protocol enforcement before adapters exist**

The bedrock alias-backed identity check (session.py:697-712) runs when `"bedrock"` appears in participant protocols and the invocation specifies `protocol="bedrock"`. A false-negative is possible if the `alias_backed` evidence is set by the host before the real BedrockTraceAdapter validates it. Until PR-10a lands, there is no authoritative mechanism to verify the evidence. This is a known gap for the beta.

---

## Residual Test Gaps

The following scenarios have no direct test coverage. None are blocking given the current behavioral analysis, but they represent exposure for future regressions.

1. **Rejected pre-call does not advance `_authorized_step_count`**: Sequence violation, participant mismatch, transition denial, role violation, and protocol violation all raise before the counter increment at line 920. No test directly asserts the counter value after a rejection.

2. **Rejected pre-call does not advance `_sequence_position`**: The position advances only in `enforce_step_post_call`. No test asserts `_sequence_position` remains unchanged after a failed `enforce_step_pre_call`.

3. **Post-call tool-budget reconciliation guard (lines 981-995)**: Unreachable under current semantics. No test exists. See F-04.

4. **`resume()` after `deny_approval()` with no pending checkpoints**: The session silently transitions to OPEN. No test covers this path. See F-03.

5. **Doctor diagnosis for `WorkflowStepBudgetExceededError` and `WorkflowHookDeniedError`**: No test verifies the code emitted for these failure types. See F-02.

6. **Composition: child that omits `required_sequence` entirely vs. child that specifies an empty list**: The check `if base_seq and (added := sorted(child_seq_set - base_seq_set))` only triggers if `base_seq` is non-empty. If the child omits `required_sequence`, `child_seq` defaults to `[]`, so `child_seq_set - base_seq_set` is empty, and no error fires. This is correct (omission inherits base). No explicit test covers this case.

7. **Escalation guard `require_approval_after_steps` with `authorized_step_count = 0`**: The trigger at lines 770-773 checks `self._authorized_step_count > 0 and self._authorized_step_count % _esc_n == 0`. The `> 0` guard prevents a spurious trigger before any step completes. No test explicitly verifies that the first call with count=0 does not trigger even when count=0 and `_esc_n=1` (where `0 % 1 == 0`).

8. **`deny_approval()` called with a matching `approval_id` when multiple checkpoints are pending**: The implementation scans `_approval_records` and picks the one matching `approval_id` with "pending" status. No test exercises multiple simultaneous pending checkpoints.

---

## Merge Verdict

**Ready with fixes.**

Two items must be resolved before merging:

1. **F-01 (High)**: Remove the six unused imports from `aigc/_internal/workflow_doctor.py:29-38`. This is a one-line fix (remove the six class names from the import list). The frozenset at lines 406-414 uses bare strings and does not need the class objects.

2. **F-02 (Medium)**: Decide how to route `WorkflowStepBudgetExceededError` and `WorkflowHookDeniedError` through `diagnose_workflow_artifact()`. Either add exception-type branches that emit the specific codes, or remove the dead `_NEXT_ACTIONS` entries and document that these failures produce a generic `POLICY_LOAD_ERROR` doctor finding (with a note for PR-09 to improve).

Items F-03 through F-06 are non-blocking: F-03 is a behavioral edge case with a guard that still protects the completion path; F-04 and F-05 are dead code with no correctness impact; F-06 is a stale tracking doc.

The core implementation — session state enforcement, composition restriction, validator hook contract, approval checkpoint semantics, budget accounting, escalation re-fire guard, and schema additions — is correct, consistent, and well-tested. Both schema copies are byte-for-byte identical. All 1359 tests pass. The public API boundary remains intact: `ValidatorHook` is not exported, `open_session()` does not accept `validator_hooks` as a parameter, and the seven frozen reason-code error classes are unchanged.
