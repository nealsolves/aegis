# AEGIS Workflow Troubleshooting Guide

This guide covers the unpublished
`aegis-ai-governance==0.9.0b1` candidate on `develop`.

This guide covers `aegis workflow doctor`, `aegis workflow lint`, the frozen
first-user reason codes, and the regulated failure-and-fix walkthrough.

## `aegis workflow doctor`

Use doctor when you want runtime or evidence-aware diagnosis:

```bash
aegis workflow doctor governance/
aegis workflow doctor workflow_artifact.json
aegis workflow doctor audit.json --kind audit_artifact --json
```

Doctor exits `0` when no error-severity findings are present and exits `1` when
at least one error-severity finding is present.

## `aegis workflow lint`

Use lint for static checks before you run a workflow:

```bash
aegis workflow lint policy.yaml
aegis workflow lint governance/
```

Lint exits `0` when no findings are present and exits `1` when one or more
static findings are present.

In the beta, lint covers policy schema validity, starter integrity,
public-import safety, impossible workflow budgets, invalid transition
references, graph/topology conflicts, handoff cycles, and unsupported binding
references.

`aegis workflow lint --json` may include bounded `details` and `witness_trace`
fields for static evidence. Lint findings do not include `severity` or
`next_action`; `aegis workflow doctor` remains the owner of severity and
remediation guidance.

## Frozen First-User Reason Codes

### `WORKFLOW_INVALID_TRANSITION`

Symptom: a public session method raises `SessionStateError`, or a failed
workflow artifact normalizes to `WORKFLOW_INVALID_TRANSITION`.

Fix: keep the lifecycle ordered:
`open_session()` -> `enforce_step_pre_call()` / `enforce_step_post_call()` ->
`complete()` or `cancel()`. If the session paused, call `resume()` before
adding more steps.

### `WORKFLOW_APPROVAL_REQUIRED`

Symptom: `WorkflowApprovalRequiredError`.

Fix: implement a real approval path, then call `session.resume()` to continue
or `session.cancel()` to stop the workflow.

### `WORKFLOW_SOURCE_REQUIRED`

Symptom: a regulated workflow raises `CustomGateViolationError` because
`context.provenance.source_ids` is missing.

Fix: provide `context.provenance.source_ids` on every governed invocation when
using `ProvenanceGate(require_source_ids=True)`.

### `WORKFLOW_TOOL_BUDGET_EXCEEDED`

Symptom: `WorkflowToolBudgetExceededError` or an audit artifact diagnosed as a
tool-budget failure.

Fix: reduce `tool_calls` or increase the allowed tool budget in policy.

### `WORKFLOW_UNSUPPORTED_BINDING`

Symptom: doctor or lint flags unsupported workflow binding references.

Fix: remove unsupported protocol references such as `grpc`, `websocket`, or
`soap`. The beta path supports local workflow use first; optional adapters come
later.

### `WORKFLOW_SESSION_TOKEN_INVALID`

Symptom: `InvocationValidationError` when completing a `SessionPreCallResult`.

Fix: use the exact single-use token returned by `enforce_step_pre_call()`,
complete it through the owning `GovernanceSession`, and mint a new token for a
new attempt.

### `WORKFLOW_STARTER_INTEGRITY_ERROR`

Symptom: lint or doctor reports missing/empty starter files, syntax errors, or
public-boundary violations.

Fix: regenerate the starter with `aegis workflow init --profile <profile>` or
repair the specific file called out by the finding.

## PR-10d Static Workflow Lint Codes

These codes are emitted by `workflow lint` when existing workflow DSL fields
prove a structural problem. Doctor promotes them to `ERROR` and attaches the
next action.

### `WORKFLOW_UNREACHABLE_STEP`

Symptom: a step in `workflow.required_sequence` cannot be reached from the
first required step through `workflow.allowed_transitions`.

Fix: add the missing transition path or remove the unreachable required step.

### `WORKFLOW_DEAD_END_STEP`

Symptom: a non-terminal required step has no valid declared successor in
`workflow.allowed_transitions`.

Fix: add a valid successor transition or make the step terminal by shortening
the required sequence.

### `WORKFLOW_REQUIRED_SEQUENCE_IMPOSSIBLE`

Symptom: consecutive required steps conflict with the transition graph.

Fix: align `workflow.required_sequence` and `workflow.allowed_transitions` so
each required pair is allowed.

### `WORKFLOW_UNBOUNDED_HANDOFF_LOOP`

Symptom: `workflow.handoffs` contains a participant cycle without `max_steps`,
`require_approval_after_steps`, or an approval-required role in the cycle.

Fix: add a step budget, add an approval break, or remove a cyclic handoff.

### `WORKFLOW_SOURCE_PROVENANCE_WARNING`

Symptom: doctor sees source-bearing governance metadata or memory-like context
without exact `source_ids` evidence.

Fix: attach `context.provenance.source_ids` for audit artifacts or
`steps[i].metadata.governance.source_ids` for workflow steps. This warning is
non-blocking by default; doctor exits `0` unless another finding is `ERROR`.

## Regulated Failure-And-Fix Flow

This is the PR-07 stop-ship walkthrough. It uses the real regulated starter,
breaks that generated `workflow_example.py`, diagnoses that same directory, then
fixes and reruns it.

### 1. Generate the starter

```bash
aegis workflow init --profile regulated-high-assurance --output-dir regulated-demo
cd regulated-demo
```

### 2. Break the generated starter

Remove the two `source_ids` lines from `workflow_example.py` so the generated
starter still uses `ProvenanceGate(require_source_ids=True)` but no longer
supplies source provenance for either step.

### 3. Run the broken starter

```bash
python workflow_example.py
```

Expected result: the run fails with `CustomGateViolationError` because
`source_ids` are missing.

### 4. Diagnose that same directory

```bash
aegis workflow doctor regulated-demo/ --json
```

Expected finding set includes `WORKFLOW_SOURCE_REQUIRED`.

### 5. Restore the same file

Put the removed `source_ids` lines back into `workflow_example.py`.

### 6. Rerun the same starter

```bash
python workflow_example.py
```

Expected output:

```text
Status:  COMPLETED
Steps:   2
```
