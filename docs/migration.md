> See [WORKFLOW_QUICKSTART.md](reference/WORKFLOW_QUICKSTART.md) for the fastest path to a working workflow.

# Migrating from Invocation-Only to Workflow Governance

This migration targets the `aegis-ai-governance==0.9.0b1` public beta. The
import package and CLI remain `aegis`.

This guide shows the smallest safe diff to add workflow governance to existing
AEGIS-governed code. The migration is **additive** — existing invocation-only code
continues to work without changes.

## When to migrate

Migrate when you want:
- **Correlated audit trail** across multiple model calls in one workflow
- **Lifecycle state** (`OPEN → COMPLETED/FAILED/CANCELED`) for multi-step processes
- **Approval checkpoints** or source-required enforcement at the session level

Single one-off calls are fine with invocation-only governance.

## The minimal diff

### Before (invocation-only)

```python
governance = aegis.AEGIS(sink=audit_sink)

pre = governance.enforce_pre_call(invocation)
output = call_model(...)
artifact = governance.enforce_post_call(pre, output)
```

### After (additive workflow adoption)

```python
governance = aegis.AEGIS(sink=audit_sink)

with governance.open_session(policy_file="policy.yaml") as session:  # + wrap
    pre = session.enforce_step_pre_call(invocation)                    # enforce_pre_call →
    output = call_model(...)                                            # unchanged
    session.enforce_step_post_call(pre, output)                        # enforce_post_call →
    session.complete()                                                  # + complete

workflow_artifact = session.workflow_artifact                           # + new artifact
```

The four changes are:
1. `with governance.open_session(...) as session:` — open a session context
2. `session.enforce_step_pre_call` instead of `governance.enforce_pre_call`
3. `session.enforce_step_post_call` instead of `governance.enforce_post_call`
4. `session.complete()` — mark the workflow as successfully finished

## Migrating evidence verification to v2

V2 evidence delivery is acknowledged and fail-closed. Instance APIs require an
explicit sink; module and decorator APIs require one-time configuration before
their first attempt:

```python
from aegis import AEGIS, JsonFileAuditSink, configure_module_enforcement

governance = AEGIS(sink=JsonFileAuditSink("audit.jsonl"))

configure_module_enforcement(
    sink=JsonFileAuditSink("module-audit.jsonl"),
)
```

The first module-level attempt seals its private runtime. Sink failure raises
`AuditSinkError` and cannot return PASS/WARN. Mutable global failure-mode APIs
are no longer part of the v2 public surface. Finalized invocation and workflow
evidence explicitly reports `signature_status` as `signed` or `unsigned`.

New invocation evidence declares `audit_schema_version: "2.0"`,
`canonicalization_profile: "aegis-json-v2"`, and a non-null content checksum.
Verification now reports content integrity, chain continuity, signature status,
anchor status, and completeness independently:

```python
from aegis import verify_chain_detailed

report = verify_chain_detailed(artifacts)
assert report.content_integrity.value == "valid"
assert report.chain_continuity.value in {"valid", "unchained"}
```

An internally valid supplied prefix still reports completeness `unproven`.
Checksum validity never implies a valid signature or an external anchor.

Legacy evidence is strict-invalid by default. A trusted host may opt in only
for the exact compatibility operations it needs:

```python
from aegis import LegacyFeature, create_legacy_authorization, verify_chain_detailed

legacy = create_legacy_authorization(
    LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
    LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION,
)
report = verify_chain_detailed(artifacts, legacy_authorization=legacy)
assert report.content_integrity.value == "legacy"
assert report.completeness.value == "unproven"
```

Policy, artifact, guard, provider, and invocation fields cannot grant this
authority. For operator-driven policy diagnostics, the equivalent narrow CLI
opt-in is `--allow-legacy-preconditions` on `aegis policy lint` and
`aegis policy validate`.

## What you get after migration

| Artifact | Before | After |
|----------|--------|-------|
| Invocation audit artifact | One per call | One per call (unchanged) |
| Workflow artifact | None | One per session (status + step checksums) |
| Session ID | None | UUID correlating all steps |
| Lifecycle state | None | `OPEN → COMPLETED / FAILED / CANCELED` |

## Verifying the migration

After migrating, assert:

```python
artifact = session.workflow_artifact
assert artifact["status"] == "COMPLETED"
assert len(artifact["steps"]) == <your step count>
```

## Example files

- `examples/migration/invocation_only.py` — the before pattern (2 independent calls)
- `examples/migration/workflow_adoption.py` — the after pattern (same 2 calls under a session)

## Error handling

`GovernanceSession.__exit__` never suppresses exceptions. If your model call raises,
the session transitions to `FAILED`, emits a workflow artifact with `status: FAILED`,
and re-raises the original exception. No special handling needed.

## Common mistakes

### Forgetting `session.complete()`

If you exit the `with` block without calling `session.complete()`, the session
transitions to `INCOMPLETE`. The workflow artifact is emitted with
`status: INCOMPLETE`. Call `complete()` before the block exits, or `cancel()`
if the workflow was intentionally abandoned.

### Calling `enforce_step_pre_call` while PAUSED

If you call `session.enforce_step_pre_call()` while the session is in the `PAUSED`
state, it raises `SessionStateError` with code `WORKFLOW_INVALID_TRANSITION`. Call
`session.resume()` first to return the session to `OPEN`.

## Getting a starter scaffold

If you are starting fresh rather than migrating:

```bash
aegis workflow init --profile minimal
cd governance
python workflow_example.py
```
