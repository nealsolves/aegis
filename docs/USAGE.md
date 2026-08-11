# AEGIS Cookbook

This document is task-oriented. Use it when you already know what AEGIS is and
want concrete integration patterns.

Use [README.md](../README.md) for the repo overview and
[INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for the full host-integration
contract.

These recipes target the `aegis-ai-governance==0.9.0b1` public beta; the import
and CLI remain `aegis`.

Source, tags, and release artifacts for versions before `0.9.0` remain in
[`nealsolves/aigc`](https://github.com/nealsolves/aigc). This repository is the
AEGIS `0.9.0`-and-later development home.

## Choosing the right API

- Use `enforce_invocation()` when you already have the model output and want
  one-call enforcement.
- Use `enforce_pre_call()` and `enforce_post_call()` when you need to block
  before token spend.
- Use `AEGIS(...)` when you want instance-scoped configuration for sinks,
  signers, policy loaders, strict mode, or custom gates.
- Use `@governed(...)` when you want to wrap a model call site directly.
- Use `AEGIS.open_session(...)` when multiple governed calls need workflow
  lifecycle, sequence, budget, approval, handoff, or correlated evidence.
- Use `aegis workflow trace` and `aegis workflow export` to inspect persisted
  invocation and workflow evidence; neither command runs the workflow.

## Recipe 1: Unified enforcement

This is the shortest path when your host assembles a complete invocation.

```python
from aegis import enforce_invocation

artifact = enforce_invocation(
    {
        "policy_file": "policies/base_policy.yaml",
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-6",
        "role": "assistant",
        "input": {"query": "Summarize incident INC-2847"},
        "output": {"result": "Summary text", "confidence": 0.94},
        "context": {
            "role_declared": True,
            "schema_exists": True,
            "tenant_id": "acme-prod",
        },
    }
)

print(artifact["enforcement_result"])
```

Use this mode when your application treats governance as a post-call boundary
around a complete model interaction.

## Recipe 2: Split enforcement

Use split mode when you want AEGIS to authorize before the model call and only
validate output after the model responds.

```python
from aegis import enforce_post_call, enforce_pre_call

pre = enforce_pre_call(
    {
        "policy_file": "policies/base_policy.yaml",
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-6",
        "role": "assistant",
        "input": {"query": "Summarize incident INC-2847"},
        "context": {
            "role_declared": True,
            "schema_exists": True,
            "tenant_id": "acme-prod",
        },
    }
)

output = model.generate(...)
artifact = enforce_post_call(pre, output)
```

Important split-mode rules:

- `output` is omitted from the pre-call invocation and supplied only in
  `enforce_post_call(...)`.
- `PreCallResult` is single-use. If the token has already been consumed, run
  `enforce_pre_call(...)` again to get a fresh one.
- Since v0.3.3, split mode is the default. Pass `pre_call_enforcement=False`
  for legacy unified behavior (deprecated).

## Recipe 3: Instance-scoped configuration

Prefer `AEGIS(...)` when you want runtime configuration without mutating global
state.

```python
from aegis import AEGIS, HMACSigner, JsonFileAuditSink

engine = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    on_sink_failure="raise",
    strict_mode=True,
    signer=HMACSigner(key=b"replace-with-a-real-secret"),
)

artifact = engine.enforce(invocation)
```

This pattern is the best default for applications that need predictable
configuration boundaries.

## Recipe 4: Wrapping a call site with `@governed`

Use the decorator when you want governance attached directly to a function that
performs the model call.

```python
from aegis import governed

@governed(
    policy_file="policies/base_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
)
def run_model(input_data, context):
    return model.generate(input_data)
```

The example above uses split mode (the default since v0.3.3). Phase A runs
before the wrapped function; Phase B validates output after. Passing
`pre_call_enforcement=True` explicitly is equivalent to the default.

To use the legacy unified mode (deprecated):

```python
from aegis import governed

@governed(
    policy_file="policies/base_policy.yaml",
    role="assistant",
    model_provider="anthropic",
    model_identifier="claude-sonnet-4-6",
    pre_call_enforcement=False,  # deprecated; will be removed in a future release
)
def run_model(input_data, context):
    return model.generate(input_data)
```

## Recipe 5: Persisting audit artifacts

Built-in sinks cover the common cases.

### File sink

```python
from aegis import AEGIS, JsonFileAuditSink

engine = AEGIS(sink=JsonFileAuditSink("audit.jsonl"))
artifact = engine.enforce(invocation)
```

### Callback sink

```python
from aegis import AEGIS, CallbackAuditSink

engine = AEGIS(sink=CallbackAuditSink(lambda artifact: db.insert(artifact)))
artifact = engine.enforce(invocation)
```

### Custom sink

```python
import json

from aegis import AEGIS, AuditSink


class SQLiteAuditSink(AuditSink):
    def __init__(self, conn):
        self._conn = conn

    def emit(self, artifact: dict) -> None:
        self._conn.execute(
            "INSERT INTO governance_log (artifact) VALUES (?)",
            [json.dumps(artifact)],
        )


engine = AEGIS(sink=SQLiteAuditSink(db_connection), on_sink_failure="raise")
artifact = engine.enforce(invocation)
```

Notes:

- In `"log"` mode, sink errors are logged and enforcement continues.
- In `"raise"` mode, sink errors propagate as `AuditSinkError`.
- Sinks receive a deep copy, so they cannot mutate the returned artifact.

## Recipe 6: Adding a custom enforcement gate

Custom gates let you inject host-specific checks at one of four insertion
points:

- `pre_authorization`
- `post_authorization`
- `pre_output`
- `post_output`

Example:

```python
from aegis import (
    AEGIS,
    EnforcementGate,
    GateResult,
    INSERTION_POST_AUTHORIZATION,
)


class TenantIsolationGate(EnforcementGate):
    name = "tenant_isolation"
    insertion_point = INSERTION_POST_AUTHORIZATION

    def evaluate(self, invocation, policy, context):
        tenant_id = invocation["context"].get("tenant_id")
        allowed_tenant = policy.get("metadata", {}).get("tenant_id")

        if allowed_tenant and tenant_id != allowed_tenant:
            return GateResult(
                passed=False,
                failures=[
                    {
                        "code": "TENANT_MISMATCH",
                        "message": "Invocation tenant does not match policy tenant",
                        "field": "context.tenant_id",
                    }
                ],
                metadata={"tenant_id": tenant_id},
            )

        return GateResult(passed=True, metadata={"tenant_id": tenant_id})


engine = AEGIS(custom_gates=[TenantIsolationGate()])
artifact = engine.enforce(invocation)
```

Custom-gate rules:

- Invocation and policy are read-only views.
- Gates return `GateResult`; they do not bypass the pipeline.
- Failures are append-only.
- Registration order is preserved within each insertion point.

## Recipe 7: Loading policies from somewhere other than disk

If policies live in a database, API, or secrets system, implement
`PolicyLoaderBase`.

```python
import yaml

from aegis import AEGIS, PolicyLoaderBase, PolicyLoadError


class DatabasePolicyLoader(PolicyLoaderBase):
    def __init__(self, db):
        self._db = db

    def load(self, policy_ref: str) -> dict:
        row = self._db.query(
            "SELECT yaml FROM governance_policies WHERE id = ?",
            [policy_ref],
        )
        if not row:
            raise PolicyLoadError(
                f"Policy {policy_ref} not found",
                details={"policy_ref": policy_ref},
            )
        return yaml.safe_load(row["yaml"])


engine = AEGIS(policy_loader=DatabasePolicyLoader(db))
artifact = engine.enforce(
    {
        **invocation,
        "policy_file": "planner-prod",
    }
)
```

The loader returns a raw policy dict. AEGIS still performs schema validation,
composition resolution, and policy-date checks after loading.

## Recipe 8: Producing a compliance report from stored artifacts

Once audit artifacts are being persisted to JSONL, the CLI can build a report.

```bash
aegis compliance export --input audit.jsonl
```

Write the report to a file:

```bash
aegis compliance export --input audit.jsonl --output compliance-report.json
```

Include individual artifacts in the report:

```bash
aegis compliance export \
  --input audit.jsonl \
  --output compliance-report.json \
  --include-artifacts
```

This is an offline reporting step over stored evidence, not a runtime
enforcement gate.

## Recipe 9: Handling failures without losing the FAIL artifact

Every governance failure raises a typed exception and attaches the FAIL artifact
at `exc.audit_artifact`.

```python
from aegis import (
    GovernanceViolationError,
    PreconditionError,
    SchemaValidationError,
    enforce_invocation,
)

try:
    enforce_invocation(invocation)
except PreconditionError as exc:
    print(exc.code)
    print(exc.audit_artifact["failure_gate"])
except SchemaValidationError as exc:
    print(exc.audit_artifact["failures"])
except GovernanceViolationError as exc:
    # Role, policy, tool, and related governance failures land here.
    persist_fail_artifact(exc.audit_artifact)
```

Practical rules:

- Handle the most specific exception type you care about.
- Use `exc.audit_artifact` when you need to persist or inspect the FAIL path.
- Treat `AuditSinkError` separately if you run with `on_sink_failure="raise"`.

## Recipe 10: Public API boundary

Only import from the top-level `aegis` package:

```python
from aegis import AEGIS, enforce_invocation, JsonFileAuditSink
```

Do not build production integrations on `aegis._internal.*`. That namespace is
private implementation detail and may change between releases.

## Recipe 11: Lineage-aware compliance report

Add `--lineage` to include DAG topology analysis alongside the standard compliance
stats. Useful for auditing agentic workflows where invocations derive from prior
invocations.

```bash
aegis compliance export --input audit_trail.jsonl --lineage
```

Write to a file and combine with `--include-artifacts`:

```bash
aegis compliance export \
  --input audit_trail.jsonl \
  --output compliance-report.json \
  --include-artifacts \
  --lineage
```

The report gains a `"lineage"` key with `total_nodes`, `duplicate_artifacts`,
`root_count`, `leaf_count`, `orphan_count`, `has_cycle`, and checksum lists
`roots`, `leaves`, `orphans`. `total_nodes == total_artifacts - duplicate_artifacts`
always holds.

## Recipe 12: Risk trend monitoring with `RiskHistory`

```python
from aegis import AEGIS, RiskHistory

aegis = AEGIS()
history = RiskHistory("summarizer-workflow")

for invocation in workflow_invocations:
    audit = aegis.enforce(invocation)
    risk_score = audit.get("risk_score")
    if risk_score is not None:
        history.record(risk_score)

if len(history.scores) >= 2:
    print(f"Trajectory: {history.trajectory()}")
    # "improving" | "stable" | "degrading"
```

## Recipe 13: Trusted checkpoints for whole-chain completeness (issue #46)

Content and signature checks prove a supplied chain is internally consistent;
they do **not** prove it is the chain that actually occurred. A trusted
checkpoint pins a chain to externally signed, provider-neutral evidence so a
later verification can report `checkpoint_proven` for a valid, anchored,
authoritative match or `contradicted` for a conflict with that trusted
authority, instead of `unproven`. Invalid, unavailable, unknown-key, revoked,
or unanchored evidence remains `unproven`. See
ADR-0015 for the full assurance scope — a `checkpoint_proven` result does not
identify the authoritative current checkpoint, enforce retention, predict
future activity, or determine organizational assurance status.

For host-owned retention, object locking, checkpoint selection, historical
verification, backup, and recovery, see the
[Append-Only Evidence Operations Guide](reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md).
That guide separates library-produced results from host retention, write
protection, and organizational assurance decisions.

The signer and verifier are **host-supplied and provider-neutral**; AEGIS ships
no key store or network client for this path. `checkpointed_at` is a signed but
host-supplied Unix second. You own where and how long you persist the record.

```python
from aegis.checkpoints import create_chain_checkpoint, TrustedChainCheckpoint
from aegis import verify_chain_detailed

# 1. Create — `signer` is your ExternalArtifactSigner
#    (signer_identity() + sign(payload, identity)).
checkpoint = create_chain_checkpoint(
    final_artifact,            # a finalized, checksum-valid v2 chain artifact
    signer,
    checkpointed_at=1_754_400_000,   # host-supplied signed time (Unix seconds)
)

# 2. Persist it yourself — AEGIS never writes to a store of its own.
stored = checkpoint.to_dict()
save_somewhere(stored)

# 3. Verify later — reconstruct the record and bind it to the expected scope.
reconstructed = TrustedChainCheckpoint.from_dict(load_from_somewhere())
report = verify_chain_detailed(
    artifacts,
    checkpoints=[reconstructed],
    checkpoint_verifier=verifier,          # host-supplied ExternalArtifactVerifier
    expected_chain_id=final_artifact["chain_id"],
)

assert report.completeness.value in {"checkpoint_proven", "contradicted"}
# checkpoint_signature_status / checkpoint_anchor_status / checkpoint_results
# expose the per-checkpoint detail behind that completeness verdict.
```

Callers that pass no `checkpoints` see the pre-#46 behavior and an `unproven`
completeness — adoption is fully additive. Workflow claims use the parallel
`create_workflow_checkpoint(...)` / `verify_workflow_claim(..., expected_checkpoint=...)`
pair with `TrustedWorkflowCheckpoint`; the two record types are never merged.

## Policy root authority

File-backed policy graphs have one canonical authority root. A plain
`load_policy("policies/entry.yaml")` call uses the entry's lexical parent
(`policies`) as that root. Use an explicit loader when a deliberate policy tree
spans multiple directories:

```python
from aegis import AEGIS, load_policy, with_retry
from aegis.policy_loader import FilePolicyLoader

loader = FilePolicyLoader("policies")
policy = load_policy("child.yaml", loader=loader)
engine = AEGIS(sink=sink, policy_loader=loader)
audit = with_retry(
    invocation,
    enforcement_fn=custom_enforce,
    policy_loader=loader,
)
```

Relative entries passed to `FilePolicyLoader("policies")` are root-relative.
Every transitive `extends` and canonical symlink target must remain inside that
root. Custom loaders cannot use `extends`. Arbitrary retry callables must be
given the exact `policy_loader` they attest to using. A containment failure is
`POLICY_PATH_OUTSIDE_ROOT`; its exception text and details contain no filesystem
paths.

The CLI uses the same namespace with `aegis policy lint/validate --policy-root
ROOT` and `aegis workflow lint/doctor --policy-root ROOT`. Without an explicit
root, each policy target gets its own lexical parent authority; an implicit
starter target is rooted at its canonical starter directory. Hostile concurrent
mutation of filesystem components is outside this guarantee: descriptor-relative
race resistance against a concurrent writer remains a non-goal.
