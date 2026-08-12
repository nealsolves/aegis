# Stateful Policy Providers

This guide describes the current source-only version-1 contract. It is not part
of the published `0.9.0b1` wheel.

## Quick start

```python
from aegis import AEGIS, JsonFileAuditSink
from aegis.stateful import InMemoryStatefulPolicyProvider, StateScopeV1

governance = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    state_provider=InMemoryStatefulPolicyProvider(),
    state_namespace="production-us-central",
)

handle = governance.enforce_pre_call(
    invocation,
    state_scope=StateScopeV1.tenant("opaque-host-tenant-key"),
)
artifact = governance.enforce_post_call(handle, output)
```

Use `enforce_pre_call_async(..., state_scope=...)` only with a provider that
declares and implements async mode. A session binds a detached scope once:

```python
session = governance.open_session(
    policy_file="policies/assistant.yaml",
    state_scope=StateScopeV1.tenant("opaque-host-tenant-key"),
)
```

Do not put tenant authority in the invocation or model context. Keys that look
like `state_scope` are ignored. Use a stable pseudonymous tenant identifier,
not an email address, display name, access token, or other direct identifier.

## Policy

```yaml
stateful:
  contract_version: 1
  policy_state_id: assistant-production
  constraints:
    - id: tenant-search-window
      kind: sliding_window_tool_calls
      tool: search
      scope: tenant
      limit: 20
      window_ms: 60000
      provider_timeout_ms: 100
      retry_horizon_ms: 1000
      on_provider_failure: deny
```

The constrained tool must already be authorized by `tools.allowed_tools`.
Version 1 accepts only the values shown for `kind`, `scope`, and failure mode.
Repeated calls to one tool aggregate into one atomic units request. Different
tools execute in constraint-ID order; earlier admissions remain consumed if a
later operation denies.

Limits may be lowered under an existing state identity. Raising a limit or
changing the window, tool, scope, operation family, state ID, or constraint ID
requires an explicit new identity and migration. Preserve namespaces and stable
IDs across compatible rolling upgrades.

## Supported and rejected surfaces

Supported:

- instance `AEGIS.enforce_pre_call` with a sync provider;
- instance `AEGIS.enforce_pre_call_async` with an async provider;
- `AEGIS.open_session(..., state_scope=...)` with a sync provider;
- actual adapter-intercepted tool dispatch through the session authorization
  seam.

Rejected with `STATEFUL_PRECALL_REQUIRED`:

- unified `AEGIS.enforce` and `enforce_async`;
- module-level enforcement;
- split and deprecated unified `@governed` decorators.

## Provider operations and failures

`aegis.stateful` exposes exact versioned operations/results, structural sync
and async protocols, normative address/fingerprint helpers, and a reusable
conformance runner. Providers must treat one operation ID plus fingerprint as
idempotent for at least their declared retention. Conflicting reuse fails
without effect. Provider clocks decide window/TTL admission; host time decides
audit timestamps.

AEGIS fails closed on unavailable, timeout, exception, malformed/stale result,
possible commit, clock uncertainty, capacity exhaustion, and contract mismatch.
Retries are bounded and reuse the identical operation. Only an exact validated
replay result can reconcile uncertainty.

## In-memory provider limitations

`InMemoryStatefulPolicyProvider` is a correctness-oriented reference. Its state
is shared only by callers using the same object in one process and disappears
on restart. It is neither distributed nor durable. Do not use it to claim
cross-process or disaster-recovery guarantees.

Before operating another backend, run `run_state_provider_conformance_v1` with
an isolated fixture and separately validate deployment topology, permissions,
replication, clock behavior, failover, retention, backups, and monitoring.

## Evidence and ownership

`metadata.stateful_decisions` is reserved, bounded, schema-validated, and
checksum/signature-covered. It records provider-declared claim classes and
safe stable identifiers. It never records tenant values, namespaces, raw
addresses, operation IDs, raw request fingerprints, provider exception text,
or arbitrary provider metadata.

AEGIS owns compilation, exact result validation, fail-closed decisions, and
evidence. The host owns provider selection, namespace, tenant pseudonymization,
credentials, topology, and operational policy. The provider/operator owns the
truth of atomicity, idempotency, clock, availability, consistency, durability,
and retained state. Descriptor claims are not independent proof of deployment
behavior. See ADR-0016.
