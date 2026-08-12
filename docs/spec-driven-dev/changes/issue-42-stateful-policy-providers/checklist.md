# Issue #42 Specification Quality and Risk Checklist

- [x] Provider, host, and AEGIS ownership boundaries are explicit.
- [x] Atomicity, clock, idempotency, retries, timeout, stale-state, partial-failure, mixed-version, and migration semantics are closed.
- [x] The first DSL primitive is bounded to tenant-scoped sliding-window tool-call limits.
- [x] Every provider failure is fail-closed and no local fallback exists.
- [x] Public provider contracts and result unions are versioned and closed.
- [x] The in-memory provider makes no distributed or durability claim.
- [x] Composition cannot remove, retarget, or widen inherited stateful constraints.
- [x] Trusted state scope is out-of-band from invocation/model data.
- [x] Supported and unsupported enforcement surfaces are enumerated.
- [x] State admission occurs before handle minting and is never rolled back.
- [x] Concurrency, duplicates, boundaries, outages, stale/malformed results, hostile objects, and evidence redaction have executable test tasks.
- [x] Audit metadata stays schema `2.0`, bounded, redacted, and signature-covered.
- [x] Old stateless policies remain compatible; old runtimes reject the unknown DSL field.
- [x] Durable backends and CEL remain out of scope; CEL receives only a post-proof ADR.
- [x] Documentation, status, compatibility, and reversal work are explicit implementation tasks.
