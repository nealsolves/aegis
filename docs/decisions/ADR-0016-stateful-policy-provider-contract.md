# ADR-0016: Stateful Policy Provider Contract

Date: 2026-08-11
Status: Accepted
Owners: Neal

---

## Context

AEGIS previously enforced only invocation-local and process-local workflow
limits. Those counters cannot safely implement cross-session quotas, replay
claims, or time windows. Embedding a database client in the policy evaluator
would also conflate policy interpretation with deployment-owned state,
credentials, tenancy, clocks, and availability.

Issue #42 therefore requires a provider-neutral contract before adding another
expression evaluator. Version 1 must prove one useful policy end to end without
claiming distributed consistency or durability that the runtime cannot verify.

## Decision

AEGIS defines a versioned `aegis.stateful` contract with exact frozen operation
and result types for monotonic counters, quotas, replay TTL claims, and sliding
windows. Providers publish one immutable descriptor snapshot per `AEGIS`
instance. AEGIS validates the contract version, supported operation families,
sync/async modes, consistency and durability domains, clock class and
resolution, idempotency retention, and size/capacity bounds before mutation.

The first DSL primitive is `sliding_window_tool_calls`. It is scoped by a
trusted host-supplied tenant value plus the stable policy state ID, constraint
ID, and tool. The policy digest binds the request and evidence but deliberately
does not partition provider state. Ordinary policy edits therefore do not reset
a limit.

State addresses use a domain-separated, type-tagged, length-framed encoding.
Operations carry AEGIS-minted identifiers and SHA-256 request fingerprints.
Retries and reconciliation always reuse the exact operation identity. Applied,
rejected-no-consumption, unavailable-no-effect, indeterminate-may-have-
committed, and invalid-request-no-effect are distinct outcomes.

State admission is the final deny-capable Phase-A check after guards, role,
preconditions, tool limits, and custom authorization gates, but before the
operation handle is minted. AEGIS accepts only an exact typed `WindowApplied`.
All configured provider failures deny. A late result, exception, timeout, or
indeterminate result can continue only after an exact bounded replay resolves
the same operation. Admissions are never rolled back after a later provider
denial, handle failure, Phase-B failure, tool failure, or evidence failure.

Version 1 supports instance split pre-call sync/async enforcement and sync
`GovernanceSession` steps. Adapter-mediated tools defer admission until the
actual filtered dispatch. Unified, module-level, and decorator surfaces reject
stateful policies with `STATEFUL_PRECALL_REQUIRED` before user code when AEGIS
controls that boundary.

## Ownership and assurance boundary

| Concern | Owner |
|---|---|
| Compile policy, mint operation identity, validate exact results, fail closed, emit bounded evidence | AEGIS |
| Select provider, namespace, pseudonymous tenant key, credentials, deployment topology, and retention | Host |
| Atomic operation semantics, clock behavior, idempotency retention, availability, storage bounds, and declared consistency/durability behavior | Provider implementation/operator |

Provider descriptors are claims checked for contract compatibility; they are
not proof that production topology, replication, clocks, access controls, or
disaster recovery match those claims. The included in-memory provider is
instance-local and non-durable. Sharing one object shares state only within that
process. Separate instances, processes, and restarts do not.

Tenant values and namespaces are secrets at the evidence boundary. Audit
records include only scope dimension names, stable policy identifiers, bounded
outcomes, provider claims, and one-way fingerprints. Provider exception text,
raw provider objects, addresses, operation IDs, namespaces, and scope values are
never recorded.

## Mixed versions and migration

Within one state identity, operation family, tool, scope shape, counted unit,
and window are immutable. Providers bind these values on first use. Lowering a
limit is monotonic tightening; raising it is not. Changing a window, tool,
scope, family, or increasing a deployed limit requires a new state identity and
an explicit host migration. Rolling processes may safely overlap only when
they preserve the identity and immutable configuration; the provider applies
the strictest observed limit.

To reverse the feature, remove stateful declarations from policy before
rolling back runtime support. AEGIS never deletes retained provider state;
cleanup and retention remain host/provider operations.

## Consequences

- Stateful policy semantics are testable without coupling AEGIS to Redis, a
  database, a cloud service, or credentials.
- Outages and uncertain commits can reduce availability because version 1 is
  fail closed.
- Multi-key requests use conservative attempt accounting rather than rollback
  or distributed transactions.
- A provider must pass the reusable conformance suite and deployment-specific
  operational validation; conformance is not production certification.

## Contract impact

- Enforcement: final Phase-A state admission on supported split/session paths.
- Policy DSL: optional closed `stateful` version-1 section.
- Audit: optional typed `metadata.stateful_decisions`; audit schema remains
  `2.0` and canonicalization remains `aegis-json-v2`.
- Compatibility: policies without `stateful` retain existing behavior and need
  no provider, namespace, or scope.
- Dependencies: none added.

## Validation

- Exact model/encoding/fingerprint and hostile-result tests.
- Atomic provider concurrency, retry, expiry, capacity, clock, and conformance
  tests across all four operation families.
- Compiler/schema/restriction tests proving stateful composition cannot widen.
- Sync, async, session, dynamic-tool, retry/reconciliation, unsupported-surface,
  redaction, schema, and checksum tests.

## References

- Issue #42.
- `docs/superpowers/specs/2026-08-11-issue-42-stateful-policy-providers-design.md`.
- `docs/reference/STATEFUL_POLICY_PROVIDERS.md`.
- ADR-0009 and ADR-0014.
