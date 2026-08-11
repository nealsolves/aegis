# Issue #42 Stateful Policy Provider Design

Date: 2026-08-11

Status: Revised after end-to-end and adversarial review; awaiting approval

Issue: [#42 — define stateful policy providers before evaluating CEL](https://github.com/nealsolves/aegis/issues/42)

Dependency baseline: the compiled-policy, non-widening restriction, normalized-outcome, process-affine operation-handle, and evidence-finalization boundaries are present on `main` through `a3ce853`.

## Executive decision

AEGIS will add a versioned, provider-neutral contract for bounded governance state before adding any general expression engine. The contract exposes typed atomic operations for monotonic counters, quota consumption, TTL-backed replay claims, and sliding-window admission. It does not expose an arbitrary key/value store or host business memory.

The first policy primitive is a cross-session sliding-window tool-call limit keyed by a trusted `tenant + policy + tool` scope. AEGIS compiles this constraint into the existing immutable policy representation, proves that composition cannot weaken it, and performs state admission as the final deny-capable Phase-A authorization check before minting the existing process-affine operation handle.

The initial implementation includes an in-memory, process-local reference provider and a reusable provider conformance kit. It adds no Redis, database, cloud, or CEL dependency. Durable backends remain separate future work.

Every provider failure is explicit. Version 1 permits only `on_provider_failure: deny`; timeout, stale state, malformed results, clock uncertainty, unknown commit status, and capacity exhaustion cannot silently fall back to session-local counters.

## Current baseline

AEGIS already provides these boundaries that this design must preserve:

- `PolicyCompiler` converts raw policies into detached immutable `CompiledPolicy` values.
- `RestrictionComparator` rejects composition and guard effects that widen authority.
- Phase A continues only from a normalized allow-class result.
- `OperationRegistry` mints single-use, issuer-instance-bound, process-affine handles.
- `EvidenceFinalizer` owns checksum, signature, and emission ordering.
- `GovernanceSession` enforces process-local step and tool-call budgets, but those counters are neither cross-session nor durable.
- Audit artifacts use strict top-level schema version `2.0`; their `metadata` object is the compatible extension point.

Stateful providers do not replace any of these units. In particular, a provider returns an admission decision, not a policy or policy overlay. Any future provider that supplies policy material must still pass through the semantic compiler and restriction comparator.

## Goals

- Define public, versioned provider protocols and closed typed request/result models.
- Cover invocation, participant, session, tenant, tool, and policy scope dimensions without making host entity memory AEGIS-owned state.
- Define atomic semantics for monotonic counters, quotas, TTL replay claims, and sliding windows.
- Define exact clock, window-boundary, idempotency, retry, concurrency, mixed-version, availability, stale-state, and partial-failure behavior.
- Provide a bounded in-memory reference provider with explicit process-local and non-durable claims.
- Provide a dependency-free reusable conformance runner with typed reports.
- Enforce one tenant-scoped sliding-window tool-call primitive end to end.
- Preserve existing stateless policy behavior and process-affine operation handles.
- Emit bounded, redacted, signature-covered state decision evidence.
- Document provider, host, and AEGIS ownership boundaries.
- Evaluate CEL in a separate ADR only after the provider and initial primitive have passing proof.

## Non-goals

- CEL or another general expression engine.
- A Redis, SQL, cloud, or other durable provider implementation.
- Cross-process or restart durability from the in-memory provider.
- Distributed transactions or rollback across different state addresses.
- Distributed or transferable operation handles.
- Arbitrary JSON, document, vector, conversation, entity, or application-memory storage.
- Automatic state migration, namespace discovery, backend provisioning, monitoring, backup, or disaster recovery.
- Trusted audit time, cryptographic proof of backend state, or proof that a deployed provider matches its conformance fixture.
- Initial DSL selection of invocation-, participant-, or session-scoped limits.
- A general decorator scope resolver.

## Approaches considered

### Selected: typed atomic operation executor

The public provider accepts a closed union of governance operations through one sync or async executor. Each operation combines its authoritative read, comparison, and update in the provider.

Advantages:

- keeps state algorithms inside the consistency boundary;
- gives retries and duplicate requests one idempotent operation identity;
- supports a reusable conformance suite;
- avoids arbitrary host-memory storage;
- allows later durable providers without a core dependency.

Cost:

- provider authors must implement the exact atomic semantics;
- providers are trusted enforcement components whose live operation cannot be proven by AEGIS artifacts alone.

### Rejected: generic compare-and-swap storage

Implementing sliding windows in AEGIS over low-level reads and writes would expose time-of-check/time-of-use races, require multi-call retry protocols, and make partial failure ambiguous. A generic value model would also invite host business memory into the governance state boundary.

### Rejected: host allow/deny callback

A callback is easy to integrate but supplies no reusable consistency, clock, idempotency, or conformance semantics. It would make an allow result depend on an unstructured host assertion.

### Rejected: core-owned durable backend

Shipping Redis, database, or cloud behavior in the core package would add credentials, networking, migrations, operational availability, and dependency obligations before the contract is proven.

## Public provider contract

### Protocols

The public `aegis.stateful` facade exposes separate structural protocols:

```python
class StatefulPolicyProviderV1(Protocol):
    def describe(self) -> StateProviderDescriptorV1: ...
    def execute(self, operation: StateOperationV1) -> StateOperationResultV1: ...


class AsyncStatefulPolicyProviderV1(Protocol):
    def describe(self) -> StateProviderDescriptorV1: ...
    async def execute_async(
        self,
        operation: StateOperationV1,
    ) -> StateOperationResultV1: ...
```

A provider may implement either or both protocols. Sync enforcement requires the sync protocol. Async enforcement requires the async protocol. AEGIS does not silently run a blocking provider in a background thread.

`describe()` returns a detached immutable descriptor containing:

- exact contract version `1`;
- provider-safe identifier;
- supported operation families and execution modes;
- consistency domain: instance, process, or distributed;
- durability domain: none, process-lifetime, or durable;
- clock identity, source class, resolution, and discontinuity behavior;
- minimum idempotency-retention horizon;
- maximum key, operation, unit, and state-capacity bounds.

The descriptor is a declared contract, not runtime proof. AEGIS validates and snapshots it before the provider is used.

### Addresses and scope

`StateAddressV1` is an immutable ordered address with two parts. Its control identity contains the host state namespace, stable `policy_state_id`, and stable constraint ID. Its scope tuple can contain these typed dimensions:

- invocation;
- participant;
- session;
- tenant;
- tool;
- policy.

Dimension values are nonempty canonical strings with byte limits. Identifiers and host namespaces use a narrower bounded ASCII grammar. Only dimensions selected by the compiled operation's scope shape are present. No address value is taken from model output or an invocation mapping merely because it has a matching field name.

Addresses are not delimiter-joined strings. Their normative encoding is a domain-separated, versioned tuple whose UTF-8 components are individually type-tagged and length-framed. It encodes the control identity first and then all contract-defined scope slots in fixed order, tagging each slot as absent or present. Present empty values are invalid before encoding, dimension names cannot repeat, and caller-provided ordering is irrelevant. Provider implementations may use a native structured key instead of these bytes only when it is injective over the same accepted address model. The conformance suite includes ambiguous-delimiter, Unicode, rejected-empty, reordered-input, absent-dimension, cross-field-shift, and maximum-length collision cases.

The initial DSL primitive constructs this provider key:

```text
host state namespace
+ opaque tenant key
+ stable policy_state_id
+ stable constraint id
+ exact tool name
```

The host supplies the tenant key as a separate `StateScopeV1` argument to enforcement or session creation. The policy digest binds the operation and evidence but does not partition stored state, because doing so would reset limits after an ordinary policy edit.

Host state namespace, `policy_state_id`, and constraint ID are migration identities. Changing one creates a different state address. Such a change is not compatible with an ordinary mixed-version rolling deployment.

### Operations

`StateOperationV1` is a closed union of frozen dataclasses. All integers are built-in, non-boolean, nonnegative, bounded values. All operations include an AEGIS-minted operation ID, canonical request fingerprint, address, relative `timeout_ms`, and retry horizon. No absolute deadline crosses the AEGIS/provider clock boundary.

The canonical request fingerprint is exactly 64 lowercase hexadecimal characters encoding `SHA-256(b"aegis-state-operation-v1\x00" + canonicalize_v2(projection).data)`. The detached projection excludes the fingerprint field itself and includes the contract version, operation family, operation ID, structured address, operation parameters, `timeout_ms`, and `retry_horizon_ms`. A provider must independently reconstruct the projection, recompute the digest, and constant-time compare it before idempotency lookup or mutation; it may not trust a caller-supplied projection or digest. A mismatch returns `INVALID_REQUEST_NO_EFFECT`.

#### Monotonic increment

- Accepts a strictly positive bounded increment.
- Atomically returns the value after increment.
- Does not expose decrement or reset.
- Detects bounded-integer overflow before mutation.

#### Quota consumption

- Accepts requested units and a limit.
- Atomically admits and increments only when `used + units <= effective_limit`.
- Denial does not change the quota usage.
- The provider stores the strictest limit observed for the address.

#### TTL replay claim

- Uses a stable replay-control address plus one bounded claim key below that control.
- Atomically claims an absent claim key through a provider-time TTL.
- A duplicate before expiry is denied without replacing or extending the original claim.
- A claim is expired exactly when `now >= expires_at`.
- TTL is bounded by the descriptor, uses provider time, and is fixed for the stable replay-control address.
- A different TTL at an already-bound replay-control address returns `INVALID_REQUEST_NO_EFFECT`; changing TTL requires a new control identity plus an explicit drain or warm-up migration.

#### Sliding-window admission

- Uses provider-controlled time for the address's consistency domain.
- Samples one bounded provider `now` value inside the atomic operation and uses that same value for every expiry, count, decision, and inserted event in the operation.
- Removes entries whose timestamps satisfy `timestamp <= now - window`.
- Counts entries in `(now - window, now]`.
- Atomically admits all requested units only when `current + units <= effective_limit`.
- Denial does not add window entries.
- Multi-unit requests are all-or-nothing.
- A rejection's `retry_after_ms` is the smallest nonnegative integer duration until enough currently live units expire under the sampled clock; it is absent when `requested_units > effective_limit`.
- An admission is not rolled back after later execution or evidence failure.

### Constraint binding and mixed versions

On first use, the provider atomically binds an address, or the stable control-address portion of a replay claim, for the active namespace's lifetime within its declared durability domain to:

- operation family;
- scope shape;
- counted unit;
- fixed window or TTL semantics where applicable;
- strictest observed limit where applicable.

All fingerprint, structural, numeric, and descriptor-bound validation occurs before an operation may create a binding. Later valid operations must match the bound family, shape, unit, and fixed window or TTL. A family or configuration conflict returns `INVALID_REQUEST_NO_EFFECT`. Normal garbage collection never removes this control binding or its strictest observed limit; only an explicitly authorized namespace retirement or provider reset may do so. This rule prevents an idle period from allowing an older process to recreate the address with a wider limit or incompatible TTL.

For quota and sliding-window operations, the provider atomically computes:

```text
effective_limit = min(stored_strictest_limit, requested_limit)
```

An older process sending a former higher limit therefore cannot relax a newer lower limit. Raising a limit or changing a window requires an explicit new state identity and migration. Compatible rolling upgrades preserve namespace, state IDs, operation family, scope, unit, and window.

### Result model

`StateOperationResultV1` is a closed union of operation-specific frozen result types under these common effect classes:

- `APPLIED`;
- `REJECTED_NO_CONSUMPTION`;
- `UNAVAILABLE_NO_EFFECT`;
- `INDETERMINATE_MAY_HAVE_COMMITTED`;
- `INVALID_REQUEST_NO_EFFECT`.

Applied and rejected payloads are specific to the operation family:

- monotonic increment returns `CounterApplied(value, state_version)`;
- quota consumption returns `QuotaApplied(used, remaining, state_version)` or `QuotaRejected(used, effective_limit, state_version)`;
- TTL replay claim returns `ReplayClaimed(expires_at, state_version)` or `ReplayDuplicate(expires_at, state_version)`;
- sliding-window admission returns `WindowApplied(used, remaining, state_version)` or `WindowRejected(used, effective_limit, retry_after_ms, state_version)`, where `retry_after_ms` is absent when the requested units can never fit under the effective limit.

Every result carries the exact contract version, operation family, operation ID, request fingerprint, effect class, and the descriptor-claim snapshot needed for validation. A bounded provider state version and provider-time observation are present only when the result's exact type requires them. `REJECTED_NO_CONSUMPTION` means no requested units, event, or replay claim were added; first-use configuration binding or monotonic limit tightening may still have occurred and is reported by a bounded `control_state_changed` boolean. Maintenance removal of records that were already expired may also occur and is not consumption. The exact common failure types are `StateUnavailableNoEffect`, `StateIndeterminateMayHaveCommitted`, and `StateInvalidRequestNoEffect`; they use closed reason enums and no provider-defined strings. An operation family cannot return another family's payload. Counter increment has no ordinary rejected result: invalid input or overflow returns `StateInvalidRequestNoEffect`, capacity or a known pre-mutation outage returns `StateUnavailableNoEffect`, and an uncertain commit returns `StateIndeterminateMayHaveCommitted`.

AEGIS authorizes a stateful tool call only from an exact, validated `WindowApplied` result for the current operation and fingerprint. Result validation covers contract version, operation family, operation ID, independently recomputed request fingerprint, exact payload type, typed effect, provider clock observation when applicable, consistency metadata, numeric bounds, and optional fixed-format provider record digest.

An explicit stale marker can never authorize. A cached result is acceptable only for an exact idempotent replay of the same operation.

Once provider execution begins, any raised exception, cancellation, late result, or unvalidated return value enters `INDETERMINATE_MAY_HAVE_COMMITTED` reconciliation; only an exact validated terminal result for the same operation can subsequently resolve it. AEGIS does not call arbitrary `str()` or `repr()` on provider exceptions or results. `UNAVAILABLE_NO_EFFECT` is valid only as a successfully returned typed result whose provider contract guarantees that no mutation occurred.

## Clock and time semantics

Provider time is authoritative for enforcement and is not trusted audit time. It does not prove real-world chronology, recency, or a legal timestamp.

All contract durations and provider-time observations are bounded integer milliseconds. The provider must use a clock appropriate to its declared consistency domain. It must prevent time from moving backward for an active address and detect clock uncertainty or discontinuity that could prematurely expire state. Detected rollback or unsafe discontinuity fails closed without using the uncertain time to admit work.

The in-memory provider uses an injected monotonic clock for tests and a monotonic runtime clock by default. A future distributed provider is responsible for a server-side or otherwise coordinated clock source and must document its guarantees and failure modes.

The operation's `timeout_ms`, sourced from the compiled constraint's `provider_timeout_ms`, is a relative budget, not a timestamp. The provider measures it from operation receipt using the provider's own monotonic duration source. AEGIS separately measures the call from immediately before dispatch using its local monotonic clock. Before mutation, an exhausted provider budget returns `UNAVAILABLE_NO_EFFECT`; after mutation begins, the provider must return the exact decided result or `INDETERMINATE_MAY_HAVE_COMMITTED`, never a claimed no-effect timeout.

Async AEGIS enforcement applies its local timeout to the await. Cancellation or timeout after dispatch is indeterminate because the provider may still commit. Sync AEGIS enforcement cannot safely preempt an arbitrary provider call; sync liveness is therefore a declared provider obligation tested by conformance. If a sync provider returns after the local budget, AEGIS discards that return and enters bounded reconciliation; the final outcome is indeterminate if reconciliation does not obtain the exact stored result. A provider that never returns can block the calling thread, so hosts that require enforceable wall-clock cancellation must use the async protocol or isolate their provider outside the core contract.

## Idempotency and retry semantics

AEGIS mints high-entropy operation IDs internally from authenticated attempt state and the compiled constraint identity. Caller tool-call IDs, invocation fields, model output, and tenant keys are not replay authority.

The first valid use of an operation ID binds it to its canonical request fingerprint. An exact duplicate returns the stored terminal result without applying the operation again; a different fingerprint returns `INVALID_REQUEST_NO_EFFECT`. Concurrent exact duplicates must converge on one mutation and one terminal result rather than both executing. Fingerprint failures do not reserve an operation ID. Typed pre-mutation unavailability is retryable and does not become a terminal result. The idempotency lookup or reservation, configuration binding, state mutation or denial, and storage of the replayable terminal result occur in one atomic provider transaction for the address.

`timeout_ms` is the budget for one provider dispatch. `retry_horizon_ms` is a larger bounded total operation budget, fixed by trusted AEGIS configuration rather than invocation or model data, and measured by AEGIS from immediately before the first dispatch. A provider measures retention from first receipt and retains the operation record through at least `first_receipt + retry_horizon_ms + timeout_ms`; its descriptor must declare a minimum that covers this requested interval. AEGIS verifies that bound before the first mutation and never starts a retry at or after its local retry-horizon cutoff. The documented worst-case provider latency is the retry horizon, not one dispatch timeout. Sliding-window events and TTL claims have their own longer semantic retention where required.

AEGIS does not retry applied, rejected, invalid-request, stale, malformed, or wrong-family results. It may retry a typed `UNAVAILABLE_NO_EFFECT` and may perform bounded reconciliation after an exception or local timeout, always with the identical operation ID and fingerprint. Only an exact validated terminal result obtained by a dispatch completed within its own timeout resolves reconciliation and, for `WindowApplied`, can authorize. A direct return that exceeded its dispatch timeout remains unusable even if its shape is valid. Exhausting the retry horizon returns `INDETERMINATE_MAY_HAVE_COMMITTED`. Caller cancellation returns indeterminate without detached background retries.

An AEGIS-internal retry reuses the same operation identity. A later independent enforcement attempt receives a new operation identity and may conservatively consume another unit if an earlier attempt had an indeterminate commit.

## Availability, capacity, and garbage collection

Version 1 supports only `on_provider_failure: deny`. There is no stale-read allow, cached allow from a different operation, or process-local fallback.

The in-memory provider has configured hard bounds for control bindings, addresses, live entries, replay records, units, and input sizes. It rejects an over-capacity operation without mutation. It never evicts live state or idempotency records merely to free space. Garbage collection may remove window events, expired replay claims, and operation-id records only after both their enforcement semantics and idempotency horizon have expired. It does not remove control bindings or stored strictest limits; reclaiming those requires an explicit reset of an isolated namespace and is never an enforcement side effect.

Capacity, timeout, malformed result, unknown version, stale result, clock uncertainty, and indeterminate commit produce separate stable reason codes and audit outcomes.

## Initial policy DSL

The policy schema adds one security-sensitive top-level section:

```yaml
stateful:
  version: "1.0"
  policy_state_id: "customer-support-governance"
  sliding_window_tool_calls:
    - id: "web-search-window"
      tool: "web_search"
      scope: "tenant"
      limit: 20
      window_seconds: 60
      provider_timeout_ms: 250
      on_provider_failure: "deny"
```

Version 1 accepts only `scope: tenant` and `on_provider_failure: deny`. The schema and semantic compiler bound list length, identifier sizes, tool names, limits, windows, timeouts, and duplicate IDs or tool constraints. A stateful tool constraint restricts existing tool authority; it never adds a tool to an allowlist.

The compiler produces immutable `CompiledStatefulPolicy` and `CompiledSlidingWindowToolConstraint` values held by `CompiledPolicy` and its authority envelope. Runtime enforcement never re-reads the raw `stateful` mapping.

## Restrictive composition

`stateful` is registered in the closed security-sensitive schema and restriction registry. A child policy cannot remove an inherited stateful section or constraint.

Version 1 prohibits `stateful` inside guard effects. Stateful constraints may be declared by a root policy and narrowed through compile-time policy composition only. The compiler rejects a guard `then` object containing `stateful`, and `CompiledPolicyOverlay` has no stateful field. This prevents a transient runtime condition from permanently lowering a provider's stored strictest limit after the guard stops matching.

For an inherited constraint, a child may only:

- preserve the host-independent policy and constraint state IDs;
- preserve tool, scope, counted unit, operation family, and window duration;
- lower or preserve the limit;
- shorten or preserve `provider_timeout_ms`;
- preserve `on_provider_failure: deny`.

A higher limit, different window, different tool or scope, longer timeout, missing constraint, changed state ID, or unknown field is widening and fails compilation. A root policy can intentionally create a new constraint, but changing a deployed state identity is documented as a state migration and incompatible rolling change.

There is one effective sliding-window constraint per tool in version 1. This avoids multiple partially committed constraints for the same address.

## Public AEGIS integration

Public types are exported through `aegis.stateful` and the stable top-level facade where appropriate:

- provider protocols and descriptor;
- state address and trusted scope values;
- operation and result types;
- normative address-encoding and operation-fingerprint helpers plus fixed test vectors;
- in-memory provider;
- conformance fixture/report types;
- typed provider, scope, protocol, availability, indeterminate, and limit errors.

Hosts bind a provider and deployment namespace to an `AEGIS` instance:

```python
governance = AEGIS(
    state_provider=provider,
    state_namespace="production-us-central",
)

scope = StateScopeV1.tenant("opaque-host-tenant-key")

handle = governance.enforce_pre_call(
    invocation,
    state_scope=scope,
)
```

`AEGIS.open_session(..., state_scope=scope)` stores a detached trusted scope for the session. Existing policies without `stateful` require neither a provider nor a scope.

Version 1 supports stateful policies only through:

- `AEGIS.enforce_pre_call(..., state_scope=...)` with a sync provider;
- `AEGIS.enforce_pre_call_async(..., state_scope=...)` with an async provider;
- `AEGIS.open_session(..., state_scope=...)` with a sync provider, including the session's static and adapter-mediated dynamic tool calls.

Version 1 rejects stateful policies on unified `AEGIS.enforce`/`enforce_async`, module-level enforcement, and `@governed` surfaces. Module-level and split-decorator paths have no trusted provider/scope binding. A split decorator encounters the rejection during Phase A before the wrapped function runs. A deprecated unified decorator must preflight and reject a stateful policy before calling the wrapped sync or async function; it may not rely on the existing post-execution unified check. Direct callers of a unified API receive `STATEFUL_PRECALL_REQUIRED`, with documentation stating that a unified call cannot retroactively provide pre-action enforcement.

Stateful policies used without the required provider, execution mode, descriptor capability, namespace, or scope fail before provider mutation. Invocation keys resembling state scope are ignored as authority. Version 1 does not extend `configure_module_enforcement` and does not add a decorator or general scope-resolver callback.

## Enforcement flow

For each invocation, AEGIS performs these steps:

1. Load and compile the complete policy once.
2. Prove compile-time composition is non-widening and reject stateful guard effects.
3. Allocate authenticated attempt identity and sanitize the trusted state scope.
4. Complete stateless Phase-A role, precondition, guard, tool, and pre/post-authorization custom-gate checks.
5. Resolve applicable stateful tool constraints from the effective compiled policy.
6. Aggregate repeated calls to the same constrained tool into one bounded unit request.
7. Preflight provider capabilities, evidence capacity, descriptor limits, and retry horizon before the first provider call.
8. Execute state admissions in deterministic constraint-ID order.
9. Continue only if every required admission returns an exact explicit admit.
10. Mint the existing process-affine operation handle.
11. Carry detached state decision evidence into the ordinary evidence draft and finalizer.

Direct split pre-call enforcement and static session steps aggregate declared repeated calls to the same constrained tool into one atomic unit request. An adapter-mediated step is marked as dynamic dispatch and defers state admission: it does not charge merely exposed or proposed tools during the enclosing step, then uses the same internal admission seam for each actual intercepted tool call immediately before dispatch and after adapter surface filtering. A tool call is charged by exactly one of these paths.

Different tools are separate provider operations. If an earlier tool is admitted and a later tool denies or becomes indeterminate, the overall invocation fails and earlier admissions remain consumed. This is explicit conservative attempt accounting. Cross-key rollback and distributed transactions are out of scope.

An admission also remains consumed if handle minting, Phase B, tool execution, evidence finalization, or sink emission later fails. Rollback would enable replay-based capacity recovery and is prohibited.

Risk scoring remains in the existing Phase-B pipeline after output validation. A Phase-B risk denial therefore leaves any Phase-A state admission consumed and records that conservative outcome in the FAIL artifact.

The state provider never receives or returns an operation handle. Existing issuer-instance and process-affinity rules remain unchanged.

## Error and outcome behavior

Stable public errors distinguish:

- provider required;
- trusted scope required;
- unsupported sync or async mode;
- descriptor or contract mismatch;
- stateful limit denied;
- provider unavailable with known no effect;
- indeterminate possible commit;
- stale, malformed, or unknown result;
- clock uncertainty;
- provider capacity exhausted;
- stateful composition widening.

All errors derive from the existing governance error hierarchy and use bounded details. Raw tenant keys, state addresses, replay IDs, namespaces, provider results, and provider exception text are excluded.

Stateful failures use the existing audit `failure_gate: "tool_validation"` value plus a specific reason code. This preserves audit-schema 2.0 compatibility.

## Audit evidence

State decisions are stored in the internally reserved `metadata.stateful_decisions` extension. The maintained audit schemas add a typed optional definition, while existing audit schema version `2.0` and canonicalization profile remain unchanged. Older validators already permit metadata extensions.

Caller invocation, context, step, adapter, and gate metadata cannot set, merge, shadow, or replace the reserved field.

Each decision record contains only:

- state decision evidence version;
- provider contract version and safe provider identifier;
- provider-declared consistency and durability domain enums;
- provider-declared clock source class;
- stable policy and constraint identifiers;
- policy digest and tool name;
- scope dimension names, not values;
- requested units, configured limit, and window;
- typed outcome and stable reason code;
- bounded attempt count, reconciliation status, and `control_state_changed` when applicable;
- bounded provider clock observation and informational remaining capacity;
- optional fixed-format provider record digest;
- a one-way AEGIS operation fingerprint.

The provider record digest is exactly 64 lowercase hexadecimal characters and is informational only. The provider contract defines it as domain-separated over the decision record, not over a tenant value alone. AEGIS never authorizes from it.

Provider exception text, tenant values, host namespaces, operation IDs, idempotency keys, arbitrary provider metadata, and raw state are never recorded. Provider-controlled objects are not stringified.

The compiler and enforcement preflight bound the number and size of prospective state decision records before any provider mutation. PASS and FAIL artifacts both carry applicable decisions. Workflow evidence binds the invocation checksum instead of duplicating provider details.

Consistency, durability, and clock fields are explicitly labeled provider claims. The existing finalizer makes the state metadata checksum- and signature-covered. This proves what AEGIS recorded; it does not prove the provider's actual state or deployment behavior.

## In-memory reference provider

`InMemoryStatefulPolicyProvider` implements both sync and async protocols and all four operation families using detached immutable requests, a lock-protected state table, bounded storage, an injectable test clock, and deterministic garbage collection.

Its declared consistency domain is callers sharing the same provider instance in one process. Its durability domain is none. Separate instances, processes, and restarts do not share state. Documentation and evidence may not describe it as distributed or durable.

The implementation favors correctness and inspectability over throughput. Durable backend evaluation begins only after this contract is frozen.

## Reusable conformance kit

The dependency-free public conformance runner accepts a test-only fixture that can:

- create isolated provider clients sharing one namespace;
- reset an isolated test namespace;
- control or simulate provider time outside the production protocol;
- expose supported sync and async modes;
- create multiple clients for the declared consistency domain.

It returns a typed report with passed, failed, and not-applicable scenarios plus fixture limitations. A mandatory scenario for a declared capability cannot be skipped while retaining an overall conformant result.

The normative provider suite contains only behavior observable through a correct provider and its fixture. A fixture may optionally expose a test-only fault controller for provider-specific outage or reconciliation testing, but fault injection is not part of the production provider protocol. Commit-then-timeout, commit-then-exception, malicious stale results, malformed objects, and unknown result variants are mandatory hostile-provider AEGIS integration tests rather than mandatory conformance scenarios that an ordinary backend fixture cannot induce.

Normative scenarios cover:

- monotonic increment, overflow, and invalid units;
- quota boundaries and monotonic limit tightening;
- TTL claim creation, duplicate claims, exact expiry, and incompatible-TTL rejection;
- sliding-window admission and exact lower-bound expiry;
- atomic multi-unit operations;
- duplicate requests and conflicting operation-ID reuse;
- incompatible operation versions and request fingerprints are rejected without effect;
- clock rollback and discontinuity;
- isolation for every scope dimension;
- concurrent clients and lost-update prevention;
- mixed old and new limits under one state identity;
- capacity exhaustion and safe garbage collection;
- sync and async semantic equivalence;
- bounded, redacted result and report fields.

The in-memory provider must pass every scenario applicable to its declared capabilities. A future durable provider must run the suite against its own isolated backend and independent clients. Conformance is semantic test evidence, not proof of production configuration, access control, failover, clock quality, or disaster recovery.

## Test design

### Compiler and schema tests

- valid initial DSL compiles into immutable typed constraints;
- unknown versions, fields, scopes, failure modes, and numeric types fail;
- booleans and coercible strings are rejected as numeric limits;
- duplicate IDs, duplicate tool constraints, oversized values, and invalid identifiers fail;
- stateful declarations inside guard effects fail;
- schema copies and security-sensitive registry remain synchronized;
- stateful constraints never grant tool authority.

### Restriction tests

- removing a stateful section or inherited constraint fails;
- raising the limit, changing window, tool, scope, IDs, or failure behavior fails;
- lengthening provider timeout fails;
- lowering the limit and shortening the timeout pass;
- guard effects containing `stateful` are rejected;
- root and merged compile-time policies receive the same restriction checks.

### Provider tests

- the reference provider passes its conformance report;
- barriers prove concurrent atomic admission without timing assumptions;
- injected clocks prove exact TTL and window boundaries;
- address and operation encodings are injective across the adversarial collision corpus;
- fixed public encoding and fingerprint vectors match the implementation;
- providers independently reject a forged or mismatched request fingerprint;
- operation families accept only their exact applied or rejected payload types;
- hostile providers exercise stale allows, malformed objects, exception bombs, delayed commit, descriptor mutation, and oversized fields;
- wrappers exercise commit-then-timeout and commit-then-exception reconciliation against AEGIS;
- provider-controlled objects whose `str()` or `repr()` raises or exposes secrets do not escape.

### Enforcement tests

- stateless denial occurs before provider mutation;
- missing provider or trusted scope fails before mutation;
- invocation data cannot override tenant scope;
- supported instance pre-call and session surfaces enforce stateful policies;
- unified, module-level, and decorator surfaces reject stateful policies before user code where AEGIS controls execution;
- static and dynamic tool calls use the shared admission seam;
- repeated tool calls aggregate atomically;
- multiple tools have deterministic conservative partial-consumption behavior;
- internal retries reuse operation identity;
- relative sync and async dispatch timeouts reject late direct returns, permit only exact bounded reconciliation, and become indeterminate when unresolved;
- state outcomes cannot mint transferable handles;
- Phase B and evidence failures do not roll back admission;
- existing stateless policies and sessions remain behaviorally compatible.

### Evidence and compatibility tests

- caller metadata cannot inject the reserved field;
- PASS and FAIL artifacts contain bounded state decisions;
- artifacts record provider-declared consistency, durability, and clock-source enums as claims;
- tenant keys, namespaces, replay keys, raw provider objects, and exception text are absent;
- old audit-schema 2.0 validators accept new artifacts;
- new validators accept artifacts without state metadata;
- checksums, signatures, and chain links cover state metadata;
- workflow checksums transitively bind stateful invocation evidence;
- packaged and repository schema copies are byte-identical;
- public API and reason-code snapshot changes are explicit;
- an old runtime rejects the new policy DSL instead of ignoring it.

## Security and privacy boundaries

The provider is a trusted authorization component. AEGIS validates its protocol behavior and can test conformance, but cannot cryptographically prove its live consistency, clock, durability, or access controls.

Tenant keys should be random or pseudonymous host identifiers rather than names, emails, account numbers, or business records. Their public value object uses a redacted representation. The host is responsible for classifying, protecting, rotating, and mapping them inside its provider.

AEGIS governance state contains counters, claims, timestamps, strictness bindings, and replay records required for policy enforcement. It does not automatically ingest host entity records, conversations, documents, model memory, or application state.

No provider failure can produce an allow result except an exact validated admission for the current operation. Evidence or provider diagnostics never become a secondary authorization input.

## Documentation and decision records

Implementation updates these durable artifacts:

- `ADR-0016` for consistency, atomicity, time, scope, availability, idempotency, mixed-version, migration, and failure semantics;
- the policy DSL specification and both packaged schema copies;
- the public integration contract and API reference;
- enforcement-pipeline and architectural-invariant documentation;
- host/provider ownership and operational guidance;
- error, audit-evidence, supported-environment, and implementation-status records.

Ownership is explicit:

- AEGIS owns compilation, non-widening comparison, typed operations, result validation, the reference provider, conformance semantics, and evidence shaping.
- The host owns tenant identity mapping, provider selection and deployment, namespace continuity, durable availability, clock quality, capacity, monitoring, access control, migration, backup, and recovery.
- The provider owns atomic behavior inside its declared consistency domain.

`ADR-0017` evaluates CEL as the final implementation task only after a committed verification report proves the provider contract, in-memory conformance, initial primitive, composition, and hostile-provider tests. The ADR may authorize a later proposal, reject CEL, or keep it deferred. It does not add CEL code under issue #42.

## Compatibility and reversal

Policies without `stateful` preserve current behavior and require no provider. The new public API is additive.

Old runtimes fail closed when presented with the new unknown policy field. Audit schema version `2.0` remains compatible because state decisions use the existing metadata extension boundary and existing `tool_validation` failure gate.

Reverting runtime code while a stateful policy remains installed therefore produces a policy-compilation failure rather than silently ignoring the constraint. A coordinated rollback removes or restores policy and runtime artifacts deliberately.

Provider state is never automatically deleted during rollback. Reusing the same host namespace and stable IDs resumes retained state. Resetting, renaming, or deleting state is a separate potentially widening migration requiring explicit authority. The in-memory provider naturally loses state when its instance ends and makes no stronger claim.

## Acceptance mapping

| Issue #42 criterion | Design evidence |
| --- | --- |
| Consistency, atomicity, clock, availability, tenancy, and failure semantics | ADR-0016 and provider contract tests |
| Public versioned protocol and typed result model | `aegis.stateful` API and snapshot tests |
| In-memory provider and reusable conformance suite | Typed conformance report and provider tests |
| One stateful primitive enforced end to end | Tenant-scoped sliding-window tool-call tests |
| Concurrency, retries, duplicates, boundaries, outages, stale state, and audit evidence | Conformance, hostile-provider, enforcement, and evidence tests |
| Child policies cannot widen stateful constraints | Schema, compiler, guard, and restriction tests |
| Host-owned versus AEGIS governance state documented | Ownership and integration guidance |
| CEL evaluated only after proof | Verification report followed by ADR-0017 |

## Resolved design decisions

- The initial primitive is a tenant-scoped sliding-window tool-call limit.
- The provider API is a typed governance-operation executor, not generic storage.
- Each operation family has exact applied/rejected result payload types under a closed common effect model.
- Scope is supplied outside invocation data.
- Provider addresses and request fingerprints use collision-resistant domain-separated canonical encodings that providers independently verify.
- Policy and constraint state IDs are stable migration identities.
- Window duration is fixed for an existing constraint ID.
- Replay TTL is fixed for an existing replay-control ID.
- Limits tighten monotonically at the provider across mixed versions.
- Timeout budgets are relative; async AEGIS can cancel locally while sync liveness remains provider-owned.
- Version 1 fails closed on every provider failure and has no local fallback.
- Partial admissions remain consumed.
- Stateful guard effects, unified enforcement, module-level enforcement, and decorators are unsupported in version 1.
- In-memory consistency is instance-local and non-durable.
- State evidence extends audit metadata without changing audit schema version `2.0`.
- Arbitrary provider evidence strings are not recorded.
- CEL remains out of scope until the implementation proof exists.

There are no unresolved material design questions.
