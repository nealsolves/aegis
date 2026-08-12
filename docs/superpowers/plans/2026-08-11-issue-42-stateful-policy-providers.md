# Issue #42 Stateful Policy Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add a versioned stateful-provider contract, a bounded in-memory reference provider and conformance kit, and end-to-end tenant-scoped sliding-window tool-call enforcement before operation-handle issuance.

**Architecture:** Public frozen operation/result models and structural provider protocols live behind `aegis.stateful`; provider-independent encoding and validation stay separate from the lock-protected reference backend. The policy compiler produces immutable sliding-window constraints, the restriction registry proves child policies cannot widen them, and instance/session Phase A performs the final state admission before the existing process-affine operation registry mints a handle. Evidence is carried as reserved, bounded metadata through the existing finalizer.

**Tech Stack:** Python 3.10–3.14, frozen dataclasses, protocols, enums, `hashlib`, `hmac`, `threading`, `asyncio`, JSON Schema Draft-07, existing canonicalization v2, `pytest`, Markdown.

## Global Constraints

- Contract version is exactly `1`; audit schema and canonicalization profile remain `2.0` and `json-v2`.
- The only version-1 DSL primitive is tenant-scoped sliding-window tool-call admission.
- Version 1 permits only `on_provider_failure: deny`; every timeout, malformed/stale result, exception, uncertain commit, clock problem, or capacity failure fails closed.
- Provider time is authoritative only for admission. AEGIS audit timestamps remain separate.
- Stateful admission is the final deny-capable Phase-A check before operation-handle issuance.
- Admissions and first-use/tightening control bindings are never rolled back after later failures.
- Different tools are separate deterministic operations; earlier successful admissions remain consumed if a later tool fails.
- Invocation content cannot provide trusted state scope. The host passes a detached `StateScopeV1` directly to instance or session APIs.
- Stateless policies remain backward compatible and require no provider, namespace, or scope.
- Module-level enforcement, unified enforcement, and decorators reject stateful policies; no caller code may run first on the deprecated unified decorator path.
- The in-memory provider is instance-local and non-durable. Add no Redis, database, cloud, CEL, or other dependency.
- Preserve process-affine, issuer-instance-bound, single-use operation handles.
- Never record raw scope values, namespaces, operation IDs, fingerprints, exception text, provider objects, or arbitrary provider metadata.
- Preserve the user's pre-existing `.gitignore` change and never stage or overwrite it.
- Use a failing test before each behavior change and retain red/green evidence.

---

## File Structure

### New implementation files

- `aegis/_internal/stateful_models.py` — enums, frozen descriptors/scopes/addresses, closed operation/result types, structural protocols, canonical encodings, fingerprints, and result validation.
- `aegis/_internal/stateful_memory.py` — bounded lock-protected reference provider implementing all four operation families and exact idempotency/configuration semantics.
- `aegis/_internal/stateful_conformance.py` — dependency-free fixture protocol, scenario/report models, and reusable conformance runner.
- `aegis/_internal/stateful_enforcement.py` — compiled-constraint admission, sync/async dispatch, reconciliation, deterministic aggregation, redacted evidence, and unsupported-surface checks.
- `aegis/stateful.py` — stable public facade for provider contracts, values, reference provider, conformance kit, and helpers.

### New tests

- `tests/test_stateful_models.py` — frozen models, redaction, address encoding, fingerprints, fixed vectors, and result-family validation.
- `tests/test_stateful_provider.py` — all operation families, concurrency, idempotency, boundaries, strictness binding, clock rollback, capacity, and hostile inputs.
- `tests/test_stateful_conformance.py` — reusable runner behavior and the in-memory provider's complete report.
- `tests/test_stateful_policy_compiler.py` — DSL/schema/compiler/guard/restriction behavior.
- `tests/test_stateful_enforcement.py` — instance sync/async, retries, outages, stale/malformed/late results, partial consumption, and unsupported surfaces.
- `tests/test_stateful_session.py` — session static aggregation, dynamic interception, scope authority, and no double charging.
- `tests/test_stateful_evidence.py` — reserved metadata, redaction, PASS/FAIL artifacts, checksums/signatures, and schema compatibility.

### Existing implementation files modified

- `aegis/_internal/compiled_policy.py`, `policy_compiler.py`, and `restrictions.py` — immutable stateful policy representation, compilation, and non-widening rules.
- `aegis/_internal/enforcement.py` and `session.py` — instance/session bindings and Phase-A admission seam.
- `aegis/_internal/decorators.py` — preflight rejection for deprecated unified decorators.
- `aegis/_internal/errors.py`, `aegis/errors.py`, and `aegis/__init__.py` — stable typed errors and public exports.
- `schemas/policy_dsl.schema.json` and `aegis/schemas/policy_dsl.schema.json` — byte-identical version-1 stateful DSL schema.
- `schemas/audit_artifact.schema.json` and `aegis/schemas/audit_artifact.schema.json` — optional typed `metadata.stateful_decisions` extension without schema-version change.

### Documentation and evidence

- `docs/decisions/ADR-0016-stateful-policy-provider-contract.md` — provider consistency, time, availability, migration, idempotency, and ownership decision.
- `docs/decisions/ADR-0017-cel-evaluation-after-stateful-provider-proof.md` — post-proof CEL decision; no CEL implementation.
- `docs/reference/STATEFUL_POLICY_PROVIDERS.md` — integration, ownership, provider claims, operations, and failure guidance.
- `docs/reference/STATEFUL_PROVIDER_VERIFICATION.md` — implementation/conformance proof mapped to issue acceptance.
- `policies/policy_dsl_spec.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`, `docs/INTEGRATION_GUIDE.md`, `docs/ENFORCEMENT_PIPELINE.md`, `ARCHITECTURAL_INVARIANTS.md`, `docs/reference/ERRORS.md`, `docs/reference/AUDIT_EVIDENCE.md`, `docs/reference/SUPPORTED_ENVIRONMENTS.md`, `implementation_status.md`, and `CHANGELOG.md` — synchronized public and operational documentation.
- `docs/spec-driven-dev/changes/issue-42-stateful-policy-providers/` — policy decision, lifecycle transitions, red/green log, reviews, and convergence evidence.

---

### Task 1: Public Contract, Encodings, and Typed Errors

**Files:**
- Create: `aegis/_internal/stateful_models.py`
- Create: `aegis/stateful.py`
- Modify: `aegis/_internal/errors.py`, `aegis/errors.py`, `aegis/__init__.py`
- Test: `tests/test_stateful_models.py`, `tests/test_errors.py`, `tests/test_public_api.py`

**Interfaces:**
- Produces: `StatefulPolicyProviderV1`, `AsyncStatefulPolicyProviderV1`, `StateProviderDescriptorV1`, `StateScopeV1`, `StateAddressV1`.
- Produces: `CounterIncrementV1`, `QuotaConsumeV1`, `ReplayClaimV1`, `SlidingWindowAdmitV1`, closed result dataclasses, and operation/result union aliases.
- Produces: `encode_state_address_v1(address) -> bytes`, `operation_fingerprint_v1(operation) -> str`, `bind_operation_fingerprint_v1(operation) -> StateOperationV1`, and `validate_state_result_v1(operation, descriptor, result)`.
- Produces: stable `StatefulPolicyError` subclasses whose details contain only bounded reason codes and safe identifiers.

- [x] **Step 1: Write failing model and public-contract tests**

Test frozen/detached values, boolean rejection for integer fields, scope redaction, descriptor bounds, protocol runtime checks, injective address encodings, fixed canonical vectors, fingerprints that change for every authoritative field, and cross-family result rejection.

```python
def test_tenant_scope_is_redacted_and_address_encoding_is_order_independent():
    scope = StateScopeV1.tenant("opaque-tenant")
    assert "opaque-tenant" not in repr(scope)
    left = StateAddressV1("ns", "policy", "constraint", scope.with_tool("search"))
    right = StateAddressV1.from_dimensions(
        "ns", "policy", "constraint", tool="search", tenant="opaque-tenant"
    )
    assert encode_state_address_v1(left) == encode_state_address_v1(right)
```

- [x] **Step 2: Run focused tests and verify missing-symbol failures**

Run: `.venv/bin/python -m pytest tests/test_stateful_models.py tests/test_errors.py tests/test_public_api.py -q`

- [x] **Step 3: Implement minimal closed models, helpers, and errors**

Use enums rather than provider-defined strings, frozen `slots=True` dataclasses with exact type/range validation, length-framed fixed-slot address encoding, canonicalization-v2 projections, SHA-256/HMAC comparison, and safe custom representations for secret-bearing scope values.

- [x] **Step 4: Run focused tests to green and lint touched source**

Run: `.venv/bin/python -m pytest tests/test_stateful_models.py tests/test_errors.py tests/test_public_api.py -q`

Run: `.venv/bin/flake8 aegis`

---

### Task 2: In-Memory Provider and Reusable Conformance Kit

**Files:**
- Create: `aegis/_internal/stateful_memory.py`
- Create: `aegis/_internal/stateful_conformance.py`
- Modify: `aegis/stateful.py`
- Test: `tests/test_stateful_provider.py`, `tests/test_stateful_conformance.py`

**Interfaces:**
- Produces: `InMemoryStatefulPolicyProvider(clock_ms=None, *, max_records=..., max_idempotency_records=...)` implementing sync and async protocols.
- Produces: `StateProviderConformanceFixtureV1`, `ConformanceScenarioResultV1`, `StateProviderConformanceReportV1`, and `run_state_provider_conformance_v1(fixture)`.
- Consumes: Task 1 operation/result contracts and fingerprint/address helpers.

- [x] **Step 1: Write failing atomic-semantic tests**

Cover monotonic overflow, quota boundaries and tightening, replay duplicate/exact expiry/fixed TTL, sliding-window exact lower-bound expiry/retry-after/all-or-nothing units, duplicate operation IDs, fingerprint conflicts, first-use binding, rollback detection, storage capacity, safe GC, and barriers proving no lost update.

```python
def test_window_expires_at_exact_lower_bound(fake_clock, provider, operation):
    assert isinstance(provider.execute(operation(units=2, limit=2)), WindowApplied)
    fake_clock.advance(operation.window_ms)
    assert isinstance(provider.execute(operation.new_id(units=2, limit=2)), WindowApplied)
```

- [x] **Step 2: Verify the provider tests fail because the provider is absent**

Run: `.venv/bin/python -m pytest tests/test_stateful_provider.py -q`

- [x] **Step 3: Implement the provider under one lock-protected transaction**

Fingerprint validation precedes lookup/mutation. Under the lock: sample one clock value, reject rollback, resolve exact replay, validate/bind immutable control configuration, tighten limits, collect expired data, apply or deny atomically, and store only terminal replayable results. Async execution delegates to the same in-process transaction without a thread.

- [x] **Step 4: Add failing conformance-runner tests, then implement the runner**

The fixture creates isolated/shared clients, resets state, and controls time outside the production protocol. Mandatory scenarios cannot become `NOT_APPLICABLE` when their capability is declared.

- [x] **Step 5: Run provider and conformance tests to green**

Run: `.venv/bin/python -m pytest tests/test_stateful_provider.py tests/test_stateful_conformance.py -q`

---

### Task 3: DSL Schema, Compiler, and Non-Widening Composition

**Files:**
- Modify: `aegis/_internal/compiled_policy.py`, `aegis/_internal/policy_compiler.py`, `aegis/_internal/restrictions.py`
- Modify: `schemas/policy_dsl.schema.json`, `aegis/schemas/policy_dsl.schema.json`
- Test: `tests/test_stateful_policy_compiler.py`, `tests/test_policy_compiler.py`, `tests/test_policy_composition.py`, `tests/test_restriction_registry.py`

**Interfaces:**
- Produces: `CompiledSlidingWindowConstraintV1` and `CompiledStatefulPolicyV1` on `CompiledPolicy.stateful` and `AuthorityEnvelope.stateful`.
- DSL shape: `stateful.contract_version`, `policy_state_id`, and `constraints[]` with exact `id`, `kind`, `tool`, `scope`, `limit`, `window_ms`, `provider_timeout_ms`, `retry_horizon_ms`, and `on_provider_failure` fields.

- [x] **Step 1: Write failing schema/compiler tests**

Cover valid compilation, deep detachment, every unknown field/version/scope/failure mode, booleans and coercible numeric strings, duplicate IDs/tools, identifiers and numeric ceilings, guard effects containing `stateful`, and stateful constraints that name tools outside inherited tool authority.

- [x] **Step 2: Verify red**

Run: `.venv/bin/python -m pytest tests/test_stateful_policy_compiler.py -q`

- [x] **Step 3: Add both byte-identical schemas and compiler-owned values**

Compile the entire section once. Require one version-1 constraint per tool, tenant scope, positive bounded integers, retry horizon not shorter than one dispatch, and the sole failure mode `deny`.

- [x] **Step 4: Add failing restriction tests and implement `StatefulRestrictionRule`**

Removing the section/constraint, raising a limit, lengthening timeout, or changing kind/tool/scope/state IDs/window/failure mode widens. Lowering a limit or shortening a timeout is allowed. A new root constraint is allowed only when no parent authority exists.

- [x] **Step 5: Run compiler/composition tests and schema parity**

Run: `.venv/bin/python -m pytest tests/test_stateful_policy_compiler.py tests/test_policy_compiler.py tests/test_policy_composition.py tests/test_restriction_registry.py -q`

Run: `.venv/bin/python -c "from pathlib import Path; assert Path('schemas/policy_dsl.schema.json').read_bytes() == Path('aegis/schemas/policy_dsl.schema.json').read_bytes()"`

---

### Task 4: Instance Phase-A Enforcement, Retry/Reconciliation, and Evidence

**Files:**
- Create: `aegis/_internal/stateful_enforcement.py`
- Modify: `aegis/_internal/enforcement.py`, `aegis/_internal/decorators.py`, `aegis/_internal/audit.py`, `aegis/_internal/evidence_finalizer.py`
- Modify: `schemas/audit_artifact.schema.json`, `aegis/schemas/audit_artifact.schema.json`
- Test: `tests/test_stateful_enforcement.py`, `tests/test_stateful_evidence.py`

**Interfaces:**
- Extends: `AEGIS(..., state_provider=None, state_namespace=None, state_retry_horizon_ms=...)`.
- Extends: `AEGIS.enforce_pre_call(invocation, *, state_scope=None)` and async equivalent.
- Produces: internal sync/async `admit_stateful_tool_calls(...) -> tuple[Mapping[str, object], ...]`.
- Preserves: module-level function signatures and stateless behavior.

- [x] **Step 1: Write failing preflight and ordering tests**

Assert missing provider/scope/mode/capability/namespace fail before mutation; stateless denial happens first; repeated tool calls aggregate into one units request; tools execute in constraint-ID order; a later denial leaves the earlier admission consumed; handle issuance happens only after all admissions.

- [x] **Step 2: Verify red, then implement sync dispatch and exact result validation**

Use provider snapshots taken at instance construction, AEGIS-minted operation IDs, descriptor-bound preflight, local monotonic budgets, exact typed allow, bounded retries for typed no-effect results, and exact reconciliation only after an indeterminate dispatch.

- [x] **Step 3: Add async timeout/cancellation and late-result tests, then implement async dispatch**

Use `asyncio.timeout`/`wait_for` semantics without invoking sync providers in threads. A timeout after dispatch is indeterminate; only a validated replay result for the identical operation can reconcile before the trusted horizon.

- [x] **Step 4: Add unsupported-surface tests and reject before caller code**

Instance/module unified APIs raise `STATEFUL_PRECALL_REQUIRED`. Module-level and split decorators fail because they have no trusted binding. Deprecated unified decorators compile/preflight before invoking the wrapped sync or async function.

- [x] **Step 5: Add evidence tests, then reserve and validate `metadata.stateful_decisions`**

PASS and FAIL artifacts include only the bounded record described by the spec. Caller/gate metadata cannot set or shadow it. The finalizer checksum/signature covers it. Existing schema-2.0 artifacts without the field remain valid.

- [x] **Step 6: Run focused integration/evidence tests**

Run: `.venv/bin/python -m pytest tests/test_stateful_enforcement.py tests/test_stateful_evidence.py tests/test_split_enforcement.py tests/test_async_enforcement.py tests/test_decorators.py tests/test_decorators_split_mode.py -q`

---

### Task 5: Governed Sessions and Dynamic Adapter Tool Calls

**Files:**
- Modify: `aegis/_internal/enforcement.py`, `aegis/_internal/session.py`
- Test: `tests/test_stateful_session.py`, `tests/test_governance_session.py`, `tests/test_openai_agents_adapter.py`, `tests/test_openai_agents_adapter_integration.py`

**Interfaces:**
- Extends: `AEGIS.open_session(..., state_scope=None)` and `GovernanceSession` storage of the detached trusted scope.
- Extends: the existing `authorize_step_tool_call(...)` adapter seam to run state admission after adapter allowlist filtering and before local workflow-budget mutation.
- Preserves: static step Phase A and process-affine session token behavior.

- [x] **Step 1: Write failing session-scope/static aggregation tests**

Assert session scope is detached, invocation keys cannot override it, static repeated calls aggregate once, Phase B does not refund admission, and stateful session policies require a sync provider.

- [x] **Step 2: Verify red, then thread the trusted scope through compiled pre-call**

Store the detached scope on session creation and pass it only through private instance boundaries. Carry decisions inside the existing operation record and emitted invocation evidence.

- [x] **Step 3: Write failing dynamic-dispatch tests and implement no-double-charge behavior**

An adapter-mediated enclosing step defers state admission for exposed/proposed tools. Each actual intercepted call is admitted immediately before dispatch, after surface filtering, and then charged to the workflow budget. Static and dynamic paths are mutually exclusive.

- [x] **Step 4: Run session and adapter regressions**

Run: `.venv/bin/python -m pytest tests/test_stateful_session.py tests/test_governance_session.py tests/test_openai_agents_adapter.py tests/test_openai_agents_adapter_integration.py -q`

---

### Task 6: Durable Documentation, ADRs, and Verification Proof

**Files:**
- Create/modify every documentation artifact listed in the File Structure section.
- Test: extend existing documentation/public-boundary/schema snapshot tests where behavior is executable.

**Interfaces:**
- Documents: public API, exact DSL, provider author obligations, trusted scope binding, failure/retry semantics, ownership, in-memory limitations, migration/reversal, and CEL deferral.

- [x] **Step 1: Write failing executable documentation/contract checks where existing suites require them**

Add schema-copy, public-export, reason-code, and maintained-document inventory expectations. Human prose is reviewed rather than grep-tested unless an existing maintained manifest is the executable contract.

- [x] **Step 2: Write ADR-0016 and integration/operations documentation**

State AEGIS/host/provider ownership explicitly, warn that provider descriptor claims are not runtime proof, document pseudonymous tenant identifiers, and provide sync/async/session examples.

- [x] **Step 3: Produce the verification report and then ADR-0017**

ADR-0017 is written only after provider, compiler, restriction, enforcement, hostile-provider, session, and evidence suites have passing recorded commands. It evaluates CEL and keeps implementation outside issue #42.

- [x] **Step 4: Synchronize status, changelog, schemas, and public references**

Do not claim merge, publication, deployment, distributed consistency, or durability.

- [x] **Step 5: Run documentation and contract tests**

Run: `.venv/bin/python -m pytest tests/test_public_api.py tests/test_errors.py tests/test_v090_contract_freeze.py tests/test_doc_parity_v090_truth.py -q`

Run: `.venv/bin/python scripts/check_doc_parity.py`

---

### Task 7: Full Validation, High-Risk Reviews, and Convergence

**Files:**
- Modify: `docs/spec-driven-dev/changes/issue-42-stateful-policy-providers/context.json`
- Modify: `docs/spec-driven-dev/changes/issue-42-stateful-policy-providers/evidence.md`
- Create: lifecycle transition and review records in that directory.

- [x] **Step 1: Run the configured full local gates**

Run: `.venv/bin/python -m pytest`

Run: `.venv/bin/flake8 aegis`

Run: `.venv/bin/python -m build`

- [x] **Step 2: Run acceptance-focused concurrency and conformance evidence again**

Run: `.venv/bin/python -m pytest tests/test_stateful_provider.py tests/test_stateful_conformance.py tests/test_stateful_enforcement.py tests/test_stateful_session.py tests/test_stateful_evidence.py -q`

- [x] **Step 3: Perform distinct correctness, security, test-adequacy, and convergence reviews**

Review the fresh spec, final diff, tests, trust boundaries, provider-controlled hostile objects, timeout/reconciliation paths, numeric and storage bounds, mixed-version rules, public exports, and rollback story. Repair all bug/risk findings within the configured three-cycle limit.

- [x] **Step 4: Re-run exact-candidate gates after every repair**

No completion claim uses stale pre-repair output.

- [x] **Step 5: Map every issue acceptance criterion to current evidence and advance the local feature lifecycle to `COMPLETE`**

Record exact policy/context/change hashes, test counts, review outcomes, implementation limitations, and the fact that remote publication was not performed.

---

## Plan Self-Review

- Every issue criterion maps to Tasks 1–7.
- Every runtime behavior slice starts with a named failing test and explicit red/green command.
- Public type names and Task-to-Task interfaces are consistent with the approved design.
- The plan contains no backend, CEL, arbitrary host-memory, distributed-handle, or production-deployment scope.
- Reversal is additive: remove stateful policies before reverting runtime code; retained provider state is never automatically deleted.
