# AEGIS Architectural Redesign + Execution Roadmap

**Date:** 2026-03-05
**Authors:** Principal Architect Review (Claude Opus)
**SDK Version Under Review:** 0.1.3 (Phase 3 Complete)
**Status:** Proposed
**Audience:** Core maintainers, contributing engineers, security reviewers

---

## 1. North Star Architecture

AEGIS is a deterministic, fail-closed policy enforcement engine for AI and agent invocations that produces tamper-evident audit artifacts
at every invocation boundary, composes hierarchically without privilege escalation, governs both individual calls and multi-step workflows,
and extends via constrained plugin points that cannot weaken enforcement guarantees.

### Architectural Properties

> **Canonical reference:** [`ARCHITECTURAL_INVARIANTS.md`](ARCHITECTURAL_INVARIANTS.md) defines the non-negotiable engineering invariants derived from these properties. Any change to the properties below must be reflected there.

1. **Determinism.** Identical policy + invocation + context = identical enforcement result + identical audit checksum. No randomness, no LLM-in-the-loop for governance decisions.
2. **Fail-closed at every layer.** Policy load failure, precondition failure, schema failure, sink failure — all block execution. No silent degradation.
3. **Tamper-evident audit chain.** Every artifact is signed, checksummed, and optionally hash-chained to its predecessor. Artifacts are schema-versioned with backward-compatible evolution.
4. **Concurrency safety.** No global mutable state. All configuration is instance-scoped. Enforcement is safe to call from multiple threads and async tasks concurrently.
5. **Composable policies with restriction semantics.** Child policies may restrict parent permissions, never silently escalate. Merge semantics are explicit (union, intersect, replace).
6. **Semantic preconditions.** Preconditions validate types, formats, and constraints — not mere key existence. Trivially-satisfiable preconditions are rejected in strict mode.
7. **Ordered evaluation with tool-first constraints.** Tool constraint validation occurs before output validation. A banned tool is caught before any output processing.
8. **Pre-action enforcement boundary proof.** Audit artifacts for enforcement
   failures MUST prove that authorization-relevant gates (tool constraints, role
   validation) were evaluated before output processing gates (schema validation,
   postconditions). The `metadata.gates_evaluated` field records the ordered list
   of gates that ran, providing verifiable evidence that the execution boundary
   was checked before any irreversible action could be approved. This is the
   difference between "we enforced the contract" and "we enforced and can prove
   it happened pre-action." CI enforces this ordering as a regression gate.
9. **Observable.** Every enforcement emits structured metrics (latency, gate,
   result) and optional OpenTelemetry spans. Sink health is monitored.
10. **Extensible without weakening.** Plugins (custom gates, policy loaders,
    sinks) execute within the enforcement boundary. No plugin can suppress a
    governance violation or skip a gate.
11. **Workflow-aware.** `GovernanceSession` tracks cross-invocation state:
    aggregate tool budgets, step sequencing, workflow-level postconditions,
    and correlated audit trails.
12. **Risk-graduated enforcement.** Policies produce a risk score. Configurable
    thresholds determine action: allow, log, review, block.
13. **Minimal dependencies.** Runtime: PyYAML + jsonschema. Optional:
    OpenTelemetry SDK, cryptography. No cloud, ML, or framework coupling.

### What We Stop Doing

1. **Stop accepting key-existence-only preconditions.** All preconditions must declare type constraints. Legacy `required: [key]` syntax enters deprecation with a compatibility shim that treats bare strings as `{type: any, required: true}`.
2. **Stop using module-level global state for sinks/config.** All mutable state moves to an `AEGIS` instance object. Module-level `set_audit_sink()` becomes a deprecated shim over a default instance.
3. **Stop merging policy lists by append-only.** Policy composition gains explicit merge strategies (`union`, `intersect`, `replace`) per field.
4. **Stop evaluating tool constraints after output validation.** Tool constraints move before schema validation in the pipeline.
5. **Stop silently dropping audit artifacts on sink failure.** Sink failures
   either raise (fail-closed) or queue for retry, configurable per deployment.
6. **Stop treating pipeline ordering as an implementation detail.** The
   evaluation order (tool constraints before schema validation) is a
   security-critical invariant, not a code convention. It MUST be enforced
   by a CI regression gate (`ci:pre-action-boundary`) that proves
   authorization-relevant gates fire before output processing gates.
   Audit artifacts record `metadata.gates_evaluated` as ordered evidence.

---

## 2. Architecture Diagnosis (Issue Ledger)

| ID | Issue | Source Doc(s) | Severity | Root Cause | Consequence | Fix Strategy |
|----|-------|---------------|----------|------------|-------------|--------------|
| D-01 | Preconditions validate key existence, not semantics | Both (BR 2.1, DR 5.2) | **CRITICAL** | DSL defines `required` as a list of strings; validator checks `key in context and bool(context[key])` | Integrators bypass governance by passing `{"key": True}`. First real-world integration proved this immediately. | Extend DSL: `required` becomes a dict of `{key: {type, pattern, enum, min_length, ...}}`. Validator uses jsonschema against each value. Bare-string syntax deprecated with shim. |
| D-02 | Global mutable sink registry; not thread-safe; silent failure on emit | Both (BR 2.2, DR 1.3) | **CRITICAL** | Module-level `_registered_sink` variable with no lock. `emit_to_sink` catches all exceptions as warnings. | Race conditions in async/threaded apps. Audit artifacts silently dropped — contradicts fail-closed guarantee. | Move sink to instance-scoped `AEGIS` config object. Add `on_sink_failure` policy: `raise` (default), `queue`, or `log`. Deprecate `set_audit_sink()`. |
| D-03 | No policy caching — full YAML parse + schema validation per invocation | Both (BR 2.3, DR 1.4) | **CRITICAL** | `load_policy()` performs file I/O, YAML parse, and JSON Schema validation on every call. No memoization. | O(n) disk reads per invocation. 100 inv/s against same policy = 300+ file reads/s. Unusable at scale. | LRU cache keyed on `(canonical_path, file_mtime)`. Cache compiled JSON Schema validators. Configurable cache size + TTL. |
| D-04 | Tool constraints validated after output validation | BR 2.4 | **CRITICAL** | Pipeline order: preconditions → schema → postconditions → tools. Historical accident from phased development. | Banned tool call approved if output passes schema. In agentic contexts, the action has already occurred. | Reorder pipeline: preconditions → **tool constraints** → schema → postconditions. Add ADR documenting new order. |
| D-05 | Exception messages leak into audit artifacts unsanitized | BR 2.5 | **CRITICAL** | `str(exc)` placed verbatim in `failures[].message`. No redaction. | PII, API keys, internal paths persisted in audit sinks. Information disclosure in compliance-sensitive environments. | Add `sanitize_failure_message(msg, redaction_patterns)` before audit emission. Default patterns: API key regex, email, SSN. Configurable per deployment. |
| D-06 | Policy composition can only expand permissions, never restrict | Both (BR 2.6, DR 1.1) | **HIGH** | Merge algorithm appends arrays and recursively merges dicts. No intersect or replace semantics. | Child policy extending base inherits all roles/tools and can only add more. Privilege escalation vector in org hierarchies. | Add `merge_strategy` per field: `union` (default for backward compat), `intersect`, `replace`. Roles and tools default to `intersect` in strict mode. |
| D-07 | Guard expression language limited to boolean lookup + equality | Both (BR 2.7, DR 1.2) | **HIGH** | Hardcoded string parser: `if " == " in expr`. No AST, no operators. | Cannot express `(is_enterprise AND audit_required) OR premium_tier`. Enterprise policies are inherently compound. | Replace string parser with a minimal expression evaluator supporting `and`, `or`, `not`, `==`, `!=`, `>`, `<`, `>=`, `<=`, `in`. Parse to AST at policy compile time. |
| D-08 | Binary PASS/FAIL — no risk scoring | Both (BR 2.8, DR 5.3) | **HIGH** | Enforcement returns a single boolean outcome. No graduated assessment. | All violations treated equally. Slightly off-schema response same severity as PII leak. Enterprises reject blunt enforcement. | Add `risk_score` field to audit artifact. Policy DSL gains `risk_weights` per gate. Enforcement modes: `strict` (binary), `risk_scored`, `warn_only`. |
| D-09 | No workflow-level governance primitives | Both (BR 2.9, DR 5.1) | **HIGH** | SDK designed for single invocation boundary. No cross-invocation state. | Agent executing 5 individually-compliant calls can compose policy-violating sequence. Largest architectural gap. | `GovernanceSession` context manager with workflow policy DSL, aggregate tool budgets, step sequencing, workflow audit artifact. |
| D-10 | Async is thread-pool wrapper with no timeout | BR 2.10 | **HIGH** | `asyncio.to_thread(load_policy, ...)` with no `wait_for`. Default thread pool size. | Network filesystem hang blocks thread indefinitely. Thread pool exhaustion under concurrency. | Wrap in `asyncio.wait_for(timeout=...)`. Configurable thread pool. Long-term: native async I/O with `aiofiles`. |
| D-11 | `@governed` decorator extracts args by position | BR 2.11 | **MEDIUM** | `args[0]` = input, `args[1]` = context. No `inspect.signature()`. | Reordered parameters → governance runs against wrong data silently. | Use `inspect.signature()` to bind by name. Define a `GovernedCallable` Protocol. Raise `TypeError` if required params missing. |
| D-12 | Condition resolution silently skips optional conditions | BR 2.12 | **MEDIUM** | Optional conditions without default omitted from resolved dict. Typos produce same error. | Debugging: `GuardEvaluationError` with no hint whether condition is missing vs. misspelled. | Emit `INFO` log for skipped conditions. Add `aegis policy lint` that warns about unreferenced conditions and guards referencing undefined conditions. |
| D-13 | Audit schema allows unbounded `metadata` and `context` | BR 2.13 | **MEDIUM** | Schema defines `metadata` and `context` as `type: object` with no constraints. `failures` has no `maxItems`. | Arbitrary data injection. Multi-megabyte JSONL lines from large failure arrays. | Add `maxProperties` on metadata/context. Add `maxItems: 1000` on failures. Validate JSON serializability at invocation boundary. |
| D-14 | No input validation for JSON serializability | BR 2.14 | **MEDIUM** | `input`, `output`, `context` not checked for serializability until checksum generation. | `datetime`/`Decimal` in invocation → confusing `TypeError` at checksum time, not at validation time. | Validate serializability in `enforce_invocation()` before pipeline entry. Raise `InvocationValidationError` with clear message. |
| D-15 | Deep copy on every guard merge | BR 2.15 | **MEDIUM** | `copy.deepcopy(policy)` called per guard. 10 guards = 10 deep copies. | Measurable performance hit on large policies with many guards. | Compile guards at policy-load time into a frozen effective policy. Single copy, then apply compiled guard effects. |

---

## 3. Design Principles + Decision Log

### ADR-D01: Eliminate Global Mutable State for Sinks and Configuration

**Decision:** Replace module-level `_registered_sink` and all `set_*()` functions with an instance-scoped `AEGIS` configuration object that holds sinks, cache settings, enforcement mode, and telemetry config.

**Context:** The current `set_audit_sink()` modifies a module-level global. This is thread-unsafe, makes testing require `setUp`/`tearDown` gymnastics, and allows silent overwrite. For an SDK targeting async FastAPI and Celery deployments, global mutable state is architecturally untenable.

**Options Considered:**
1. **Thread-safe global with lock.** Add `threading.Lock` around `_registered_sink` access. Keeps the current API.
2. **Instance-scoped `AEGIS` object.** All config (sink, cache, mode) lives on an instance. No module-level mutation.
3. **Context-variable scoped config.** Use `contextvars.ContextVar` to scope config per async task / thread.

**Chosen Option:** Option 2 — Instance-scoped `AEGIS` object.

**Tradeoffs:**
- (+) Eliminates all global mutable state.
- (+) Multiple `AEGIS` instances with different configs (e.g., per-tenant) become trivial.
- (+) Testing: create instance, no global cleanup needed.
- (-) Breaking API change for `set_audit_sink()` callers.

**Implications:** `enforce_invocation()` becomes `aegis_instance.enforce(invocation)`. The module-level `enforce_invocation()` becomes a deprecated shim over a default singleton. Migration: 1-line change per call site.

**Migration Impact:** LOW — shim preserves backward compatibility for 2 releases (deprecation warnings from v0.2.0, removal at v1.0.0).

---

### ADR-D02: Typed Semantic Preconditions

**Decision:** Preconditions must declare type and constraint information. The validator uses JSON Schema to validate each required context value, not just check key existence.

**Context:** The first real-world integration bypassed preconditions by passing `{"role_declared": True}`. The SDK made incorrect usage easier than correct usage. Key-existence checks are governance theater.

**Options Considered:**
1. **Typed preconditions via inline JSON Schema subset.** Each required key declares `{type, pattern, enum, min_length, ...}`. Validator generates a JSON Schema per-key and validates.
2. **Preconditions reference a separate JSON Schema file.** `pre_conditions: {schema: "schemas/context.json"}`. Full JSON Schema power.
3. **Custom validator functions.** Preconditions specify Python callables.

**Chosen Option:** Option 1 — Inline JSON Schema subset.

**Tradeoffs:**
- (+) Self-contained in policy YAML. No external schema files to manage.
- (+) Familiar syntax for anyone who knows JSON Schema.
- (+) Backward-compatible with shim: bare string `session_id` → `{session_id: {type: any}}`.
- (-) Less expressive than full JSON Schema (no `$ref`, no `allOf`).
- (-) Requires policy DSL schema update.

**Implications:** `policy_dsl.schema.json` updated to accept both `required: [str]` (deprecated) and `required: {key: {type, ...}}`. Validator dispatches based on type. Strict mode rejects bare-string syntax.

**Migration Impact:** LOW — backward-compatible shim. Strict mode opt-in initially.

---

### ADR-D03: Policy Compilation and Caching Lifecycle

**Decision:** Introduce a `PolicyCompiler` that produces a frozen `CompiledPolicy` object, cached by `(canonical_path, mtime)` in an LRU cache. Guard expressions are parsed to AST at compile time.

**Context:** Every `enforce_invocation()` call performs: file read, YAML parse, schema validate, and guard string parsing. At 100+ inv/s against the same policy, this is hundreds of redundant I/O and parse operations per second.

**Options Considered:**
1. **LRU cache on `load_policy()` return value.** Cache the dict. Simple, but guards are still parsed per-invocation.
2. **`PolicyCompiler` producing frozen `CompiledPolicy`.** Compile guards to AST, pre-compute effective policies per guard combination, cache compiled JSON Schema validators. Single object cached.
3. **External compilation step (CLI).** `aegis policy compile` produces a binary artifact. Load from binary at runtime.

**Chosen Option:** Option 2 — `PolicyCompiler` with `CompiledPolicy`.

**Tradeoffs:**
- (+) Amortizes all parse/compile work to first load.
- (+) Guard AST enables richer expression language without per-invocation parse cost.
- (+) Compiled JSON Schema validators eliminate repeated `Draft7Validator(schema)` construction.
- (-) Cache invalidation complexity (mtime + optional TTL).
- (-) Memory usage for large cache sizes.

**Implications:** `load_policy()` becomes `PolicyCompiler.compile(path) -> CompiledPolicy`. The compiled policy is immutable (frozen dataclass or `__slots__` object). Cache is instance-scoped on the `AEGIS` object.

**Migration Impact:** LOW — internal change. `enforce_invocation()` still accepts `policy_file` string; compilation is transparent.

---

### ADR-D04: Pipeline Ordering — Tool Constraints Before Output Validation

**Decision:** Reorder the enforcement pipeline so tool constraints are evaluated immediately after preconditions, before output schema validation.

**Context:** Current order: preconditions → schema → postconditions → tools. A banned tool call can pass schema validation, making the tool constraint violation fire after the invocation is already "approved" by schema. In agentic systems, the tool action may have already executed.

**Options Considered:**
1. **Move tools before schema.** New order: preconditions → **tools** → schema → postconditions.
2. **Parallel evaluation of tools and schema.** Evaluate both, fail if either fails. Reduces latency.
3. **Keep current order.** Document as known limitation.

**Chosen Option:** Option 1 — Tools before schema.

**Tradeoffs:**
- (+) Banned tools fail fast, before output is processed.
- (+) Aligns with security principle: deny unauthorized actions before inspecting their results.
- (-) Golden replay fixtures must be updated (different failure order).
- (-) Minor: tool constraint errors no longer show schema validation state.

**Implications:** New pipeline: guard evaluation → role validation → precondition
validation → **tool constraint validation** → output schema validation →
postcondition validation → audit generation. Golden replays updated.

**Pre-action boundary proof:** This reorder is not merely an implementation
detail — it is a security-critical invariant. The enforcement pipeline MUST
record `metadata.gates_evaluated` as an ordered list of gate names that
executed. For FAIL artifacts, this list proves which gates ran before the
failing gate. A CI gate (`ci:pre-action-boundary`) asserts: for any
invocation where both tool constraints and schema validation would fail,
the audit artifact's `failure_gate` is `tool_validation` and
`metadata.gates_evaluated` does not contain `schema_validation`.

**Development rule:** Any PR that modifies `_run_pipeline()` or adds new
gates to the enforcement pipeline MUST update the
`ci:pre-action-boundary` golden replay fixtures and MUST NOT reorder
authorization gates (role, preconditions, tools) after output processing
gates (schema, postconditions). This ordering is enforced by CI, not by
code review alone.

**Supersedes:** This decision supersedes the pipeline ordering established
in ADR-0004 (Phase 3 Production Readiness), which placed tool constraints
after postconditions due to phased development sequencing.

**Migration Impact:** LOW — no public API change. Audit artifacts may show
different `failure_gate` for invocations that would fail both tool and
schema gates (now fails on tool first).

---

### ADR-D05: Audit Schema Versioning and Exception Sanitization

**Decision:** Audit schema version follows semver. Schema changes are backward-compatible within a major version. Exception messages are sanitized before inclusion in audit artifacts via configurable redaction patterns.

**Context:** `str(exc)` is included verbatim in audit `failures[].message`. This can contain PII, API keys, or internal paths. The audit schema has no versioning strategy beyond a string field.

**Options Considered:**
1. **Strip all exception details from audit.** Only include error code and gate. Safe but loses diagnostic value.
2. **Sanitize with configurable regex patterns.** Default patterns for common secrets (API keys, emails, SSNs). Users add domain-specific patterns.
3. **Separate "internal" and "external" failure records.** Internal includes full details (logs only). External is sanitized (audit artifacts).

**Chosen Option:** Option 2 — Sanitize with configurable patterns.

**Tradeoffs:**
- (+) Preserves diagnostic value while removing sensitive data.
- (+) Configurable: enterprises add their own patterns.
- (-) Regex-based sanitization is imperfect (false negatives possible).
- (-) Adds a processing step to the hot path.

**Schema Versioning Strategy:**
- Format: `MAJOR.MINOR` (e.g., `1.1`, `1.2`, `2.0`).
- MINOR bump: additive fields, new enum values. Readers must tolerate unknown fields.
- MAJOR bump: removed fields, changed semantics, structural changes. Requires migration tooling.
- Current: `1.1`. Next: `1.2` (adds `risk_score`, `signature`, `redacted_fields`).

**Migration Impact:** LOW — additive schema change. Existing consumers unaffected.

---

### ADR-D06: Policy Composition with Restriction Semantics

**Decision:** Policy composition gains explicit `merge_strategy` per field. Default for `roles` and `tools.allowed_tools` changes from `union` to `intersect` in strict mode, preventing privilege escalation.

**Context:** Current merge: arrays are appended. A child policy extending a base with `roles: [analyst, admin]` that declares `roles: [analyst]` results in `[analyst, admin, analyst]`. The child has more permissions than intended. This is a privilege escalation vector.

**Options Considered:**
1. **Per-field `merge_strategy` annotation.** Each composable field declares `_merge: intersect|union|replace`.
2. **Global merge mode on the child policy.** `extends_mode: restrict|extend`.
3. **Separate `restrict` block.** Child declares `restrict: {roles: [analyst]}` alongside `extends`.

**Chosen Option:** Option 1 — Per-field `merge_strategy`.

**Tradeoffs:**
- (+) Fine-grained control: restrict roles but extend preconditions.
- (+) Explicit intent in the policy file.
- (-) More complex DSL. More validation rules.
- (-) Default behavior change in strict mode (intersect vs. union) could surprise existing users.

**Implications:** Policy DSL schema gains optional `_merge` key on composable fields. Non-strict mode preserves current union behavior for backward compatibility. Strict mode defaults to intersect for security-sensitive fields.

**Migration Impact:** MEDIUM — behavioral change in strict mode. Non-strict mode unchanged. Migration guide documents how to explicitly set `_merge: union` to preserve old behavior.

---

### ADR-D07: Workflow-Level Governance Primitives

**Decision:** Introduce `GovernanceSession` as a stateful context manager that tracks cross-invocation governance constraints including aggregate tool budgets, step sequencing, and workflow-level postconditions. Produces a workflow-level audit artifact that correlates individual step audits.

**Context:** Every major AI deployment pattern in 2026 involves multi-step workflows. The SDK governs individual invocations but cannot reason about sequences. An agent executing 5 individually-compliant tool calls could compose a policy-violating sequence.

**Options Considered:**
1. **`GovernanceSession` context manager.** Wraps multiple `enforce()` calls. Tracks aggregate state. Produces workflow audit.
2. **Workflow policy compiler.** Define workflow as a DAG in YAML. Compiler generates per-step policies with cross-step constraints injected.
3. **External workflow engine integration.** Provide hooks for LangGraph/CrewAI to call enforcement. No native workflow concept.

**Chosen Option:** Option 1 — `GovernanceSession`.

**Tradeoffs:**
- (+) Minimal API surface: `session.enforce(inv)` instead of `enforce_invocation(inv)`.
- (+) Workflow audit artifact correlates all steps.
- (+) Aggregate constraints (total tool calls, step budget) are enforceable.
- (-) Introduces state into a previously stateless system.
- (-) Session lifecycle management (timeout, cleanup) adds complexity.

**Implications:** New `aegis.session` module. Workflow policy DSL extension in `policy_dsl.schema.json`. Audit schema `1.3` adds `workflow_id`, `step_index`, `parent_audit_id`. `GovernanceSession` is instance-scoped (no global state).

**Migration Impact:** NONE — additive capability. Existing single-invocation usage unchanged.

---

### ADR-D08: Risk Scoring and Graduated Enforcement

**Decision:** Policies declare `risk_weights` per enforcement gate. Enforcement computes a `risk_score` (0.0–1.0). Configurable thresholds determine action: allow, log-and-allow, require-review, block.

**Context:** Binary PASS/FAIL forces all violations into exception-raising. A slightly off-schema response is treated identically to a banned tool call. Enterprises need graduated response.

**Options Considered:**
1. **Risk scoring in enforcement pipeline.** Each gate contributes a weighted score. Thresholds configurable.
2. **Risk scoring as a post-enforcement plugin.** Enforcement remains binary; a separate scoring pass runs after.
3. **Multiple enforcement modes without scoring.** `strict`, `warn`, `permissive` modes. No numerical score.

**Chosen Option:** Option 1 — Risk scoring in enforcement pipeline.

**Tradeoffs:**
- (+) Single pass: enforcement and scoring in one pipeline run.
- (+) Risk score in audit artifact enables analytics and trending.
- (+) Thresholds are policy-driven, not code-driven.
- (-) Score semantics must be well-defined to avoid "magic number" confusion.
- (-) `warn_only` mode technically violates fail-closed principle — must be explicitly opted into with audit trail.

**Implications:** Audit artifact gains `risk_score: float` and `enforcement_mode: strict|risk_scored|warn_only`. In `warn_only` mode, violations are logged but not raised. Audit artifact clearly marks `enforcement_result: "WARN"` (new enum value). `strict` mode preserves current binary behavior.

**Migration Impact:** LOW — `strict` is the default. New modes are opt-in.

---

### ADR-D09: Observability Hooks and Metrics Interface

**Decision:** Add an `ObservabilityProvider` interface with a default no-op implementation and an optional OpenTelemetry implementation. Enforcement emits spans and counters at each gate.

**Context:** The SDK logs via Python `logging` with `NullHandler`. No metrics, no tracing, no structured telemetry. Production deployments are blind to enforcement latency, pass/fail rates, and sink health.

**Options Considered:**
1. **OpenTelemetry-native.** Require `opentelemetry-api` as optional dependency. Emit spans + metrics directly.
2. **Abstract `ObservabilityProvider`.** Define interface; provide OTel implementation as optional extra.
3. **Callback hooks only.** `on_enforcement_start`, `on_enforcement_end`, `on_gate_pass`, `on_gate_fail`.

**Chosen Option:** Option 2 — Abstract provider with OTel implementation.

**Tradeoffs:**
- (+) No forced dependency on OTel.
- (+) Users can implement for Datadog, Prometheus, custom systems.
- (-) One more abstraction to maintain.
- (-) Without the OTel implementation, users must write their own.

**Implications:** `ObservabilityProvider` in `aegis.observability`. Default: `NullObservabilityProvider`.
Optional extra: `pip install aegis[opentelemetry]`. Emits: `aegis.enforcement.duration` histogram,
`aegis.enforcement.result` counter (labels: policy, role, result, gate), `aegis.enforcement.gate.duration` per gate.

**Migration Impact:** NONE — additive. No existing behavior changes.

---

### ADR-D10: Plugin System Without Weakening Enforcement

**Decision:** Introduce `EnforcementGate` as an abstract interface for custom validation gates. Custom gates are registered on the
`AEGIS` instance and execute within the pipeline at designated extension points (pre-schema, post-schema). Custom gates may FAIL
enforcement but may NOT suppress failures from core gates.

**Context:** The SDK needs extensibility (content safety, PII detection, custom validators) but cannot allow plugins to bypass governance. The enforcement pipeline must remain a closed system where every gate's veto is final.

**Options Considered:**
1. **Middleware chain.** Pre/post hooks around the full pipeline. Middleware can modify invocation and audit artifact.
2. **Custom `EnforcementGate` in pipeline.** Gates run at fixed extension points. Can only add failures, not remove them.
3. **Event-based hooks.** Emit events at each gate. Listeners can observe but not modify.

**Chosen Option:** Option 2 — Custom `EnforcementGate` with constrained insertion.

**Tradeoffs:**
- (+) Custom gates participate in enforcement: their failures are real governance failures.
- (+) Cannot suppress core gate failures (append-only failure list).
- (+) Gates produce structured audit metadata like core gates.
- (-) Fixed extension points limit where gates can run.
- (-) Gate ordering between custom gates needs definition.

**Implications:** Two extension points: `ExtensionPoint.PRE_SCHEMA` (after preconditions, before output schema) and
`ExtensionPoint.POST_SCHEMA` (after schema, before postconditions). Custom gates receive
`(invocation, effective_policy, accumulated_failures)` and return `GateResult(passed, failures, metadata)`.
Accumulated failures are append-only; gates cannot clear them.

**Migration Impact:** NONE — additive capability.

---

### Existing ADR Cross-Reference

The following ADRs in `docs/decisions/` were reviewed for alignment with this
roadmap. All are incorporated; partial supersessions are noted.

| ADR | Title | Status vs. Roadmap |
| --- | ----- | ------------------ |
| ADR-0001 | Phase 1 Failure Audit Emission | **Aligned.** Foundational — the roadmap assumes FAIL audit artifacts are always emitted. No changes needed. |
| ADR-0002 | Relaxed setuptools Requirement | **Aligned.** Operational packaging decision outside architectural scope. |
| ADR-0003 | Phase 2 Error Taxonomy Additions | **Aligned.** The three typed exceptions (`ConditionResolutionError`, `GuardEvaluationError`, `ToolConstraintViolationError`) are assumed throughout the target pipeline and `failure_gate` enum. |
| ADR-0004 | Phase 3 Production Readiness | **Partially superseded.** Sink design (module-global `set_audit_sink()` with silent failure) is superseded by ADR-D01 (instance-scoped AEGIS, fail-closed sinks). Decorator positional arg extraction is superseded by D-11 (`inspect.signature()` binding). Pipeline ordering (tools after postconditions) is superseded by ADR-D04 (tools before schema). Async enforcement and structured logging decisions remain valid. |
| ADR-0005 | Absolute Policy Path Support | **Aligned.** The `PolicyCompiler` still accepts path strings; absolute path support remains valid. |
| ADR-0006 | Audit Artifact Context Inclusion | **Aligned.** The target audit artifact includes `context` as a required top-level field. D-13 adds `maxProperties` bounds on context, building on this decision. |
| ADR-0007 | Pre-Action Enforcement Boundary Proof | **New.** Formalizes `metadata.gates_evaluated`, `ci:pre-action-boundary` CI gate, and pipeline ordering development rule. Implements Architectural Property #8 and "What We Stop Doing" #6. Proves enforcement happened pre-action, not just that enforcement happened. |
| ADR-0008 | Governance Artifact Chain | **New.** Formalizes optional hash-chain linking (`previous_audit_checksum`, `chain_index`, `chain_id`) for tamper-evident audit sequences. Implements the signing/chaining aspects of ADR-D05 as a standalone decision with its own verification function. Scheduled for v0.3.0. |

---

## 4. Proposed Target Architecture

### 4.1 Current High-Level Flow (as-is)

```
Caller
  │
  ▼
enforce_invocation(invocation: dict)          ← module-level function
  │
  ├─ load_policy(policy_file)                 ← YAML read + parse + validate (every call)
  │    └─ resolve extends (recursive)
  │
  ├─ evaluate_guards(policy, context)         ← string-parsed conditions
  │    └─ resolve_conditions()
  │    └─ merge guard effects (deep copy per guard)
  │
  ├─ validate_role(role, effective_policy)
  │
  ├─ validate_preconditions(context, policy)  ← key-existence check only
  │
  ├─ validate_schema(output, schema)          ← JSON Schema Draft-07
  │
  ├─ validate_postconditions(policy)
  │
  ├─ validate_tool_constraints(invocation, policy)  ← AFTER schema (wrong order)
  │
  ├─ generate_audit_artifact(...)             ← PASS artifact
  │    └─ canonical_json_bytes → SHA-256
  │
  └─ emit_to_sink(artifact)                   ← global _registered_sink (silent fail)
       │
       ▼
  return audit_artifact
```

### 4.2 Target High-Level Flow

> **Canonical reference:** [`ENFORCEMENT_PIPELINE.md`](ENFORCEMENT_PIPELINE.md) documents the current enforcement pipeline stages and extension points. The flow below describes the target architecture; the standalone doc reflects the shipping implementation.

```
Caller
  │
  ▼
aegis = AEGIS(sink=..., cache_size=..., mode=..., observability=...)   ← instance-scoped config
  │
  ▼
aegis.enforce(invocation)                      ← instance method
  │
  ├─ [OBSERVE] span: aegis.enforcement
  │
  ├─ validate_invocation_shape(invocation)    ← JSON serializability + required fields
  │
  ├─ policy = PolicyCache.get_or_compile(path)
  │    └─ PolicyCompiler.compile(path)
  │         ├─ YAML read + parse
  │         ├─ resolve extends (recursive, with restriction merge)
  │         ├─ validate against policy_dsl.schema.json
  │         ├─ compile guard expressions to AST
  │         └─ compile JSON Schema validators
  │         └─ return CompiledPolicy (frozen)
  │
  ├─ effective = evaluate_guards(compiled_policy, context)  ← AST-evaluated conditions
  │
  ├─ validate_role(role, effective)
  │
  ├─ validate_preconditions(context, effective)  ← TYPED: validates value types/formats
  │
  ├─ validate_tool_constraints(invocation, effective)  ← BEFORE schema (correct order)
  │
  ├─ [EXTENSION POINT: PRE_SCHEMA] custom gates
  │
  ├─ validate_schema(output, compiled_schema_validator)
  │
  ├─ [EXTENSION POINT: POST_SCHEMA] custom gates
  │
  ├─ validate_postconditions(effective)
  │
  ├─ compute_risk_score(gate_results, risk_weights)
  │
  ├─ apply_enforcement_mode(risk_score, thresholds)
  │    ├─ strict: binary PASS/FAIL
  │    ├─ risk_scored: threshold-based
  │    └─ warn_only: log + WARN result
  │
  ├─ artifact = generate_audit_artifact(...)
  │    ├─ record metadata.gates_evaluated[]    ← ordered gate execution proof
  │    ├─ sanitize_failure_messages(redaction_patterns)
  │    ├─ canonical_json_bytes → SHA-256
  │    ├─ sign_artifact(signer)                 ← optional HMAC/asymmetric
  │    └─ chain_artifact(previous_hash)         ← optional hash chain
  │
  ├─ emit_to_sink(artifact)                     ← instance-scoped sink, fail-closed
  │    └─ on failure: raise | queue | log (configurable)
  │
  ├─ [OBSERVE] metrics: aegis.enforcement.result, aegis.enforcement.duration
  │
  └─ return audit_artifact
```

### 4.3 Target Internal Layering

```
┌─────────────────────────────────────────────────────────────┐
│                     PUBLIC API (stable)                       │
│                                                               │
│  AEGIS(config)           ← configuration + enforcement entry   │
│  .enforce(inv)          ← sync enforcement                    │
│  .enforce_async(inv)    ← async enforcement                   │
│  .session(workflow_policy) → GovernanceSession                │
│  Invocation.builder()   ← builder pattern                     │
│  AuditSink (ABC)        ← sink interface                      │
│  EnforcementGate (ABC)  ← custom gate interface               │
│  PolicyLoader (ABC)     ← custom loader interface             │
│  ObservabilityProvider  ← telemetry interface                 │
│  Exception hierarchy    ← typed errors                        │
│  CompiledPolicy         ← frozen policy object (read-only)    │
├───────────────────────────────────────────────────────────────┤
│                   INTERNAL INTERFACES                         │
│                                                               │
│  PolicyCompiler         ← YAML → CompiledPolicy               │
│  PolicyCache            ← LRU cache with mtime invalidation   │
│  GuardEvaluator         ← AST-based condition evaluation      │
│  PreconditionValidator  ← typed value validation              │
│  ToolConstraintEngine   ← ordered tool checking               │
│  RiskScorer             ← gate weights → score                │
│  AuditArtifactBuilder   ← gate ordering proof + signing       │
│  FailureSanitizer       ← regex-based message redaction       │
├───────────────────────────────────────────────────────────────┤
│                   EXTENSION POINTS                            │
│                                                               │
│  EnforcementGate        ← PRE_SCHEMA, POST_SCHEMA             │
│    ✓ MAY: add failures, add metadata, read invocation         │
│    ✗ MAY NOT: suppress failures, skip gates, modify invoc.    │
│                                                               │
│  PolicyLoader           ← filesystem, remote, in-memory       │
│    ✓ MAY: resolve policy_ref to dict from any source          │
│    ✗ MAY NOT: return invalid policy (schema-validated after)   │
│                                                               │
│  AuditSink              ← JSONL, DB, SIEM, callback           │
│    ✓ MAY: persist artifact to any backend                     │
│    ✗ MAY NOT: modify artifact, suppress emission              │
│                                                               │
│  ObservabilityProvider   ← OTel, Datadog, custom              │
│    ✓ MAY: emit spans, metrics, logs                           │
│    ✗ MAY NOT: affect enforcement outcome                      │
│                                                               │
│  AuditSigner            ← HMAC, RSA, custom                   │
│    ✓ MAY: sign artifact bytes                                 │
│    ✗ MAY NOT: modify artifact content                         │
└───────────────────────────────────────────────────────────────┘
```

---

## 5. Concrete Technical Spec

### 5.1 New/Changed Abstractions

#### `AEGIS` (Configuration + Entry Point)

- **Responsibilities:** Hold instance-scoped configuration. Provide `enforce()` and `enforce_async()` methods. Own the `PolicyCache`, sink, signer, and observability provider.
- **Inputs:** `AEGISConfig` (sink, cache_size, cache_ttl, enforcement_mode, strict_mode, redaction_patterns, signer, observability_provider, custom_gates, policy_loader, thread_pool_size).
- **Outputs:** `enforce(invocation) -> AuditArtifact dict`.
- **Determinism:** Deterministic given identical config + invocation. Config is immutable after construction.
- **Thread safety:** All methods are thread-safe. No mutable instance state after `__init__`. Cache uses `threading.Lock`.
- **Failure modes:** Config validation errors raise `ValueError` at construction time (fail fast). `enforce()` preserves existing fail-closed semantics.

#### `PolicyCompiler` / `CompiledPolicy`

- **Responsibilities:** Parse YAML, resolve `extends` with merge strategies, validate against schema, compile guard expressions to AST, compile JSON Schema validators.
- **Inputs:** `policy_file: str` (path or policy_ref), `PolicyLoader` instance.
- **Outputs:** `CompiledPolicy` (frozen dataclass).
- **Determinism:** Same policy file + same content → same `CompiledPolicy`.
- **Thread safety:** `compile()` is pure (no mutation). `CompiledPolicy` is frozen.
- **Failure modes:** `PolicyLoadError` (file not found, YAML parse), `PolicyValidationError` (schema validation), `PolicyCompositionError` (cycle, invalid merge strategy).

#### `PolicyCache`

- **Responsibilities:** LRU cache of `CompiledPolicy` objects, keyed by `(canonical_path, file_mtime)`.
- **Inputs:** `path: str`, `cache_size: int`, `cache_ttl: Optional[int]`.
- **Outputs:** `CompiledPolicy`.
- **Determinism:** Cache hit returns same object. Cache miss compiles and stores.
- **Thread safety:** `threading.Lock` around cache access. Compilation outside lock.
- **Failure modes:** Cache miss delegates to `PolicyCompiler` (same failure modes). Stale mtime triggers recompile.

#### `InvocationContext` (Validation)

- **Responsibilities:** Validate invocation dict shape, JSON serializability, and required fields at pipeline entry.
- **Inputs:** `invocation: Mapping`.
- **Outputs:** Validated invocation (unchanged if valid).
- **Determinism:** Pure validation.
- **Thread safety:** Stateless.
- **Failure modes:** `InvocationValidationError` with specific field diagnostics.

#### `AuditArtifactBuilder`

- **Responsibilities:** Construct audit artifact, record ordered gate execution
  list (`metadata.gates_evaluated`), sanitize failure messages, compute
  checksums, sign artifact, chain to previous artifact.
- **Inputs:** Invocation, policy, gate results (ordered), risk score, signer,
  previous hash.
- **Outputs:** Complete audit artifact dict with `metadata.gates_evaluated`
  proving execution order.
- **Determinism:** Deterministic except for `timestamp` (frozen in tests).
- **Thread safety:** Stateless builder. Signer is thread-safe.
- **Failure modes:** Serialization failure → `InvocationValidationError` (fail-closed, artifact still emitted as FAIL).

#### `SinkRegistry` (Instance-Scoped)

- **Responsibilities:** Emit audit artifacts to configured sink with configurable failure behavior.
- **Inputs:** `AuditSink` instance, `on_failure: "raise" | "queue" | "log"`.
- **Outputs:** None (side effect: persist artifact).
- **Determinism:** Emission is a side effect (not deterministic), but the decision to emit is deterministic.
- **Thread safety:** Sink's `emit()` is called under a lock if `on_failure="queue"`. User-provided sinks must document their thread safety.
- **Failure modes:** `raise`: `AuditSinkError` propagates. `queue`: failed artifacts queued for retry. `log`: current behavior (WARNING log).

#### `ToolConstraintEngine`

- **Responsibilities:** Validate tool calls against policy allowlists and max_calls. Execute before schema validation.
- **Inputs:** `invocation["tool_calls"]`, `effective_policy["tools"]`.
- **Outputs:** `ToolConstraintResult(tools_checked, violations)`.
- **Determinism:** Pure function.
- **Thread safety:** Stateless.
- **Failure modes:** `ToolConstraintViolationError` on first violation (unchanged).

#### `GuardEvaluator` (AST-Based)

- **Responsibilities:** Evaluate guard conditions using pre-compiled AST. Support `and`, `or`, `not`, comparison operators, `in` operator.
- **Inputs:** `CompiledPolicy.guard_asts`, `resolved_conditions`, `invocation`.
- **Outputs:** `(effective_policy, guards_evaluated, conditions_resolved)`.
- **Determinism:** Pure function on compiled AST + resolved conditions.
- **Thread safety:** Stateless.
- **Failure modes:** `GuardEvaluationError` for type mismatches in evaluation. Compile-time errors caught by `PolicyCompiler`.

### 5.2 Public API Changes

#### New APIs

| API | Purpose |
|-----|---------|
| `AEGIS(config)` | Instance-scoped configuration + enforcement |
| `aegis.enforce(invocation) -> dict` | Instance-level sync enforcement |
| `aegis.enforce_async(invocation) -> dict` | Instance-level async enforcement |
| `aegis.session(workflow_policy) -> GovernanceSession` | Workflow governance (M3) |
| `Invocation.builder()` | Builder pattern for invocation construction |
| `EnforcementGate` (ABC) | Custom gate plugin interface |
| `PolicyLoader` (ABC) | Custom policy loader interface |
| `ObservabilityProvider` (ABC) | Telemetry interface |
| `AuditSigner` (ABC) | Artifact signing interface |
| `HMACSigner` | HMAC-SHA256 signer implementation |

#### Deprecated APIs (removed at v1.0.0)

| API | Replacement | Migration |
|-----|-------------|-----------|
| `set_audit_sink(sink)` | `AEGIS(sink=sink)` | 1-line change |
| `get_audit_sink()` | `aegis_instance.sink` | Property access |
| `enforce_invocation(inv)` | `aegis_instance.enforce(inv)` | 1-line change |
| `enforce_invocation_async(inv)` | `aegis_instance.enforce_async(inv)` | 1-line change |
| `pre_conditions.required: [str, ...]` | `pre_conditions.required: {key: {type: ...}}` | YAML update |

#### Backward-Compatible Shims

```python
# Module-level shim (deprecated)
_default_instance: AEGIS | None = None

def enforce_invocation(invocation):
    warnings.warn("Use AEGIS(...).enforce() instead", DeprecationWarning, stacklevel=2)
    global _default_instance
    if _default_instance is None:
        _default_instance = AEGIS()
    return _default_instance.enforce(invocation)

def set_audit_sink(sink):
    warnings.warn("Use AEGIS(sink=sink) instead", DeprecationWarning, stacklevel=2)
    global _default_instance
    if _default_instance is None:
        _default_instance = AEGIS(sink=sink)
    else:
        _default_instance = AEGIS(sink=sink, **_default_instance._config_snapshot())
```

#### Breaking Changes

None in the 4-week window. Deprecations in v0.2.0. Removals in v1.0.0 (6+ months).

### 5.3 Audit Schema Versioning

**Schema Version Strategy:**
- Format: `MAJOR.MINOR` (semver without patch).
- Current: `1.1`.
- Next planned bumps: `1.2` (risk_score, signature, redacted_fields), `1.3` (workflow_id, step_index, parent_audit_id).

**Backward Compatibility Rules:**
- MINOR bumps: additive only (new fields, new enum values). Consumers MUST tolerate unknown fields.
- MAJOR bumps: structural changes, field removal, semantic changes. Require migration tooling and at least 1 release of deprecation warning.
- All fields added in MINOR bumps MUST have defaults or be nullable.

**Redaction/Sanitization Rules:**
- `failures[].message` is passed through `FailureSanitizer` before inclusion.
- Default patterns: API key formats (`sk-...`, `key-...`, Bearer tokens), email addresses, credit card numbers, SSN patterns.
- Custom patterns configurable via `AEGIS(redaction_patterns=[...])`.
- Redacted values replaced with `[REDACTED:<pattern_name>]`.
- Audit artifact gains `redacted_fields: [str]` listing which fields were sanitized.

**Signer/Verifier Interface:**

```python
class AuditSigner(ABC):
    @abstractmethod
    def sign(self, artifact_bytes: bytes) -> str:
        """Return signature string (e.g., 'hmac-sha256:abc123...')."""

    @abstractmethod
    def key_id(self) -> str:
        """Return identifier for the signing key."""

class AuditVerifier(ABC):
    @abstractmethod
    def verify(self, artifact_bytes: bytes, signature: str) -> bool:
        """Return True if signature is valid."""
```

Audit artifact gains:
```json
{
  "signature": "hmac-sha256:abc123...",
  "signer_key_id": "prod-2026",
  "previous_audit_checksum": "sha256:def456..."
}
```

---

## 6. Prioritized Execution Roadmap

### 6.1 Next 2–4 Weeks (Immediate Development)

| # | Deliverable | Why Top Priority | Dependencies | Risk | Estimate | Acceptance Criteria | Tests Required | Docs to Update |
|---|-------------|-----------------|--------------|------|----------|-------------------|----------------|----------------|
| 1 | **`AEGIS` config object with instance-scoped sink** | Eliminates global mutable state (D-02). Foundation for all other changes. | None | Low | M | `AEGIS(sink=JsonFileAuditSink(...)).enforce(inv)` works. No module-level `_registered_sink` mutation. Thread-safety test with 10 concurrent enforcements. | Unit: config validation. Integration: multi-thread enforcement. Golden replay: updated fixtures. | PROJECT.md, README.md |
| 2 | **Backward-compat shims for `enforce_invocation` + `set_audit_sink`** | Prevents breaking existing users while #1 ships. | #1 | Low | S | `enforce_invocation(inv)` emits `DeprecationWarning` and delegates to default `AEGIS` instance. Existing tests pass unchanged. | Unit: shim delegation. Unit: deprecation warning emitted. | Migration guide (new doc) |
| 3 | **Typed precondition validation** | Fixes D-01 (CRITICAL). Core governance gap. | None | Med | M | `required: {session_id: {type: string, pattern: "^[a-f0-9-]{36}$"}}` validated. `{"session_id": True}` fails with `PreconditionError`. Bare-string `required: [key]` still works (deprecated). | Unit: typed validation per type (string, int, bool, enum, pattern). Unit: backward-compat shim. Golden replay: new precondition fixtures. | Policy DSL spec, `policy_dsl.schema.json` |
| 4 | **Pipeline reorder: tools before schema + pre-action boundary proof** | Fixes D-04 (CRITICAL). Security-critical ordering. Establishes pre-action enforcement boundary as a provable invariant. | None | Low | S | Tool constraint violations fire before schema validation. Audit artifact `failure_gate` is `tool_validation` when both would fail. `metadata.gates_evaluated` records ordered gate list as execution proof. CI gate `ci:pre-action-boundary` enforces ordering as regression test. | Golden replay: updated failure-order fixtures. Unit: pipeline order verification. Unit: `gates_evaluated` ordering assertion. | ADR-D04 (this doc), enforcement docs, CLAUDE.md |
| 5 | **Exception message sanitization in audit artifacts** | Fixes D-05 (CRITICAL). Information disclosure. | None | Low | S | Default redaction patterns strip API key formats, emails, SSNs from `failures[].message`. `redacted_fields` added to audit artifact. | Unit: each default pattern. Unit: custom patterns. Integration: end-to-end with sensitive exception. | Audit schema (v1.2 additive), security docs |
| 6 | **Policy caching with LRU + mtime invalidation** | Fixes D-03 (CRITICAL). Performance blocker. | #1 (cache lives on AEGIS instance) | Med | M | Second `enforce()` with same policy skips file I/O. Modified file triggers recompile. Configurable `cache_size`. | Unit: cache hit/miss. Unit: mtime invalidation. Benchmark: 100 enforcements, <10ms after first. | Configuration docs |
| 7 | **Sink failure mode configuration** | Completes D-02 fix. Fail-closed at persistence layer. | #1 | Low | S | `AEGIS(sink=..., on_sink_failure="raise")` propagates `AuditSinkError`. Default: `"raise"`. `"log"` preserves current behavior. | Unit: each failure mode. Integration: sink that throws. | Configuration docs |
| 8 | **Invocation shape validation (JSON serializability)** | Fixes D-14. Clear errors at boundary. | None | Low | S | `datetime` in `context` → `InvocationValidationError("Field 'context.timestamp' is not JSON-serializable")` at enforce entry, not at checksum time. | Unit: each non-serializable type. Unit: nested non-serializable. | Error reference docs |
| 9 | **Audit schema bounds (`maxItems`, `maxProperties`)** | Fixes D-13. Prevents resource exhaustion. | None | Low | S | `failures` array capped at 1000. `metadata`/`context` capped at 100 keys. Exceeding raises `InvocationValidationError`. | Unit: boundary values. Unit: over-limit rejection. | Audit schema update |
| 10 | **`Invocation.builder()` pattern** | DX improvement from both docs. Reduces boilerplate. | None | Low | S | Builder validates at `.build()` time. Missing required field → `ValueError`. Type hints for IDE support. | Unit: builder validation. Unit: missing field errors. | Quickstart guide, README |
| 11 | **Decorator fix: `inspect.signature()` binding** | Fixes D-11. Silent wrong-data extraction. | None | Low | S | Decorator binds by parameter name, not position. Reordered params work correctly. Missing `input_data` → `TypeError`. | Unit: reordered params. Unit: keyword args. Unit: missing params. | Decorator docs |
| 12 | **Strict mode for minimum viable policy** | Prevents governance theater. DX from integration feedback. | #3 (typed preconditions) | Low | S | `AEGIS(strict_mode=True)` rejects policies without roles, without preconditions, with bare-string preconditions. Warning in non-strict mode. | Unit: each rejection case. Unit: warning in non-strict. | Configuration docs, policy authoring guide |
| 13 | **Internal import deprecation warnings** | Protects public/private boundary. | None | Low | S | `from aegis.enforcement import enforce_invocation` emits `DeprecationWarning`. `from aegis import enforce_invocation` does not. | Unit: warning on internal import. Unit: no warning on public import. | Migration guide |

### 6.2 Milestone 1: v0.2.0 (0–3 months)

**Capabilities Shipped:**
- Instance-scoped `AEGIS` configuration (no global state)
- Typed precondition validation with backward-compatible shim
- Correct pipeline ordering (tools before schema)
- Exception sanitization in audit artifacts
- Policy caching with LRU + mtime invalidation
- Invocation builder pattern
- Fixed decorator with signature inspection
- Strict mode for minimum viable policies
- Deprecation warnings on internal imports and legacy APIs
- Enhanced guard expression language (AST-based: `and`, `or`, `not`, comparisons)
- Policy CLI: `aegis policy lint`, `aegis policy validate`
- Audit schema v1.2 (risk_score placeholder, redacted_fields, signature placeholder)

**Target Metrics:**
- DX: Time from `pip install aegis` to first governed invocation < 5 minutes (with quickstart).
- Performance: Cached policy enforcement < 1ms for simple policies (benchmark suite).
- Correctness: 100% golden replay pass rate. Zero precondition bypass in test suite.
- Coverage: >= 90% line coverage maintained.

**Release Notes Outline:**
- BREAKING (managed): `set_audit_sink()` and `enforce_invocation()` deprecated (shims provided).
- SECURITY: Exception messages sanitized in audit artifacts. Preconditions now validate value types.
- PERFORMANCE: Policy caching eliminates redundant I/O. 50-100x speedup for repeated policy enforcement.
- DX: Builder pattern, strict mode, enhanced guards, CLI tools.

### 6.3 Milestone 2: v0.3.0 (3–6 months)

**Capabilities Shipped:**
- Risk scoring engine with `strict`, `risk_scored`, `warn_only` enforcement modes
- Audit artifact signing (HMAC-SHA256 with pluggable `AuditSigner`)
- Policy composition with restriction semantics (`_merge: intersect|union|replace`)
- Pluggable `PolicyLoader` interface (filesystem, remote registry, in-memory)
- Policy versioning with `effective_date` / `expiration_date`
- OpenTelemetry integration (`pip install aegis[opentelemetry]`)
- Policy testing framework (`aegis.testing.PolicyTestCase`)
- Tamper-evident audit chain (hash linking)
- Compliance export CLI (`aegis audit export --format csv`)
- Custom `EnforcementGate` plugin interface

**Target Metrics:**
- DX: Policy test suite runs in < 2 seconds for 50 test cases.
- Performance: Risk scoring adds < 0.1ms to enforcement latency.
- Correctness: Risk score determinism verified via golden replays. Signing verified via round-trip.
- Security: Policy composition cannot escalate privileges (verified by adversarial test suite).

**Release Notes Outline:**
- GOVERNANCE: Risk scoring enables graduated enforcement. Policy composition now supports restriction.
- COMPLIANCE: Audit artifact signing for SOC 2 / ISO 27001. Tamper-evident chaining. Export for regulatory submission.
- EXTENSIBILITY: Custom enforcement gates, custom policy loaders.
- OBSERVABILITY: OpenTelemetry spans and metrics.

### 6.4 Milestone 3: v1.0.0 (6–12 months)

**Capabilities Shipped:**
- `GovernanceSession` for multi-step workflow governance
- Workflow policy DSL (step sequencing, aggregate tool budgets, workflow postconditions)
- Workflow-level audit artifacts with step correlation
- Human-in-the-loop escalation policies
- Agent identity and capability manifests
- Distributed audit correlation (`trace_id`, `span_id`, `parent_audit_id`)
- Audit retention policy configuration
- Removal of all deprecated APIs (clean v1.0 surface)
- Native async I/O (aiofiles) replacing thread-pool wrapper
- Pre-built policy templates (content moderation, RAG, agent workflow, PII, model routing)
- Policy template registry CLI (`aegis policy template list/apply`)

**Target Metrics:**
- DX: Multi-step agent governed end-to-end in < 30 lines of user code.
- Performance: Workflow governance overhead < 5% vs. sum of individual enforcements.
- Correctness: 5-step agent workflow golden replay passes deterministically.
- Compliance: Mock SOC 2 audit passes using only AEGIS audit artifacts as evidence.

**Release Notes Outline:**
- v1.0 STABLE API: All deprecated shims removed. Public API frozen for semantic versioning.
- AGENTIC: Workflow governance, agent identity, escalation policies.
- COMPLIANCE: Distributed audit correlation, retention policies, regulatory-ready.
- ASYNC: Native async I/O, configurable timeouts, thread pool configuration.

---

## 7. "Stop-Ship" Release Gates

> **Canonical reference:** [`RELEASE_GATES.md`](../releases/RELEASE_GATES.md) is the standalone release gate specification. The tables below provide roadmap-specific context; the standalone doc is the authoritative gate list for CI enforcement.

These gates must pass before each milestone release. CI enforces them.

### v0.2.0 Gates

| Gate | Verification Method |
|------|-------------------|
| Determinism guarantee | Golden replay suite passes. Same invocation → same checksum across 1000 runs. |
| Concurrency safety | 50-thread concurrent enforcement test with instance-scoped `AEGIS`. No races, no shared state corruption. |
| Precondition bypass impossible | Adversarial test: `{"key": True}`, `{"key": ""}`, `{"key": 0}`, `{"key": None}` all fail typed preconditions. |
| Pipeline ordering correct | Tool constraint violation fires before schema validation when both would fail (golden replay). |
| Pre-action boundary proof | `metadata.gates_evaluated` records ordered gate list. For dual tool+schema failures, `failure_gate` is `tool_validation` and `schema_validation` never appears in `gates_evaluated`. CI gate: `ci:pre-action-boundary`. |
| Exception sanitization | No API key pattern, email, or SSN survives in `failures[].message` (regex scan of all test audit artifacts). |
| Backward compatibility | All v0.1.3 test cases pass against v0.2.0 with deprecation warnings only (no errors). |
| Audit artifact schema valid | All emitted artifacts validate against `audit_artifact.schema.json` v1.2. |
| Doc completeness | README quickstart works end-to-end. Migration guide covers all deprecated APIs. Policy DSL spec updated. |
| Examples tested | All `examples/` scripts run without error. |
| Coverage >= 90% | `pytest --cov-fail-under=90` passes. |

### v0.3.0 Gates (additional)

| Gate | Verification Method |
|------|-------------------|
| Risk score determinism | Same invocation → same risk score across 1000 runs (golden replay). |
| Signature round-trip | Sign artifact → verify artifact succeeds. Tampered artifact → verify fails. |
| Policy restriction correctness | Child policy with `_merge: intersect` on roles: resulting roles are subset of base. Adversarial test with 100 policy compositions. |
| No privilege escalation | Fuzzer: random child policy cannot grant roles/tools not in base policy. |
| Custom gate isolation | Custom gate that throws does not suppress core gate failures. Custom gate cannot clear accumulated failures. |

### v1.0.0 Gates (additional)

| Gate | Verification Method |
|------|-------------------|
| Workflow governance end-to-end | 5-step agent workflow with aggregate tool budget, step sequencing, and workflow postcondition. Golden replay. |
| Escalation policy | High-risk invocation triggers escalation callback. Timeout results in deny. |
| API stability | Public API diff against v0.3.0: no removals except previously-deprecated items. |
| Compliance evidence | Mock auditor reviews AEGIS audit trail for a 10-invocation workflow and confirms: integrity, completeness, correlation, retention metadata. |

---

## 8. Threat Model Snapshot

> **Canonical reference:** [`AEGIS_THREAT_MODEL.md`](AEGIS_THREAT_MODEL.md) is the full threat model. This section summarizes threats in the context of roadmap mitigations; the standalone doc is authoritative for security review.

### Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| **Negligent integrator** | Wants governance to "just pass" so their app works. | Passes trivially-satisfying preconditions, uses empty policies, ignores strict mode. |
| **Malicious insider** | Wants to bypass governance for unauthorized actions. | Can modify context values, forge tool call metadata, tamper with audit artifacts at rest. |
| **Malicious plugin author** | Wants to weaken enforcement through a custom gate or sink. | Can register custom `EnforcementGate` or `AuditSink` that suppresses failures or drops artifacts. |
| **Integration bug** | Accidental misconfiguration. | Wrong policy file path, mismatched schema, stale cached policy. |
| **External attacker** | Wants to exploit governed AI system via prompt injection or tool misuse. | Controls user input reaching `invocation["input"]` or `invocation["context"]`. |

### Attack Surfaces and Mitigations

| Attack Surface | Attack Vector | Mitigation | Roadmap Item |
|---------------|--------------|------------|--------------|
| **Precondition bypass** | Pass `{"key": True}` to satisfy key-existence check | Typed preconditions with value validation | Week 1-2, #3 |
| **Policy theater** | Empty policy with no roles, no schema, no preconditions | Strict mode rejects minimum-viable-policy violations | Week 3-4, #12 |
| **Sink tampering** | Malicious sink drops artifacts silently | `on_sink_failure="raise"` (default). Sink cannot modify artifact (receives copy). | Week 1-2, #7 |
| **Exception injection** | Craft input that produces exceptions containing secrets | Failure message sanitization with redaction patterns | Week 1-2, #5 |
| **Plugin suppression** | Custom gate clears accumulated failures | Append-only failure list. Custom gates cannot access mutable failure state. | M2, custom gates |
| **Privilege escalation via composition** | Child policy adds roles/tools beyond parent scope | `_merge: intersect` for security-sensitive fields in strict mode | M2, restriction semantics |
| **Tool constraint timing** | Banned tool passes because tool check runs after schema | Pipeline reorder: tools before schema. `metadata.gates_evaluated` proves ordering. CI gate `ci:pre-action-boundary` prevents regression. | Week 1-2, #4 |
| **Audit artifact forgery** | Attacker modifies artifact at rest | HMAC signing + verification. Hash-chain detects gaps. | M2, signing |
| **Cache poisoning** | Modify policy file between mtime check and read | Atomic read + mtime recheck after parse. File hash comparison for high-security mode. | Week 2-3, #6 |
| **Context injection** | Attacker controls `context` values to influence guards | Guard expressions evaluated against typed conditions only. No arbitrary code execution. | M1, AST guards |
| **Workflow constraint evasion** | Agent splits workflow across sessions to reset budgets | Workflow ID tracking. Session binding to authenticated caller. | M3, GovernanceSession |

---

## 9. What I Need From Maintainers

| # | Question / Decision | Why It Matters | Default If No Answer |
|---|-------------------|---------------|---------------------|
| 1 | **Default `on_sink_failure` mode?** `raise` is fail-closed correct but breaks apps that treat governance as optional today. | Determines whether v0.2.0 is a behavioral breaking change for sink failures. | `raise` for strict mode, `log` for non-strict mode. |
| 2 | **Bare-string precondition deprecation timeline?** Immediate warning vs. silent acceptance for N releases. | Affects how aggressively we push integrators to typed preconditions. | Emit `DeprecationWarning` from v0.2.0. Error in strict mode from v0.2.0. Remove bare-string support in v1.0.0. |
| 3 | **Guard expression language scope?** Minimal (and/or/not/comparisons) vs. full expression language (functions, list comprehensions). | Determines M1 engineering effort and DSL complexity. | Minimal: `and`, `or`, `not`, `==`, `!=`, `>`, `<`, `>=`, `<=`, `in`. No functions. |
| 4 | **Audit schema major version bump tolerance?** v1.2 (additive) is safe. v2.0 (structural) requires migration tooling. | Determines if we can restructure `metadata` in M2 or must keep flat. | MINOR bumps only through v1.0.0. First MAJOR bump at v2.0.0 if needed. |
| 5 | **Target Python version floor?** Currently supports 3.9+. Some features (e.g., `match` statements, `TypeAlias`) require 3.10+. | Affects syntax choices and available standard library features. | Maintain 3.9+ through v1.0.0. |

If these questions are unblocked by the defaults, no maintainer input is needed to begin immediate development.

---

*This document is designed to be copied directly into the project's architecture documentation and used as the source of truth for PR planning. Engineers can begin work on items #1–#5 immediately — they have no inter-dependencies and each has clear acceptance criteria and test requirements.*
