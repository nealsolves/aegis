# AEGIS Architectural Invariants

This document defines the non-negotiable engineering invariants of the AEGIS Governance SDK.

These invariants exist to prevent architectural drift.

Current public beta baseline: `aegis-ai-governance==0.9.0b1`, released from
`main` with audit schema `v1.4`. Current source after that release emits audit
schema `v2.0`; the `v1.4` statement is release history.

The packaged beta public surface adds `AEGIS.open_session(...)`,
`GovernanceSession`, `SessionPreCallResult`, `aegis workflow init`,
`aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`, and
`aegis workflow export`. Workflow checks wrap the invocation kernel; they do not
change its ordered gates.

`ValidatorHook` remains internal, not public. `AgentIdentity` and
`AgentCapabilityManifest` are not current public types. Bedrock, A2A, and
OpenAI Agents integrations are optional public submodules, not top-level
re-exports.

Invariant 18 describes external trust-anchor contracts implemented in the
current source tree after `0.9.0b1`. They are not in that published wheel or
tag, and no later published version is assigned yet.

Any change that violates these invariants must not be merged.

If an invariant must change, the change requires:

1. An ADR
2. Updated golden replay tests
3. Updated CI release gates
4. Documentation updates

---

## 1. Deterministic Governance Boundary

Governance must be deterministic.

Given identical:

* policy
* invocation input
* invocation output
* context

The enforcement result must always be identical.

No randomness is allowed in governance logic.

The governance system must never depend on:

* LLM output
* prompt interpretation
* probabilistic scoring

---

## 2. Fail-Closed Enforcement

Governance failures must stop execution.

Examples:

* invalid policy
* missing precondition
* unauthorized role
* tool constraint violation
* schema violation

V2 evidence delivery is fail-closed. Every public attempt allocates bounded
identity before parsing input, and every terminal artifact crosses the single
evidence finalizer. A sink exception raises
`AuditSinkError(code="AUDIT_DELIVERY_FAILED")`; it cannot return an allow-class
result. Legacy best-effort behavior is isolated from, and cannot configure, an
instance or module v2 runtime.

The system must never degrade into permissive mode for governance gates or
evidence delivery.

Core governance gates (role, precondition, tool, schema, postcondition) are
always fail-closed. Below the fixed critical ceiling, risk scoring has two
explicitly configured non-blocking threshold modes: `risk_scored` and
`warn_only`. Equality with a policy threshold is a breach. A score at or above
`0.90` blocks in every mode. Sink failures are configurable and do not affect
the governance decision.

---

## 3. Enforcement Boundary

All governance must execute inside the enforcement pipeline.

No system component may bypass:

* policy validation
* authorization
* preconditions
* tool constraints
* schema validation
* postconditions
* audit artifact generation

All enforcement must route through the governance engine.

Every loader-to-enforcement boundary must immediately produce a
`CompiledPolicy` with legacy authority disabled. Authorization gates may read
only typed compiled fields; raw policy dictionaries are confined to loader and
compiler compatibility APIs outside authorization.

---

## 4. Pipeline Ordering

The enforcement pipeline executes in a fixed order.

1. custom gates (pre_authorization)
2. guard evaluation
3. role validation
4. precondition validation
5. tool constraint validation
6. custom gates (post_authorization)
7. custom gates (pre_output)
8. schema validation
9. postcondition validation
10. custom gates (post_output)
11. risk scoring (the `0.90` critical ceiling blocks in every mode; below it,
    strict blocks threshold breaches while risk_scored and warn_only warn)
12. audit artifact generation

Tool validation must occur before schema validation.

Unauthorized actions must fail before output processing.

Pipeline ordering must never change without an ADR.

---

## 5. Pre-Action Enforcement Proof

Audit artifacts must prove enforcement occurred before action.

Each artifact must include ordered gate evidence:

* unified mode: `metadata.gates_evaluated`
* split mode: `metadata.pre_call_gates_evaluated`
* split mode Phase B completion: `metadata.post_call_gates_evaluated`

This ordered list shows which gates executed.

This mechanism proves that enforcement occurred before output propagation.

---

## 6. Tamper-Evident Audit Artifacts

Audit artifacts must be verifiable for covered-content changes. AEGIS
checksums, HMAC signatures, and hash-chain links provide tamper-evidence; they
do not make a mutable artifact or its storage immutable.

Each artifact includes:

* input checksum
* output checksum
* timestamp
* enforcement result
* failure gate
* metadata

Artifacts include governance-enrichment fields introduced in v0.3.0 (M2):

* `risk_score` — populated by the risk scoring engine when the policy declares risk configuration
* `signature` — populated by `ArtifactSigner` (HMAC-SHA256 via `HMACSigner`) when signing is enabled
* `chain_id`, `chain_index`, `previous_audit_checksum` — populated by `AuditChain` for sequential integrity verification

The optional strict `signature_metadata` field is a source-only addition after
the `0.9.0b1` release. It is populated only by
`sign_artifact_with_metadata()` and covered by that signature.

Hash-chain verification applies to the sequence supplied for verification. It
does not detect replacement of a complete otherwise-valid chain without an
external trusted checkpoint, establish sequence completeness, or provide WORM
storage. Trusted checkpoints (issue #46) are the additive, host-driven control
that detects whole-chain replacement for an expected scope when a validly signed,
anchored checkpoint is retained and presented; a host that omits or withholds the
checkpoint keeps the pre-#46 `unproven` result, so checkpoint omission and
rollback remain host-owned residuals. AEGIS never creates an automatic checkpoint
sink, discovers a key over the network, retries a host signer, or promotes
completeness from an artifact signature alone. See ADR-0015.

---

## 7. Append-Only Failure Model

Governance failures accumulate during enforcement.

Failures may be added by:

* core pipeline gates
* plugin enforcement gates

Failures may never be removed.

Plugins cannot suppress already-recorded governance violations. Once a core
gate records a failure, no subsequent plugin gate may remove or override it.
Failures are append-only within a pipeline execution.

Pre-authorization custom gates execute before core validation gates. A
pre-auth gate failure halts the pipeline before core gates run; this is
intentional pipeline sequencing. Their failures are classified as
`custom_gate_violation`, not a suppression of a recorded core failure,
because no core gate has yet evaluated.

---

## 8. Instance-Scoped Configuration

Global mutable state is discouraged for new code.

Configuration should exist within an `AEGIS` instance.

Example:

```python
AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    on_sink_failure="raise",
    strict_mode=True,
    redaction_patterns=None,
)
```

Module-level enforcement uses a private runtime configured once with
`configure_module_enforcement(...)`. The first attempt atomically seals that
runtime. The deprecated `set_audit_sink()` registry is not consulted by v2.

---

## 9. Policy Composition Semantics

Policies compose via `extends` inheritance with recursive merge.

Current merge rules:

* ordinary arrays use the configured append, union, intersect, or replace
  strategy
* dicts recurse
* scalars replace
* authorization-bearing `roles`, `tools.allowed_tools`, and workflow
  participants use complete replacement plus subset validation
* an inherited `workflow.required_sequence` is exact across composition and
  guard overlays
* absent tool configuration and explicit empty `allowed_tools` remain distinct;
  the latter denies all tool calls

Circular dependency chains are detected and rejected at load time.

Privilege escalation prevention via `union`/`intersect`/`replace` semantics
is implemented in v0.3.0 (M2) through the `composition_strategy` policy field.

---

## 10. Replayable Governance

Every enforcement must be reproducible for investigation.

Replay requires:

* policy
* invocation
* context

Golden replay tests verify that repeating the same inputs produces identical
results.

This diagnostic replayability is not a security claim that signed artifacts
cannot be replayed. AEGIS does not prevent presentation or reuse of otherwise
valid evidence.

---

## 11. Provider Independence

Governance must remain provider-agnostic.

The enforcement system must not depend on:

* OpenAI APIs
* Anthropic APIs
* provider-specific safety layers

AEGIS governs invocation boundaries.

Not model providers.

---

## 12. Split Enforcement Execution Mode

Split enforcement is an additive execution mode introduced in `v0.3.2`.

It does not change any architectural invariant. Specifically:

* Gate ordering remains fixed (Invariant 4). Phase A executes authorization gates; Phase B executes output gates; the model call occurs at the boundary between them.
* Fail-closed behavior remains unchanged (Invariant 2). Phase A FAIL stops execution before the model call.
* Exactly one audit artifact is emitted per invocation attempt (Invariant 6). A Phase-A-only FAIL produces one FAIL artifact. A complete split invocation produces one final artifact.
* Unified mode remains backward-compatible and fully supported.
* Policy evaluation in Phase B must use the Phase A effective policy — no reload from disk.
* Phase A and Phase B use the same compiled authority object in-process.
  Serialized transfer uses one canonical compiled DTO plus an authenticated,
  domain-separated content digest. The digest is verified before
  reconstruction and before Phase B use; transfer must not serialize a raw
  policy snapshot or call `compile_policy()` during reconstruction.

Hosts using legacy unified mode via `pre_call_enforcement=False` are unaffected
by split mode internals; the pipeline ordering and artifact contract are unchanged.

---

## 13. Additive Audit Schema Evolution

Schema versions may only add optional fields. No existing required field may be
removed or renamed. No new required fields may be added. Every artifact valid
under schema version `N` must remain valid under version `N+1`.

---

## 14. Provenance is Optional, Not Enforcement-Gating

`provenance` in audit artifacts is always optional. The enforcement pipeline
must not fail or alter its gate sequence based on the presence or absence of
provenance metadata unless a `ProvenanceGate` is explicitly registered by the
host.

---

## 15. Lineage Reconstruction is Read-Only and Off Hot Path

`AuditLineage` reads existing audit artifacts to reconstruct dependency graphs.
It must not modify artifacts, invoke enforcement, or run during the enforcement
hot path unless the host explicitly calls it.

---

## 16. One Audit Artifact Per Invocation Attempt

Every invocation attempt — whether it succeeds or fails, whether it runs in
unified mode or split mode — must produce exactly one audit artifact. This
invariant holds across `enforce_invocation`, `enforce_pre_call`/`enforce_post_call`,
`AEGIS.enforce`, and `@governed`.

---

## 17. Advisory Utilities Must Not Alter Enforcement Semantics

`RiskHistory` and similar advisory utilities must not change the enforcement
pipeline outcome, gate order, or audit artifact content for any invocation they
observe. They are observers, not participants.

---

## 18. External Signature Trust Boundary

Metadata-aware signing is the finalizer-owned v2 path. Legacy byte signers are
adapted behind the finalizer protocol; both invocation and workflow evidence
use domain-separated payloads.

The following rules are invariant:

* `signature_metadata` is strict, versioned, and entirely covered by the
  metadata-aware signature.
* invocation signatures use `aegis.invocation.v2`; workflow signatures use
  `aegis.workflow.v2`
* missing signers produce explicit `signature_status: "unsigned"`
* signer identity and receipt must agree on algorithm, encoding, opaque key
  reference, and exact immutable key version before the artifact is mutated
* AEGIS keeps untouched core identity and metadata snapshots and gives signer
  and verifier adapters disposable equal copies
* signing failure leaves the artifact unchanged; detailed verification never
  mutates the artifact
* when configured, a host-owned chain linker reserves `chain_id`, `chain_index`,
  `previous_audit_checksum`, and `reservation_id` before checksum construction
  and signing; the four fields are complete or absent
* `previous_audit_checksum` is the prior artifact's v2 content checksum, never a
  signature or storage-provider digest
* the finalizer order is reserve, attach coordinates, checksum, sign, validate,
  emit, then commit; pre-ack failures abort and post-ack commit failures never
  attempt to retract acknowledged evidence
* workflow evidence is not chain-linkable in this contract
* the host-configured verifier resolves the exact key reference and version;
  artifact data never triggers provider or network lookup
* the metadata-declared algorithm is not authorization; the resolved key policy
  must permit it
* signature validity and external anchoring are independent status axes; valid
  does not mean anchored
* unavailable signing or verification never weakens or changes the governance
  decision already recorded by the artifact
* `signed_at` is host-observed time, not trusted timestamp evidence
* exact valid parsed `signature_metadata` is returned as untrusted,
  artifact-declared, contractually non-secret data, including when no verifier
  is configured; hosts apply their own redaction before logging it
* core-generated result messages, exceptions, details, and logs never echo
  artifact metadata, payloads, raw signatures, secrets, or provider responses

The host owns key resolution, trusted-anchor configuration, credentials,
provider transport, retry and timeout behavior, availability policy, and
artifact storage. The bundled `AuditChain` is a single-process linker with one
outstanding reservation and no crash-persistence guarantee; hosts own recovery
or reconciliation after sink acknowledgement and before commit. AEGIS verifies
only the supplied sequence's internal continuity. Those artifact-level axes do
not claim replay prevention, sequence completeness, complete-chain replacement
or tail-truncation detection, trusted time, immutable or WORM storage,
certification, or regulatory compliance. Issue #46's implemented trusted
checkpoints detect divergence from a valid, anchored, authoritative pin when
presented; latest retrieval and omission/rollback protection remain host
responsibilities.

---

## 19. Workflow Claimed-Set Evidence

Each workflow attempt receives a permanent, gapless `step_index` under the
session attempt lock before authorization gates run. Finalization requires
exactly one terminal invocation artifact per allocated attempt. The workflow
artifact's `step_count` and ordered `invocations` entries pair each index with
that terminal invocation artifact's v2 content checksum; these claim fields are
covered by the workflow content checksum and any configured workflow signature.

`steps` remains a convenience summary for workflow timelines and may omit a
rejected attempt. It is never the source of the signed claimed set. Workflow
artifacts are separate evidence and are not invocation-chain artifacts.

`verify_workflow_claim(workflow, invocations, *, expected_checkpoint=None)` checks
the supplied ordered invocation set independently of signature verification.
Its `claim_status`, `signature_status`, and `completeness` axes are deliberately
separate. A signed workflow without a trusted verifier has
`signature_status=INDETERMINATE`. A non-`None` `expected_checkpoint` is now
honored (issue #46, current source): a valid, anchored `TrustedWorkflowCheckpoint`
promotes completeness to `checkpoint_proven` for the expected scope, and an
authoritative mismatch reports `contradicted`. Invalid, unavailable,
unknown-key, revoked, or unanchored evidence remains `unproven` even when its
structural binding matches or conflicts. Completeness from an artifact
signature alone is never inferred. See ADR-0015.

Workflow-signed proves integrity and order of the claimed supplied set. It does
not prove the host disclosed every invocation. Completeness remains unproven
until a trusted checkpoint binds the expected head/count. Only valid, anchored,
authoritative evidence can then detect divergence; latest retrieval and
checkpoint omission/rollback remain host responsibilities.

The verifier bounds claims and supplied artifacts to 1,024 entries each,
measured input to 4 MiB, nesting to 32 levels, and reports to 100 errors.
Exceeding an input budget fails closed with
`WORKFLOW_VERIFICATION_LIMIT_EXCEEDED`.

A session admits at most 1,024 workflow attempts. A later request fails before
attempt-envelope or step-index allocation with
`SESSION_ATTEMPT_LIMIT_EXCEEDED`.

Exception-path workflow summaries contain only a bounded `exception_type` and
stable `SESSION_BODY_EXCEPTION` reason code; raw exception messages are not
signed.

---

## 20. Single Compiled Policy Interpretation

Policy loading, workflow lint, unified enforcement, split enforcement, async
entry points, instance methods, adapters, and sessions share one compiler
contract.

The following rules are invariant:

* compilation occurs exactly once immediately after each policy load or cache
  retrieval used for enforcement
* roles, tools, risk, typed preconditions, cumulative guard effects, output
  validation, postconditions, and workflow limits are read from compiled fields
* authority envelopes contain explicit immutable per-field values, never a
  generic restriction or effective-policy mapping
* guard effects compile to typed immutable overlays at the load boundary and
  are applied cumulatively without policy-map reconstruction or recompilation
* runtime risk overrides may only tighten compiled authority and the critical
  ceiling remains fixed at `0.90`
* policy-backed sessions pin the open-time compiled policy; steps and dynamic
  tool calls consume that authority without reload or recompile
* lint reports the shared compiler's stable error code and path, resolving
  source-relative `extends` chains before compiling composed files
* architecture fitness tests cover compiler/load calls, compiled-policy alias
  data flow, generic policy-shaped snapshots, session reloads, and compiled
  parameter contracts across guards, enforcement, sessions, tools, risk,
  retry, lint, and CLI modules

---

## 21. Closed Extension Outcomes and Detached Gate Inputs

Custom gates receive detached, recursively immutable projections built from an
explicit compiler-field allowlist. No supplied argument may expose a live
policy, invocation, context backing collection, registry, signer, sink, or
operation. This is not a Python sandbox claim; it is the enforceable guarantee
that gate arguments provide no handle to AEGIS enforcement state.

Custom gates, internal validator hooks, and risk scoring must authorize only
through `NormalizedOutcome`. The only continuation classes are `ALLOW` and
`WARN`. Denials, contradictory or malformed results, unknown decisions,
timeouts, exceptions, and exhausted hook execution failures are closed
non-continuation outcomes. No authorization consumer may independently branch
on raw gate failures, hook decision strings, `RiskScore.exceeded`, or risk mode.

---

## Summary

The architectural invariants guarantee:

* deterministic governance
* provable enforcement
* auditability
* security

They can support host-owned audit and assurance programs, but do not certify a
deployment or establish compliance.

Any change that weakens these guarantees must not be accepted.
