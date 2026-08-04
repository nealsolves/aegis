# AEGIS Threat Model

This document describes the threat model for the AEGIS Governance SDK.

AEGIS enforces deterministic governance over AI invocations.
The purpose of this threat model is to identify how governance could fail
and how the architecture prevents those failures.

This document assumes an adversarial environment.

Current public beta boundary: `aegis-ai-governance==0.9.0b1` adds
`GovernanceSession`, workflow lifecycle and budget checks, the workflow
trace/export operator surface, and optional adapter submodules. The public beta
is released from `main`. The host still owns model calls, tools,
transport, credentials, retries, orchestration, external-signing key
resolution, and artifact storage; adapter input is host-supplied evidence and
remains untrusted until normalized and enforced.

The external trust-anchor contracts described below are implemented in the
current source tree after `0.9.0b1`; they are not in that published wheel or
tag, and no later published version is assigned yet.

---

## Security Objective

AEGIS must guarantee:

1. governance enforcement occurs before irreversible actions
2. enforcement decisions are deterministic
3. governance artifacts are tamper-evident
4. enforcement cannot be bypassed through trivial manipulation
5. extensions cannot weaken core governance guarantees

---

## Security Boundary

The security boundary of AEGIS is the enforcement engine.

```
Application
│
▼
AEGIS Enforcement Boundary
│
▼
External Systems
```

All AI invocation governance must pass through this boundary.

Anything outside the enforcement boundary is considered untrusted.

---

## Threat Actor Classes

AEGIS considers four attacker types.

### 1. Negligent Integrator

**Capabilities:**

* incorrectly configures policy
* provides incomplete invocation context
* bypasses enforcement APIs

**Risks:**

* governance bypass
* incomplete validation

**Mitigations:**

* fail-closed enforcement
* policy schema validation
* required invocation fields
* typed precondition validation

---

### 2. Malicious Insider

**Capabilities:**

* modifies invocation payload
* attempts to manipulate context
* attempts to hide violations

**Risks:**

* unauthorized tool execution
* role escalation
* policy bypass

**Mitigations:**

* deterministic enforcement
* role validation
* tool constraint enforcement
* audit artifact checksums
* enforcement ordering guarantees

---

### 3. Malicious Plugin Author

**Capabilities:**

* writes custom enforcement gates
* attempts to weaken enforcement logic
* attempts to hide failures

**Risks:**

* governance bypass through extension points

**Mitigations:**

* append-only failure model
* plugin isolation
* restricted extension points
* CI verification of failure propagation

Custom gates cannot remove or suppress already-recorded core gate failures.
Pre-authorization gates run before core gates by design and are classified
separately as `custom_gate_violation`.

---

### 4. External Attacker

**Capabilities:**

* prompt injection
* malicious input payloads
* adversarial model output

**Risks:**

* tool abuse
* data exfiltration
* policy evasion

**Mitigations:**

* deterministic governance
* tool constraint validation
* schema validation
* precondition enforcement

AEGIS does not trust model output.

All model output must pass schema validation.

---

## Attack Surface

The AEGIS system exposes the following surfaces.

---

### Policy Files

**Attack vector:** malicious policy modification

**Risks:**

* unauthorized permissions
* weakened governance rules

**Mitigations:**

* policy schema validation
* optional policy signing
* versioned policy files

---

### Invocation Context

**Attack vector:** manipulated invocation payload

**Risks:**

* precondition bypass
* role escalation

**Mitigations:**

* strict field validation
* typed preconditions
* required context fields

---

### Model Output

**Attack vector:** malicious model output

**Risks:**

* schema violation
* tool abuse
* unsafe actions

**Mitigations:**

* schema validation
* postcondition checks
* tool constraints

Model output is treated as untrusted input.

---

### Tool Invocation

**Attack vector:** unauthorized external actions

**Examples:**

* uncontrolled web search
* database writes
* external API calls

**Mitigations:**

* tool constraint validation
* tool budgets
* allowed tool lists

---

### Signed Audit Artifacts

**Attack vectors:**

* artifact-declared algorithms or key locations attempting to select trust
* mutable key aliases changing between identity preparation and signing
* signer or verifier adapters mutating the frozen values they receive
* modified signature metadata
* impossible, hostile, or unavailable external-verifier responses
* replay or replacement of otherwise valid evidence
* sink acknowledgement followed by a crash before chain-reservation commit
* storage-write attackers deleting a valid tail or replacing a complete valid chain
* a host presenting a signed workflow while omitting invocation attempts

**Risks:**

* algorithm or key-version confusion
* false external-anchor claims
* partial mutation that leaves misleading evidence
* disclosure of payloads, signatures, credentials, or provider errors
* treating tamper-evidence as immutable storage or complete-chain proof

**Mitigations and boundary:**

* all strict `signature_metadata` fields are included in the signed bytes
* signer identity and receipt must pin the same opaque key reference and exact
  immutable key version
* AEGIS retains untouched core identity and metadata snapshots and gives
  adapters disposable equal copies
* the host-configured verifier resolves key reference and version; AEGIS never
  performs artifact-driven or network key lookup
* the resolved key policy, not the metadata-declared algorithm, authorizes the
  algorithm
* signature status and anchor status are validated as independent axes; a valid
  signature is not necessarily anchored
* signing failure leaves the artifact unchanged and detailed verification is
  non-mutating
* core-generated result messages, exceptions, details, and logs use bounded,
  sanitized data rather than raw provider responses or artifact-declared
  metadata values
* exact valid parsed `signature_metadata` remains available as explicitly
  untrusted artifact data; hosts keep it non-secret and apply their own
  redaction before logging it
* a host-owned chain linker reserves the complete coordinate set before the v2
  content checksum and signature are created, so every signature covers chain
  placement
* pre-ack failures abort the reservation; post-ack commit failures are surfaced
  distinctly and can be reconciled by reservation ID against observed sink state
* supplied-sequence verification checks content and internal continuity without
  promoting either result into a sequence-completeness claim
* each workflow attempt receives a gapless index under a session lock before
  authorization gates; every allocated attempt must have exactly one terminal
  invocation artifact before workflow finalization
* workflow content and any configured workflow signature cover `step_count` and
  the ordered `invocations` pairs of allocated index and invocation content
  checksum; the legacy `steps` summary is not the signed claimed set
* workflow artifacts are deliberately detached from invocation audit chains;
  they cannot substitute for invocation evidence during claimed-set verification

The host owns the trust store or key resolver, credentials, secret keys,
provider transport, retries, timeouts, availability behavior, and storage.
`signed_at` is a host-observed Unix second, not trusted timestamp evidence.
External signer or verifier availability cannot change the governance result
already recorded in an artifact.

Residual limits are deliberate: HMAC and hash chaining are tamper-evidence, not
immutable storage. A valid or anchored result does not prevent replay, prove
sequence completeness, detect replacement of a complete valid chain without a
trusted checkpoint, provide WORM retention, or establish certification or
regulatory compliance. An attacker with storage-write access can replace a
complete chain or remove a valid tail while leaving the supplied sequence
internally consistent. Roadmap item #46 is the separate control that binds
trusted heads to v2 content checksums. The bundled `AuditChain` is in-memory and
does not claim crash persistence; hosts must reconcile the emit/commit crash
window or provide a persistent linker.

Workflow-signed proves integrity and order of the claimed supplied set. It does
not prove the host disclosed every invocation. Completeness remains unproven
until a trusted checkpoint binds the expected head/count.

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

## Governance Bypass Attempts

This section describes common bypass attempts and their mitigations.

---

### Bypass Attempt: Trivial Precondition

**Example:**

```python
context = { "tenant_id": true }
```

**Risk:** Key existence validation incorrectly passes.

**Mitigation:** Typed preconditions required.

```yaml
tenant_id:
  type: string
  pattern: "^[A-Z0-9]{8}$"
```

---

### Bypass Attempt: Plugin Suppresses Failure

**Example:** plugin removes failure

**Mitigation:** Failures are append-only. Custom gates cannot suppress
already-recorded core gate failures. Once a core gate records a failure,
no subsequent plugin gate may remove it.

Pre-authorization gates run before core gates by design and are classified
separately as `custom_gate_violation`. A pre-auth gate failure halts the
pipeline before core gates execute; this is intentional pipeline sequencing,
not a suppression exception. The non-suppression guarantee applies to gates
running after a core gate has already evaluated and recorded a failure.

---

### Bypass Attempt: Enforcement Ordering Manipulation

**Example:** schema validation before tool validation

**Risk:** Unauthorized tool calls could execute.

**Mitigation:** Fixed pipeline ordering. CI verifies pipeline ordering.

---

### Bypass Attempt: Silent Enforcement Failure

**Example:** audit sink failure ignored

**Risk:** audit artifact lost

**Mitigation:** V2 enforcement requires an acknowledged sink. Successful
synchronous `emit()` return is acknowledgement; any exception raises
`AuditSinkError(code="AUDIT_DELIVERY_FAILED")` and blocks both allow- and
deny-class completion. `AEGIS(sink=...)` and the sealed module runtime accept
only fail-closed delivery. Mutable global failure-mode controls are outside the
v2 public surface.

---

## Enforcement Proof

Audit artifacts prove enforcement occurred.

Artifacts contain:

`metadata.gates_evaluated`

Example:

```json
[
  "guard_evaluation",
  "role_validation",
  "precondition_validation",
  "tool_constraint_validation"
]
```

This proves governance occurred before action.

---

## Audit Integrity

Artifacts include checksums for tamper-evidence.

* `input_checksum`
* `output_checksum`

Governance-enrichment fields (v0.3.0):

* `risk_score` — populated by the risk scoring engine when the governing policy declares risk configuration (v0.3.0)
* `signature` — populated by `ArtifactSigner` (HMAC-SHA256) when signing is enabled on the AEGIS instance (v0.3.0)

Cryptographic chaining fields (v0.3.0):

* `chain_id`, `chain_index`, `previous_audit_checksum` — populated by `AuditChain` for tamper-evident sequential integrity (v0.3.0)

Source-only trust-anchor field added after the `0.9.0b1` release:

* optional strict `signature_metadata` — populated only by the opt-in
  metadata-aware external signing helper and covered by its signature; it is
  untrusted artifact-declared data and must be host-redacted before logging

Modification of covered content causes the corresponding checksum or signature
verification to fail. These checks do not make the underlying storage
immutable. Chain verification reasons about the chain presented to it and,
without an external trusted checkpoint, does not detect replacement of the
complete chain.

---

## Supply Chain Security

AEGIS dependencies must be verified.

Recommended practices:

* pinned dependency versions
* vulnerability scanning
* reproducible builds

---

## Non-Goals

AEGIS does not attempt to solve:

* model hallucinations
* model bias
* provider safety systems
* replay prevention or proof that a supplied sequence is complete
* trusted timestamping or timestamp-authority evidence
* trusted complete-chain checkpoints or whole-chain replacement detection
* WORM storage, retention, object locking, or disaster recovery
* provider signing transport, credentials, retries, or key-rotation operations
* certification or a regulatory-compliance determination

AEGIS governs invocation boundaries, not model reasoning.

---

## Residual Risk

Remaining risks include:

* integrator misuse of enforcement APIs
* compromised runtime environments
* malicious policy authors
* compromised host key-resolution or anchor configuration
* unavailable external signers, verifiers, or artifact storage
* replay or complete replacement of valid evidence

These risks must be addressed through operational controls.

---

## Security Posture Summary

AEGIS provides the following guarantees:

* deterministic governance enforcement
* fail-closed security model
* provable enforcement boundary
* tamper-evident audit artifacts
* plugin-safe extension architecture

These guarantees can supply inputs to host-owned audit and assurance programs.
They do not certify a deployment, establish compliance, or replace operational
controls for credentials, transport, availability, trusted checkpoints, and
storage.
