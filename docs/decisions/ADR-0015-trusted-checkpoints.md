# ADR-0015: Trusted External Checkpoints

Date: 2026-08-06
Status: Accepted
Owners: Neal

---

## Context

AEGIS produces per-invocation audit artifacts and, through issue #44's external
trust-anchor signing (ADR-0012), lets a host attach provider-neutral signatures
and anchors to a single artifact. ADR-0008 defines the governance artifact
chain and its content/continuity checks. None of these prove *completeness*: a
verifier that receives a chain or a finalized workflow claim cannot tell whether
the sequence it was handed is the sequence that actually occurred, or whether a
prefix, suffix, or interior segment was dropped before verification.

Issue #46 adds an explicit, host-driven mechanism to checkpoint a chain or a
finalized workflow claim against externally signed, provider-neutral evidence,
so a later verification can distinguish "internally consistent" from
"consistent *and* pinned to a checkpoint the host trusts." The mechanism is
deliberately narrow: it proves that the evidence presented at verification
matches a checkpoint that was signed at some earlier host-declared moment. It
does not, and cannot, prove liveness, storage integrity, or future behavior.

Checkpoint source material is untrusted input. A checkpoint record may not
authorize its own signing algorithm, discover a key over the network, select
its own storage, or assert that it is the most recent checkpoint.

## Decision

### Two explicit record types

- `TrustedChainCheckpoint` pins the selected chain identity, terminal
  coordinate and length, artifact schema, and terminal artifact content
  checksum. Creation validates its source as finalized, chained, and
  checksum-valid; later verification independently evaluates the supplied
  artifacts' content and continuity before comparing them with the pin.
- `TrustedWorkflowCheckpoint` pins one finalized, checksum-valid workflow claim.

The two record types are never merged into a single envelope; a chain
checkpoint and a workflow checkpoint carry different scope identity
(`chain_id` + `chain_index` versus `session_id`) and are validated against
different source shapes. Each record exposes `to_dict()` for host persistence
and a classmethod `from_dict(value)` for host reconstruction; both round-trips
are pure, allocate no capabilities, and reject malformed input with
`CheckpointError`.

### Explicit, host-owned creation

Checkpoints are created only by an explicit call, never by an automatic sink or
finalizer hook:

- `create_chain_checkpoint(artifact, signer, *, checkpointed_at)` returns a
  `TrustedChainCheckpoint`.
- `create_workflow_checkpoint(workflow, signer, *, checkpointed_at)` returns a
  `TrustedWorkflowCheckpoint`.

`signer` is a **provider-neutral**, host-supplied `ExternalArtifactSigner`
(`signer_identity()` plus `sign(payload, identity)`); AEGIS ships no built-in
key store, network client, or provider SDK for this path. `checkpointed_at` is
a **signed host-supplied time**: it is included in the signed payload so it
cannot be altered after the fact, but AEGIS does not independently verify that
this time is accurate, monotonic, or recent. The lifecycle after creation is
**host-owned**: the host chooses whether, where, and how long to persist
`checkpoint.to_dict()`, and supplies the reconstructed record back at
verification time. AEGIS never writes a checkpoint to a store of its own.

### Verification is additive and scoped

Detailed verification stays source-compatible. Callers that pass no checkpoint
evidence see the pre-#46 behavior and an `unproven` completeness.

- `verify_chain_detailed(artifacts, *, checkpoints=..., checkpoint_verifier=...,
  expected_chain_id=...)` returns a `ChainVerificationReport`.
- `verify_workflow_claim(workflow, invocations, *, expected_checkpoint=...,
  checkpoint_verifier=...)` returns a `WorkflowVerificationReport`.

`expected_chain_id` (chain) and `expected_checkpoint` (workflow) let the caller
bind verification to a specific scope; a mismatch is reported, never silently
accepted. The report separates integrity from completeness across three
additive checkpoint fields:

- `checkpoint_signature_status` — whether the supplied checkpoint's external
  signature verified.
- `checkpoint_anchor_status` — whether the checkpoint signature is externally
  anchored.
- `checkpoint_results` — the per-checkpoint `CheckpointVerificationResult`
  tuple, each carrying its own `binding_status`.

### Completeness is a distinct axis

`Completeness` has exactly three values and is never inferred from an artifact
signature alone:

- `unproven` — no trusted checkpoint evidence bound the presented sequence.
- `checkpoint_proven` — presented evidence matched valid, anchored checkpoint
  evidence for the expected scope.
- `contradicted` — presented evidence conflicts with the checkpoint.

`checkpoint_proven` is reachable only when the authoritative checkpoint
signature is `VALID`, anchored, structurally matched, and the required full
chain or workflow claim conditions hold. `contradicted` likewise requires a
valid, anchored authoritative match/conflict condition. Invalid, unavailable,
unknown-key, revoked, or unanchored evidence remains `unproven` even when its
structural binding matches or conflicts. A valid *artifact* signature never
promotes completeness on its own.

### Independent verification axes

The report keeps eight axes deliberately separate so no result masquerades as a
stronger one. Content, continuity, and the artifact-level signature/anchor axes
describe the supplied evidence itself; the checkpoint-level axes and completeness
describe whether that evidence is pinned to trusted external evidence.

| Axis | Question it answers | Promotes completeness? |
|------|---------------------|------------------------|
| Content integrity | Does each artifact's content match its checksum? | No |
| Chain continuity | Are the supplied coordinates/links internally consistent? | No |
| Artifact signature status | Did the artifact's own external signature verify? | No |
| Artifact anchor status | Is that artifact signature externally anchored? | No |
| Checkpoint signature status | Did the supplied checkpoint's external signature verify? | Only in combination |
| Checkpoint anchor status | Is the checkpoint signature externally anchored? | Only in combination |
| Checkpoint binding status | Does the presented sequence match the checkpoint's pinned scope? | Only in combination |
| Completeness | Is the sequence pinned to a trusted checkpoint? | Is the axis |

Completeness reaches `checkpoint_proven` only when the checkpoint signature is
`VALID`, the checkpoint is anchored, and binding matches for the expected scope;
a valid and anchored authoritative conflict is `contradicted`. Invalid,
unavailable, unknown-key, revoked, or unanchored evidence and absence of
checkpoint evidence stay `unproven`.

## Assurance scope — what trusted checkpoints do NOT prove

To prevent over-trust, the contract is bounded explicitly. A `checkpoint_proven`
result **does not prove**:

- **Latest retrieval.** It does not prove the host handed the verifier the most
  recent checkpoint; the host owns storage and selection, so a stale but
  validly signed checkpoint verifies.
- **WORM / append-only storage.** AEGIS provides no write-once or append-only
  store and makes no durability, immutability, or retention guarantee about
  where the host keeps records.
- **Future activity.** A checkpoint pins state at its signed host time; it says
  nothing about activity after that moment.
- **Certification or compliance.** Producing or verifying checkpoints is not a
  certification, audit result, or statement of regulatory compliance.

When valid, anchored, authoritative checkpoint evidence is presented, AEGIS
does detect divergence from the pinned chain head or workflow claim. That
bounded detection does not transfer responsibility for latest retrieval,
omission detection, or rollback protection from the host.

### Test-only architecture guard and its residuals

A separate, **test-only** architecture tripwire in
`tests/test_architecture_security_boundaries.py`
(`_checkpoint_boundary_violations_for_source` and
`_checkpoint_callback_order_violations_for_source`) statically scans the
checkpoint modules to catch capability introduction and preflight-ordering
regressions from ordinary future editing. It is a best-effort guard, **not** a
production control and **not** an airtight proof. Its documented, accepted
**residuals** are:

- **Source-owner attacker.** An attacker who can rewrite `aegis._internal` (and
  the test allowlists) already exceeds any checkpoint-API authority; this is
  outside the threat model and is not statically closable by an AST checker.
- **Adversarially crafted aliasing/laundering shapes.** A hand-authored
  taint-analysis approach cannot enumerate every syntactic shape (dict-value
  aliases, attribute-stored handlers, method-dispatched capability returns). A
  re-scope to allowlist-conformance was designed and then abandoned on
  2026-08-06 as not worth the round-by-round cost.

For anything outside the bounded guard, **code review** is the compensating
control: the mandatory pre-push review of every changed file owns the property
that a preflight still validates and that no new capability is introduced.

## Consequences

- Hosts gain a real completeness signal without AEGIS taking ownership of
  storage, keys, transport, or time.
- The verification API stays backward compatible: no-checkpoint calls remain
  `unproven` and source-compatible.
- Assurance claims are narrow and auditable; the "does not prove" list and the
  test-guard residuals are recorded here rather than implied.

## Alternatives rejected

- **Single-envelope record** merging chain and workflow checkpoints — rejected;
  it conflates two distinct scope identities and validation shapes.
- **Automatic checkpoint storage / finalizer sink** — rejected; it would give
  AEGIS storage ownership and hide an untrusted-time, untrusted-store
  dependency behind an implicit hook.
- **Promoting completeness from an artifact signature** — rejected; integrity
  and completeness are separate axes, and conflating them would let a valid
  signature masquerade as proof of a complete sequence.

## References

- ADR-0008: Governance artifact chain (forward reference to this ADR).
- ADR-0012: External trust-anchor signing contracts (forward reference to this
  ADR).
- Issue #46: Trusted external checkpoints.
