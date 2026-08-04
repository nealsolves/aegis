# Issue #46 Trusted Checkpoints and Adversarial Anchor Verification Design

Date: 2026-08-04

Status: Approved

Issue: [#46 — trusted chain checkpoints and adversarial anchor verification](https://github.com/nealsolves/aegis/issues/46)

## Executive decision

AEGIS will provide explicit, provider-neutral APIs that create and verify
signed checkpoint records. Hosts remain responsible for storing, publishing,
retaining, retrieving, and protecting those records.

Two distinct public record types will be implemented:

- `TrustedChainCheckpoint`
- `TrustedWorkflowCheckpoint`

They share hardened internal signing and parsing machinery but have separate
schemas, payload types, signing profiles, and domains. Checkpoint creation does
not run automatically during invocation or workflow finalization.

## Goals

- Detect whole-chain replacement when a trusted checkpoint exists.
- Detect checkpoint-relative tail deletion and divergence.
- Preserve internal chain validity as distinct from externally anchored
  assurance.
- Externally anchor finalized workflow evidence and its authoritative B4
  claimed set.
- Support current and historical signing keys, rotation, revocation, and
  multiple chain checkpoints.
- Return typed, bounded, sanitized failures for malformed or unsupported
  evidence.
- Prevent replay between invocation artifacts, chain checkpoints, and workflow
  checkpoints.
- Keep checkpoint storage and lifecycle host-owned.

## Non-goals

- Automatic checkpoint emission during enforcement or workflow finalization.
- AEGIS-owned checkpoint storage, retention, WORM controls, transport, or
  discovery.
- Provider credentials, retry policies, network timeouts, or key lookup.
- Trusted timestamping, transparency logs, certification, or compliance claims.
- Replacing #47's operational storage guidance.
- Proving that no activity occurred after a checkpoint was created.

## Approaches considered

### Selected: separate public record types

Each checkpoint type has an independent public contract and domain. Shared
internal utilities handle bounded JSON parsing, canonicalization, receipt
validation, and result normalization.

This provides the strongest type-confusion and cross-domain replay protection.

### Rejected: one discriminated checkpoint envelope

This would reduce the public type count, but every consumer would need to branch
correctly on a shared record and signing path.

### Rejected: opaque host-defined anchor callbacks only

The existing callback model cannot provide deterministic schemas, portable
records, typed rotation behavior, or consistent adversarial verification.

## Architecture and public API

Add `aegis.checkpoints`, with top-level re-exports where appropriate:

```python
create_chain_checkpoint(
    artifact,
    signer,
    *,
    checkpointed_at,
) -> TrustedChainCheckpoint

create_workflow_checkpoint(
    workflow,
    signer,
    *,
    checkpointed_at,
) -> TrustedWorkflowCheckpoint

verify_chain_detailed(
    artifacts,
    *,
    signature_verifier=None,
    anchor_verifier=None,
    checkpoints=(),
    checkpoint_verifier=None,
) -> ChainVerificationReport

verify_workflow_claim(
    workflow,
    invocations,
    *,
    expected_checkpoint=None,
    checkpoint_verifier=None,
) -> WorkflowVerificationReport
```

Creation returns immutable, JSON-serializable records and performs no storage
operation. Stored records can be reconstructed with bounded `from_dict()`
methods. Integrated verification accepts either the corresponding record type
or an exact plain JSON dictionary. Calls without checkpoints retain current
behavior.

## Extension of the #44 contracts

The protocol shapes remain unchanged:

- `ExternalArtifactSigner`
- `ExternalArtifactVerifier`
- `SignerIdentity`
- `SigningReceipt`
- `ExternalVerificationOutcome`
- `ArtifactVerificationResult`

The closed metadata value domain is extended backward-compatibly:

```python
EvidenceType.CHAIN_CHECKPOINT = "chain_checkpoint"
EvidenceType.WORKFLOW_CHECKPOINT = "workflow_checkpoint"
```

New signing profiles are:

- `aegis-chain-checkpoint-v1`
- `aegis-workflow-checkpoint-v1`

Checkpoint metadata uses the B1 canonicalization profile, `aegis-json-v2`.
Existing audit-artifact metadata remains valid byte-for-byte.

Conceptual signing payloads are:

```text
AEGIS-SIGNATURE\0
aegis-chain-checkpoint-v1\0
chain_checkpoint\0
<canonical-v2 record without signature>
```

```text
AEGIS-SIGNATURE\0
aegis-workflow-checkpoint-v1\0
workflow_checkpoint\0
<canonical-v2 record without signature>
```

The implementation plan must freeze the exact concatenated bytes as conformance
vectors. Signature metadata is included in the canonical record; only the
`signature` field is excluded from the signed payload.

## Chain checkpoint record

`TrustedChainCheckpoint` is an exact-key, versioned record containing:

- `checkpoint_schema_version = "1"`
- `checkpoint_profile = "aegis-chain-checkpoint-v1"`
- `canonicalization_profile = "aegis-json-v2"`
- `chain_id`
- `chain_index`
- `chain_length`
- `artifact_schema_version = "2.0"`
- `artifact_checksum`
- `checkpointed_at`
- `signature_metadata`
- `signature`

Required invariants:

- `chain_length == chain_index + 1`.
- The source is a checksum-valid v2 invocation artifact.
- All four chain-coordinate fields are present and valid.
- `artifact_checksum` equals the source artifact's v2 checksum.
- `checkpointed_at == signature_metadata.signed_at`.
- No unknown or extension fields are accepted in v1.
- Empty chains cannot be checkpointed.

The artifact checksum already covers the chain ID, index, previous checksum,
and reservation ID. Anchoring that checksum therefore binds the complete signed
chain placement.

## Workflow checkpoint record

`TrustedWorkflowCheckpoint` is an exact-key, versioned record containing:

- `checkpoint_schema_version = "1"`
- `checkpoint_profile = "aegis-workflow-checkpoint-v1"`
- `canonicalization_profile = "aegis-json-v2"`
- `workflow_schema_version = "2.0"`
- `session_id`
- `final_status`
- `step_count`
- the exact ordered `invocations` pairs
- `workflow_checksum`
- `checkpointed_at`
- `signature_metadata`
- `signature`

Required invariants:

- The source is a schema-valid, checksum-valid finalized v2 workflow artifact.
- `final_status` is copied from the source `status`.
- `step_count` and `invocations` satisfy the existing B4 gapless claimed-set
  contract.
- `workflow_checksum` equals the source workflow's final v2 checksum.
- `checkpointed_at == signature_metadata.signed_at`.
- No unknown or extension fields are accepted in v1.

The anchor deliberately binds B4's authoritative ordered `invocations` claim.
It does not use the legacy `steps` or `invocation_audit_checksums` convenience
fields.

`COMPLETED`, `FAILED`, `CANCELED`, and `INCOMPLETE` workflows may all be
anchored. Evidence completeness remains independent of whether the workflow
completed successfully.

## Creation flow

Both creators:

1. Preflight the source under fixed resource limits.
2. Require an exact plain v2 artifact.
3. Verify its checksum and applicable schema or claim invariants.
4. Copy only stable checkpoint fields into a detached record.
5. Obtain and normalize the signer's immutable identity.
6. Construct checkpoint-specific signature metadata.
7. Canonicalize the checkpoint payload.
8. Call the external signer once.
9. Validate the receipt against the untouched prepared identity.
10. Validate the signature encoding.
11. Return an immutable record.

Any failure returns no partial record, performs no storage action, and leaves
the source artifact unchanged.

`checkpointed_at` is a signed host-observed Unix second. It is not trusted
timestamp evidence.

## Verification reports

`ChainVerificationReport` retains its current content, continuity,
artifact-signature, generic-anchor, and completeness axes. It gains:

- `checkpoint_signature_status`
- `checkpoint_anchor_status`
- `checkpoint_results`

`WorkflowVerificationReport` gains the same three checkpoint fields while
retaining its existing claim, signature, completeness, and error fields.

`checkpoint_results` contains the per-record #44
`ArtifactVerificationResult` values. Aggregate statuses use the worst supplied
outcome. With no checkpoint, `checkpoint_results` is empty,
`checkpoint_signature_status` is `UNSIGNED`, and
`checkpoint_anchor_status` is `NOT_EVALUATED`.

A malformed or unsupported supplied checkpoint has no per-record result. It
adds a bounded error, forces aggregate `checkpoint_signature_status` to
`INDETERMINATE` and `checkpoint_anchor_status` to `INVALID`, and prevents any
completeness promotion. Completeness remains `UNPROVEN` because untrusted input
cannot prove a contradiction. Only a successfully verified external anchor
that conflicts with supplied evidence can produce `CONTRADICTED`.

The existing chain `anchor_status` continues to describe artifact-signature or
compatibility callback anchoring. It cannot be interpreted as checkpoint
assurance. The deprecated `anchor_verifier` may continue affecting that
compatibility axis, but it cannot change `checkpoint_anchor_status` or promote
completeness.

## Verification flow

Verification proceeds as follows:

1. Materialize checkpoint input within count limits.
2. Measure bytes, depth, node count, and cycles before canonicalization.
3. Parse the exact record schema.
4. Reject unsupported versions and cross-type records.
5. Canonicalize exact payload bytes.
6. Invoke the external verifier once per unique parseable checkpoint.
7. Validate its closed #44 outcome.
8. Independently verify chain or workflow evidence.
9. Compare externally anchored checkpoints with the supplied evidence.
10. Aggregate statuses and bounded errors.

Exact duplicate checkpoints are canonicalized and verified once. Repetition
adds no assurance. Malformed, revoked, unknown-key, unavailable, or conflicting
supplied checkpoints cannot be hidden by another successful checkpoint.

## Chain checkpoint semantics

| Situation | Checkpoint anchor | Completeness |
| --- | --- | --- |
| No checkpoint | `NOT_EVALUATED` | `UNPROVEN` |
| Valid but externally unanchored checkpoint | `UNANCHORED` | `UNPROVEN` |
| Anchored checkpoint matches a full chain from index `0` through its trusted head | `ANCHORED` | `CHECKPOINT_PROVEN` |
| Anchored checkpoint matches an earlier head but the supplied chain continues | `ANCHORED` | `UNPROVEN` |
| Anchored checkpoint matches a partial chain beginning after index `0` | `ANCHORED` | `UNPROVEN` |
| Full chain begins at `0`, but an anchored checkpoint proves a later missing head | `INVALID` | `CONTRADICTED` |
| Anchored checkpoint conflicts with the artifact at its position | `INVALID` | `CONTRADICTED` |
| Two anchored checkpoints conflict at the same position | `INVALID` | `CONTRADICTED` |
| Invalid signature, unknown or revoked key, or unavailable verifier | Typed outcome; no trust promotion | `UNPROVEN` |

A stale checkpoint proves only its historical prefix. It cannot prove
completeness for a longer supplied chain. A partial chain beginning after index
`0` may be externally matched, but cannot receive global `CHECKPOINT_PROVEN`
completeness.

An internally valid whole-chain replacement remains internally valid but
becomes `CONTRADICTED` when its checksum conflicts with an anchored checkpoint.

## Multiple checkpoints, rotation, and revocation

Chain checkpoints are treated as an unordered set.

- Matching checkpoints at different positions may use different key versions.
- Current and historical keys are accepted according to the host verifier's
  policy.
- Rotation does not invalidate previously accepted historical checkpoints.
- A verifier-reported revoked key does not promote trust.
- Because #44 has no time-scoped revocation model, a currently revoked outcome
  fails closed even if the record predates revocation.
- Exact duplicate records are deduplicated.
- Two externally anchored records for the same coordinate with different
  checksums are conflicting authorities and produce `CONTRADICTED`.

## Workflow checkpoint semantics

A workflow receives `CHECKPOINT_PROVEN` completeness only when:

- The workflow content and schema are valid.
- Its B4 claimed set is valid.
- The supplied invocation set matches exactly.
- The checkpoint signature is valid.
- The external verifier reports the checkpoint anchored.
- Workflow schema version, session ID, final status, step count, ordered
  invocation pairs, and workflow checksum all match.

An externally anchored mismatch in any bound field produces `CONTRADICTED`. A
valid but unanchored checkpoint, malformed checkpoint, unknown key, revoked key,
unavailable verifier, or missing checkpoint leaves completeness `UNPROVEN`. A
checkpoint cannot convert an invalid workflow claim into a valid claim.

## Replay behavior

- Repeating the same checkpoint adds no assurance.
- A stale chain checkpoint cannot prove a later head.
- An externally anchored checkpoint from another chain contradicts the expected
  chain binding; an untrusted record cannot prove that contradiction.
- An externally anchored workflow checkpoint from another session contradicts
  the workflow binding; an untrusted record cannot prove that contradiction.
- Invocation artifacts cannot parse as checkpoint records.
- Chain checkpoints cannot parse or verify as workflow checkpoints.
- Workflow checkpoints cannot parse or verify as chain checkpoints.
- Domain, profile, payload type, and exact schema are all checked independently.

## Errors and failure containment

Direct creation and parsing use a public `CheckpointError` with stable codes
including:

- `CHECKPOINT_INPUT_INVALID`
- `CHECKPOINT_SOURCE_INVALID`
- `CHECKPOINT_VERSION_UNSUPPORTED`
- `CHECKPOINT_PROFILE_INVALID`
- `CHECKPOINT_SIGNING_ERROR`

Integrated verification converts catchable failures into bounded
`VerificationError` entries.

Provider exceptions, raw provider messages, payload bytes, signatures,
credentials, secret material, and untrusted artifact field values never appear
in core-generated messages, details, or logs. Unparseable checkpoint data never
reaches the external verifier.

## Resource limits

- Maximum 64 unique chain checkpoints per verification call.
- Maximum one workflow checkpoint per workflow verification call.
- Maximum 1,024 workflow invocation claims.
- Maximum 4 MiB measured checkpoint or source evidence.
- Maximum nesting depth of 32.
- Maximum 65,536 measured nodes.
- Maximum 100 returned verification errors.
- Maximum one verifier call per unique parseable checkpoint.

Oversized, cyclic, custom-container, non-string-key, or non-JSON input fails
before canonicalization or provider invocation. The independent limit of 64
chain checkpoints is required because each unique record may cause an external
verifier call.

## Test strategy

Implementation follows test-first red/green cycles.

Coverage includes:

- Frozen canonical payload and signature vectors for both domains.
- Exact schema parsing and round trips.
- Unsupported versions and profiles.
- Missing, extra, wrongly typed, Boolean, oversized, cyclic, and deeply nested
  fields.
- Identity and receipt mismatch.
- Provider alias rotation between preparation and signing.
- Malformed signatures and hostile provider results.
- Current, historical, unknown, revoked, and unavailable keys.
- Input non-mutation and atomic failure.
- Provider-call and error-count bounds.
- Field and link mutation.
- Deletion, insertion, and reordering.
- Duplicate and stale replay.
- Partial chains.
- Tail truncation.
- Complete internally valid chain replacement.
- Conflicting anchored checkpoints.
- Workflow session, status, count, index, invocation-checksum, and
  workflow-checksum mutation.
- Workflow deletion, insertion, reordering, incomplete supplied evidence,
  replay, and complete replacement.
- Invocation/checkpoint and chain/workflow cross-type replay.
- Every relevant adversarial scenario both without an external checkpoint and
  with one.
- Compatibility for existing calls without checkpoints.
- Architecture enforcement proving no storage, sink, credential, retry,
  discovery, or AEGIS-owned network path.

## Documentation

Update maintained public documentation for:

- Checkpoint creation and verification.
- Assurance axes and example outcomes.
- Threat-model changes.
- Architectural invariants.
- Compatibility and migration behavior.
- Versioned signing profiles.
- Rotation, revocation, and historical verification semantics.

Documentation will explicitly distinguish:

- Tamper-evidence from external anchoring.
- External anchoring from append-only or WORM storage.
- Checkpoint-relative completeness from proof of all future activity.
- Host-observed time from trusted timestamp evidence.
- Security assurance from certification or compliance.

Detailed storage operations and lifecycle guidance remain in #47.

## Adversarial design review

The second review of the consolidated design found and resolved four
consistency risks:

1. The current #44 `SignatureMetadata` value domain cannot be reused unchanged;
   it requires a backward-compatible extension for the two new evidence types
   and profiles.
2. Existing artifact `anchor_status` cannot represent checkpoint completeness
   without conflating separate assurances, so checkpoint axes remain
   independent.
3. A checkpoint ahead of a supplied full chain proves tail deletion and yields
   `CONTRADICTED`; a stale checkpoint behind a longer chain remains only
   historical evidence.
4. Checkpoint count needs its own cap because each unique record can trigger a
   provider call.

No section relies on AEGIS-owned storage, treats host time as trusted, lets
artifact signatures prove chain completeness, or permits cross-type fallback.

## Acceptance-criteria mapping

| Issue #46 acceptance criterion | Design coverage |
| --- | --- |
| Creation and verification use #44 contracts | Extension of the #44 contracts; creation and verification flows |
| Distinguish unanchored from checkpoint-validated chains | Independent checkpoint report axes and chain semantics |
| Detect internally valid whole-chain replacement | Chain checkpoint semantics and adversarial tests |
| Workflow-specific non-replayable domain | Workflow record and domain-separated payload |
| Detect workflow field mutation | Workflow binding rules and test strategy |
| Cover rotation and historical verification | Multiple checkpoints, rotation, and revocation |
| Cover mutation, deletion, insertion, reordering, replay, and replacement | Test strategy and deterministic semantics |
| Typed bounded failures for unsupported or malformed evidence | Errors, failure containment, and resource limits |

## Completion criteria

Issue #46 is complete when:

- Both record contracts and public creators are implemented.
- Chain and workflow verification consume the typed checkpoints.
- Exact signing-domain vectors are frozen.
- Adversarial coverage maps to every issue acceptance criterion.
- Existing no-checkpoint behavior remains compatible.
- Maintained security and integration documentation describes the new assurance
  boundary without claiming immutable storage, trusted time, certification, or
  compliance.
- The complete test suite and security-boundary checks pass.
