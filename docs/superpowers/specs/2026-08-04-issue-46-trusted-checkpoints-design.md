# Issue #46 Trusted Checkpoints and Adversarial Anchor Verification Design

Date: 2026-08-04

Status: Historical approved design — implemented; ADR-0015 is authoritative

Issue: [#46 — trusted chain checkpoints and adversarial anchor verification](https://github.com/nealsolves/aegis/issues/46)

## Executive decision

AEGIS provides explicit, provider-neutral APIs that create and verify
signed checkpoint records. Hosts remain responsible for storing, publishing,
retaining, retrieving, and protecting those records.

Two distinct public record types are implemented:

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

Add `aegis.checkpoints`:

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
    expected_chain_id=None,
) -> ChainVerificationReport

verify_workflow_claim(
    workflow,
    invocations,
    *,
    expected_checkpoint=None,
    checkpoint_verifier=None,
) -> WorkflowVerificationReport
```

Creation returns immutable records whose `to_dict()` methods produce exact
JSON-native dictionaries, and performs no storage operation. Stored records
can be reconstructed with bounded `from_dict()` methods. Integrated
verification accepts either the corresponding record type or an exact plain
JSON dictionary. Calls without checkpoints retain current behavior.

The top-level `aegis` API re-exports both creators, both record types,
`CheckpointError`, `CheckpointSignatureStatus`, `CheckpointBindingStatus`, and
`CheckpointVerificationResult`. `CheckpointError` is also exported from
`aegis.errors`; the other checkpoint contracts are owned by
`aegis.checkpoints`. Existing verification functions remain exported from
their current public modules and from `aegis`.

`expected_chain_id` is an optional host-selected logical-chain scope. When it
is supplied, only checkpoints with that `chain_id` are in scope, and supplied
chain evidence claiming a different `chain_id` conflicts with an externally
anchored in-scope checkpoint. When it is omitted, verification derives scope
from an internally valid supplied chain. In that compatibility mode, AEGIS can
detect replacement only within the same `chain_id`; a host that needs to detect
replacement of the identifier itself must pass `expected_chain_id`.
When non-`None`, `expected_chain_id` must satisfy the same non-empty,
512-character bound as artifact `chain_id`; invalid scope input fails before
checkpoint parsing or provider invocation. If no explicit scope is supplied
and the evidence cannot establish one internally valid `chain_id`, parsed
chain checkpoints remain `NOT_EVALUATED` rather than selecting a scope from
untrusted input.

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

`SignatureMetadata` retains its exact existing keys and schema version. Its
three related discriminator fields are validated as one closed tuple, never as
independent allowlists:

| Payload type | Signing profile | Metadata `canonicalization_version` |
| --- | --- | --- |
| `audit_artifact` | `aegis-signature-v1` | `aegis-canonical-json-v1` |
| `chain_checkpoint` | `aegis-chain-checkpoint-v1` | `aegis-json-v2` |
| `workflow_checkpoint` | `aegis-workflow-checkpoint-v1` | `aegis-json-v2` |

The first row and its signing bytes remain valid byte-for-byte. Every other
combination is rejected before provider invocation. A checkpoint record must
also satisfy these cross-field invariants:

- `checkpoint_profile == signature_metadata.signing_profile`.
- `canonicalization_profile ==
  signature_metadata.canonicalization_version`.
- The record type, metadata `payload_type`, and selected tuple row agree.
- `checkpointed_at == signature_metadata.signed_at`.

Checkpoint creation uses an internal profile-specific metadata constructor;
it does not weaken the existing audit-artifact constructor or accept
caller-selected discriminator combinations.
The tuple matrix governs the typed #44 metadata passed to providers. It does
not remove or reinterpret the existing finalizer-level
`canonicalization_profile` field in signed audit and workflow artifacts.

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

Checkpoint signatures use a dedicated `CheckpointSignatureStatus` enum with
`NOT_EVALUATED`, `VALID`, `INVALID`, `UNKNOWN_KEY`, `REVOKED`, and
`INDETERMINATE`. It deliberately has no `UNSIGNED` state because a checkpoint
record always contains a signature; absence of a record is not an unsigned
record.

`checkpoint_results` contains immutable `CheckpointVerificationResult`
wrappers rather than bare #44 results. Each wrapper contains:

- all caller input indexes represented by an exact-record deduplication;
- the parsed checkpoint record;
- its scope identifier (`chain_id` or `session_id`);
- its chain coordinate when applicable;
- the optional #44 `ArtifactVerificationResult` for its signature; and
- a `CheckpointBindingStatus` of `NOT_EVALUATED`, `MATCHED`, `HISTORICAL`,
  `PARTIAL`, `OUTSIDE`, `AHEAD`, `CONFLICT`, or `OUT_OF_SCOPE`.

The #44 result is absent only when a parsed record is out of scope, or when no
trusted chain scope can be established, and is therefore deliberately not sent
to the provider. The wrapper separates cryptographic/provider assurance from
the record's relationship to the supplied evidence. `MATCHED` means an exact
terminal chain head or exact workflow binding. `HISTORICAL` means an earlier
matching prefix, `PARTIAL` means a matching coordinate in a chain whose prefix
from zero was not supplied, `OUTSIDE` means the coordinate precedes the
supplied partial-chain window and cannot be compared, and `AHEAD` means the
checkpoint claims a later trusted head.
Structural binding is computed for every parseable in-scope checkpoint,
independently of its provider outcome, but only a signature reported as
externally anchored may promote or contradict completeness.

Aggregate checkpoint statuses consider parse failures and in-scope records;
`OUT_OF_SCOPE` records cannot promote or degrade assurance for the target.
Trusted conflicts still override successful matches. With no in-scope
checkpoint and no malformed or unsupported checkpoint input,
`checkpoint_results` may contain out-of-scope diagnostics but
`checkpoint_signature_status` and `checkpoint_anchor_status` are both
`NOT_EVALUATED`.

Aggregation is deterministic and retains full detail in `checkpoint_results`.
For signatures, the precedence is `INDETERMINATE`, `INVALID`, `REVOKED`,
`UNKNOWN_KEY`, `VALID`, then `NOT_EVALUATED`. For anchors, the precedence is
`INVALID`, `NOT_EVALUATED`, `UNANCHORED`, then `ANCHORED`. A malformed record or
provider contract failure therefore makes the signature aggregate
`INDETERMINATE`; malformed input also makes the anchor aggregate `INVALID`.
The same-named #44 signature outcomes map directly to checkpoint signature
statuses. A provider-reported `UNSIGNED` outcome is contextually impossible for
a checkpoint record and is a provider contract failure.
An externally anchored `CONFLICT`, including conflict between two trusted
records, overrides the checkpoint anchor aggregate to `INVALID` even though
the provider reported each underlying anchor as valid.
Completeness can become `CHECKPOINT_PROVEN` only when every parseable in-scope
record has a valid signature, is externally anchored, and is mutually
consistent, with at least one terminal `MATCHED` record. Any externally
anchored `CONFLICT` record, or an `AHEAD` record compared with an otherwise
valid full chain beginning at index zero, makes completeness `CONTRADICTED`
even if another record matches.

A malformed or unsupported supplied checkpoint has no per-record result. It
adds a bounded error, forces aggregate `checkpoint_signature_status` to
`INDETERMINATE` and `checkpoint_anchor_status` to `INVALID`, and prevents any
completeness promotion. Completeness remains `UNPROVEN` because untrusted input
cannot prove a contradiction. Only a successfully verified external anchor
that conflicts with supplied evidence can produce `CONTRADICTED`.

For source compatibility, all new report fields are appended after the current
fields and have defaults: checkpoint signature `NOT_EVALUATED`, checkpoint
anchor `NOT_EVALUATED`, and an empty result tuple. Existing positional and
keyword construction of `ChainVerificationReport` and
`WorkflowVerificationReport` therefore remains valid.

The existing chain `anchor_status` continues to describe artifact-signature or
compatibility callback anchoring. It cannot be interpreted as checkpoint
assurance. The deprecated `anchor_verifier` may continue affecting that
compatibility axis, but it cannot change `checkpoint_anchor_status` or promote
completeness.

## Verification flow

Verification proceeds as follows:

1. Materialize the chain-checkpoint iterable and workflow-invocation iterable
   within their raw supplied-element limits. Chain artifacts retain the
   existing exact-list input contract and are rejected above their count
   limit; the singular workflow checkpoint is measured directly.
2. Measure the complete source-evidence and checkpoint input graph under one
   aggregate byte, depth, node, and cycle budget before checksum traversal,
   canonicalization, or provider invocation.
3. Independently verify chain or workflow evidence.
4. Parse the exact record schema.
5. Reject unsupported versions and cross-type records.
6. Resolve the target scope and mark unrelated records `OUT_OF_SCOPE` without
   invoking the provider for them.
7. Canonicalize exact payload bytes.
8. Invoke the external verifier once per unique, parseable, in-scope
   checkpoint.
9. Validate its closed #44 outcome.
10. Compare externally anchored checkpoints with the supplied evidence.
11. Aggregate statuses and bounded errors.

Exact duplicate checkpoints are canonicalized and verified once, with every
original input position retained on the result wrapper. Deduplication reduces
provider calls but never the raw input count. Repetition adds no assurance.
Malformed, revoked, unknown-key, unavailable, or conflicting in-scope supplied
checkpoints cannot be hidden by another successful checkpoint.

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
| Parsed checkpoint is outside the selected `chain_id` scope | `NOT_EVALUATED` for that record | No effect; bounded scope error |
| Invalid signature, unknown or revoked key, or unavailable verifier | Typed outcome; no trust promotion | `UNPROVEN` |

A stale checkpoint proves only its historical prefix. It cannot prove
completeness for a longer supplied chain. A partial chain beginning after index
`0` may be externally matched, but cannot receive global `CHECKPOINT_PROVEN`
completeness. A checkpoint before the supplied partial window is `OUTSIDE` and
cannot establish whether the missing prefix matches; a checkpoint after that
window is `AHEAD` but does not contradict completeness because the supplied
evidence was already partial.

An internally valid whole-chain replacement remains internally valid but
becomes `CONTRADICTED` when its checksum conflicts with an anchored checkpoint.
If the replacement also changes `chain_id`, that conclusion requires the host
to pass the original logical identifier as `expected_chain_id`.

## Multiple checkpoints, rotation, and revocation

Chain checkpoints are treated as an unordered set.

- The raw iterable is consumed only through the bounded element immediately
  after the limit; infinite duplicate streams cannot reach deduplication
  unboundedly.
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
- Records at different coordinates are compared through the supplied chain's
  links. Without the intervening chain evidence, the checkpoint records alone
  do not prove whether two nonadjacent coordinates share one history.

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

Missing, duplicate, extra selected same-session, or reordered supplied
invocation evidence makes `claim_status` `INVALID`. Unrelated well-formed
invocations from other sessions retain B4's existing filtering behavior.
Without an externally anchored matching workflow checkpoint, completeness
remains `UNPROVEN`. With an externally anchored checkpoint that exactly binds
the workflow's authoritative B4 claim, the same supplied-evidence mismatch
makes completeness `CONTRADICTED`: the trusted claim and the evidence presented
for it cannot both be complete. The anchor does not repair or validate the
supplied invocation set.

## Replay behavior

- Repeating the same checkpoint adds no assurance.
- A stale chain checkpoint cannot prove a later head.
- A checkpoint whose `chain_id` differs from the selected chain scope is
  `OUT_OF_SCOPE`, is not sent to the provider, and cannot contradict or promote
  the target. If `expected_chain_id` names the scope and the supplied evidence
  claims a different identifier, a verified in-scope checkpoint can contradict
  that evidence.
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
`VerificationError` entries. Stable checkpoint verification codes include
`CHECKPOINT_INPUT_INVALID`, `CHECKPOINT_LIMIT_EXCEEDED`,
`CHECKPOINT_SCOPE_INVALID`, `CHECKPOINT_SCOPE_MISMATCH`,
`CHECKPOINT_RECORD_INVALID`, `CHECKPOINT_VERIFICATION_ERROR`, and
`CHECKPOINT_BINDING_CONFLICT`. Errors identify only a bounded caller input
index or trusted structural category; they do not echo record values.

Provider exceptions, raw provider messages, payload bytes, signatures,
credentials, secret material, and untrusted artifact field values never appear
in core-generated messages, details, or logs. Unparseable checkpoint data never
reaches the external verifier.

## Resource limits

- Maximum 1,024 chain artifacts per verification call.
- Maximum 64 total supplied chain checkpoint elements per verification call,
  including malformed and duplicate elements. Detecting overflow performs at
  most one additional iterator read and then stops.
- Maximum one workflow checkpoint per workflow verification call.
- Maximum 1,024 workflow claimed-set entries and maximum 1,024 supplied
  workflow invocation elements.
- Maximum 4 MiB aggregate measured input per verification call, covering the
  full chain artifact list plus all checkpoint records, or the workflow plus
  supplied invocation artifacts plus its checkpoint.
- Maximum nesting depth of 32 per measured JSON document.
- Maximum 65,536 aggregate measured nodes.
- Maximum 100 returned verification errors.
- Maximum one artifact-signature verifier call per chain artifact after the
  aggregate preflight succeeds.
- Maximum one checkpoint-verifier call per unique, parseable, in-scope
  checkpoint.

Oversized, cyclic, custom-container, non-string-key, or non-JSON input fails
before checksum or continuity traversal, canonicalization, any artifact or
checkpoint provider invocation, or the compatibility anchor callback. Limit
failure returns a bounded typed error. It leaves completeness `UNPROVEN` and
leaves unevaluated axes in their `NOT_EVALUATED` or `INDETERMINATE` state. The
independent raw limit of 64 chain checkpoints prevents duplicate and malformed
streams from exhausting work before deduplication.

## Authority and provenance boundary

`CHECKPOINT_PROVEN` is relative to an in-scope checkpoint supplied by the host
and reported as anchored by the configured verifier. AEGIS verifies the
record's signature, external-anchor outcome, and binding to supplied evidence;
it does not prove that the host retrieved the latest record, selected the
correct logical chain, obtained it from protected storage, or supplied every
authoritative checkpoint.

The host owns authenticated retrieval, rollback protection, checkpoint-set
selection, retention, and storage provenance. Omitting a later checkpoint can
reduce assurance to `UNPROVEN`; AEGIS cannot infer the omitted record. Explicit
`expected_chain_id` is the mechanism for binding chain verification to a
host-selected logical scope. Workflow verification treats its singular
`expected_checkpoint` as the host-selected authority for that workflow, so an
externally anchored session mismatch is a contradiction rather than an
out-of-scope set member.

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
- Raw duplicate/malformed checkpoint stream bounds and aggregate chain-artifact
  preflight limits.
- Field and link mutation.
- Deletion, insertion, and reordering.
- Duplicate and stale replay.
- Partial chains.
- Tail truncation.
- Complete internally valid chain replacement.
- Conflicting anchored checkpoints.
- Out-of-scope chain checkpoints, explicit logical-chain scope, and chain-ID
  replacement with and without `expected_chain_id`.
- Workflow session, status, count, index, invocation-checksum, and
  workflow-checksum mutation.
- Workflow deletion, insertion, reordering, incomplete supplied evidence,
  replay, and complete replacement.
- Invocation/checkpoint and chain/workflow cross-type replay.
- Every relevant adversarial scenario both without an external checkpoint and
  with one.
- Compatibility for existing calls without checkpoints.
- Compatibility for direct construction of the existing report dataclasses.
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

Maintained documentation distinguishes:

- Tamper-evidence from external anchoring.
- External anchoring from append-only or WORM storage.
- Checkpoint-relative completeness from proof of all future activity.
- Host-observed time from trusted timestamp evidence.
- Security assurance from certification or compliance.
- Signature validity from host-controlled checkpoint provenance, freshness,
  and authoritative-set selection.

Detailed storage operations and lifecycle guidance remain in #47.

## Adversarial design review

The consolidated design has undergone two review rounds. The current revision
resolves these identified risks:

1. `SignatureMetadata` now has an exact compatibility matrix and cross-field
   invariants instead of independent profile allowlists.
2. Incomplete supplied workflow evidence has explicit `INVALID` and
   `UNPROVEN`/`CONTRADICTED` outcomes depending on anchored authority.
3. The chain-checkpoint cap applies to raw consumed elements before
   deduplication.
4. Chain artifacts and checkpoints share a bounded aggregate preflight before
   traversal or provider calls.
5. Unrelated chain checkpoints are out of scope, while `expected_chain_id`
   preserves detection of logical-chain identifier replacement.
6. Checkpoint absence is `NOT_EVALUATED`, not `UNSIGNED`.
7. `CheckpointVerificationResult` records both the #44 provider result and the
   evidence-binding relationship.
8. New report fields are appended with defaults to preserve construction
   compatibility.
9. `CHECKPOINT_PROVEN` is explicitly relative to host-supplied authoritative
   records; storage provenance and freshness remain host responsibilities.

The amended text then underwent two fresh adversarial passes. Those passes
also made mixed-outcome aggregation deterministic, prevented invalid evidence
from selecting chain scope, covered coordinates outside a supplied partial
window, preserved exact existing iterable contracts, and made public exports
and serialization behavior explicit.

No section relies on AEGIS-owned storage, treats host time as trusted, lets
artifact signatures prove chain completeness, permits cross-type fallback, or
lets an unrelated checkpoint degrade a selected chain.

## Acceptance-criteria mapping

| Issue #46 acceptance criterion | Design coverage |
| --- | --- |
| Creation and verification use #44 contracts | Extension of the #44 contracts; creation and verification flows |
| Distinguish unanchored from checkpoint-validated chains | Independent checkpoint report axes and chain semantics |
| Detect internally valid whole-chain replacement | Chain checkpoint semantics and adversarial tests |
| Detect replacement of the logical chain identifier | `expected_chain_id`, scope semantics, and adversarial tests |
| Workflow-specific non-replayable domain | Workflow record and domain-separated payload |
| Detect workflow field mutation | Workflow binding rules and test strategy |
| Cover rotation and historical verification | Multiple checkpoints, rotation, and revocation |
| Cover mutation, deletion, insertion, reordering, replay, and replacement | Test strategy and deterministic semantics |
| Typed bounded failures for unsupported or malformed evidence | Errors, failure containment, and resource limits |

## Completion criteria

Issue #46 was implemented with these completion conditions satisfied:

- Both record contracts and public creators are implemented.
- Chain and workflow verification consume the typed checkpoints.
- Exact signing-domain vectors are frozen.
- Adversarial coverage maps to every issue acceptance criterion.
- Existing no-checkpoint behavior remains compatible.
- Maintained security and integration documentation describes the new assurance
  boundary without claiming immutable storage, trusted time, certification, or
  compliance.
- The complete test suite and security-boundary checks pass.
