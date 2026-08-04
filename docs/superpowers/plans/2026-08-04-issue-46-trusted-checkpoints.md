# Trusted Checkpoints and Adversarial Anchor Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit provider-neutral APIs that create signed chain and
workflow checkpoint records for host-owned storage and use those records to
detect chain or finalized-workflow replacement without conflating internal
validity, signature validity, anchoring, and completeness.

**Architecture:** Add immutable checkpoint records and public creators in a
new `aegis.checkpoints` boundary. Reuse the #44 signer/verifier protocols and
normalized outcomes, while keeping checkpoint signing domains and binding
results separate from artifact signatures. Extract shared verification
contracts and bounded JSON-input machinery so chain and workflow verification
can preflight all supplied evidence before traversal or provider invocation.

**Tech Stack:** Python 3.10+, frozen dataclasses, enums, RFC 8785 through the
existing `aegis-json-v2` canonicalizer, `hashlib`, existing `jsonschema`
validators, pytest, and standard-library deterministic HMAC test doubles.

## Global Constraints

- Work only in the existing isolated branch/worktree
  `codex/issue-46-trusted-checkpoints`.
- Run every command from that worktree root. Test commands use the repository
  environment at `../../.venv/bin/python`, which is already populated and was
  used for the verified baseline.
- Before implementation, invoke `superpowers:test-driven-development` and read
  its required good-test guidance; every behavior change follows a witnessed
  red/green cycle.
- Use `apply_patch` for source, test, plan, and documentation edits.
- Checkpoint creation remains an explicit provider-neutral API. It returns a
  signed record and never stores, emits, publishes, retries, discovers keys,
  loads credentials, or performs network I/O.
- Hosts own checkpoint storage, authenticated retrieval, authoritative-set
  selection, freshness, rollback protection, retention, and provenance.
- Preserve the existing #44 audit tuple byte-for-byte:
  `("audit_artifact", "aegis-signature-v1",
  "aegis-canonical-json-v1")`.
- Add only the closed checkpoint tuples
  `("chain_checkpoint", "aegis-chain-checkpoint-v1", "aegis-json-v2")`
  and
  `("workflow_checkpoint", "aegis-workflow-checkpoint-v1",
  "aegis-json-v2")`; reject every mixed tuple before provider invocation.
- The only excluded checkpoint signing field is top-level `signature`;
  `signature_metadata` is inside the canonical signed record.
- `checkpointed_at` is a non-negative host-observed Unix second and equals
  `signature_metadata.signed_at`; it is not trusted timestamp evidence.
- Preserve no-checkpoint behavior and direct positional/keyword construction
  of existing verification report dataclasses.
- Chain artifacts remain an exact `list`; chain checkpoints accept a bounded
  iterable; workflow invocations retain their existing ordered-iterable
  contract; workflow checkpoints remain singular.
- Verification limits are: 1,024 chain artifacts; 64 total raw chain
  checkpoint elements; one workflow checkpoint; 1,024 workflow claim entries;
  1,024 supplied workflow artifacts; 4 MiB aggregate bytes; depth 32 per JSON
  document; 65,536 aggregate nodes; and 100 returned errors.
- A verification-limit failure occurs before checksum/continuity work,
  canonicalization, artifact or checkpoint verifier calls, and the deprecated
  compatibility anchor callback.
- Never expose provider exceptions/messages, payload bytes, signatures,
  credentials, secret material, key material, or untrusted field values in
  AEGIS-generated errors, details, or logs.
- Verification may call the checkpoint verifier at most once per unique,
  parseable, in-scope record. Deduplication never reduces the raw input-count
  budget.
- No new runtime dependency or provider adapter is part of issue #46.
- Before presenting any implementation result, perform two independent
  adversarial reviews and run fresh verification commands.

## File Structure

### New production files

- `aegis/checkpoints.py` — public checkpoint records, statuses, result wrapper,
  and creators facade.
- `aegis/_internal/checkpoint_models.py` — exact immutable record schemas,
  checkpoint-specific enums, result wrappers, cross-field validation, and
  JSON-native round trips.
- `aegis/_internal/checkpoint_signing.py` — source validation, profile-specific
  metadata construction, canonical signing bytes, signer receipt validation,
  and the two explicit creation APIs.
- `aegis/_internal/checkpoint_verification.py` — common bounded checkpoint
  preparation, detached reparsing, deduplication, signed-payload verification,
  and deterministic aggregation.
- `aegis/_internal/chain_checkpoint_verification.py` — chain scope selection,
  coordinate binding, multiple-record conflict handling, and chain
  completeness evaluation.
- `aegis/_internal/workflow_checkpoint_verification.py` — singular workflow
  binding and workflow completeness evaluation.
- `aegis/_internal/verification_contracts.py` — cycle-free home for the existing
  shared `Completeness` and `VerificationError` contracts.
- `aegis/_internal/verification_limits.py` — iterative JSON measurement,
  bounded iterable consumption, aggregate budgets, and bounded error storage.
- `docs/decisions/ADR-0015-trusted-checkpoints.md` — accepted architectural
  decision and assurance boundary.

### New tests

- `tests/test_checkpoint_models.py` — exact record shape, immutability,
  round-trip, metadata matrix, and hostile parsing.
- `tests/test_checkpoint_creation.py` — source validation, frozen payload
  vectors, receipt pinning, atomic failure, and provider neutrality.
- `tests/test_checkpoint_verification_boundary.py` — prepared-payload verifier,
  limits, deduplication, aggregation, provider failures, and redaction.
- `tests/test_chain_checkpoint_verification.py` — chain binding, truncation,
  replacement, partial windows, multiple checkpoints, scope, and rotation.
- `tests/test_workflow_checkpoint_verification.py` — finalized workflow binding,
  supplied-set contradiction, cross-session replay, and mutation.
- `tests/test_checkpoint_public_api.py` — public identity, exports, report
  constructor compatibility, and architecture boundaries.

### Existing production files to modify

- `aegis/_internal/signature_models.py` — add the two evidence types and replace
  independent fixed-value checks with the exact three-row compatibility map.
- `aegis/_internal/external_signing.py` — extract one reusable prepared-payload
  verification helper while preserving all audit signing bytes and behavior.
- `aegis/_internal/errors.py` and `aegis/errors.py` — add and export
  `CheckpointError`.
- `aegis/_internal/verification.py` — bound chain input, append checkpoint
  report fields with defaults, and integrate prepared chain checkpoint
  evaluation.
- `aegis/_internal/workflow_verification.py` — use shared budgets, append report
  defaults, and integrate the singular workflow checkpoint.
- `aegis/audit_chain.py`, `aegis/workflow_verification.py`, and
  `aegis/__init__.py` — preserve existing re-exports and add the approved
  checkpoint public surface.

### Existing tests and docs to modify

- `tests/test_signature_models.py`, `tests/test_external_signing.py`,
  `tests/test_typed_chain_verification.py`,
  `tests/test_workflow_claimed_set_verifier.py`, `tests/test_public_api.py`,
  `tests/test_architecture_security_boundaries.py`, and
  `tests/test_doc_parity_v090_truth.py` — compatibility and boundary coverage.
- `tests/support/external_signing.py` — add call capture and explicit anchored
  historical-key fixtures without changing current default outcomes.
- `README.md`, `CHANGELOG.md`, `docs/USAGE.md`,
  `docs/INTEGRATION_GUIDE.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md`,
  `docs/migration.md`, `docs/architecture/AEGIS_THREAT_MODEL.md`, and
  `docs/architecture/ARCHITECTURAL_INVARIANTS.md` — maintained public guidance
  and security truth.

---

### Task 1: Extend the closed #44 signature-metadata domain

**Files:**

- Modify: `aegis/_internal/signature_models.py:19-33,205-248`
- Modify: `tests/test_signature_models.py:36-49,66-85,193-245`
- Modify: `tests/test_external_signing.py:44-169`

**Interfaces:**

- Consumes: existing `SignatureMetadata`, `EvidenceType`,
  `SIGNATURE_METADATA_SCHEMA_VERSION`, `SIGNING_PROFILE`, and
  `CANONICALIZATION_VERSION`.
- Produces: `EvidenceType.CHAIN_CHECKPOINT`,
  `EvidenceType.WORKFLOW_CHECKPOINT`, `CHAIN_CHECKPOINT_SIGNING_PROFILE`,
  `WORKFLOW_CHECKPOINT_SIGNING_PROFILE`,
  `CHECKPOINT_CANONICALIZATION_VERSION`, and exact tuple validation in
  `SignatureMetadata`.

- [ ] **Step 1: Add failing compatibility-matrix tests**

```python
CHECKPOINT_CASES = (
    (
        EvidenceType.CHAIN_CHECKPOINT,
        "aegis-chain-checkpoint-v1",
        "aegis-json-v2",
    ),
    (
        EvidenceType.WORKFLOW_CHECKPOINT,
        "aegis-workflow-checkpoint-v1",
        "aegis-json-v2",
    ),
)


@pytest.mark.parametrize("payload_type,profile,canonicalization", CHECKPOINT_CASES)
def test_metadata_accepts_only_closed_checkpoint_tuple(
    payload_type, profile, canonicalization
):
    metadata = _metadata(
        payload_type=payload_type,
        signing_profile=profile,
        canonicalization_version=canonicalization,
    )
    assert SignatureMetadata.from_dict(metadata.to_dict()) == metadata


@pytest.mark.parametrize("payload_type,profile,canonicalization", [
    (EvidenceType.AUDIT_ARTIFACT, "aegis-chain-checkpoint-v1", "aegis-json-v2"),
    (EvidenceType.CHAIN_CHECKPOINT, "aegis-signature-v1", "aegis-json-v2"),
    (EvidenceType.CHAIN_CHECKPOINT, "aegis-chain-checkpoint-v1",
     "aegis-canonical-json-v1"),
    (EvidenceType.WORKFLOW_CHECKPOINT, "aegis-chain-checkpoint-v1",
     "aegis-json-v2"),
])
def test_metadata_rejects_cross_profile_tuple(
    payload_type, profile, canonicalization
):
    with pytest.raises(SignatureMetadataError):
        _metadata(
            payload_type=payload_type,
            signing_profile=profile,
            canonicalization_version=canonicalization,
        )
```

- [ ] **Step 2: Run the focused tests and witness the red state**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_signature_models.py::test_metadata_accepts_only_closed_checkpoint_tuple \
  tests/test_signature_models.py::test_metadata_rejects_cross_profile_tuple
```

Expected: FAIL because the checkpoint enum members/constants do not exist and
the constructor accepts only the audit tuple.

- [ ] **Step 3: Implement one exact compatibility map**

```python
CHAIN_CHECKPOINT_SIGNING_PROFILE = "aegis-chain-checkpoint-v1"
WORKFLOW_CHECKPOINT_SIGNING_PROFILE = "aegis-workflow-checkpoint-v1"
CHECKPOINT_CANONICALIZATION_VERSION = "aegis-json-v2"


class EvidenceType(str, Enum):
    AUDIT_ARTIFACT = "audit_artifact"
    CHAIN_CHECKPOINT = "chain_checkpoint"
    WORKFLOW_CHECKPOINT = "workflow_checkpoint"


_SIGNATURE_METADATA_PROFILES = frozenset({
    (EvidenceType.AUDIT_ARTIFACT, SIGNING_PROFILE, CANONICALIZATION_VERSION),
    (
        EvidenceType.CHAIN_CHECKPOINT,
        CHAIN_CHECKPOINT_SIGNING_PROFILE,
        CHECKPOINT_CANONICALIZATION_VERSION,
    ),
    (
        EvidenceType.WORKFLOW_CHECKPOINT,
        WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        CHECKPOINT_CANONICALIZATION_VERSION,
    ),
})
```

Replace the three independent fixed-value checks in
`SignatureMetadata.__post_init__` with membership in that set. Preserve the
existing schema-version, identity, enum, and timestamp validation exactly.

- [ ] **Step 4: Freeze audit compatibility and all mixed-tuple rejection**

Extend the tests to assert the existing audit metadata dictionary and
`_metadata_signing_payload()` frozen bytes remain unchanged. Generate the
Cartesian product of all three evidence types, profiles, and canonicalization
versions and assert exactly the three listed tuples construct successfully.

- [ ] **Step 5: Run the complete signature boundary tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_signature_models.py \
  tests/test_external_signing.py \
  tests/test_external_signing_conformance.py \
  tests/test_external_signing_schema.py
```

Expected: PASS, including the pre-existing audit signing vector.

- [ ] **Step 6: Commit the closed metadata extension**

```bash
git add aegis/_internal/signature_models.py \
  tests/test_signature_models.py tests/test_external_signing.py
git commit -m "feat: extend signature metadata for checkpoints"
```

### Task 2: Add immutable checkpoint record and error contracts

**Files:**

- Create: `aegis/_internal/checkpoint_models.py`
- Create: `aegis/_internal/verification_limits.py`
- Create: `aegis/checkpoints.py`
- Create: `tests/test_checkpoint_models.py`
- Modify: `aegis/_internal/errors.py:221-245`
- Modify: `aegis/errors.py:1-77`
- Modify: `tests/test_errors.py:1-35`

**Interfaces:**

- Consumes: Task 1's checkpoint evidence types/profiles,
  `SignatureMetadata`, `ArtifactVerificationResult`, `AnchorStatus`, and
  `validate_encoded_signature()`.
- Produces the checkpoint public contracts below plus
  `VerificationInputError` and `VerificationBudget` for bounded parsing:

```python
class CheckpointSignatureStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN_KEY = "unknown_key"
    REVOKED = "revoked"
    INDETERMINATE = "indeterminate"


class CheckpointBindingStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    MATCHED = "matched"
    HISTORICAL = "historical"
    PARTIAL = "partial"
    OUTSIDE = "outside"
    AHEAD = "ahead"
    CONFLICT = "conflict"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class TrustedChainCheckpoint:
    checkpoint_schema_version: str
    checkpoint_profile: str
    canonicalization_profile: str
    chain_id: str
    chain_index: int
    chain_length: int
    artifact_schema_version: str
    artifact_checksum: str
    checkpointed_at: int
    signature_metadata: SignatureMetadata
    signature: str

    # Public methods:
    # to_dict() -> dict[str, object]
    # from_dict(value: object) -> TrustedChainCheckpoint


@dataclass(frozen=True, slots=True)
class TrustedWorkflowCheckpoint:
    checkpoint_schema_version: str
    checkpoint_profile: str
    canonicalization_profile: str
    workflow_schema_version: str
    session_id: str
    final_status: str
    step_count: int
    invocations: tuple[tuple[int, str], ...]
    workflow_checksum: str
    checkpointed_at: int
    signature_metadata: SignatureMetadata
    signature: str

    # Public methods:
    # to_dict() -> dict[str, object]
    # from_dict(value: object) -> TrustedWorkflowCheckpoint


CheckpointRecord = TrustedChainCheckpoint | TrustedWorkflowCheckpoint


@dataclass(frozen=True, slots=True)
class CheckpointVerificationResult:
    input_indexes: tuple[int, ...]
    checkpoint: CheckpointRecord
    scope_id: str
    chain_index: int | None
    signature_result: ArtifactVerificationResult | None
    binding_status: CheckpointBindingStatus
```

- [ ] **Step 1: Write failing exact-shape and error-contract tests**

Test that `CheckpointError("safe")` has code `CHECKPOINT_INPUT_INVALID`, that
both record types reject unknown/missing keys, raw enum strings, Boolean
integers, invalid hex checksums, empty/oversized scope IDs, invalid status,
non-gapless workflow claims, metadata/profile/type mismatches,
`checkpointed_at != signed_at`, and invalid encoded signatures.

```python
def test_chain_checkpoint_round_trip_is_exact_and_immutable(chain_record_dict):
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    assert record.to_dict() == chain_record_dict
    assert TrustedChainCheckpoint.from_dict(record.to_dict()) == record
    with pytest.raises(FrozenInstanceError):
        record.chain_index = 9


def test_workflow_checkpoint_detaches_nested_claim(workflow_record_dict):
    source = deepcopy(workflow_record_dict)
    record = TrustedWorkflowCheckpoint.from_dict(source)
    source["invocations"][0]["checksum"] = "f" * 64
    assert record.invocations[0][1] != "f" * 64
```

- [ ] **Step 2: Run the new model tests and witness import failure**

Run: `../../.venv/bin/python -m pytest -q tests/test_checkpoint_models.py tests/test_errors.py`

Expected: FAIL because checkpoint modules and `CheckpointError` do not exist.

- [ ] **Step 3: Add `CheckpointError` with caller-selected stable subcodes**

```python
class CheckpointError(AIGCError):
    """Raised when a checkpoint cannot be created or parsed safely."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "CHECKPOINT_INPUT_INVALID",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
```

Export it from `aegis.errors` and the new `aegis.checkpoints` facade; do not yet
add top-level `aegis` exports.

- [ ] **Step 4: Implement the bounded JSON preflight used by every parser**

Add `VerificationInputError`, `VerificationBudget`, and iterative
`VerificationBudget.measure(value)` to `verification_limits.py`. The initial
implementation enforces 4 MiB, depth 32, and 65,536 nodes without recursion,
truthiness, repr, custom-container methods, or scalar subclasses. It resets its
cycle-detection set for each document while retaining aggregate byte/node
counters. It rejects out-of-range integers, non-finite floats, and lone Unicode
surrogates during measurement so later canonicalization never receives input
outside the strict v2 JSON domain.

```python
@dataclass(slots=True)
class VerificationBudget:
    remaining_bytes: int = 4 * 1024 * 1024
    remaining_nodes: int = 65_536

    def measure(self, value: object) -> int:
        consumed_bytes, consumed_nodes = _measure_json_document(
            value,
            byte_limit=self.remaining_bytes,
            node_limit=self.remaining_nodes,
            depth_limit=32,
        )
        self.remaining_bytes -= consumed_bytes
        self.remaining_nodes -= consumed_nodes
        return consumed_bytes
```

- [ ] **Step 5: Implement exact record parsers and immutable nested storage**

Use `type(value) is dict`, exact key sets, plain JSON scalar checks, safe-integer
bounds from `canonicalization.SAFE_INTEGER_MAX`, 64-character lowercase hex
checksums, exact source schema versions (`artifact_schema_version == "2.0"`
and `workflow_schema_version == "2.0"`), the four workflow terminal statuses,
`chain_length == chain_index + 1`, and ordered gapless workflow pairs. Parse metadata only through
`SignatureMetadata.from_dict()` and validate all four record/metadata
cross-fields before constructing a record. Begin each `from_dict()` with a
fresh `VerificationBudget().measure(value)` and convert
`VerificationInputError` into a sanitized `CheckpointError`.
Use `CHECKPOINT_VERSION_UNSUPPORTED` for a non-`"1"` record version,
`CHECKPOINT_PROFILE_INVALID` for profile/type/canonicalization cross-field
failure, and `CHECKPOINT_INPUT_INVALID` for all other malformed record input.
Reject workflow claims above 1,024 entries before building the immutable tuple.
Route direct dataclass construction through the same invariant checks in
`__post_init__`; `from_dict()` is not the only validation boundary.
Require an exact `SignatureMetadata` instance, snapshot it with the core-owned
`SignatureMetadata.to_dict(metadata)` implementation, and reparse that snapshot
before accepting it. This rejects subclasses and exact instances forged with
`object.__setattr__` without dispatching through attacker-controlled methods.
Both record `to_dict()` implementations must likewise serialize nested
metadata through `SignatureMetadata.to_dict(self.signature_metadata)`, never a
dynamically dispatched `self.signature_metadata.to_dict()` call.

```python
@classmethod
def from_dict(cls, value: object) -> TrustedChainCheckpoint:
    try:
        VerificationBudget().measure(value)
        parsed = _parse_chain_record(value)
    except VerificationInputError as exc:
        raise CheckpointError(
            "Checkpoint record exceeds a configured limit",
            code="CHECKPOINT_INPUT_INVALID",
        ) from exc
    return cls(**parsed)
```

- [ ] **Step 6: Add parser adversaries and non-mutation coverage**

Parametrize missing, extra, subclassed, cyclic, deeply nested, non-string-key,
oversized, type-confused, cross-profile, chain-as-workflow, and
workflow-as-chain inputs. Assert safe error codes/details and deep equality of
the original input after success and failure. Construct a forged record with
`object.__new__`, mutate fields through `object.__setattr__`, and subclass each
record type. Repeat the forged-instance test for nested `SignatureMetadata`;
integrated verification in Tasks 5 and 7 must reserialize exact
base-class instances and reparse them, and must reject subclasses without
trusting overridden methods.

Also validate `CheckpointVerificationResult`: exact non-empty integer input
indexes, exact checkpoint/result/status types, scope ID equality with the
record, `chain_index` present only for chain records, and a `None` signature
result only for `NOT_EVALUATED` or `OUT_OF_SCOPE` binding.

- [ ] **Step 7: Run model/error tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_models.py tests/test_errors.py tests/test_signature_models.py
```

Expected: PASS.

- [ ] **Step 8: Commit the record contracts**

```bash
git add aegis/_internal/checkpoint_models.py \
  aegis/_internal/verification_limits.py aegis/checkpoints.py \
  aegis/_internal/errors.py aegis/errors.py \
  tests/test_checkpoint_models.py tests/test_errors.py
git commit -m "feat: add trusted checkpoint records"
```

### Task 3: Implement explicit checkpoint creation and frozen signing bytes

**Files:**

- Create: `aegis/_internal/checkpoint_signing.py`
- Create: `tests/test_checkpoint_creation.py`
- Modify: `aegis/checkpoints.py`
- Modify: `tests/support/external_signing.py:105-263`

**Interfaces:**

- Consumes: Task 2 records and `VerificationBudget`, the existing
  `ExternalArtifactSigner`,
  `SignerIdentity`, `SigningReceipt`, `_normalize_identity()`,
  `_validate_receipt()`, `_normalized_signature()`, the v2 canonicalizer, and
  existing `_audit_validator()`/`_workflow_validator()` schema validators.
- Produces:

```text
create_chain_checkpoint(
    artifact: object,
    signer: ExternalArtifactSigner,
    *,
    checkpointed_at: int,
) -> TrustedChainCheckpoint

create_workflow_checkpoint(
    workflow: object,
    signer: ExternalArtifactSigner,
    *,
    checkpointed_at: int,
) -> TrustedWorkflowCheckpoint
```

- [ ] **Step 1: Write failing happy-path and frozen-vector tests**

Build finalized v2 invocation/workflow fixtures through existing finalizers,
not handwritten incomplete stand-ins. Assert that creation returns a detached
immutable record and that `signer.payloads` contains exactly one payload.

```python
def test_chain_checkpoint_payload_matches_frozen_vector(chained_artifact):
    signer = DeterministicExternalSigner()
    checkpoint = create_chain_checkpoint(
        chained_artifact, signer, checkpointed_at=1_725_000_000
    )
    assert len(signer.payloads) == 1
    assert signer.payloads[0] == CHAIN_CHECKPOINT_VECTOR
    assert checkpoint.to_dict() == EXPECTED_CHAIN_RECORD


def test_workflow_checkpoint_payload_matches_frozen_vector(finalized_workflow):
    signer = DeterministicExternalSigner()
    checkpoint = create_workflow_checkpoint(
        finalized_workflow, signer, checkpointed_at=1_725_000_001
    )
    assert signer.payloads[0] == WORKFLOW_CHECKPOINT_VECTOR
    assert checkpoint.to_dict() == EXPECTED_WORKFLOW_RECORD
```

- [ ] **Step 2: Run the vector tests and witness missing creators**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_creation.py::test_chain_checkpoint_payload_matches_frozen_vector \
  tests/test_checkpoint_creation.py::test_workflow_checkpoint_payload_matches_frozen_vector
```

Expected: FAIL because the creators are not exported.

- [ ] **Step 3: Implement profile-specific metadata and payload construction**

```python
_SIGNATURE_DOMAIN = b"AEGIS-SIGNATURE\x00"


def _checkpoint_payload(
    unsigned_record: dict[str, object], metadata: SignatureMetadata
) -> bytes:
    signable = dict(unsigned_record)
    signable.pop("signature", None)
    signable["signature_metadata"] = metadata.to_dict()
    return (
        _SIGNATURE_DOMAIN
        + metadata.signing_profile.encode("utf-8")
        + b"\x00"
        + metadata.payload_type.value.encode("utf-8")
        + b"\x00"
        + canonicalize_v2(signable).data
    )
```

Construct metadata only from a core-normalized identity and the creator's
fixed record type/profile. Never accept profile, evidence type, key reference,
key version, or algorithm as creator arguments.
Make `_checkpoint_payload()` validate that record profile,
canonicalization profile, metadata tuple, record type, and signed time agree;
Task 5 and Task 7 must reuse this one function for verification payloads.

- [ ] **Step 4: Implement chain source validation and atomic signing**

Require a plain schema-valid/checksum-valid v2 invocation artifact with all
four valid chain coordinates. Copy `chain_id`, `chain_index`, `checksum`, and
schema version; derive `chain_length = chain_index + 1`. Prepare immutable
identity, retain that trusted copy for metadata and receipt comparison, pass a
separate disposable `SignerIdentity` copy to `signer.sign()`, sign once,
require an exact receipt echo against the retained copy, validate encoding,
then construct the record only after every step succeeds.

```python
VerificationBudget().measure(artifact)
if (
    type(artifact) is not dict
    or not _audit_validator().is_valid(artifact)
    or verify_content_checksum_v2(artifact) is not ContentIntegrity.VALID
    or not _valid_chain_source(artifact)
):
    raise CheckpointError(
        "Chain checkpoint source is invalid",
        code="CHECKPOINT_SOURCE_INVALID",
    )
```

Catch `VerificationInputError` and return only a sanitized
`CheckpointError(code="CHECKPOINT_INPUT_INVALID")`; do not enter schema,
checksum, identity, or signer code after a limit failure.
After the receipt is validated, attach `signature_metadata` and `signature` to
the detached dictionary and return
`TrustedChainCheckpoint.from_dict(signed_record)` so
creation and stored-record parsing share one final invariant gate. Apply the
same final construction rule to workflow checkpoints.

- [ ] **Step 5: Implement workflow source validation and atomic signing**

Require a plain schema-valid/checksum-valid finalized v2 workflow with terminal
status and an exact gapless B4 `invocations` claim. Copy only schema version,
session, status, step count, ordered pairs, and final checksum. Do not copy
legacy `steps`, convenience checksum arrays, metadata, failures, or timestamps
other than the explicit `checkpointed_at`.

```python
claim = tuple(
    (entry["step_index"], entry["checksum"])
    for entry in workflow["invocations"]
)
unsigned_record = {
    "checkpoint_schema_version": "1",
    "checkpoint_profile": WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    "canonicalization_profile": "aegis-json-v2",
    "workflow_schema_version": workflow["workflow_schema_version"],
    "session_id": workflow["session_id"],
    "final_status": workflow["status"],
    "step_count": workflow["step_count"],
    "invocations": [
        {"step_index": index, "checksum": checksum}
        for index, checksum in claim
    ],
    "workflow_checksum": workflow["checksum"],
    "checkpointed_at": checkpointed_at,
}
```

- [ ] **Step 6: Add adversarial creation tests**

Cover wrong artifact type, unchained invocation, checksum/schema mutation,
Boolean coordinates/time, malformed/gapped workflow claim, incomplete source,
identity exception, non-identity, receipt exception, non-receipt, receipt
rotation, signature encoding failure, mutation of disposable identity, and all
`SENSITIVE_CORPUS` values. For every failure assert source deep equality,
zero returned record, no storage/sink callback, and sanitized error/log text.
Map invalid source evidence to `CHECKPOINT_SOURCE_INVALID` and every
identity/sign/receipt/signature failure to `CHECKPOINT_SIGNING_ERROR`, chaining
the provider exception only as the private cause.

- [ ] **Step 7: Run creation and existing signing tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_creation.py \
  tests/test_external_signing.py \
  tests/test_evidence_finalizer_signing.py
```

Expected: PASS.

- [ ] **Step 8: Commit the explicit creators**

```bash
git add aegis/_internal/checkpoint_signing.py aegis/checkpoints.py \
  tests/test_checkpoint_creation.py tests/support/external_signing.py
git commit -m "feat: create signed checkpoint records"
```

### Task 4: Extract shared verification contracts, limits, and provider boundary

**Files:**

- Create: `aegis/_internal/verification_contracts.py`
- Modify: `aegis/_internal/verification_limits.py`
- Create: `tests/test_checkpoint_verification_boundary.py`
- Modify: `aegis/_internal/verification.py:72-108,490-554`
- Modify: `aegis/_internal/workflow_verification.py:24-176,472-624`
- Modify: `aegis/_internal/external_signing.py:384-503`
- Modify: `aegis/audit_chain.py:13-19`
- Modify: `tests/test_external_signing.py:560-1110`
- Modify: `tests/test_typed_chain_verification.py`
- Modify: `tests/test_workflow_claimed_set_verifier.py:384-710`

**Interfaces:**

- Consumes: Task 2's `VerificationInputError`/`VerificationBudget`, existing
  `Completeness`, `VerificationError`, workflow iterative measurement,
  `_normalize_external_outcome()`, and `ExternalArtifactVerifier`.
- Produces bounded materialization/error collection and prepared-payload
  verification:

```text
materialize_bounded_iterable(
    value: object,
    *,
    max_items: int,
    reject_mappings: bool = True,
) -> list[object]

BoundedVerificationErrors.append(error: VerificationError) -> None

_verify_prepared_payload_detailed(
    payload: bytes,
    signature: str,
    metadata: SignatureMetadata,
    verifier: ExternalArtifactVerifier | None,
) -> ArtifactVerificationResult
```

- [ ] **Step 1: Add failing extraction and preflight-order tests**

Test that existing `Completeness`/`VerificationError` public identities remain
the same after extraction, the budget counts aggregate bytes/nodes, nesting is
limited per document, cycles/custom containers/non-string keys fail, bounded
materialization performs at most `max_items + 1` reads without `len()` or
`__length_hint__`, and all 101st+ errors are dropped.

Also add a regression test proving workflow invocation preflight completes
before the workflow artifact signature verifier is called.

- [ ] **Step 2: Run focused tests and witness missing shared primitives**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_verification_boundary.py \
  tests/test_typed_chain_verification.py \
  tests/test_workflow_claimed_set_verifier.py
```

Expected: FAIL on the new imports/preflight-order assertion.

- [ ] **Step 3: Move shared contracts without changing public identity**

Move the existing definitions verbatim to `verification_contracts.py`, import
them into `verification.py` and `workflow_verification.py`, and continue
re-exporting them through `aegis.audit_chain`, `aegis.workflow_verification`,
and `aegis`. Existing callers importing from `_internal.verification` must also
continue to resolve because that module imports the names.

```python
class Completeness(str, Enum):
    UNPROVEN = "unproven"
    CHECKPOINT_PROVEN = "checkpoint_proven"
    CONTRADICTED = "contradicted"


@dataclass(frozen=True, slots=True)
class VerificationError:
    code: str
    message: str
    index: int | None = None
```

- [ ] **Step 4: Extend the iterative budget with bounded materialization and errors**

Retain Task 2's byte/node/depth measurement. Add bounded iterable
materialization and error collection, porting current workflow behavior. Do not
call user truthiness, length hints, repr, or string formatting. Convert only
internal exceptions to caller-specific fixed `VerificationError` codes.
Preserve `WORKFLOW_VERIFICATION_LIMIT_EXCEEDED` for any workflow aggregate
budget failure. Use `CHAIN_VERIFICATION_LIMIT_EXCEEDED` for chain artifact or
chain aggregate byte/node/depth failures; the checkpoint iterable's own raw
count limit uses `CHECKPOINT_LIMIT_EXCEEDED`.

```python
items: list[object] = []
iterator = iter(value)
while True:
    try:
        item = next(iterator)
    except StopIteration:
        return items
    if len(items) >= max_items:
        raise VerificationInputError
    items.append(item)
```

- [ ] **Step 5: Refactor workflow and chain preflight ordering**

Keep the chain outer input an exact list. Measure the chain list before
`_verify_content()`, `_verify_continuity()`, `_verify_signatures()`, or the
compatibility callback. Task 5 will extend that same preflight to the new
checkpoint iterable. For workflows, measure the workflow, materialize and
measure supplied invocations, and measure the existing placeholder checkpoint
input before `_verify_signatures()`.

```python
budget = VerificationBudget()
budget.measure(artifacts)
# Only after measurement succeeds may checksum/signature verification begin.
```

- [ ] **Step 6: Extract prepared-payload verification**

Move the provider-call and normalized-outcome portion of
`verify_artifact_detailed()` into `_verify_prepared_payload_detailed()`. The
helper must make a disposable metadata copy, return the fixed unavailable
outcome when the verifier is absent, reject `UNSIGNED`/legacy/missing-metadata
external outcomes, normalize provider messages to core-owned strings, and
sanitize exceptions. Keep audit artifact parsing and audit signing-payload
construction in `verify_artifact_detailed()`.

```python
if verifier is None:
    return ArtifactVerificationResult(
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
        _SAFE_REASON_MESSAGES[VerificationReasonCode.VERIFIER_UNAVAILABLE],
        metadata,
    )
disposable_metadata = SignatureMetadata.from_dict(metadata.to_dict())
try:
    outcome = verifier.verify(payload, signature, disposable_metadata)
except Exception as exc:
    raise VerificationContractError(
        "External verifier failed unexpectedly", details={}
    ) from exc
return _normalize_external_outcome(outcome, metadata)
```

- [ ] **Step 7: Prove no #44 regression**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_external_signing.py \
  tests/test_external_signing_conformance.py \
  tests/test_typed_chain_verification.py \
  tests/test_workflow_claimed_set_verifier.py \
  tests/test_checkpoint_verification_boundary.py
```

Expected: PASS, including frozen audit payload vectors, provider-call counts,
and prior no-checkpoint reports.

- [ ] **Step 8: Commit the shared verification foundation**

```bash
git add aegis/_internal/verification_contracts.py \
  aegis/_internal/verification_limits.py \
  aegis/_internal/external_signing.py aegis/_internal/verification.py \
  aegis/_internal/workflow_verification.py aegis/audit_chain.py \
  tests/test_checkpoint_verification_boundary.py \
  tests/test_external_signing.py tests/test_typed_chain_verification.py \
  tests/test_workflow_claimed_set_verifier.py
git commit -m "refactor: share bounded verification primitives"
```

### Task 5: Integrate one chain checkpoint without changing existing axes

**Files:**

- Create: `aegis/_internal/checkpoint_verification.py`
- Create: `aegis/_internal/chain_checkpoint_verification.py`
- Create: `tests/test_chain_checkpoint_verification.py`
- Modify: `aegis/_internal/verification.py:85-104,490-554`
- Modify: `aegis/audit_chain.py:13-35`

**Interfaces:**

- Consumes: Tasks 2-4 records/results, the single Task 3
  `_checkpoint_payload()` constructor, prepared-payload verifier, shared
  budget, `ContentIntegrity`, `ChainContinuity`, `Completeness`, and the
  existing artifact-verification axes.
- Produces:

```text
CheckpointEvaluation(
    signature_status: CheckpointSignatureStatus,
    anchor_status: AnchorStatus,
    completeness: Completeness,
    results: tuple[CheckpointVerificationResult, ...],
)

prepare_chain_checkpoint_input(
    artifacts: list[object],
    checkpoints: object,
    expected_chain_id: object,
    budget: VerificationBudget,
    errors: BoundedVerificationErrors,
) -> PreparedChainCheckpoints | None

evaluate_chain_checkpoints(
    prepared: PreparedChainCheckpoints,
    artifacts: list[object],
    *,
    content_valid: bool,
    continuity_valid: bool,
    verifier: ExternalArtifactVerifier | None,
    errors: BoundedVerificationErrors,
) -> CheckpointEvaluation
```

`chain_checkpoint_verification.py` must not import
`aegis._internal.verification`: it receives the two primitive validity flags
shown above and returns checkpoint-only contracts, preventing a reverse import
through the module that integrates it.

Extend the public verifier exactly as approved:

```text
verify_chain_detailed(
    artifacts: object,
    *,
    signature_verifier: object | None = None,
    anchor_verifier: object | None = None,
    legacy_authorization: object | None = None,
    checkpoints: object = (),
    checkpoint_verifier: object | None = None,
    expected_chain_id: object | None = None,
) -> ChainVerificationReport
```

Append after `errors` with defaults:

```python
checkpoint_signature_status: CheckpointSignatureStatus = (
    CheckpointSignatureStatus.NOT_EVALUATED
)
checkpoint_anchor_status: AnchorStatus = AnchorStatus.NOT_EVALUATED
checkpoint_results: tuple[CheckpointVerificationResult, ...] = ()
```

- [ ] **Step 1: Write failing no-checkpoint and single-checkpoint tests**

```python
def test_no_checkpoint_preserves_current_report(valid_chain):
    before = verify_chain_detailed(valid_chain)
    after = verify_chain_detailed(valid_chain, checkpoints=())
    assert after == before
    assert after.checkpoint_signature_status is CheckpointSignatureStatus.NOT_EVALUATED
    assert after.checkpoint_results == ()


def test_anchored_terminal_checkpoint_proves_complete_chain(
    valid_chain, chain_checkpoint, verifier
):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[chain_checkpoint],
        checkpoint_verifier=verifier,
    )
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert report.checkpoint_anchor_status is AnchorStatus.ANCHORED
    assert report.completeness is Completeness.CHECKPOINT_PROVEN
    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.MATCHED
```

- [ ] **Step 2: Run the single-checkpoint tests and witness API failure**

Run: `../../.venv/bin/python -m pytest -q tests/test_chain_checkpoint_verification.py -k 'no_checkpoint or terminal_checkpoint'`

Expected: FAIL because reports and verifier keywords do not exist.

- [ ] **Step 3: Implement bounded preparation and scope derivation**

Consume at most 65 raw checkpoint elements, measure all chain/checkpoint input
before checksum/continuity work or provider calls, parse exact chain records,
canonicalize for exact-record deduplication, retain all source indexes, and
validate explicit `expected_chain_id`. Without explicit scope, derive scope
only when content and continuity establish one internally valid chain ID;
otherwise keep parsed
records `NOT_EVALUATED` and do not call the checkpoint verifier.
Reject a non-list chain, more than 1,024 artifacts, or an invalid explicit
scope before consuming the checkpoint iterable.
Use `CHECKPOINT_INPUT_INVALID` for a non-iterable/exceptional checkpoint input,
`CHECKPOINT_SCOPE_INVALID` for invalid explicit scope,
`CHECKPOINT_RECORD_INVALID` for malformed records,
`CHECKPOINT_VERIFICATION_ERROR` for provider contract failures, and
`CHECKPOINT_BINDING_CONFLICT` for trusted conflicts. Emit errors in caller
input order and let `BoundedVerificationErrors` retain only the first 100.
For `type(value) is TrustedChainCheckpoint`, require exact scalar field types,
call the core-owned class implementation
`TrustedChainCheckpoint.to_dict(value)`, and pass the result through
`TrustedChainCheckpoint.from_dict()`; never trust instance fields directly or
dispatch to a subclass override.

```python
budget = VerificationBudget()
budget.measure(artifacts)
raw_checkpoints = materialize_bounded_iterable(checkpoints, max_items=64)
budget.measure(raw_checkpoints)
prepared = _parse_chain_checkpoints(raw_checkpoints, errors)
# Only now evaluate content, continuity, artifact signatures, or callbacks.

scope_id = (
    expected_chain_id
    if expected_chain_id is not None
    else _derived_chain_id(artifacts, content_valid, continuity_valid)
)
if scope_id is None:
    return _not_evaluated_results(parsed_records)
in_scope = [record for record in parsed_records if record.chain_id == scope_id]
```

- [ ] **Step 4: Implement structural binding for one checkpoint**

For a full chain beginning at zero classify the checkpoint as `MATCHED`,
`HISTORICAL`, `AHEAD`, or `CONFLICT`. For a partial chain classify coordinates
inside the supplied window as `PARTIAL`/`CONFLICT`, before it as `OUTSIDE`, and
after it as `AHEAD`. Compute the relationship regardless of signature result,
but change completeness only for `VALID/ANCHORED` results.

```python
if checkpoint.chain_index < first_index:
    return CheckpointBindingStatus.OUTSIDE
if checkpoint.chain_index > last_index:
    return CheckpointBindingStatus.AHEAD
artifact = artifacts[checkpoint.chain_index - first_index]
if artifact.get("checksum") != checkpoint.artifact_checksum:
    return CheckpointBindingStatus.CONFLICT
if first_index > 0:
    return CheckpointBindingStatus.PARTIAL
if checkpoint.chain_index == last_index:
    return CheckpointBindingStatus.MATCHED
return CheckpointBindingStatus.HISTORICAL
```

- [ ] **Step 5: Integrate the report while preserving old axes**

Keep content, continuity, artifact `signature_status`, legacy/generic
`anchor_status`, and `internal_valid` unchanged. A terminal trusted match on a
valid full chain produces `CHECKPOINT_PROVEN`; a trusted conflict or trusted
ahead head on such a chain produces `CONTRADICTED`; all unanchored, unknown,
revoked, unavailable, partial, outside, historical, malformed, or absent cases
remain `UNPROVEN` unless a trusted contradiction exists.

```python
if trusted_conflict or (trusted_ahead and full_chain):
    completeness = Completeness.CONTRADICTED
elif terminal_trusted_match and all_in_scope_trusted_and_consistent:
    completeness = Completeness.CHECKPOINT_PROVEN
else:
    completeness = Completeness.UNPROVEN
```

- [ ] **Step 6: Add mutation, stale, partial, and truncation tests**

Cover body/checksum/link mutation, exact historical match followed by a longer
tail, partial chain with checkpoint inside/before/after its window, empty and
unchained inputs, full-chain tail deletion, insertion, deletion, reorder, and a
checksum-valid whole-chain replacement with the same `chain_id`.

- [ ] **Step 7: Run chain checkpoint and compatibility tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_chain_checkpoint_verification.py \
  tests/test_typed_chain_verification.py \
  tests/test_chain_signature_vectors.py \
  tests/test_legacy_authority_boundary.py
```

Expected: PASS.

- [ ] **Step 8: Commit single-chain checkpoint verification**

```bash
git add aegis/_internal/checkpoint_verification.py \
  aegis/_internal/chain_checkpoint_verification.py \
  aegis/_internal/verification.py aegis/audit_chain.py \
  tests/test_chain_checkpoint_verification.py
git commit -m "feat: verify trusted chain checkpoints"
```

### Task 6: Harden multiple chain checkpoints, scope, rotation, and resources

**Files:**

- Modify: `aegis/_internal/checkpoint_verification.py`
- Modify: `aegis/_internal/chain_checkpoint_verification.py`
- Modify: `aegis/_internal/verification.py`
- Modify: `tests/test_chain_checkpoint_verification.py`
- Modify: `tests/test_checkpoint_verification_boundary.py`
- Modify: `tests/support/external_signing.py`

**Interfaces:**

- Consumes: Task 5's prepared chain input and evaluation.
- Produces: deterministic multi-record aggregation, raw count/provider/error
  ceilings, `expected_chain_id` replacement detection, out-of-scope skipping,
  and current/historical/unknown/revoked/unavailable key behavior.

- [ ] **Step 1: Add failing duplicate, scope, and rotation tests**

```python
def test_exact_duplicates_count_raw_but_verify_once(valid_chain, checkpoint, verifier):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[checkpoint, checkpoint.to_dict()],
        checkpoint_verifier=verifier,
    )
    assert verifier.call_count == 1
    assert report.checkpoint_results[0].input_indexes == (0, 1)


def test_out_of_scope_checkpoint_is_not_a_dos(valid_chain, other_checkpoint, verifier):
    report = verify_chain_detailed(
        valid_chain,
        checkpoints=[other_checkpoint],
        checkpoint_verifier=verifier,
    )
    assert verifier.call_count == 0
    assert report.completeness is Completeness.UNPROVEN
    assert report.checkpoint_results[0].binding_status is CheckpointBindingStatus.OUT_OF_SCOPE


def test_expected_chain_id_detects_identifier_replacement(
    replacement_chain, original_checkpoint, verifier
):
    report = verify_chain_detailed(
        replacement_chain,
        expected_chain_id="original-chain",
        checkpoints=[original_checkpoint],
        checkpoint_verifier=verifier,
    )
    assert report.completeness is Completeness.CONTRADICTED
```

- [ ] **Step 2: Run focused tests and witness missing aggregation behavior**

Run: `../../.venv/bin/python -m pytest -q tests/test_chain_checkpoint_verification.py -k 'duplicate or scope or rotation or replacement'`

Expected: at least the new call-count, scope, and mixed-outcome cases fail.

- [ ] **Step 3: Implement exact deduplication and deterministic aggregation**

Use canonical full signed-record bytes as the deduplication key. Preserve the
first-record order and collect every duplicate input index. Apply signature
precedence `INDETERMINATE > INVALID > REVOKED > UNKNOWN_KEY > VALID >
NOT_EVALUATED` and anchor precedence `INVALID > NOT_EVALUATED > UNANCHORED >
ANCHORED`. Malformed/provider-contract failures force
`INDETERMINATE/INVALID`; anchored binding conflicts force aggregate anchor
`INVALID`.

```python
_SIGNATURE_PRECEDENCE = {
    CheckpointSignatureStatus.NOT_EVALUATED: 0,
    CheckpointSignatureStatus.VALID: 1,
    CheckpointSignatureStatus.UNKNOWN_KEY: 2,
    CheckpointSignatureStatus.REVOKED: 3,
    CheckpointSignatureStatus.INVALID: 4,
    CheckpointSignatureStatus.INDETERMINATE: 5,
}
signature_status = max(
    statuses,
    key=_SIGNATURE_PRECEDENCE.__getitem__,
    default=CheckpointSignatureStatus.NOT_EVALUATED,
)
```

Define the analogous anchor map
`INVALID > NOT_EVALUATED > UNANCHORED > ANCHORED`, with
`AnchorStatus.NOT_EVALUATED` as the empty default. Add explicit tests for an
empty set, out-of-scope-only set, malformed-only set, and every two-status
combination so aggregation never relies on enum declaration order.

- [ ] **Step 4: Implement scope and authoritative-conflict rules**

Skip provider invocation for records whose `chain_id` differs from selected
scope and emit bounded `CHECKPOINT_SCOPE_MISMATCH`. With explicit scope,
evidence claiming a different chain ID conflicts only after at least one
in-scope checkpoint verifies as anchored. Do not use record order or an
unverified checkpoint to select scope.

```python
if record.chain_id != scope_id:
    results.append(
        _result(
            record,
            binding_status=CheckpointBindingStatus.OUT_OF_SCOPE,
            signature_result=None,
        )
    )
    errors.append(_error("CHECKPOINT_SCOPE_MISMATCH", "Checkpoint is out of scope"))
    continue
```

- [ ] **Step 5: Implement rotation, revocation, and conflict behavior**

Accept current and historical key versions exactly as the host verifier
reports them. Do not reinterpret `checkpointed_at` for key policy. Revoked,
unknown, unavailable, or unanchored records cannot promote completeness and
cannot be hidden by an anchored record. Two anchored records with the same
coordinate and different checksums are conflicting authorities. Compare
different coordinates only through supplied chain links.

```python
trusted_by_coordinate: dict[tuple[str, int], str] = {}
for result in results:
    if result.signature_result is None or not result.signature_result.is_anchored:
        continue
    coordinate = (result.scope_id, result.chain_index)
    prior = trusted_by_coordinate.setdefault(
        coordinate,
        result.checkpoint.artifact_checksum,
    )
    if prior != result.checkpoint.artifact_checksum:
        trusted_conflict = True
```

- [ ] **Step 6: Add hard resource and hostile-provider tests**

Cover 65 distinct, duplicate, malformed, infinite, exception-raising, and
hostile-length-hint checkpoint iterables; 1,025 chain artifacts; 4 MiB bytes;
65,537 nodes; depth 33; cycles; custom containers; non-string keys; 101+ errors;
and provider exception/malformed/impossible outcome. Assert at most 65 iterator
reads, at most 64 checkpoint verifier calls, zero calls for failed preflight or
out-of-scope records, no compatibility callback, and no `SENSITIVE_CORPUS` in
errors/logs.

Extend the deterministic verifier without changing its default outcomes:

```python
class DeterministicExternalVerifier:
    @property
    def call_count(self) -> int:
        return len(self.calls)
```

Initialize `self.calls: list[tuple[bytes, str, SignatureMetadata]] = []` in the
existing constructor and append `(payload, signature, metadata)` as the first
line of the existing `verify()` method; retain its current outcome logic.

For historical-key acceptance, build a test-local copy of
`default_key_records()` with only `version/historical.anchor_status` replaced
by `AnchorStatus.ANCHORED`; do not change the existing default fixture relied
on by #44 tests.

- [ ] **Step 7: Run all chain and boundary tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_chain_checkpoint_verification.py \
  tests/test_checkpoint_verification_boundary.py \
  tests/test_typed_chain_verification.py \
  tests/test_chain_signature_vectors.py
```

Expected: PASS.

- [ ] **Step 8: Commit adversarial chain hardening**

```bash
git add aegis/_internal/checkpoint_verification.py \
  aegis/_internal/chain_checkpoint_verification.py \
  aegis/_internal/verification.py \
  tests/test_chain_checkpoint_verification.py \
  tests/test_checkpoint_verification_boundary.py \
  tests/support/external_signing.py
git commit -m "test: harden adversarial chain checkpoints"
```

### Task 7: Integrate the singular workflow checkpoint

**Files:**

- Create: `tests/test_workflow_checkpoint_verification.py`
- Modify: `aegis/_internal/checkpoint_verification.py`
- Create: `aegis/_internal/workflow_checkpoint_verification.py`
- Modify: `aegis/_internal/workflow_verification.py:153-176,472-624`
- Modify: `aegis/workflow_verification.py:1-13`
- Modify: `tests/test_workflow_claimed_set_verifier.py:94-105,299-325`

**Interfaces:**

- Consumes: checkpoint records/provider boundary/shared budget and the existing
  B4 `_validate_claim()`, session filtering, invocation comparison, workflow
  schema/checksum, and artifact-signature axes.
- Produces:

```text
prepare_workflow_checkpoint_input(
    expected_checkpoint: object | None,
    budget: VerificationBudget,
    errors: BoundedVerificationErrors,
) -> PreparedWorkflowCheckpoint | None

evaluate_workflow_checkpoint(
    prepared: PreparedWorkflowCheckpoint,
    workflow: dict[str, object],
    *,
    workflow_content_valid: bool,
    claim_valid: bool,
    verifier: ExternalArtifactVerifier | None,
    errors: BoundedVerificationErrors,
) -> CheckpointEvaluation

verify_workflow_claim(
    workflow: object,
    invocations: object,
    *,
    expected_checkpoint: object | None = None,
    checkpoint_verifier: object | None = None,
) -> WorkflowVerificationReport
```

`workflow_checkpoint_verification.py` must not import
`aegis._internal.workflow_verification`. The integrating module converts its
existing content and claim enums to the primitive flags above, avoiding a
reverse import while preserving the public enum identities.

Append after existing `errors` with the same three defaults used by
`ChainVerificationReport`.

- [ ] **Step 1: Replace the issue-46 placeholder test with failing behavior tests**

Delete the old assertion for `WORKFLOW_CHECKPOINT_UNSUPPORTED`. Add exact
matching, no-checkpoint compatibility, and anchored supplied-set contradiction
tests.

```python
def test_matching_anchored_workflow_checkpoint_proves_exact_claim(
    evidence_set, workflow_checkpoint, verifier
):
    workflow, invocations = evidence_set
    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )
    assert report.claim_status is WorkflowClaimStatus.VALID
    assert report.completeness is Completeness.CHECKPOINT_PROVEN


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra", "reordered"])
def test_anchored_claim_contradicts_incomplete_supplied_evidence(
    evidence_set, workflow_checkpoint, verifier, mutation
):
    workflow, invocations = mutate_supplied_set(evidence_set, mutation)
    report = verify_workflow_claim(
        workflow,
        invocations,
        expected_checkpoint=workflow_checkpoint,
        checkpoint_verifier=verifier,
    )
    assert report.claim_status is WorkflowClaimStatus.INVALID
    assert report.completeness is Completeness.CONTRADICTED
```

- [ ] **Step 2: Run the workflow checkpoint tests and witness placeholder behavior**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_workflow_checkpoint_verification.py
```

Expected: FAIL because non-`None` checkpoints still return the placeholder
unsupported result.

- [ ] **Step 3: Prepare and verify the singular checkpoint under the shared budget**

Measure the workflow, supplied invocations, and checkpoint before artifact or
checkpoint verifier calls. Parse only `TrustedWorkflowCheckpoint`, construct
its canonical signed payload, call the verifier once, and return a
`CheckpointVerificationResult` at input index `(0,)`. Malformed/cross-type
records yield bounded fixed errors and never reach the provider. Reparse exact
base-class record instances through core-owned `to_dict()` and `from_dict()`;
reject subclasses and forged invalid instances before the provider.
Before snapshotting a typed workflow record, require `type(invocations) is
tuple`, enforce the 1,024 count on that tuple, and require every item to be an
exact two-item tuple of scalar fields. Then call the class implementation
directly (`TrustedWorkflowCheckpoint.to_dict(value)`), not `value.to_dict()`,
so a forged instance cannot force an unbounded intermediate list or override
dispatch before measurement.

```python
budget = VerificationBudget()
budget.measure(workflow)
supplied = materialize_bounded_iterable(invocations, max_items=1_024)
budget.measure(supplied)
if type(expected_checkpoint) is TrustedWorkflowCheckpoint:
    snapshot = TrustedWorkflowCheckpoint.to_dict(expected_checkpoint)
    budget.measure(snapshot)
elif expected_checkpoint is not None:
    budget.measure(expected_checkpoint)
# Artifact and checkpoint verifier calls occur only below this preflight.
```

- [ ] **Step 4: Implement exact workflow binding**

Compare workflow schema version, session ID, final status, step count, ordered
`(step_index, checksum)` pairs, and final workflow checksum. A full match is
`MATCHED`; any field mismatch is `CONFLICT`. The singular checkpoint is
explicitly host-selected, so an anchored session mismatch is a contradiction,
not `OUT_OF_SCOPE`.

```python
bound_workflow = {
    "workflow_schema_version": workflow.get("workflow_schema_version"),
    "session_id": workflow.get("session_id"),
    "final_status": workflow.get("status"),
    "step_count": workflow.get("step_count"),
    "invocations": workflow.get("invocations"),
    "workflow_checksum": workflow.get("checksum"),
}
binding = (
    CheckpointBindingStatus.MATCHED
    if bound_workflow == _workflow_binding(checkpoint)
    else CheckpointBindingStatus.CONFLICT
)
```

- [ ] **Step 5: Preserve claim validity while applying completeness semantics**

The existing B4 verifier remains authoritative for `claim_status`. A
checkpoint never repairs it. An exact valid claim plus matching anchored
checkpoint becomes `CHECKPOINT_PROVEN`. Missing/duplicate/extra same-session or
reordered evidence remains `INVALID`; if the checkpoint anchors the unchanged
authoritative claim it becomes `CONTRADICTED`, otherwise `UNPROVEN`. Unrelated
well-formed other-session artifacts remain filtered and do not invalidate the
claim.

```python
if anchored_checkpoint_conflict:
    completeness = Completeness.CONTRADICTED
elif claim_status is WorkflowClaimStatus.VALID and anchored_checkpoint_match:
    completeness = Completeness.CHECKPOINT_PROVEN
elif claim_status is WorkflowClaimStatus.INVALID and anchored_checkpoint_match:
    completeness = Completeness.CONTRADICTED
else:
    completeness = Completeness.UNPROVEN
```

- [ ] **Step 6: Add workflow mutation, replay, key, and limit tests**

Cover mutation of schema version, session, terminal status, step count,
step index, invocation checksum, claim order, and workflow checksum; whole
workflow replacement; chain-as-workflow and invocation-as-workflow replay;
current/historical/unknown/revoked/unavailable keys; unanchored/invalid anchor;
malformed provider results; source/checkpoint non-mutation; 4 MiB aggregate
budget; 1,025 claim or supplied entries; cycles/depth/nodes; and 100-error cap.

- [ ] **Step 7: Run workflow and chain regression tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_workflow_checkpoint_verification.py \
  tests/test_workflow_claimed_set_verifier.py \
  tests/test_workflow_claimed_set.py \
  tests/test_chain_checkpoint_verification.py
```

Expected: PASS.

- [ ] **Step 8: Commit workflow checkpoint verification**

```bash
git add aegis/_internal/checkpoint_verification.py \
  aegis/_internal/workflow_checkpoint_verification.py \
  aegis/_internal/workflow_verification.py aegis/workflow_verification.py \
  tests/test_workflow_checkpoint_verification.py \
  tests/test_workflow_claimed_set_verifier.py
git commit -m "feat: verify trusted workflow checkpoints"
```

### Task 8: Freeze the public API and provider-neutral architecture boundary

**Files:**

- Create: `tests/test_checkpoint_public_api.py`
- Modify: `aegis/checkpoints.py`
- Modify: `aegis/__init__.py:19-117,167-297`
- Modify: `aegis/audit_chain.py`
- Modify: `aegis/workflow_verification.py`
- Modify: `tests/test_public_api.py:44-102,383-565`
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:**

- Consumes: all completed checkpoint contracts and integrated verifiers.
- Produces: stable identical checkpoint exports from `aegis`,
  `aegis.checkpoints`, with `CheckpointError` additionally identical through
  `aegis.errors`; existing verification functions and reports remain available from `aegis.audit_chain` and
  `aegis.workflow_verification` without adding checkpoint-model aliases there.

- [ ] **Step 1: Add failing export identity and report-compatibility tests**

```python
def test_checkpoint_public_exports_are_identical():
    assert aegis.create_chain_checkpoint is checkpoints.create_chain_checkpoint
    assert aegis.create_workflow_checkpoint is checkpoints.create_workflow_checkpoint
    assert aegis.TrustedChainCheckpoint is checkpoints.TrustedChainCheckpoint
    assert aegis.TrustedWorkflowCheckpoint is checkpoints.TrustedWorkflowCheckpoint
    assert aegis.CheckpointError is checkpoints.CheckpointError
    assert aegis.CheckpointError is errors.CheckpointError


def test_existing_report_construction_remains_source_compatible():
    chain = ChainVerificationReport(
        ContentIntegrity.VALID,
        ChainContinuity.VALID,
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        Completeness.UNPROVEN,
        (),
    )
    assert chain.checkpoint_results == ()
    workflow = WorkflowVerificationReport(
        WorkflowClaimStatus.VALID,
        SignatureStatus.UNSIGNED,
        Completeness.UNPROVEN,
        (),
    )
    assert workflow.checkpoint_results == ()
```

- [ ] **Step 2: Run public tests and witness missing top-level exports**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_public_api.py tests/test_public_api.py
```

Expected: FAIL on missing `aegis` checkpoint names.

- [ ] **Step 3: Add exact facade and top-level exports**

Export both creators, both record types, `CheckpointError`,
`CheckpointSignatureStatus`, `CheckpointBindingStatus`, and
`CheckpointVerificationResult` from `aegis`. Keep profile constants in
the internal modules; do not add unapproved profile constants to the public
API. Preserve all current names and `__all__` entries.

```python
from aegis.checkpoints import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
    TrustedChainCheckpoint,
    TrustedWorkflowCheckpoint,
    create_chain_checkpoint,
    create_workflow_checkpoint,
)
```

- [ ] **Step 4: Add architecture-source tests for forbidden capabilities**

Extend AST/import/call inspection to assert the checkpoint modules contain no
sink imports, filesystem writes, socket/HTTP/cloud SDK imports, credential or
environment lookup, sleep/retry loops, thread/process dispatch, mutable global
storage, or calls into enforcement/session finalization. Assert creators call
only the caller-supplied signer and verifiers call only the caller-supplied
verifier after preflight.

```python
FORBIDDEN_CHECKPOINT_IMPORT_ROOTS = {
    "boto3", "google.cloud", "requests", "socket", "subprocess"
}
FORBIDDEN_CHECKPOINT_CALLS = {
    "open", "sleep", "getenv", "putenv", "urlopen"
}
```

- [ ] **Step 5: Add public introspection and typing tests**

Assert exact `inspect.signature()` results for all four public functions, enum
value sets, frozen/slots dataclasses, `to_dict()` JSON serializability, module
identity, `__all__` completeness, and that no private checkpoint helper leaks
through a public facade.

```python
signature = inspect.signature(aegis.create_chain_checkpoint)
assert tuple(signature.parameters) == ("artifact", "signer", "checkpointed_at")
assert signature.parameters["checkpointed_at"].kind is inspect.Parameter.KEYWORD_ONLY
assert set(checkpoints.__all__) == EXPECTED_CHECKPOINT_EXPORTS
```

- [ ] **Step 6: Run public and architecture tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_checkpoint_public_api.py \
  tests/test_public_api.py \
  tests/test_architecture_security_boundaries.py
```

Expected: PASS.

- [ ] **Step 7: Commit the public boundary**

```bash
git add aegis/checkpoints.py aegis/__init__.py aegis/audit_chain.py \
  aegis/workflow_verification.py tests/test_checkpoint_public_api.py \
  tests/test_public_api.py tests/test_architecture_security_boundaries.py
git commit -m "feat: publish trusted checkpoint API"
```

### Task 9: Document assurance, storage ownership, and migration behavior

**Files:**

- Create: `docs/decisions/ADR-0015-trusted-checkpoints.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md:1-30`
- Modify: `docs/USAGE.md`
- Modify: `docs/INTEGRATION_GUIDE.md:191-232`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/migration.md:89-128`
- Modify: `docs/reference/WORKFLOW_QUICKSTART.md:87-106`
- Modify: `docs/reference/WORKFLOW_CLI.md:24-40`
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md:340-410`
- Modify: `docs/decisions/ADR-0008-governance-artifact-chain.md`
- Modify: `docs/decisions/ADR-0012-external-trust-anchor-signing.md`
- Modify: `tests/test_doc_parity_v090_truth.py`
- Modify: `tests/test_architecture_security_boundaries.py`

**Interfaces:**

- Consumes: final public API and exact assurance outcomes.
- Produces: maintained documentation that distinguishes internal
  tamper-evidence, artifact signatures, external artifact anchoring, trusted
  checkpoint anchoring, checkpoint-relative completeness, and host storage
  provenance.

- [ ] **Step 1: Add failing documentation-parity assertions**

Assert the maintained docs contain the exact creation/verification function
names, both record/profile names, `expected_chain_id`, all three checkpoint
report fields, the three completeness values, provider-neutral/host-owned
storage language, signed host-time disclaimer, and explicit statements that
AEGIS does not prove latest retrieval, WORM/append-only storage, future
activity, certification, or compliance.

- [ ] **Step 2: Run documentation tests and witness missing content**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_doc_parity_v090_truth.py \
  tests/test_architecture_security_boundaries.py
```

Expected: FAIL on the new trusted-checkpoint anchors.

- [ ] **Step 3: Write ADR-0015 and architectural truth**

Record the two separate record types, exact signing domains, explicit creation,
host-owned lifecycle, scope rules, rotation/revocation policy, resource/error
limits, and rejected single-envelope/automatic-storage alternatives. Update the
threat model for whole-chain and finalized-workflow replacement plus checkpoint
omission/rollback residual risk. Update invariants to forbid automatic sinks,
network/key discovery, provider retries, and completeness promotion from
artifact signatures alone.
Add forward references from ADR-0008 and ADR-0012 to ADR-0015 without rewriting
their historical decisions.

- [ ] **Step 4: Add public creation and verification recipes**

Show a provider-neutral signer/verifier object supplied by the host, call
`create_chain_checkpoint(artifact, signer, checkpointed_at=observed_time)`,
persist `checkpoint.to_dict()` in host code, reconstruct with
`TrustedChainCheckpoint.from_dict(stored_record)`, and verify with
`expected_chain_id`. Add the analogous workflow example. Examples must not
suggest a built-in checkpoint store, automatic finalizer hook, or that host
time/storage is trusted by AEGIS.
Replace the stale “unavailable until #46” text in the workflow quickstart and
architectural invariants. Keep the workflow CLI's non-checkpoint boundary, but
point users to the `expected_checkpoint` parameter of the Python
`verify_workflow_claim` API instead of describing #46 as future work.

- [ ] **Step 5: Update migration, changelog, and assurance tables**

Describe no-checkpoint calls as source-compatible and still `UNPROVEN`; list
the new default report fields; explain when to pass `expected_chain_id`; and
add the source-only feature under `CHANGELOG.md` without changing a released
test-count claim. Include a table separating content, continuity, artifact
signature, generic artifact anchor, checkpoint signature, checkpoint anchor,
binding, and completeness.

- [ ] **Step 6: Compile documentation examples and run parity tests**

Run:

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_doc_parity_v090_truth.py \
  tests/test_architecture_security_boundaries.py \
  tests/test_checkpoint_public_api.py
```

Expected: PASS.

- [ ] **Step 7: Commit maintained documentation**

```bash
git add README.md CHANGELOG.md docs/USAGE.md docs/INTEGRATION_GUIDE.md \
  docs/PUBLIC_INTEGRATION_CONTRACT.md docs/migration.md \
  docs/reference/WORKFLOW_QUICKSTART.md docs/reference/WORKFLOW_CLI.md \
  docs/architecture/AEGIS_THREAT_MODEL.md \
  docs/architecture/ARCHITECTURAL_INVARIANTS.md \
  docs/decisions/ADR-0008-governance-artifact-chain.md \
  docs/decisions/ADR-0012-external-trust-anchor-signing.md \
  docs/decisions/ADR-0015-trusted-checkpoints.md \
  tests/test_doc_parity_v090_truth.py \
  tests/test_architecture_security_boundaries.py
git commit -m "docs: explain trusted checkpoint assurance"
```

### Task 10: Run final adversarial verification and close issue acceptance gaps

**Files:**

- Review and, when a new failing test demonstrates a defect, modify only files
  already listed by Tasks 1-9.
- Review: `docs/superpowers/specs/2026-08-04-issue-46-trusted-checkpoints-design.md`
- Review: all checkpoint source/tests/docs from Tasks 1-9.

**Interfaces:**

- Consumes: complete issue #46 implementation.
- Produces: verified acceptance-criteria evidence and a clean, reviewable
  branch; no new feature surface.

- [ ] **Step 1: Run the focused checkpoint suite**

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_signature_models.py \
  tests/test_external_signing.py \
  tests/test_checkpoint_models.py \
  tests/test_checkpoint_creation.py \
  tests/test_checkpoint_verification_boundary.py \
  tests/test_chain_checkpoint_verification.py \
  tests/test_workflow_checkpoint_verification.py \
  tests/test_checkpoint_public_api.py
```

Expected: PASS.

- [ ] **Step 2: Run existing chain/workflow/public/security regressions**

```bash
../../.venv/bin/python -m pytest -q \
  tests/test_typed_chain_verification.py \
  tests/test_chain_signature_vectors.py \
  tests/test_workflow_claimed_set.py \
  tests/test_workflow_claimed_set_verifier.py \
  tests/test_public_api.py \
  tests/test_architecture_security_boundaries.py \
  tests/test_doc_parity_v090_truth.py
```

Expected: PASS.

- [ ] **Step 3: Run the complete suite**

Run: `../../.venv/bin/python -m pytest -q`

Expected: all tests PASS with zero failures.

- [ ] **Step 4: Run source and diff hygiene checks**

```bash
../../.venv/bin/python -m compileall -q aegis tests
git diff --check
git status --short --branch
```

Expected: compilation and diff checks exit zero; status contains only intended
issue #46 changes or is clean after commits.

- [ ] **Step 5: Perform first adversarial implementation review**

Trace every approved-spec requirement to code and a witnessed test. Attack
profile/type/canonicalization confusion, signature-field exclusion, receipt
rotation, body/link/claim mutation, tail deletion, whole-record replacement,
cross-type replay, out-of-scope checkpoint DoS, checkpoint omission, duplicate
streams, partial windows, resource exhaustion, provider exception leakage, and
report-axis conflation. Fix any finding through a new failing test, minimal
implementation, focused pass, and regression pass.

- [ ] **Step 6: Perform a second independent adversarial review**

Start from public APIs and attacker-controlled inputs rather than the first
review's requirement map. Verify provider-call ordering/counts, no storage or
network capability, aggregate precedence, dataclass/source compatibility,
rotation/revocation semantics, host-authority wording, and that
`CHECKPOINT_PROVEN` is impossible without `VALID/ANCHORED` trusted evidence.
Again, fix findings only through witnessed red/green cycles.

- [ ] **Step 7: Re-run all verification after review fixes**

Run:

```bash
../../.venv/bin/python -m pytest -q
../../.venv/bin/python -m compileall -q aegis tests
git diff --check
```

Expected: all commands exit zero after the final edit.

- [ ] **Step 8: Commit any review-driven corrections**

If the reviews produced changes:

```bash
git add aegis tests README.md CHANGELOG.md docs
git commit -m "fix: address checkpoint adversarial review"
```

If no files changed, do not create an empty commit.

## Acceptance-Criteria Trace

| Issue #46 requirement | Implemented and verified in |
| --- | --- |
| Provider-neutral explicit creation; signed return; host storage | Tasks 3, 8, 9 |
| Separate chain/workflow records and domains | Tasks 1-3 |
| Exact #44 metadata compatibility and provider outcomes | Tasks 1, 4 |
| Zero/one/multiple checkpoints with raw limits | Tasks 5-7 |
| Internally valid unanchored versus checkpoint-validated | Tasks 5-7 |
| Whole-chain replacement and tail deletion | Tasks 5-6 |
| Chain-ID replacement and unrelated-record DoS resistance | Task 6 |
| Partial, stale, outside, ahead, conflict, and duplicate semantics | Tasks 5-6 |
| Current/historical/unknown/revoked/unavailable keys | Tasks 6-7 |
| Finalized workflow and authoritative B4 claim binding | Tasks 3, 7 |
| Workflow mutation, incomplete supplied evidence, and replay | Task 7 |
| Typed bounded sanitized failures and provider-call ceilings | Tasks 2, 4, 6-7 |
| Existing report and no-checkpoint compatibility | Tasks 4-5, 7-8 |
| No automatic storage/network/credentials/retries | Tasks 3, 8-9 |
| Accurate external-assurance and provenance documentation | Task 9 |
| Two adversarial reviews before presentation | Task 10 |
