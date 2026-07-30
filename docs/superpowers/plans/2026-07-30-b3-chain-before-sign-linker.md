# B3 Chain-Before-Sign Linker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let hosts supply invocation-chain placement before checksum/signature construction so signatures transitively authenticate stable content-checksum coordinates.

**Architecture:** A host-owned synchronous `ChainLinker` reserves one `ChainCoordinates` object. `EvidenceFinalizer` validates and attaches it before B1 checksum and B2 signing, then commits the reservation only after acknowledged emission or aborts it on failure. AEGIS owns coverage, not global ordering or storage; workflow artifacts never call the linker.

**Tech Stack:** Python 3.10+, protocols and frozen dataclasses, B1 content checksum, B2 finalizer, existing `AuditChain`, pytest threading.

## Global Constraints

- `previous_audit_checksum` is exactly the previous v2 content checksum, never a signature, signed-object digest, or storage digest.
- First entry uses `previous_audit_checksum=None`.
- Coordinate set is complete or absent; partial coordinates fail closed.
- Host owns namespace, atomic index allocation, storage, retention, and checkpoints.
- Coordinates are attached before checksum and signature.
- Re-signing/key rotation does not change content checksum or chain linkage.
- Linker failure cannot silently emit unchained evidence when chaining is configured.
- Workflow evidence does not join invocation chains.

---

### Task 1: Define and validate the host linker contract

**Files:**
- Create: `aegis/_internal/chain_linker.py`
- Create: `tests/test_chain_linker_contract.py`
- Modify: `aegis/_internal/errors.py`

**Interfaces:**
- Produces: `ChainLinkRequest(attempt_id, artifact_type, correlation_id)`
- Produces: `ChainCoordinates(chain_id, chain_index, previous_audit_checksum)`
- Produces: `ChainLinker.reserve(request) -> ChainReservation`
- Produces: `ChainReservation.coordinates`, `.commit(content_checksum)`, `.abort()`
- Produces: `validate_chain_coordinates(value) -> ChainCoordinates`.

- [ ] **Step 1: Write malformed-coordinate tests**

```python
@pytest.mark.parametrize("coordinates", [
    {"chain_id": "c", "chain_index": 1},
    {"chain_id": "", "chain_index": 0, "previous_audit_checksum": None},
    {"chain_id": "c", "chain_index": -1, "previous_audit_checksum": None},
    {"chain_id": "c", "chain_index": 1, "previous_audit_checksum": "signature-value"},
])
def test_invalid_coordinates_fail_closed(coordinates):
    with pytest.raises(ChainLinkError):
        validate_chain_coordinates(coordinates)
```

- [ ] **Step 2: Run and verify missing module**

Run: `.venv/bin/pytest tests/test_chain_linker_contract.py -v`

Expected: FAIL on import.

- [ ] **Step 3: Implement closed coordinate validation**

```python
@dataclass(frozen=True, slots=True)
class ChainCoordinates:
    chain_id: str
    chain_index: int
    previous_audit_checksum: str | None

    def __post_init__(self) -> None:
        if not self.chain_id or self.chain_index < 0:
            raise ChainLinkError("Invalid chain coordinates", code="CHAIN_COORDINATES_INVALID")
        if self.chain_index == 0 and self.previous_audit_checksum is not None:
            raise ChainLinkError("First entry must have no previous checksum", code="CHAIN_PREVIOUS_INVALID")
        if self.chain_index > 0 and not _is_sha256(self.previous_audit_checksum):
            raise ChainLinkError("Previous content checksum required", code="CHAIN_PREVIOUS_INVALID")


class ChainReservation(Protocol):
    @property
    def coordinates(self) -> ChainCoordinates: ...
    def commit(self, content_checksum: str) -> None: ...
    def abort(self) -> None: ...
```

- [ ] **Step 4: Run contract tests**

Run: `.venv/bin/pytest tests/test_chain_linker_contract.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/chain_linker.py aegis/_internal/errors.py tests/test_chain_linker_contract.py
git commit -m "feat: define host-owned chain linker"
```

### Task 2: Attach coordinates before checksum and signature

**Files:**
- Modify: `aegis/_internal/evidence_finalizer.py`
- Modify: `aegis/_internal/enforcement.py`
- Create: `tests/test_chain_before_sign.py`
- Modify: `tests/test_evidence_finalizer_signing.py`

**Interfaces:**
- `EvidenceFinalizerConfig.chain_linker: ChainLinker | None`
- Workflow `EvidenceDraft` explicitly sets `chain_eligible=False`.

- [ ] **Step 1: Write #52 ordering tests**

```python
def test_chain_coordinates_are_checksum_and_signature_covered(finalizer):
    artifact = finalizer.finalize(invocation_draft())
    tampered = copy.deepcopy(artifact)
    tampered["chain_index"] += 1
    assert verify_content_checksum_v2(tampered) is False
    assert verify_artifact(tampered, signer) is False
```

Add an event recorder asserting `link -> checksum -> sign -> schema -> emit`.

- [ ] **Step 2: Run and verify current sign-before-link behavior**

Run: `.venv/bin/pytest tests/test_chain_before_sign.py tests/test_evidence_finalizer_signing.py -v`

Expected: FAIL.

- [ ] **Step 3: Integrate the linker**

```python
reservation = None
if draft.chain_eligible and self._chain_linker is not None:
    reservation = self._chain_linker.reserve(ChainLinkRequest.from_draft(draft))
    coordinates = validate_chain_coordinates(reservation.coordinates)
    artifact.update(coordinates.to_artifact_fields())
```

This code runs before `content_checksum_v2()`. After acknowledged emission,
call `reservation.commit(artifact["checksum"])`. In the finalizer's exception
path call `reservation.abort()` before re-raising. Linker exceptions normalize
to `ChainLinkError`; finalization stops without emission.

- [ ] **Step 4: Prohibit workflow linkage**

Reject a workflow draft carrying chain fields or `chain_eligible=True`.

Run: `.venv/bin/pytest tests/test_chain_before_sign.py tests/test_evidence_finalizer_signing.py tests/test_workflow_evidence_signing.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/evidence_finalizer.py aegis/_internal/enforcement.py tests/test_chain_before_sign.py tests/test_evidence_finalizer_signing.py
git commit -m "fix: attach chain coordinates before signing"
```

### Task 3: Adapt `AuditChain` to the linker contract

**Files:**
- Modify: `aegis/_internal/audit_chain.py`
- Modify: `aegis/audit_chain.py`
- Modify: `tests/test_audit_chain.py`
- Create: `tests/test_audit_chain_linker.py`

**Interfaces:**
- `AuditChain.reserve(request) -> ChainReservation`
- No method mutates an already finalized artifact.

- [ ] **Step 1: Write single-process allocation tests**

Test index 0/null previous, index 1/previous content checksum, a second
concurrent reservation waiting for the first commit, abort/retry without an
index gap, and refusal to commit a malformed content checksum.

- [ ] **Step 2: Run and verify current mutation-based chain utility**

Run: `.venv/bin/pytest tests/test_audit_chain_linker.py tests/test_audit_chain.py -v`

Expected: FAIL against the old append/mutate API.

- [ ] **Step 3: Implement locked allocation**

Use one `threading.Condition` and permit only one outstanding reservation. A
second caller waits until the first reservation commits or aborts. Commit
advances the index and last content checksum, then notifies waiters; abort
releases the slot without advancing either value. This deliberately serializes
the in-memory host linker while leaving global ordering outside AEGIS
enforcement.

- [ ] **Step 4: Preserve legacy API only behind deprecation**

If public compatibility requires old `append()`, mark it legacy and prevent its output from satisfying v2 chain verification.

Run: `.venv/bin/pytest tests/test_audit_chain_linker.py tests/test_audit_chain.py tests/test_typed_chain_verification.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/_internal/audit_chain.py aegis/audit_chain.py tests/test_audit_chain.py tests/test_audit_chain_linker.py
git commit -m "refactor: make audit chain a host linker"
```

### Task 4: Add re-signing, mutation, documentation, and #46 handoff vectors

**Files:**
- Create: `tests/test_chain_signature_vectors.py`
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/decisions/ADR-0008-governance-artifact-chain.md`

**Interfaces:**
- Produces deterministic vectors consumed by #46 checkpoint tests.

- [ ] **Step 1: Add stable vector tests**

Prove re-signing with a new key changes signature metadata/signature but not checksum, `chain_id`, `chain_index`, or `previous_audit_checksum`. Prove deleting/reordering without an anchor remains completeness-unproven.

- [ ] **Step 2: Run vectors**

Run: `.venv/bin/pytest tests/test_chain_signature_vectors.py tests/test_chain_before_sign.py tests/test_typed_chain_verification.py -v`

Expected: PASS.

- [ ] **Step 3: Update threat-model claims**

State that supplied-sequence continuity is internally verifiable, storage-write attackers can replace/truncate without an external checkpoint, and #46 binds trusted heads to content checksums.

- [ ] **Step 4: Update linker contract docs**

Use the exact sentence: “`previous_audit_checksum` is the prior artifact’s v2 content checksum; it is never a signature or storage-provider digest.”

- [ ] **Step 5: Commit**

```bash
git add tests/test_chain_signature_vectors.py docs/architecture/AEGIS_THREAT_MODEL.md docs/architecture/ARCHITECTURAL_INVARIANTS.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/decisions/ADR-0008-governance-artifact-chain.md
git commit -m "docs: define signed chain linkage assurance"
```

## B3 Completion Gate

Run:

```bash
.venv/bin/pytest tests/test_chain_linker_contract.py tests/test_chain_before_sign.py tests/test_audit_chain_linker.py tests/test_chain_signature_vectors.py tests/test_typed_chain_verification.py -v
.venv/bin/pytest -q
```

Expected: both commands exit `0`; #52 is closed and #46 receives stable signature-covered content-checksum coordinates.
