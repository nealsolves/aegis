# ADR-0008: Governance Artifact Chain (Tamper-Evident Audit Sequence)

Date: 2026-03-05
Status: Accepted
Owners: Neal

---

## Context

V2 invocation artifacts have content checksums and may be signed, but independent
artifacts do not establish their order. Linking each artifact to its predecessor can
detect modification, insertion, deletion, or reordering within a sequence presented for
verification. It cannot prove that the presented sequence is complete.

Chain placement has to be covered by both the v2 content checksum and the signature. A
post-sign append API would mutate finalized evidence, invalidate its signature, or leave
the placement unsigned. At the same time, AEGIS cannot own storage ordering, durable
sequence state, or recovery policy for every host.

## Decision

AEGIS accepts an optional host-owned `ChainLinker`. The invocation evidence finalizer uses
it in this strict order:

1. reserve the next host placement;
2. attach the complete coordinate set;
3. compute the v2 content checksum;
4. sign and schema-validate the artifact;
5. emit it and obtain sink acknowledgement;
6. commit the reservation using the finalized content checksum.

Failures before acknowledgement abort the reservation. A commit failure after
acknowledgement is reported as a distinct post-ack failure and does not attempt to retract
or abort evidence the sink has already accepted. The opaque reservation ID lets a host
reconcile that crash window against observed sink state.

The complete coordinate set is:

```json
{
  "chain_id": "analytics-session-001",
  "chain_index": 42,
  "previous_audit_checksum": "0123456789abcdef...",
  "reservation_id": "opaque-host-reservation"
}
```

`previous_audit_checksum` is the prior artifact’s v2 content checksum; it is never a signature or storage-provider digest.
The first artifact uses `null`. The four fields are complete or absent; partial
caller-supplied coordinates are invalid. Workflow evidence is outside this linker contract.

`AuditChain` is the bundled in-memory implementation. It serializes one outstanding
reservation, supports bounded reservation waits, idempotent commit/abort behavior, and
reservation reconciliation. It does not claim crash persistence. Hosts that require
durable cross-process ordering provide a persistent `ChainLinker`.

```python
from aegis import AEGIS, AuditChain, HMACSigner, JsonFileAuditSink

chain = AuditChain(chain_id="analytics-session-001")
aegis = AEGIS(
    sink=JsonFileAuditSink("audit.jsonl"),
    signer=HMACSigner(key=b"host-managed-key"),
    chain_linker=chain,
)
artifact = aegis.enforce(invocation)
```

`AuditChain.append()` remains deprecated for offline compatibility. New enforcement code
must configure the linker so chain placement is finalized before signing.

## Verification and Assurance Boundary

`verify_chain_detailed()` independently reports content integrity, chain continuity,
signature status, anchor status, and completeness. For the sequence supplied by the
caller, it verifies checksum integrity, coordinate continuity, and predecessor checksum
links. A reordered or internally truncated supplied sequence is invalid.

A valid prefix is still internally continuous, so completeness always remains `unproven`
without an external trusted checkpoint. An attacker with storage-write access can remove a
valid tail or replace an entire valid chain. Hash chaining is tamper-evidence, not immutable
or WORM storage. Issue #46 (ADR-0015) adds the separate, additive trusted-checkpoint
control that binds a chain head to externally signed evidence and promotes completeness to
`checkpoint_proven` for an expected scope; it does not change this ADR's chain-before-sign
decision.

## Options Considered

### AEGIS-owned counter after signing

Rejected because it mutates finalized evidence and leaves chain placement outside the
signature. It also incorrectly makes the enforcement object responsible for host storage
ordering and durable recovery.

### Host-owned reserve/commit linker (chosen)

Keeps storage and ordering authority with the host while making chain-before-sign coverage
an AEGIS invariant. The transaction boundary is explicit, including the unavoidable
sink-acknowledgement/commit crash window.

### Merkle batches or external transparency log

Not required by the SDK core. Hosts may implement either behind their storage and trusted
checkpoint controls; neither changes the finalizer's content or signature coverage.

## Consequences

- Chain coordinates, checksum, and signature describe one immutable finalized artifact.
- Concurrent producers must serialize or coordinate placement through their linker.
- The schema adds four optional fields as a complete set; only
  `previous_audit_checksum` may be `null`, and only at index zero.
- Re-signing for key rotation changes the signature layer without changing the content
  checksum or chain coordinates.
- Sink acknowledgement and chain commit remain separate operations; persistent linkers
  must define reconciliation and recovery.
- Verification detects breaks inside the supplied sequence but makes no completeness,
  replay-prevention, retention, certification, or compliance claim.

## Validation

- contract tests cover malformed coordinates and linker failures;
- ordering tests prove reserve/attach/checksum/sign/validate/emit/commit sequencing;
- concurrency tests prove no gaps after abort/retry and one outstanding placement;
- reconciliation tests cover the post-ack commit crash window;
- deterministic vectors prove key rotation preserves chain coordinates and checksums;
- deletion/reordering vectors keep completeness `unproven` without an external anchor.
