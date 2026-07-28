# ADR-0012: External Trust-Anchor Signing Contracts

Date: 2026-07-28
Status: Accepted
Owners: Neal

---

## Context

AEGIS has an established optional `ArtifactSigner` contract, a built-in
`HMACSigner`, a `signature: string | null` artifact field, and boolean
`verify_artifact()` results. That contract provides a cryptographic
tamper-evidence check, but it does not identify an algorithm, encoding, key
reference, immutable key version, signing profile, payload type,
canonicalization version, or signing time. A boolean result also cannot express
whether a valid signature is externally anchored.

The new boundary must support host adapters for KMS, Key Vault, HSM, and similar
services without adding a provider SDK, network client, credential store, or
storage dependency to AEGIS. Artifact content is untrusted input. In particular,
an artifact may not authorize its own algorithm, select a key through network
discovery, or assert that it is anchored.

The threat model includes algorithm and key-version confusion, cross-domain
signature reuse, mutable aliases changing between identity preparation and
signing, impossible or hostile verifier outcomes, partial artifact mutation,
and disclosure of signatures, payloads, credentials, secrets, or raw provider
responses through errors or logs.

### Constraints

- Existing `ArtifactSigner`, `HMACSigner`, `sign_artifact()`,
  `verify_artifact()`, automatic `AEGIS(signer=...)` signing, stored legacy
  artifacts, and fixed HMAC signatures remain unchanged.
- Metadata-aware signing and detailed verification are explicit, additive
  opt-ins.
- The base package remains provider-neutral and dependency-free.
- Signer identity is known before bytes are constructed and is confirmed by the
  signing receipt.
- Verification distinguishes cryptographic validity from external anchoring.
- Signer or verifier availability never changes the governance decision already
  recorded in an artifact.

---

## Decision

Adopt additive, layered public contracts:

- `ExternalArtifactSigner` exposes `signer_identity()` and signs exact bytes,
  returning a `SigningReceipt`.
- `ExternalArtifactVerifier` verifies exact bytes using a host-configured trust
  store or resolver and returns `ExternalVerificationOutcome`.
- `sign_artifact_with_metadata()` performs metadata-aware signing.
- `verify_artifact_detailed()` returns `ArtifactVerificationResult`.
- Frozen value objects, closed enums, bounded strings, typed errors, and a
  closed outcome matrix validate both sides of the boundary.

The host configures key resolution. AEGIS passes the parsed
`key_reference` and immutable `key_version` to the verifier; it never
dereferences artifact data or performs provider discovery. The verifier must
resolve that exact pair from host-approved configuration, verify that the
resolved key policy permits the metadata-declared algorithm, and derive anchor
status from trusted configuration. Declaring an algorithm in metadata is not
authorization to use it.

### Signed bytes and pinned identity

For signing profile `aegis-signature-v1`, the exact bytes are:

```text
b"AEGIS-SIGNATURE\x00"
+ b"aegis-signature-v1\x00"
+ b"audit_artifact\x00"
+ canonical_json_bytes(artifact_without_signature)
```

`artifact_without_signature` includes the complete, validated
`signature_metadata` object. Only the signature value is excluded.

Before constructing those bytes, the signer returns a `SignerIdentity` with
`algorithm`, `signature_encoding`, `key_reference`, and `key_version`. After
signing, `SigningReceipt` must echo all four values exactly. A mismatch,
including alias rotation to another key version, is a contract error and
neither metadata nor signature is attached.

`key_reference` is a non-secret opaque identifier. Hosts must not place
credentials, secret key material, access tokens, unrestricted provider
responses, or a locator that they expect AEGIS to dereference in it.

### Strict metadata

`signature_metadata` is an optional, non-null, strict object. When present, it
requires exactly:

- `schema_version = "1"`
- `signing_profile = "aegis-signature-v1"`
- `canonicalization_version = "aegis-canonical-json-v1"`
- `payload_type = "audit_artifact"`
- `algorithm`
- `signature_encoding` (`"hex"` or `"base64"`)
- `key_reference`
- `key_version`
- `signed_at`

Unknown or missing fields are rejected. Values are bounded and encoded
signatures are strictly validated. `signed_at` is a host-supplied, non-negative
integer Unix second. It is observational metadata, not trusted time, a
timestamp-authority statement, or replay protection.

The top-level `signature` remains `string | null`. Verification and anchor
statuses are computed at verification time and are never stored in
`signature_metadata`. The audit schema remains `1.4`; the optional metadata
object has its own version, so legacy artifact output and signatures do not
change.

### Independent verification axes

`SignatureStatus` and `AnchorStatus` are independent. A valid signature is not
necessarily anchored. `ArtifactVerificationResult.is_signature_valid` is true
only for `SignatureStatus.VALID`; `is_anchored` is true only for
`AnchorStatus.ANCHORED`. Callers that require both assurances must check both.

The complete allowed matrix is:

| Signature status | Anchor status | Allowed reason codes |
| --- | --- | --- |
| `UNSIGNED` | `NOT_EVALUATED` | `UNSIGNED` |
| `VALID` | `NOT_EVALUATED` | `LEGACY_SIGNATURE_VALID` |
| `VALID` | `UNANCHORED` | `LEGACY_SIGNATURE_VALID`, `SIGNATURE_VALID_UNANCHORED` |
| `VALID` | `ANCHORED` | `SIGNATURE_VALID_ANCHORED` |
| `VALID` | `INVALID` | `ANCHOR_INVALID` |
| `INVALID` | `NOT_EVALUATED` | `LEGACY_SIGNATURE_INVALID`, `SIGNATURE_INVALID`, `ALGORITHM_NOT_ALLOWED` |
| `UNKNOWN_KEY` | `NOT_EVALUATED` | `KEY_UNKNOWN` |
| `REVOKED` | `NOT_EVALUATED` | `KEY_REVOKED` |
| `INDETERMINATE` | `NOT_EVALUATED` | `SIGNATURE_METADATA_MISSING`, `VERIFIER_UNAVAILABLE` |

No other combination is valid. An external verifier also may not return
legacy-only, unsigned, or missing-metadata reasons for metadata-aware evidence.
Malformed or contradictory outcomes raise `VerificationContractError`.

### Availability and errors

Signer inability or refusal raises a sanitized `ArtifactSigningError`; invalid
identity or receipt data raises `SigningContractError`. The original artifact
remains deeply equal to its pre-call state. Metadata and signature are applied
together only after every signer response has been validated.

For metadata-aware verification:

- no configured verifier returns
  `INDETERMINATE / NOT_EVALUATED / VERIFIER_UNAVAILABLE`;
- a verifier may explicitly return that same allowed result for declared
  unavailability;
- an unexpected verifier exception is sanitized and raised as
  `VerificationContractError`;
- malformed metadata raises `SignatureMetadataError`.

Verification does not mutate the artifact. Availability affects only whether a
signature can be evaluated; it never converts an unavailable check to valid or
changes the artifact's recorded governance result.

Errors and results use bounded, AEGIS-controlled messages. They do not expose
canonical payload bytes, signature contents, credentials, tokens, secret key
material, unrestricted provider errors, or raw provider responses.

### Legacy compatibility

Legacy signing and boolean verification retain their original signatures and
meaning. `verify_artifact(artifact, signer) -> bool` answers only whether the
supplied legacy signer verifies the reconstructed payload. A `True` result does
not assert an external anchor.

Detailed verification maps a valid legacy HMAC signature to
`VALID / UNANCHORED / LEGACY_SIGNATURE_VALID`. A valid unknown custom legacy
signer maps to `VALID / NOT_EVALUATED / LEGACY_SIGNATURE_VALID`, because AEGIS
cannot infer that signer's trust boundary.

---

## Options Considered

### Option A: Additive layered contracts (chosen)

Pros:

- Preserves legacy artifacts, signers, boolean verification, and HMAC golden
  signatures.
- Separates signing from verification for least-privilege deployments.
- Keeps provider and storage concerns outside the core.
- Makes identity pinning and impossible outcomes testable.

Cons:

- Maintains legacy and metadata-aware paths side by side.
- Requires callers needing external assurance to inspect two status axes.

### Option B: Extend `ArtifactSigner`

Pros:

- One signer abstraction.

Cons:

- Breaks third-party subclasses and existing integrations.
- Couples signing and verification responsibilities.
- Cannot preserve stored evidence semantics cleanly.

### Option C: Replace `signature` with an envelope

Pros:

- Groups signature and metadata in one object.

Cons:

- Breaks the artifact schema, golden signatures, stored artifacts, and public
  examples.
- Requires a release-wide migration unrelated to the trust-boundary contract.

---

## Consequences

- Metadata, identity, and immutable key version are cryptographically bound to
  the artifact.
- The host owns its approved key map or resolver, algorithm policy, secrets,
  credentials, provider transport, retries, timeouts, availability behavior,
  and artifact storage.
- AEGIS performs one identity-preparation call and one sign call for
  metadata-aware signing, and at most one verifier call for detailed
  verification. It performs no credential lookup, retry, storage operation,
  provider discovery, or network call.
- HMAC signatures and checksum/hash chains provide tamper-evidence only. They
  do not make storage immutable.
- A verifier can establish a valid signature and configured anchor for one
  artifact, but #44 does not detect replacement of an entire otherwise-valid
  chain, replay of valid evidence, or sequence incompleteness without an
  external trusted checkpoint.
- Signing is atomic with respect to AEGIS's own update, not concurrent
  mutation. Signing the same mutable artifact concurrently is not thread-safe.
- Re-signing an already signed artifact and asynchronous signer/verifier
  contracts remain out of scope.

### Explicit non-goals and follow-on ownership

- **#45:** provider-specific KMS or HSM integration, SDKs, credentials,
  transport, retries, and operational key rotation.
- **#46:** trusted audit-chain checkpoints, whole-chain replacement detection,
  and finalized workflow-evidence anchoring.
- **#47:** WORM or append-only storage guidance, retention, object locking,
  disaster recovery, and maintained public-claims enforcement.

#44 also makes no claim of trusted timestamping, replay prevention,
sequence completeness, certificate PKI, timestamp-authority service,
certification, regulatory compliance, provider availability, or durable
storage.

---

## Contract Impact

- Enforcement pipeline impact: None; signer or verifier availability never
  changes recorded governance decisions.
- Policy DSL impact: None.
- Schema impact: Optional strict `signature_metadata` in both audit schema
  copies; audit schema version remains `1.4`.
- Audit artifact impact: Opt-in metadata-aware artifacts add
  `signature_metadata`; `signature` remains `string | null`; statuses are not
  persisted.
- Golden replays impact: Legacy artifacts and fixed HMAC signatures remain
  unchanged.
- Structural impact: Provider-neutral public contracts and frozen result/value
  types are exported from `aegis.signing` and top-level `aegis`.
- Backward compatibility: Additive; existing HMAC and custom `ArtifactSigner`
  call sites remain supported.

---

## Validation

- [x] Public value contracts, metadata schema, and outcome matrix tests
- [x] Atomic signing, non-mutating verification, identity/receipt pinning, and
  redaction tests
- [x] Legacy HMAC golden and custom-signer compatibility tests
- [x] Deterministic signer/verifier conformance kit
- [x] Schema-copy, public-export, packaging, and no-cloud-dependency checks
- [x] Executable public documentation examples and public-import checks

---

## References

- `docs/superpowers/specs/2026-07-28-issue-44-trust-anchor-contracts-design.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `docs/architecture/AEGIS_THREAT_MODEL.md`
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- `docs/decisions/ADR-0008-governance-artifact-chain.md`
- Issues #39, #44, #45, #46, and #47
