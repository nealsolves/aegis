# Issue #44 External Trust-Anchor Contracts Design

Date: 2026-07-28  
Status: Approved for implementation planning  
Parent issue: [#39](https://github.com/nealsolves/aegis/issues/39)  
Delivery issue: [#44](https://github.com/nealsolves/aegis/issues/44)

## Summary

AEGIS currently signs audit artifacts with an optional `ArtifactSigner`
interface and a built-in HMAC-SHA256 implementation. The signature is a single
string without a versioned description of the algorithm, encoding, key
identity, key version, signing profile, payload type, canonicalization
contract, or signing time. Verification returns only a boolean.

Issue #44 introduces dependency-free contracts for metadata-aware external
signing and structured verification. The design is additive: existing HMAC and
custom signer behavior remains unchanged, while callers that need external
trust information opt into a new signing helper and a detailed verification
result.

Cryptographic signature validity and external anchoring are modeled as
independent dimensions. A valid signature does not imply an external trust
anchor, immutable storage, trusted time, replay prevention, or complete-chain
integrity.

## Goals

- Define a cloud-neutral contract suitable for KMS, Key Vault, HSM, and similar
  external signer implementations.
- Record versioned, bounded, non-secret signature metadata before signing so
  the metadata is covered by the signature.
- Preserve the existing `ArtifactSigner`, `HMACSigner`, `sign_artifact()`, and
  `verify_artifact()` contracts.
- Add detailed verification results that distinguish signature validity from
  external anchoring.
- Prevent algorithm confusion, key-version confusion, domain confusion, and
  partial artifact mutation on signing failure.
- Provide a deterministic test double and reusable conformance assertions for
  later provider integrations.
- Keep the base package free of cloud, HSM, networking, credential, and storage
  dependencies.

## Non-Goals

- Provider-specific SDK integration, credentials, transport, retries, or
  operational key-rotation workflows. These belong to #45.
- Trusted audit-chain checkpoints, whole-chain replacement detection, or
  finalized workflow-evidence anchoring. These belong to #46.
- WORM storage, retention, object locking, disaster recovery, or maintained
  public-claims enforcement. These belong to #47.
- Re-signing an already signed artifact.
- Asynchronous signer or verifier contracts.
- Certificate PKI, timestamp-authority services, storage lifecycle management,
  or automatic network retrieval of keys and certificates.
- Treating host-observed signing time as trusted timestamp evidence.
- Changing enforcement decisions based on signer or verifier availability.

## Requirements Locked by Review

- Metadata-aware signing is opt-in.
- The current boolean verification API remains available and retains its
  cryptographic-validity meaning.
- Structured verification is additive.
- Signature status and anchor status are separate axes.
- Every design section receives a draft pass and an adversarial completeness
  pass before approval.
- The implementation uses test-driven development.

## Options Considered

### Option A: Additive layered contracts

Keep the existing signer hierarchy and boolean helpers unchanged. Add
metadata-aware signer and verifier contracts, an explicit metadata-aware
signing helper, and a detailed verification helper.

Advantages:

- Preserves current custom signer subclasses and HMAC behavior.
- Keeps metadata-aware security rules isolated and testable.
- Allows provider integrations to arrive later without cloud dependencies.
- Avoids changing stored legacy evidence.

Costs:

- Maintains legacy and metadata-aware paths side by side.
- Requires explicit compatibility tests to prevent semantic drift.

### Option B: Extend `ArtifactSigner` directly

Add required identity, metadata, and detailed verification methods to the
existing abstract base class.

Advantages:

- One signer abstraction.
- Fewer top-level concepts.

Costs:

- Breaks every third-party `ArtifactSigner` subclass.
- Couples signing and verification even when least-privilege deployments
  separate those responsibilities.
- Makes a non-breaking migration impossible.

### Option C: Replace the signature string with an envelope

Replace `signature: string | null` with an object containing the signature and
all associated metadata.

Advantages:

- Cohesive storage representation.
- Natural place for future fields.

Costs:

- Breaks schemas, stored artifacts, examples, custom integrations, and golden
  signatures.
- Requires a release-wide artifact migration.

### Decision

Choose Option A. Compatibility is a security and adoption requirement, not
merely a convenience. New contracts must not silently renegotiate the meaning
or representation of existing evidence.

## Compatibility Contract

The following behavior remains unchanged:

- `ArtifactSigner.sign(payload: bytes) -> str`
- `ArtifactSigner.verify(payload: bytes, signature: str) -> bool`
- `HMACSigner` signature generation and verification
- `sign_artifact(artifact, signer)` mutation behavior
- `verify_artifact(artifact, signer) -> bool`
- `AEGIS(signer=...)` construction and automatic legacy signing
- Legacy audit artifact shape when metadata-aware signing is not used
- Fixed-input HMAC golden signatures
- Existing custom `ArtifactSigner` subclasses

The existing boolean API answers only whether the supplied signer verifies the
signature over the reconstructed payload. For HMAC artifacts, a `True` result
does not imply external anchoring. Callers that require external assurance use
the detailed API and inspect both status axes.

## Public Model

The exact names are fixed for implementation planning.

### Version constants

- `SIGNATURE_METADATA_SCHEMA_VERSION = "1"`
- `SIGNING_PROFILE = "aegis-signature-v1"`
- `CANONICALIZATION_VERSION = "aegis-canonical-json-v1"`

### Enumerations

`EvidenceType`

- `AUDIT_ARTIFACT = "audit_artifact"`
- Reserved future values may be added only with a new signing-profile review.

`SignatureEncoding`

- `HEX = "hex"`
- `BASE64 = "base64"`

`SignatureStatus`

- `UNSIGNED`
- `VALID`
- `INVALID`
- `UNKNOWN_KEY`
- `REVOKED`
- `INDETERMINATE`

`AnchorStatus`

- `NOT_EVALUATED`
- `UNANCHORED`
- `ANCHORED`
- `INVALID`

`VerificationReasonCode`

A closed enum of stable machine-readable reasons:

- `UNSIGNED`
- `LEGACY_SIGNATURE_VALID`
- `LEGACY_SIGNATURE_INVALID`
- `SIGNATURE_VALID_UNANCHORED`
- `SIGNATURE_VALID_ANCHORED`
- `SIGNATURE_INVALID`
- `SIGNATURE_METADATA_MISSING`
- `ALGORITHM_NOT_ALLOWED`
- `KEY_UNKNOWN`
- `KEY_REVOKED`
- `VERIFIER_UNAVAILABLE`
- `ANCHOR_INVALID`

Reason codes are more specific than the two status axes but cannot contradict
them.

### `SignerIdentity`

A frozen value object supplied before signing:

- `algorithm`
- `signature_encoding`
- `key_reference`
- `key_version`

All fields are bounded and validated. `key_reference` is an opaque,
host-approved identifier. It must not contain credentials, secret key
material, access tokens, unrestricted provider responses, or a URL that AEGIS
will dereference.

Initial bounds:

- `algorithm`: 1-128 printable ASCII characters from `[A-Za-z0-9._-]`
- `key_reference`: 1-512 printable non-control characters
- `key_version`: 1-128 printable ASCII characters from `[A-Za-z0-9._:/-]`
- `signed_at`: integer greater than or equal to zero
- encoded signature: 1-16,384 characters

Hex signatures must be lowercase, even-length hexadecimal without a prefix.
Base64 signatures must use canonical RFC 4648 encoding without whitespace.

### `SignatureMetadata`

A frozen value object stored on the artifact:

- `schema_version`
- `signing_profile`
- `canonicalization_version`
- `payload_type`
- `algorithm`
- `signature_encoding`
- `key_reference`
- `key_version`
- `signed_at`

`signed_at` is an integer Unix epoch second supplied by the host-side
orchestration clock. It records when the host initiated the signing operation;
it is not trusted time evidence and does not prevent replay.

Verification status and anchor status are never stored in
`signature_metadata`. They are computed at verification time. Persisting them
would make the values stale and allow an artifact to assert its own trust.

### `ArtifactVerificationResult`

A frozen result object containing:

- `signature_status`
- `anchor_status`
- `reason_code`
- a bounded, sanitized message
- normalized non-secret signature metadata when validly parsed

The result exposes convenience properties for cryptographic validity and
external anchoring without collapsing those properties into one status.

The result never contains:

- canonical payload bytes
- signature contents
- secret key material
- credentials or tokens
- raw provider responses
- unrestricted provider error text

## External Contracts

The public contracts and associated result type are:

- `ExternalArtifactSigner`
- `ExternalArtifactVerifier`
- `SigningReceipt`
- `ExternalVerificationOutcome`

### Metadata-aware signer

The signer contract operates on bytes and has no provider dependency.

Conceptual protocol:

```python
class ExternalArtifactSigner(Protocol):
    def signer_identity(self) -> SignerIdentity: ...

    def sign(
        self,
        payload: bytes,
        identity: SignerIdentity,
    ) -> SigningReceipt: ...
```

`SigningReceipt` contains the encoded signature and echoes the algorithm,
encoding, immutable key reference, and immutable key version actually used.

It must:

1. Expose a stable `SignerIdentity` before the payload is constructed.
2. Sign the exact bytes supplied by AEGIS.
3. Return a signature string plus a receipt confirming the immutable key
   version, algorithm, and encoding actually used.
4. Fail if it cannot use the prepared identity exactly.

The receipt prevents an alias rotation or provider-side key change between
identity preparation and signing from creating false metadata. AEGIS compares
the receipt with the prepared identity before attaching either metadata or the
signature.

### Metadata-aware verifier

The verifier contract encapsulates a host-configured trust store or key
resolver. AEGIS passes bounded parsed metadata; it does not perform provider or
network discovery.

Conceptual protocol:

```python
class ExternalArtifactVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome: ...
```

`ExternalVerificationOutcome` contains the two status axes, a stable reason
code, and a bounded safe message. It does not contain raw provider evidence.

The verifier must:

1. Resolve only a host-approved key reference and immutable key version.
2. Confirm that the resolved key policy permits the declared algorithm.
3. Verify the exact domain-separated payload.
4. Determine anchor status from trusted verifier configuration, never from the
   artifact.
5. Return a bounded outcome that conforms to the status invariants.

Provider-specific transports, credentials, timeouts, and retries remain inside
the host adapter. The core contract defines how a declared unavailability
condition is reported without exposing provider internals.

## Signature Metadata Schema

The strict audit artifact schemas gain an optional `signature_metadata`
property. When present it is a non-null object with no additional properties.
Every field listed in `SignatureMetadata` is required.

The schema constrains:

- the metadata schema version
- the signing profile
- the canonicalization version
- the supported audit-artifact payload type
- string lengths and safe character sets
- supported signature encodings
- non-negative integer signing time

The top-level `signature` field remains `string | null`.

The audit schema remains `v1.4` for #44. Metadata-aware signing is an opt-in
additive extension, and the metadata object carries an independent version.
This avoids changing current artifact output or HMAC golden signatures. A
future release-wide audit-schema bump requires a separate migration decision.

Both copies remain byte-for-byte identical:

- `schemas/audit_artifact.schema.json`
- `aegis/schemas/audit_artifact.schema.json`

## Canonicalization and Domain Separation

Legacy signing continues to use the current canonical JSON payload unchanged.

Metadata-aware signing uses a versioned signing profile. The profile:

1. Creates a temporary evidence object containing validated
   `signature_metadata` and no signature value.
2. Produces canonical JSON using the named canonicalization version.
3. Prefixes the canonical bytes with a fixed AEGIS signature-profile domain and
   the closed evidence type.

For profile `aegis-signature-v1`, the signed bytes are exactly:

```text
UTF8("AEGIS-SIGNATURE\0")
+ UTF8("aegis-signature-v1\0")
+ UTF8("audit_artifact\0")
+ canonical_json_bytes(artifact_without_signature)
```

The signature metadata is therefore covered by the signature. Only the
signature value itself is excluded.

Callers cannot supply arbitrary evidence-type or signing-profile strings.
Closed enums and versioned profile implementations prevent a caller from
downgrading domain separation or replaying a signature across evidence types.

Identical artifact content, signer identity, signing time, evidence type, and
profile produce identical bytes. Changing any signed field changes the payload
and invalidates verification.

## Signing Flow

`sign_artifact_with_metadata()` is an explicit opt-in helper.

1. Validate that the artifact is not already signed and has no stale signature
   metadata.
2. Ask the signer for an immutable `SignerIdentity`.
3. Validate the identity and construct `SignatureMetadata` using a closed
   evidence type, fixed profile versions, and an injected signing time.
4. Build a temporary artifact containing the metadata and no signature.
5. Canonicalize and domain-separate the temporary artifact.
6. Ask the signer to sign those exact bytes with the prepared identity.
7. Validate the returned signature type, encoding, length, and signer receipt.
8. Attach both `signature_metadata` and `signature` to the original artifact
   only after all prior steps succeed.

The helper's atomicity guarantee concerns its own mutation of the artifact. It
does not make concurrent mutation of the same dictionary safe; sharing a
mutable artifact between signing calls is outside #44.

If any step fails, the input artifact remains deeply equal to its pre-call
state.

## Verification Flow

`verify_artifact_detailed()` never mutates its input.

1. A null or missing signature returns
   `UNSIGNED / NOT_EVALUATED` without invoking a verifier.
2. A signature without metadata is treated as legacy evidence:
   - `HMACSigner` validity maps to `VALID` or `INVALID`, with
     `AnchorStatus.UNANCHORED`.
   - An unknown custom legacy signer maps valid signatures to
     `AnchorStatus.NOT_EVALUATED` because AEGIS cannot infer the trust boundary.
3. Metadata-aware evidence is parsed, bounded, and version-checked before the
   external verifier is called.
4. The identical domain-separated payload is reconstructed.
5. The verifier resolves only the configured key/version and checks the
   permitted algorithm, signature, and external anchor.
6. AEGIS validates the verifier response and normalizes it into
   `ArtifactVerificationResult`.

Declared verifier timeouts or unavailability map to
`INDETERMINATE / NOT_EVALUATED`. They never become valid.

The orchestrator rejects impossible combinations. Examples include:

- `ANCHORED` with a signature status other than `VALID`
- `UNSIGNED` with an evaluated anchor
- `UNKNOWN_KEY` with `ANCHORED`
- a reason code that contradicts either status axis

The complete allowed outcome matrix is:

| Signature status | Anchor status | Allowed reasons |
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

No other combination is valid.

Unsupported metadata versions and key-version receipt mismatches do not enter
the outcome matrix. They raise typed contract errors as defined below.

## Error Model

New typed errors inherit from `AIGCError` and carry stable codes.

The exact public exception names are:

- `SignatureMetadataError` with code `SIGNATURE_METADATA_INVALID`
- `ArtifactSigningError` with code `ARTIFACT_SIGNING_ERROR`
- `SigningContractError` with code `SIGNING_CONTRACT_ERROR`
- `VerificationContractError` with code `VERIFICATION_CONTRACT_ERROR`

### Evidence outcomes

Expected evidence states return `ArtifactVerificationResult`, including:

- unsigned evidence
- signature mismatch
- unknown key
- revoked key
- missing external anchor
- invalid external anchor
- declared verifier unavailability

### Operational signing errors

When no trustworthy signature was produced, metadata-aware signing raises a
typed signing error. The artifact remains unchanged.

Examples:

- declared signer unavailability
- signer refusal
- unsupported prepared identity
- invalid signature encoding

### Contract errors

Programmer misuse, malformed signer/verifier responses, unsupported contract
versions, identity/receipt mismatches, and impossible status combinations raise
typed contract errors.

Expected provider unavailability is not treated as a programming defect.
Unexpected provider exceptions are sanitized before wrapping. Messages,
details, results, and logs exclude payloads, signatures, secrets, credentials,
and raw provider responses.

## Security Invariants

- Artifact metadata never asserts its own anchor status.
- Artifact key references never cause automatic network retrieval.
- The trusted verifier, not the artifact, determines which key references,
  versions, and algorithms are acceptable.
- The algorithm in artifact metadata is not sufficient authorization; the
  resolved key policy must permit it.
- The signer must confirm the exact immutable key version used.
- All signature metadata is signed.
- Signing failure cannot leave partially signed evidence.
- Verification cannot mutate evidence.
- External signer or verifier availability cannot alter the governance result
  already recorded by the artifact.
- `signed_at` is observational, not trusted time.
- Valid signatures do not imply replay protection, sequence completeness,
  immutable storage, certification, or compliance.

## Testing Strategy

Implementation follows red-green-refactor. Every new behavior begins with a
failing test that fails for the intended reason.

### Legacy compatibility

- Fixed HMAC golden signatures remain unchanged.
- Legacy boolean verification results remain unchanged.
- Existing custom `ArtifactSigner` subclasses instantiate and work unchanged.
- `AEGIS(signer=...)` produces the existing artifact shape.

### Metadata and schema

- Valid metadata serializes deterministically.
- Invalid versions, algorithms, encodings, key references, key versions,
  timestamps, field lengths, control characters, and additional properties are
  rejected.
- Historical and metadata-aware artifacts validate.
- Root and packaged schemas are byte-for-byte identical.

### Canonicalization and domain separation

- Frozen inputs produce frozen golden payload bytes and signatures.
- Different evidence types produce different signing payloads for otherwise
  identical content.
- Changes to metadata, artifact fields, algorithm, key version, signing time,
  payload type, or profile invalidate verification.

### Atomic signing

- Signer unavailability leaves the artifact unchanged.
- Invalid signature values leave the artifact unchanged.
- Identity/receipt mismatches leave the artifact unchanged.
- A simulated alias rotation between identity preparation and signing fails
  without mutation.
- Already signed or stale-metadata artifacts are rejected without mutation.

### Detailed verification

- Cover every valid signature/anchor status combination.
- Cover unsigned, invalid, unknown, revoked, invalid-anchor, and indeterminate
  outcomes.
- Reject every impossible combination.
- Resolve current, historical, unknown, and revoked key versions exactly.
- Do not invoke the verifier for unsigned, structurally invalid, or unsupported
  evidence.
- Assert deep equality before and after verification.

### Redaction and packaging

- Injected credentials, provider secrets, raw signatures, and payload fragments
  do not appear in results, exceptions, details, or captured logs.
- New public types import from supported modules and top-level `aegis`.
- Importing the base package does not import or require cloud SDKs.

### Reusable conformance kit

A deterministic test double and shared assertion module exercise:

- stable signer identity
- exact key-version pinning
- deterministic payload signing
- signature and anchor outcomes
- historical, unknown, and revoked keys
- declared unavailability
- malformed contract responses
- redaction requirements

Issue #45 reuses the same assertions for its provider recipe or optional
integration.

### Verification gates

- Targeted signing and schema tests
- Complete Python test suite
- Coverage at or above the existing 90% gate
- Lint
- Schema parity and documentation parity
- Distribution-candidate validation

## Documentation Plan

### ADR-0012

The implementation adds `docs/decisions/ADR-0012-external-trust-anchor-signing.md`
with:

- the threat model and trust assumptions
- the additive layered decision
- options considered
- domain separation and key-resolution rules
- signer/verifier availability behavior
- compatibility and schema consequences
- the complete-chain-replacement limitation
- ownership boundaries and non-goals

### Maintained public documentation

Update:

- `docs/architecture/AEGIS_THREAT_MODEL.md`
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- `CHANGELOG.md`
- README language where needed for claims parity

The documentation must state:

- valid is not the same as externally anchored
- HMAC and hash chaining provide tamper-evidence, not immutable storage
- host-observed signing time is not trusted timestamp evidence
- boolean verification proves only the legacy cryptographic check
- external availability does not weaken governance decisions
- credentials, secret keys, provider transport, and storage lifecycle remain
  host-owned

## Rollout

- The new path is opt-in through `sign_artifact_with_metadata()`.
- Existing engine construction and automatic HMAC signing remain unchanged.
- Legacy paths incur no metadata, provider call, import, or runtime overhead.
- Metadata-aware signing makes one signer contract call.
- Metadata-aware verification makes at most one verifier contract call.
- AEGIS performs no retry, provider discovery, credential lookup, storage
  operation, or network call.

Engine-level metadata-aware signer integration is intentionally deferred until
the provider contract is proven through #45.

## Follow-On Tracking

- #45 consumes the contracts for an optional KMS or HSM integration path.
- #46 consumes the contracts for trusted audit-chain checkpoints and finalized
  workflow-evidence anchoring.
- #47 consumes the contracts and checkpoint semantics for append-only
  operational guidance and claims enforcement.
- #39 remains open until all children and its parent acceptance criteria are
  complete.

Before #44 implementation begins, #46's issue body must explicitly name
finalized workflow evidence in its scope and acceptance criteria.

## Acceptance-Criteria Mapping

| #44 acceptance criterion | Design coverage |
| --- | --- |
| ADR defines trust model and non-goals | ADR-0012 and Documentation Plan |
| Versioned public signer metadata | Public Model and Signature Metadata Schema |
| Typed signature and anchor outcomes | Public Model and Verification Flow |
| Existing HMAC compatibility | Compatibility Contract and legacy tests |
| Deterministic payload conformance | Canonicalization and Testing Strategy |
| Test double covers errors, keys, and revocation | Reusable Conformance Kit |
| No cloud or HSM core dependency | External Contracts, Non-Goals, and Rollout |

## Completion Criteria

Issue #44 is complete when:

- ADR-0012 and all public contracts are implemented.
- Every acceptance criterion maps to passing tests or maintained
  documentation.
- Legacy artifact output and fixed-input HMAC signatures remain unchanged.
- Both audit schema copies are identical.
- No cloud or HSM dependency is added.
- No raw secret, payload, signature, or provider response appears in a result,
  exception, or log.
- Targeted, full-suite, coverage, lint, parity, and distribution validation
  gates pass.
- #45, #46, and #47 can consume the frozen contracts without changing their
  semantics.
