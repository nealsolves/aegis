# External Trust-Anchor Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dependency-free, metadata-aware external signing and detailed verification contracts while preserving every legacy HMAC, custom signer, engine-construction, artifact-shape, and boolean-verification behavior.

**Architecture:** Keep `aegis._internal.signing` as the unchanged legacy boundary. Put immutable public values and validation in `signature_models.py`, provider-neutral protocols and orchestration in `external_signing.py`, and re-export both paths through the existing public modules. Metadata-aware signing builds and signs a temporary artifact before one atomic update; detailed verification separates cryptographic signature status from host-determined anchor status and validates every external outcome against a closed matrix.

**Tech Stack:** Python 3.10+, standard-library `dataclasses`, `enum`, `typing.Protocol`, canonical JSON from `aegis._internal.utils`, JSON Schema draft-07, pytest, jsonschema, flake8.

## Global Constraints

- Preserve `ArtifactSigner`, `HMACSigner`, `_canonical_signing_payload()`, `sign_artifact()`, `verify_artifact()`, `AEGIS(signer=...)`, custom legacy subclasses, legacy artifact shape, and fixed HMAC output byte-for-byte.
- Add no cloud SDK, HSM SDK, credential provider, network, retry, storage, certificate, timestamp-authority, or asynchronous dependency.
- Keep audit schema version `1.4`; version only the optional `signature_metadata` object.
- Keep `signature` as `string | null` and never persist signature or anchor status in the artifact.
- Sign all metadata using the exact `aegis-signature-v1` domain-separated byte contract.
- Resolve trust only through the host-supplied verifier. Artifact fields never trigger discovery or network access.
- Attach `signature_metadata` and `signature` only after identity, payload, receipt, and encoded signature validation succeeds.
- Never mutate an artifact during detailed verification.
- Never put payload bytes, signature contents, keys, credentials, tokens, raw provider responses, or unrestricted provider errors in results, exceptions, details, or logs.
- Treat `signed_at` as a host-observed Unix second, not trusted time or replay protection.
- Use red-green-refactor for every task. Do not add implementation before observing the task's intended test failure.
- Run each task's focused tests before committing. Keep commits limited to that task.

---

## File and Module Map

### Core implementation

- `aegis/_internal/signing.py` — legacy implementation; behavior must not change.
- `aegis/_internal/signature_models.py` — constants, enums, immutable value objects, parsing, bounds, encoding checks, and the allowed verification matrix.
- `aegis/_internal/external_signing.py` — signer/verifier protocols, domain-separated payload construction, atomic signing, detailed legacy verification, metadata-aware verification, response normalization, and safe error wrapping.
- `aegis/_internal/errors.py` — four stable typed contract/signing errors.
- `aegis/signing.py` — supported signing API re-exports.
- `aegis/errors.py` — supported error re-exports.
- `aegis/__init__.py` — top-level supported re-exports.

### Schemas

- `schemas/audit_artifact.schema.json` — source audit schema with optional strict `signature_metadata`.
- `aegis/schemas/audit_artifact.schema.json` — packaged byte-identical schema.

### Tests and conformance kit

- `tests/test_signature_models.py` — value validation, serialization, messages, properties, and status matrix.
- `tests/test_external_signing.py` — frozen payload, atomic signing, detailed verification, compatibility, mutation, and redaction tests.
- `tests/test_external_signing_schema.py` — historical/new schema acceptance, invalid metadata rejection, and schema-copy parity.
- `tests/test_public_api.py` — supported import and exception-code coverage.
- `tests/test_signing.py` — fixed legacy HMAC golden value and custom-subclass regression.
- `tests/test_golden_replay_signing.py` — unchanged engine artifact shape.
- `tests/__init__.py` — makes the reusable conformance helpers importable.
- `tests/support/__init__.py` — test-support package marker.
- `tests/support/external_signing.py` — deterministic signer/verifier with current, historical, unknown, revoked, unavailable, and malformed modes.
- `tests/signing_conformance.py` — reusable assertions that issue #45 adapters can invoke.
- `tests/test_external_signing_conformance.py` — runs the shared assertions against the deterministic test double.

### Maintained documentation

- `docs/decisions/ADR-0012-external-trust-anchor-signing.md` — accepted trust-model decision.
- `docs/architecture/AEGIS_THREAT_MODEL.md` — spoofing, substitution, replay, availability, and trust-boundary analysis.
- `docs/architecture/ARCHITECTURAL_INVARIANTS.md` — signed-metadata, atomicity, trust-resolution, and two-axis invariants.
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` — exact public types, helper signatures, semantics, and examples.
- `README.md` — concise capability and limitation language.
- `CHANGELOG.md` — additive contract entry and compatibility statement.

---

### Task 1: Add typed errors and immutable signature values

**Files:**

- Create: `aegis/_internal/signature_models.py`
- Modify: `aegis/_internal/errors.py`
- Create: `tests/test_signature_models.py`

**Interfaces:**

- Constants: `SIGNATURE_METADATA_SCHEMA_VERSION`, `SIGNING_PROFILE`, `CANONICALIZATION_VERSION`, `MAX_SIGNATURE_LENGTH = 16_384`, `MAX_VERIFICATION_MESSAGE_LENGTH = 1_024`.
- String enums: `EvidenceType`, `SignatureEncoding`, `SignatureStatus`, `AnchorStatus`, `VerificationReasonCode`.
- Frozen values: `SignerIdentity`, `SignatureMetadata`, `SigningReceipt`, `ExternalVerificationOutcome`, `ArtifactVerificationResult`.
- Serialization: `SignatureMetadata.to_dict()` and `SignatureMetadata.from_dict(value)`.
- Properties: `ArtifactVerificationResult.is_signature_valid` and `ArtifactVerificationResult.is_anchored`.
- Errors: `SignatureMetadataError`, `ArtifactSigningError`, `SigningContractError`, `VerificationContractError`.

- [x] **Step 1: Write failing tests for stable errors, constants, enums, and frozen values**

Add tests that assert the exact error codes and enum values:

```python
def test_contract_error_codes_are_stable():
    cases = [
        (SignatureMetadataError, "SIGNATURE_METADATA_INVALID"),
        (ArtifactSigningError, "ARTIFACT_SIGNING_ERROR"),
        (SigningContractError, "SIGNING_CONTRACT_ERROR"),
        (VerificationContractError, "VERIFICATION_CONTRACT_ERROR"),
    ]
    for error_type, code in cases:
        error = error_type("safe message")
        assert isinstance(error, AIGCError)
        assert error.code == code
        assert error.details == {}


def test_signer_identity_is_frozen_and_typed():
    identity = SignerIdentity(
        algorithm="HSM-SHA256",
        signature_encoding=SignatureEncoding.BASE64,
        key_reference="production/audit-key",
        key_version="version/17",
    )
    assert identity.signature_encoding is SignatureEncoding.BASE64
    with pytest.raises(FrozenInstanceError):
        identity.key_version = "version/18"
```

Assert the exact string values:

```python
assert SIGNATURE_METADATA_SCHEMA_VERSION == "1"
assert SIGNING_PROFILE == "aegis-signature-v1"
assert CANONICALIZATION_VERSION == "aegis-canonical-json-v1"
assert EvidenceType.AUDIT_ARTIFACT.value == "audit_artifact"
assert SignatureEncoding.HEX.value == "hex"
assert SignatureEncoding.BASE64.value == "base64"
assert {item.value for item in SignatureStatus} == {
    "unsigned", "valid", "invalid", "unknown_key", "revoked", "indeterminate"
}
assert {item.value for item in AnchorStatus} == {
    "not_evaluated", "unanchored", "anchored", "invalid"
}
```

- [x] **Step 2: Run the tests and verify import failures**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_signature_models.py -v
```

Expected: collection fails because `aegis._internal.signature_models` and the four new errors do not exist.

- [x] **Step 3: Add the four typed errors**

Append four direct `AIGCError` subclasses to `aegis/_internal/errors.py`. Each constructor accepts `message: str` and optional `details: dict | None`, and passes only its fixed code to `AIGCError`.

```python
class SignatureMetadataError(AIGCError):
    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(
            message, code="SIGNATURE_METADATA_INVALID", details=details
        )


class ArtifactSigningError(AIGCError):
    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message, code="ARTIFACT_SIGNING_ERROR", details=details)


class SigningContractError(AIGCError):
    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message, code="SIGNING_CONTRACT_ERROR", details=details)


class VerificationContractError(AIGCError):
    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(
            message, code="VERIFICATION_CONTRACT_ERROR", details=details
        )
```

- [x] **Step 4: Implement exact model fields and validation**

Use `class Name(str, Enum)` for every enum. Give `VerificationReasonCode` these exact values:

```python
UNSIGNED = "unsigned"
LEGACY_SIGNATURE_VALID = "legacy_signature_valid"
LEGACY_SIGNATURE_INVALID = "legacy_signature_invalid"
SIGNATURE_VALID_UNANCHORED = "signature_valid_unanchored"
SIGNATURE_VALID_ANCHORED = "signature_valid_anchored"
SIGNATURE_INVALID = "signature_invalid"
SIGNATURE_METADATA_MISSING = "signature_metadata_missing"
ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
KEY_UNKNOWN = "key_unknown"
KEY_REVOKED = "key_revoked"
VERIFIER_UNAVAILABLE = "verifier_unavailable"
ANCHOR_INVALID = "anchor_invalid"
```

Implement these exact frozen dataclass fields:

```python
@dataclass(frozen=True)
class SignerIdentity:
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str


@dataclass(frozen=True)
class SignatureMetadata:
    schema_version: str
    signing_profile: str
    canonicalization_version: str
    payload_type: EvidenceType
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str
    signed_at: int


@dataclass(frozen=True)
class SigningReceipt:
    signature: str
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str


@dataclass(frozen=True)
class ExternalVerificationOutcome:
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    reason_code: VerificationReasonCode
    message: str


@dataclass(frozen=True)
class ArtifactVerificationResult:
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    reason_code: VerificationReasonCode
    message: str
    signature_metadata: SignatureMetadata | None
```

Validation rules:

- Require `algorithm` length 1–128 and full match `[A-Za-z0-9._-]+`.
- Require `key_reference` length 1–512 and every character `str.isprintable()` with no control character.
- Require `key_version` length 1–128 and full match `[A-Za-z0-9._:/-]+`.
- Reject `bool` and non-`int` values for `signed_at`; require `signed_at >= 0`.
- Require metadata versions and payload type to equal the three fixed constants and `EvidenceType.AUDIT_ARTIFACT`.
- Require exact metadata keys in `from_dict`; reject missing and additional keys before conversion.
- Convert only valid enum strings to enums and wrap conversion failures as `SignatureMetadataError` with safe field-only details.
- Require every enum-typed field to be an instance of its declared enum;
  reject look-alike raw strings in direct dataclass construction.
- Require `message` to be a string no longer than 1,024 characters.
- Require signatures to be strings of length 1–16,384.
- For hex, require lowercase, even length, and full match `[0-9a-f]+`.
- For base64, reject whitespace and require strict RFC 4648 decoding followed by re-encoding equality.
- Put signature validation in `validate_encoded_signature(signature, encoding)`.
- Put matrix validation in `validate_verification_outcome(signature_status, anchor_status, reason_code)`.
- Have `SigningReceipt.__post_init__()` validate its echoed identity fields and
  encoded signature. Revalidate the same data at the orchestration trust
  boundary because a structural protocol implementation can still return an
  object that bypassed normal construction.

The closed matrix is:

```python
ALLOWED_VERIFICATION_OUTCOMES = {
    (SignatureStatus.UNSIGNED, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.UNSIGNED,
    },
    (SignatureStatus.VALID, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.LEGACY_SIGNATURE_VALID,
    },
    (SignatureStatus.VALID, AnchorStatus.UNANCHORED): {
        VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
    },
    (SignatureStatus.VALID, AnchorStatus.ANCHORED): {
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
    },
    (SignatureStatus.VALID, AnchorStatus.INVALID): {
        VerificationReasonCode.ANCHOR_INVALID,
    },
    (SignatureStatus.INVALID, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
        VerificationReasonCode.SIGNATURE_INVALID,
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
    },
    (SignatureStatus.UNKNOWN_KEY, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.KEY_UNKNOWN,
    },
    (SignatureStatus.REVOKED, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.KEY_REVOKED,
    },
    (SignatureStatus.INDETERMINATE, AnchorStatus.NOT_EVALUATED): {
        VerificationReasonCode.SIGNATURE_METADATA_MISSING,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
    },
}
```

`ExternalVerificationOutcome.__post_init__()` and `ArtifactVerificationResult.__post_init__()` call the message and matrix validators. The two convenience properties compare only their own axes:

```python
@property
def is_signature_valid(self) -> bool:
    return self.signature_status is SignatureStatus.VALID

@property
def is_anchored(self) -> bool:
    return self.anchor_status is AnchorStatus.ANCHORED
```

- [x] **Step 5: Add exhaustive negative and round-trip model tests**

Parameterize invalid algorithms, key references, key versions, timestamps, signatures, enum strings, missing metadata fields, extra metadata fields, and unsupported versions. Include boundary values at 1/128, 1/512, and 16,384 characters. Assert:

- `SignatureMetadata.to_dict()` returns all nine JSON-native fields in declared order.
- `SignatureMetadata.from_dict(metadata.to_dict()) == metadata`.
- input dictionaries are not mutated.
- unsupported versions raise `SignatureMetadataError`.
- each allowed matrix row constructs successfully.
- every other status-axis pair and every contradictory reason raises `VerificationContractError`.
- oversized messages raise `VerificationContractError`.

- [x] **Step 6: Run focused tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_signature_models.py -v
```

Expected: all model and error tests pass.

- [x] **Step 7: Commit**

```bash
git add aegis/_internal/errors.py aegis/_internal/signature_models.py tests/test_signature_models.py
git commit -m "feat(signing): add trust-anchor value contracts"
```

---

### Task 2: Define provider-neutral protocols and freeze the signed-byte contract

**Files:**

- Create: `aegis/_internal/external_signing.py`
- Modify: `tests/test_external_signing.py`

**Interfaces:**

- `@runtime_checkable class ExternalArtifactSigner(Protocol)`.
- `@runtime_checkable class ExternalArtifactVerifier(Protocol)`.
- Internal `_metadata_signing_payload(artifact, metadata) -> bytes`.
- Internal `_metadata_from_identity(identity, signed_at) -> SignatureMetadata`.

- [ ] **Step 1: Write the failing protocol and golden-payload tests**

Use a minimal artifact and hard-code the expected bytes:

```python
def test_metadata_signing_payload_matches_frozen_profile():
    artifact = {"audit_schema_version": "1.4", "signature": None}
    metadata = SignatureMetadata(
        schema_version="1",
        signing_profile="aegis-signature-v1",
        canonicalization_version="aegis-canonical-json-v1",
        payload_type=EvidenceType.AUDIT_ARTIFACT,
        algorithm="HSM-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="audit-key",
        key_version="version/7",
        signed_at=123,
    )
    expected_json = (
        b'{"audit_schema_version":"1.4","signature_metadata":{'
        b'"algorithm":"HSM-SHA256",'
        b'"canonicalization_version":"aegis-canonical-json-v1",'
        b'"key_reference":"audit-key","key_version":"version/7",'
        b'"payload_type":"audit_artifact","schema_version":"1",'
        b'"signature_encoding":"hex","signed_at":123,'
        b'"signing_profile":"aegis-signature-v1"}}'
    )
    expected = (
        b"AEGIS-SIGNATURE\x00"
        b"aegis-signature-v1\x00"
        b"audit_artifact\x00"
        + expected_json
    )
    assert _metadata_signing_payload(artifact, metadata) == expected
```

Also assert:

- the original artifact remains equal to a deep copy;
- `signature` is excluded even when non-null;
- `signature_metadata` is included;
- changing any artifact field or any one of the nine metadata fields changes the payload, except unsupported fixed versions are rejected before payload construction;
- concrete structural test doubles satisfy the runtime protocols.

- [ ] **Step 2: Run the test and verify the missing module failure**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py -v
```

Expected: collection fails because `aegis._internal.external_signing` does not exist.

- [ ] **Step 3: Add the exact protocol methods**

```python
@runtime_checkable
class ExternalArtifactSigner(Protocol):
    def signer_identity(self) -> SignerIdentity:
        raise NotImplementedError

    def sign(
        self, payload: bytes, identity: SignerIdentity
    ) -> SigningReceipt:
        raise NotImplementedError


@runtime_checkable
class ExternalArtifactVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        raise NotImplementedError
```

These protocols import no provider module and perform no I/O.

- [ ] **Step 4: Implement exact metadata and payload construction**

`_metadata_from_identity()` must require an actual `SignerIdentity`, reject `bool` timestamps, and copy the four identity fields into fixed metadata:

```python
return SignatureMetadata(
    schema_version=SIGNATURE_METADATA_SCHEMA_VERSION,
    signing_profile=SIGNING_PROFILE,
    canonicalization_version=CANONICALIZATION_VERSION,
    payload_type=EvidenceType.AUDIT_ARTIFACT,
    algorithm=identity.algorithm,
    signature_encoding=identity.signature_encoding,
    key_reference=identity.key_reference,
    key_version=identity.key_version,
    signed_at=signed_at,
)
```

`_metadata_signing_payload()` must:

1. shallow-copy the root artifact;
2. remove `signature`;
3. set `signature_metadata` from `metadata.to_dict()`, replacing any temporary caller value;
4. canonicalize with `canonical_json_bytes`;
5. prefix exactly:

```python
_SIGNATURE_DOMAIN = b"AEGIS-SIGNATURE\x00"
return (
    _SIGNATURE_DOMAIN
    + SIGNING_PROFILE.encode("utf-8")
    + b"\x00"
    + EvidenceType.AUDIT_ARTIFACT.value.encode("utf-8")
    + b"\x00"
    + canonical_json_bytes(signable)
)
```

- [ ] **Step 5: Run focused tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py -v
```

Expected: protocol and payload tests pass.

- [ ] **Step 6: Commit**

```bash
git add aegis/_internal/external_signing.py tests/test_external_signing.py
git commit -m "feat(signing): define external signing byte contract"
```

---

### Task 3: Implement atomic metadata-aware signing

**Files:**

- Modify: `aegis/_internal/external_signing.py`
- Modify: `tests/test_external_signing.py`

**Interfaces:**

- `sign_artifact_with_metadata(artifact, signer, *, signed_at) -> dict[str, Any]`.
- Internal `_validate_receipt(receipt, identity) -> None`.

- [ ] **Step 1: Write failing happy-path and atomicity tests**

Use a recording signer that exposes a stable identity and returns a matching receipt. Assert:

```python
result = sign_artifact_with_metadata(
    artifact, signer, signed_at=1_721_600_000
)
assert result is artifact
assert artifact["signature_metadata"] == {
    "schema_version": "1",
    "signing_profile": "aegis-signature-v1",
    "canonicalization_version": "aegis-canonical-json-v1",
    "payload_type": "audit_artifact",
    "algorithm": "HSM-SHA256",
    "signature_encoding": "hex",
    "key_reference": "audit-key",
    "key_version": "version/7",
    "signed_at": 1_721_600_000,
}
assert artifact["signature"] == signer.receipt.signature
assert signer.payload == _metadata_signing_payload(
    {"audit_schema_version": "1.4", "signature": None},
    SignatureMetadata.from_dict(artifact["signature_metadata"]),
)
```

For each failure mode, deep-copy before the call and assert exact equality afterward:

- already non-null `signature`;
- stale `signature_metadata`, including when signature is null;
- invalid timestamp;
- identity method raises;
- identity has the wrong runtime type;
- signer raises `ArtifactSigningError`;
- signer raises an unexpected exception containing a credential and payload fragment;
- receipt has the wrong runtime type;
- empty, oversized, uppercase hex, odd hex, prefixed hex, whitespace base64, or non-canonical base64 signature;
- algorithm, encoding, key reference, or key version differs between identity and receipt;
- simulated alias rotation changes receipt key version.

- [ ] **Step 2: Run tests and verify the missing helper failure**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py -k signing -v
```

Expected: tests fail because `sign_artifact_with_metadata` does not exist.

- [ ] **Step 3: Implement validation-before-mutation flow**

The helper must follow this order:

```python
def sign_artifact_with_metadata(
    artifact: dict[str, Any],
    signer: ExternalArtifactSigner,
    *,
    signed_at: int,
) -> dict[str, Any]:
    if artifact.get("signature") is not None:
        raise ArtifactSigningError("Artifact is already signed")
    if "signature_metadata" in artifact:
        raise ArtifactSigningError("Artifact contains stale signature metadata")

    try:
        identity = signer.signer_identity()
    except Exception:
        raise ArtifactSigningError("External signer could not prepare identity")

    if not isinstance(identity, SignerIdentity):
        raise SigningContractError("Signer returned an invalid identity")

    metadata = _metadata_from_identity(identity, signed_at)
    payload = _metadata_signing_payload(artifact, metadata)

    try:
        receipt = signer.sign(payload, identity)
    except Exception:
        raise ArtifactSigningError("External signer did not produce a signature")

    _validate_receipt(receipt, identity)
    validate_encoded_signature(receipt.signature, identity.signature_encoding)
    artifact.update(
        signature_metadata=metadata.to_dict(),
        signature=receipt.signature,
    )
    return artifact
```

Do not re-raise any adapter-created exception, even an
`ArtifactSigningError`, because its text/details are outside the core's
redaction boundary. Do not log the exception, payload, receipt, or signature.
`_validate_receipt()` requires an actual `SigningReceipt`, compares all four
echoed identity fields, and raises
`SigningContractError("Signing receipt does not match prepared identity")`
with no sensitive values in `details`.

Map malformed encoded signature content to `ArtifactSigningError("Signer returned an invalid encoded signature")`; preserve no validation error text that may contain the signature.

- [ ] **Step 4: Add the success-path tamper test**

After signing, change each of these independently and assert a separately constructed verifier no longer accepts the recorded payload/signature pair:

- a normal artifact field;
- `algorithm`;
- `key_reference`;
- `key_version`;
- `signed_at`;
- `payload_type`;
- `signing_profile`;
- `canonicalization_version`.

For the three fixed contract fields, mutate the stored dictionary directly; detailed parsing will later reject the unsupported value before verifier invocation.

- [ ] **Step 5: Run focused tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py -k "signing or payload" -v
```

Expected: all payload, signing, receipt, atomicity, and mutation tests pass.

- [ ] **Step 6: Commit**

```bash
git add aegis/_internal/external_signing.py tests/test_external_signing.py
git commit -m "feat(signing): add atomic metadata-aware signing"
```

---

### Task 4: Add detailed legacy verification without changing the boolean API

**Files:**

- Modify: `aegis/_internal/external_signing.py`
- Modify: `tests/test_external_signing.py`
- Modify: `tests/test_signing.py`
- Modify: `tests/test_golden_replay_signing.py`

**Interfaces:**

- `verify_artifact_detailed(artifact, *, legacy_signer=None, verifier=None) -> ArtifactVerificationResult`.
- Legacy branch helper `_verify_legacy_artifact(artifact, signer)`.

- [ ] **Step 1: Freeze the existing legacy contract with failing regression additions**

Add a fixed HMAC golden assertion using the current implementation:

```python
def test_legacy_hmac_signature_golden_value_is_unchanged():
    artifact = _sample_artifact()
    signature = HMACSigner(key=b"golden-key").sign(
        _canonical_signing_payload(artifact)
    )
    assert signature == "ce02bf635e950b0e7782f933ba2c4f595dfb9d1204dc05d3b1cd02587c459bd1"
```

The expected value above was captured from the unchanged baseline. Do not
derive it inside the assertion.

Add a two-method custom `ArtifactSigner` subclass and assert it still
instantiates, signs, and verifies. In `tests/test_golden_replay_signing.py`,
assert `AEGIS(signer=HMACSigner(key=b"golden-test-key"))` output has
`signature` but does not have `signature_metadata`.

- [ ] **Step 2: Write failing detailed legacy-verification tests**

Cover:

- missing or null signature returns `UNSIGNED / NOT_EVALUATED / UNSIGNED`, does not call either supplied verifier, and has `signature_metadata is None`;
- signed legacy HMAC success returns `VALID / UNANCHORED / LEGACY_SIGNATURE_VALID`;
- signed legacy HMAC failure returns `INVALID / NOT_EVALUATED / LEGACY_SIGNATURE_INVALID`;
- signed custom legacy success returns `VALID / NOT_EVALUATED / LEGACY_SIGNATURE_VALID`;
- signed custom legacy failure returns `INVALID / NOT_EVALUATED / LEGACY_SIGNATURE_INVALID`;
- signature with no metadata and no legacy signer returns `INDETERMINATE / NOT_EVALUATED / SIGNATURE_METADATA_MISSING`;
- every branch leaves the artifact deeply equal to a snapshot;
- an unexpected legacy verifier exception becomes `VerificationContractError` with a generic message and empty safe details.

- [ ] **Step 3: Run the tests and verify the missing detailed helper failure**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py tests/test_signing.py tests/test_golden_replay_signing.py -v
```

Expected: detailed-verification tests fail because the helper is missing; all pre-existing legacy tests still pass.

- [ ] **Step 4: Implement the unsigned and legacy branches**

Use this public signature:

```python
def verify_artifact_detailed(
    artifact: Mapping[str, Any],
    *,
    legacy_signer: ArtifactSigner | None = None,
    verifier: ExternalArtifactVerifier | None = None,
) -> ArtifactVerificationResult:
```

Branch order:

1. If `artifact.get("signature") is None`, return the unsigned result before parsing metadata or calling either verifier.
2. If `signature_metadata` is absent and `legacy_signer` is absent, return the metadata-missing result.
3. If metadata is absent and a legacy signer exists, reconstruct bytes using the unchanged `_canonical_signing_payload(dict(artifact))`, call its `verify`, and map the result.
4. Only `isinstance(legacy_signer, HMACSigner)` permits `AnchorStatus.UNANCHORED` on a valid result. Valid unknown custom signers use `NOT_EVALUATED`.
5. Never infer an anchor from a custom signer.
6. Never pass through a caught exception's string.

Use fixed, non-sensitive messages such as `"Artifact is unsigned"`, `"Legacy signature is valid"`, `"Legacy signature is invalid"`, and `"Signature metadata and legacy verifier are unavailable"`.

- [ ] **Step 5: Re-run legacy and detailed tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py tests/test_signing.py tests/test_golden_replay_signing.py -v
```

Expected: all tests pass, including the unchanged golden HMAC and engine-shape regressions.

- [ ] **Step 6: Commit**

```bash
git add aegis/_internal/external_signing.py tests/test_external_signing.py tests/test_signing.py tests/test_golden_replay_signing.py
git commit -m "feat(signing): add detailed legacy verification"
```

---

### Task 5: Implement metadata-aware verification and outcome enforcement

**Files:**

- Modify: `aegis/_internal/external_signing.py`
- Modify: `tests/test_external_signing.py`

**Interfaces:**

- Metadata-aware branch in `verify_artifact_detailed()`.
- Internal `_normalize_external_outcome(outcome, metadata)`.
- Internal fixed `_SAFE_REASON_MESSAGES` mapping.

- [ ] **Step 1: Write failing tests for every external outcome**

For a valid metadata-aware artifact, parameterize all externally valid rows:

```python
[
    (VALID, UNANCHORED, SIGNATURE_VALID_UNANCHORED),
    (VALID, ANCHORED, SIGNATURE_VALID_ANCHORED),
    (VALID, INVALID, ANCHOR_INVALID),
    (INVALID, NOT_EVALUATED, SIGNATURE_INVALID),
    (INVALID, NOT_EVALUATED, ALGORITHM_NOT_ALLOWED),
    (UNKNOWN_KEY, NOT_EVALUATED, KEY_UNKNOWN),
    (REVOKED, NOT_EVALUATED, KEY_REVOKED),
    (INDETERMINATE, NOT_EVALUATED, VERIFIER_UNAVAILABLE),
]
```

Assert the normalized result retains parsed metadata and exposes the correct convenience properties. Separately assert:

- valid current and historical immutable key versions are passed exactly to the verifier;
- unknown and revoked key versions return their statuses;
- a verifier is called at most once;
- absence of a verifier returns `INDETERMINATE / NOT_EVALUATED / VERIFIER_UNAVAILABLE`;
- unsupported schema/profile/canonicalization/payload versions, missing fields, extra fields, bad bounds, and bad signature encodings raise `SignatureMetadataError` without verifier invocation;
- a non-string signature raises `SignatureMetadataError` without verifier invocation;
- each impossible status/reason combination raises `VerificationContractError`;
- a non-`ExternalVerificationOutcome` response raises `VerificationContractError`;
- unexpected verifier exceptions become a generic `VerificationContractError`;
- verifier-returned `UNSIGNED`, either legacy reason, or
  `SIGNATURE_METADATA_MISSING` is rejected as contextually impossible on the
  metadata-aware branch even when the general result matrix admits that row;
- provider `message` content is not copied into the normalized result;
- the input remains deeply equal before and after success, evidence outcomes, and exceptions.

- [ ] **Step 2: Run metadata-aware tests and verify intended failures**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing.py -k "detailed or metadata or outcome or verifier" -v
```

Expected: metadata-aware cases fail because the verifier branch is not implemented.

- [ ] **Step 3: Implement parse-before-provider verification**

After the unsigned and legacy branches:

1. Require the signature to be a string.
2. Parse a mapping-only `signature_metadata` with `SignatureMetadata.from_dict()`.
3. Validate the signature with `validate_encoded_signature()`.
4. Rebuild the exact metadata signing payload from the parsed object.
5. If no verifier exists, return the fixed unavailable result.
6. Call `verifier.verify(payload, signature, metadata)` once.
7. Catch every adapter exception, including adapter-created AEGIS exceptions,
   and replace it with
   `VerificationContractError("External verifier failed unexpectedly")`.
   Core validation errors occur outside this `try` block and retain their
   stable type.
8. Require an actual `ExternalVerificationOutcome`.
9. Validate the closed matrix again at the trust boundary.
10. Reject `UNSIGNED`, `LEGACY_SIGNATURE_VALID`,
    `LEGACY_SIGNATURE_INVALID`, and `SIGNATURE_METADATA_MISSING` as
    contextually impossible responses from a verifier that was called only
    after finding a signature and valid metadata.
11. Return `ArtifactVerificationResult` using a core-owned safe message for
    the reason code, never `outcome.message`.

Use a complete fixed mapping:

```python
_SAFE_REASON_MESSAGES = {
    VerificationReasonCode.UNSIGNED: "Artifact is unsigned",
    VerificationReasonCode.LEGACY_SIGNATURE_VALID: "Legacy signature is valid",
    VerificationReasonCode.LEGACY_SIGNATURE_INVALID: "Legacy signature is invalid",
    VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: "Signature is valid but not externally anchored",
    VerificationReasonCode.SIGNATURE_VALID_ANCHORED: "Signature is valid and externally anchored",
    VerificationReasonCode.SIGNATURE_INVALID: "Signature is invalid",
    VerificationReasonCode.SIGNATURE_METADATA_MISSING: "Signature metadata is unavailable",
    VerificationReasonCode.ALGORITHM_NOT_ALLOWED: "The configured key does not permit the declared algorithm",
    VerificationReasonCode.KEY_UNKNOWN: "The configured verifier does not recognize the key version",
    VerificationReasonCode.KEY_REVOKED: "The configured verifier reports the key version as revoked",
    VerificationReasonCode.VERIFIER_UNAVAILABLE: "External verification is unavailable",
    VerificationReasonCode.ANCHOR_INVALID: "The external anchor is invalid",
}
```

Do not add logging on the metadata-aware path. A declared timeout or unavailability is an `ExternalVerificationOutcome`, not an exception.

- [ ] **Step 4: Add cross-type and downgrade defenses**

Assert:

- removing metadata from a metadata-aware artifact does not allow the external verifier to run;
- copying its signature to a legacy artifact does not validate with the legacy HMAC signer;
- changing `payload_type` is rejected before verifier invocation;
- changing `signing_profile` or `canonicalization_version` is a typed metadata error, not a retry or fallback;
- the verifier receives the parsed immutable version, never a mutable caller dictionary;
- artifact-supplied fields never cause any resolver other than the supplied verifier call.

- [ ] **Step 5: Run focused tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_signature_models.py tests/test_external_signing.py tests/test_signing.py tests/test_golden_replay_signing.py -v
```

Expected: all model, signing, detailed verification, downgrade, and compatibility tests pass.

- [ ] **Step 6: Commit**

```bash
git add aegis/_internal/external_signing.py tests/test_external_signing.py
git commit -m "feat(signing): verify external trust outcomes"
```

---

### Task 6: Extend strict schemas and publish the additive API

**Files:**

- Modify: `schemas/audit_artifact.schema.json`
- Modify: `aegis/schemas/audit_artifact.schema.json`
- Modify: `aegis/signing.py`
- Modify: `aegis/errors.py`
- Modify: `aegis/__init__.py`
- Create: `tests/test_external_signing_schema.py`
- Modify: `tests/test_public_api.py`
- Modify: `tests/test_audit_artifact_contract.py`
- Modify: `tests/test_chain_schema_compliance.py`

**Interfaces:**

- Public signing exports include all three version constants, five enums, five frozen values, two protocols, `sign_artifact_with_metadata`, and `verify_artifact_detailed`.
- Public error exports include all four new errors.
- Optional top-level schema property `signature_metadata`.

- [ ] **Step 1: Write failing schema and public-import tests**

Schema tests must validate:

- a historical artifact with no metadata;
- the normal generated artifact with `signature: null` and no metadata;
- a fully signed metadata-aware artifact;
- rejection of `signature_metadata: null`;
- rejection of every missing required metadata field;
- rejection of every additional metadata field;
- rejection of unsupported fixed versions or payload type;
- rejection of invalid algorithm/key/version patterns and lengths;
- rejection of negative or non-integer `signed_at`;
- acceptance of `signature` as string or null only;
- byte-for-byte equality of the two schema files.

Public tests import every symbol from both `aegis.signing` and top-level `aegis`, every error from `aegis.errors` and top-level `aegis`, and assert top-level objects are identical to their module exports.

- [ ] **Step 2: Run tests and verify schema/public failures**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing_schema.py tests/test_public_api.py tests/test_audit_artifact_contract.py tests/test_chain_schema_compliance.py -v
```

Expected: metadata-aware artifacts fail strict validation and public imports fail.

- [ ] **Step 3: Add the exact optional schema object to the source copy**

Insert beside `signature`:

```json
"signature_metadata": {
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "signing_profile",
    "canonicalization_version",
    "payload_type",
    "algorithm",
    "signature_encoding",
    "key_reference",
    "key_version",
    "signed_at"
  ],
  "properties": {
    "schema_version": {"type": "string", "const": "1"},
    "signing_profile": {"type": "string", "const": "aegis-signature-v1"},
    "canonicalization_version": {"type": "string", "const": "aegis-canonical-json-v1"},
    "payload_type": {"type": "string", "const": "audit_artifact"},
    "algorithm": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._-]+$"
    },
    "signature_encoding": {"type": "string", "enum": ["hex", "base64"]},
    "key_reference": {
      "type": "string",
      "minLength": 1,
      "maxLength": 512,
      "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"
    },
    "key_version": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._:/-]+$"
    },
    "signed_at": {"type": "integer", "minimum": 0}
  }
}
```

Copy the completed source schema to the package schema and verify with `cmp`; do not hand-edit the second copy independently.

- [ ] **Step 4: Add explicit public re-exports**

Update each import block and `__all__` rather than using wildcard imports. Include:

```python
SIGNATURE_METADATA_SCHEMA_VERSION
SIGNING_PROFILE
CANONICALIZATION_VERSION
EvidenceType
SignatureEncoding
SignatureStatus
AnchorStatus
VerificationReasonCode
SignerIdentity
SignatureMetadata
SigningReceipt
ExternalVerificationOutcome
ArtifactVerificationResult
ExternalArtifactSigner
ExternalArtifactVerifier
sign_artifact_with_metadata
verify_artifact_detailed
```

Add the four error names to both public error surfaces and top-level `aegis`.

- [ ] **Step 5: Run schema, API, and full legacy signing tests**

Run:

```bash
cmp schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json
../../.venv/bin/python -m pytest tests/test_external_signing_schema.py tests/test_public_api.py tests/test_audit_artifact_contract.py tests/test_chain_schema_compliance.py tests/test_signing.py tests/test_golden_replay_signing.py -v
```

Expected: `cmp` exits 0 and all selected tests pass without changing audit schema version `1.4`.

- [ ] **Step 6: Commit**

```bash
git add schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json aegis/signing.py aegis/errors.py aegis/__init__.py tests/test_external_signing_schema.py tests/test_public_api.py tests/test_audit_artifact_contract.py tests/test_chain_schema_compliance.py
git commit -m "feat(signing): publish trust-anchor contracts"
```

---

### Task 7: Build the reusable conformance kit and prove redaction

**Files:**

- Create: `tests/__init__.py`
- Create: `tests/support/__init__.py`
- Create: `tests/support/external_signing.py`
- Create: `tests/signing_conformance.py`
- Create: `tests/test_external_signing_conformance.py`
- Modify: `tests/test_external_signing.py`

**Interfaces:**

- `DeterministicExternalSigner`.
- `DeterministicExternalVerifier`.
- `assert_external_signer_conformance(signer_factory)`.
- `assert_external_verifier_conformance(signed_artifact_factory, verifier_factory)`.

- [ ] **Step 1: Write the failing conformance runner**

`tests/test_external_signing_conformance.py` calls the two shared assertion functions with deterministic factories. The shared assertions must cover:

- stable identity across repeated calls;
- exact payload bytes and deterministic signatures;
- receipt identity equality;
- current and historical version verification;
- unknown key, revoked key, invalid signature, unanchored, anchored, invalid anchor, algorithm denied, and declared unavailable outcomes;
- simulated key alias rotation producing a receipt mismatch;
- malformed identity, receipt, and verifier outcome;
- signer and verifier unexpected exceptions;
- artifact immutability on every error;
- result/error/log redaction.

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing_conformance.py -v
```

Expected: collection fails because the support and conformance modules do not exist.

- [ ] **Step 2: Implement deterministic test-only signer behavior**

Use standard-library HMAC-SHA256 only. The signer accepts immutable key records keyed by version, returns a fixed `SignerIdentity`, signs the exact supplied bytes, and returns lowercase hex. Test-controlled modes may raise `ArtifactSigningError`, raise an unexpected exception, return malformed data, or rotate the receipt version after signing. It must never be imported by `aegis`.

- [ ] **Step 3: Implement deterministic test-only verifier behavior**

The verifier resolves only `(key_reference, key_version)` from its constructor-supplied mapping, checks the configured allowed algorithm, verifies the exact supplied bytes, and derives anchor status from constructor-supplied trusted state. It returns only `ExternalVerificationOutcome`.

Its modes must deterministically produce all valid outcome rows and selected malformed combinations. Unknown or revoked versions must not fall back to the current key. No mode performs I/O.

- [ ] **Step 4: Implement reusable assertions without provider assumptions**

Factories are callables so issue #45 can supply a provider recipe without inheriting the deterministic classes. Keep shared assertions restricted to the public contracts; test-double-specific rotation controls remain in `tests/test_external_signing_conformance.py`.

- [ ] **Step 5: Add an adversarial redaction corpus**

Inject all of these into raised exception strings and external outcome messages:

```text
AKIAIOSFODNN7EXAMPLE
Bearer provider-token-123
super-secret-key-material
raw-signature-deadbeef
{"audit_schema_version":"1.4","private":"payload-fragment"}
https://provider.invalid/raw/response?id=credential
```

For every call, inspect:

- `str(exception)`;
- `exception.details`;
- normalized result fields;
- `caplog.text`.

Assert none contains any corpus value or recorded canonical payload/signature. The core may use only its fixed safe messages and field/reason identifiers.

- [ ] **Step 6: Run conformance and all signing tests**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_external_signing_conformance.py tests/test_external_signing.py tests/test_signature_models.py tests/test_signing.py tests/test_golden_replay_signing.py -v
```

Expected: all conformance, redaction, atomicity, model, and compatibility tests pass.

- [ ] **Step 7: Prove the base package has no provider dependency**

Run:

```bash
../../.venv/bin/python -c "import aegis; print(aegis.SIGNING_PROFILE)"
git diff HEAD~1 -- pyproject.toml
rg -n "boto|azure|google.cloud|vault|pkcs11|requests|httpx" aegis pyproject.toml
```

Expected: import prints `aegis-signature-v1`; `pyproject.toml` has no dependency change; the search finds no new provider/network import in the signing implementation.

- [ ] **Step 8: Commit**

```bash
git add tests/__init__.py tests/support/__init__.py tests/support/external_signing.py tests/signing_conformance.py tests/test_external_signing_conformance.py tests/test_external_signing.py
git commit -m "test(signing): add external signer conformance kit"
```

---

### Task 8: Document the trust boundary, public contract, and limitations

**Files:**

- Create: `docs/decisions/ADR-0012-external-trust-anchor-signing.md`
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md`
- Modify: `docs/architecture/ARCHITECTURAL_INVARIANTS.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**

- Accepted ADR and maintained public documentation matching the implemented names and behavior.

- [ ] **Step 1: Record the approved documentation-only TDD exception and baseline**

Human prose does not receive source-text change-detector tests. The user
approved validating this task with executable public examples, repository
documentation checks, and two manual review passes instead.

Run:

```bash
../../.venv/bin/python -m doctest docs/PUBLIC_INTEGRATION_CONTRACT.md
../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py
```

Expected: the existing documentation baseline passes before edits.

- [ ] **Step 2: Write ADR-0012**

Use the repository ADR template and set status `Accepted`. Include:

- context and threat model;
- additive layered decision and rejected alternatives;
- exact domain bytes;
- immutable identity/receipt pinning;
- host-configured verifier and no artifact-driven lookup;
- two independent status axes and the complete allowed matrix;
- signer/verifier availability semantics;
- strict metadata schema and audit schema `1.4` consequence;
- atomicity and non-mutation;
- legacy compatibility;
- redaction rules;
- complete-chain replacement, replay, trusted-time, WORM, provider transport, credential, and storage non-goals;
- signing the same mutable artifact concurrently is not thread-safe, and
  re-signing and asynchronous contracts remain out of scope;
- #45, #46, and #47 ownership.

- [ ] **Step 3: Update maintained architecture and integration documents**

`docs/PUBLIC_INTEGRATION_CONTRACT.md` must contain doctest-executable public
examples for:

1. defining an `ExternalArtifactSigner`;
2. signing with an explicit integer `signed_at`;
3. defining a host-configured `ExternalArtifactVerifier`;
4. checking both `result.is_signature_valid` and `result.is_anchored`;
5. legacy `verify_artifact()` semantics.

The threat model and invariants must state:

- metadata is signed and strict;
- key reference and immutable version are host resolved;
- metadata-declared algorithm is not authorization;
- valid does not mean anchored;
- HMAC/hash chaining is tamper-evidence, not immutable storage;
- availability never weakens the recorded governance decision;
- host time is not trusted time;
- no replay, sequence-completeness, certification, or compliance claim.

README and CHANGELOG get concise language only; do not duplicate the full contract.

- [ ] **Step 4: Check every documented snippet against the public API**

Run:

```bash
../../.venv/bin/python -m doctest docs/PUBLIC_INTEGRATION_CONTRACT.md
../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py
../../.venv/bin/python scripts/check_doc_parity.py
```

Expected: doctest and public-import checks pass. Documentation parity introduces
no #44 regression; record the four unrelated baseline inventory failures
separately if they remain.

- [ ] **Step 5: Perform two documentation review passes**

Pass 1 checks that all public names, signatures, constants, status semantics,
error codes, and examples match the implemented API.

Pass 2 checks every security claim and non-goal from the approved design,
including valid-versus-anchored, HMAC/hash-chain limitations, observational
time, host ownership, availability, replay, complete-chain replacement, WORM,
and #45/#46/#47 boundaries.

- [ ] **Step 6: Commit**

```bash
git add docs/decisions/ADR-0012-external-trust-anchor-signing.md docs/architecture/AEGIS_THREAT_MODEL.md docs/architecture/ARCHITECTURAL_INVARIANTS.md docs/PUBLIC_INTEGRATION_CONTRACT.md README.md CHANGELOG.md
git commit -m "docs(signing): define external trust-anchor boundary"
```

---

### Task 9: Run complete verification and close the #44 acceptance map

**Files:**

- Modify only if a verification failure identifies an issue in the files already listed.
- Update: `docs/superpowers/plans/2026-07-28-issue-44-trust-anchor-contracts.md` checkboxes as tasks complete.

**Interfaces:**

- No new interface; this task verifies the frozen public and artifact
  contracts produced by Tasks 1–8.

- [ ] **Step 1: Run the focused signing and schema suite**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_signature_models.py tests/test_external_signing.py tests/test_external_signing_schema.py tests/test_external_signing_conformance.py tests/test_signing.py tests/test_golden_replay_signing.py tests/test_public_api.py tests/test_audit_artifact_contract.py tests/test_chain_schema_compliance.py -v
```

Expected: all focused tests pass.

- [ ] **Step 2: Run the complete Python suite**

Run:

```bash
../../.venv/bin/python -m pytest -q
```

Expected: the full suite passes with no new warnings.

- [ ] **Step 3: Run coverage and lint gates**

Run:

```bash
../../.venv/bin/python -m pytest --cov=aegis --cov-report=term-missing --cov-fail-under=90
../../.venv/bin/python -m flake8 aegis
```

Expected: coverage is at least 90% and flake8 exits 0.

- [ ] **Step 4: Run schema, public-doc, and documentation parity gates**

Run:

```bash
cmp schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json
../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py
../../.venv/bin/python scripts/check_doc_parity.py
```

Expected:

- schema copies are byte-identical;
- public docs use no internal imports;
- #44 introduces no documentation-parity regression.

The baseline has four unrelated pre-existing parity inventory failures for the July 25/26 demo design and plan files. Record them separately if they remain; do not attribute them to #44 and do not broaden this branch to repair them.

- [ ] **Step 5: Validate the distribution candidate**

Run:

```bash
../../.venv/bin/python -m build
../../.venv/bin/python scripts/validate_v090_distribution_candidate.py
```

Expected: wheel/sdist construction and candidate validation pass, and the packaged schema/API behave like the source tree.

- [ ] **Step 6: Perform the first final review pass: acceptance completeness**

Build a checklist from the design's seven #44 acceptance rows and link each to:

- at least one passing test;
- the implementation file;
- the maintained documentation section.

Confirm explicit coverage of HMAC compatibility, custom signer compatibility, engine artifact shape, deterministic domain bytes, every outcome-matrix row, impossible outcomes, current/historical/unknown/revoked keys, atomic failure, no-mutation verification, schema parity, redaction, and no cloud dependency.

- [ ] **Step 7: Perform the second final review pass: adversarial security audit**

Review the final diff and search for accidental leakage or scope expansion:

```bash
git diff main...HEAD --check
git diff main...HEAD --stat
rg -n "str\\(exc|repr\\(exc|logger\\.|signature.*details|payload.*details|provider.*details" aegis/_internal/signature_models.py aegis/_internal/external_signing.py
rg -n "boto|azure|google.cloud|vault|pkcs11|requests|httpx|retry|credential" aegis pyproject.toml
rg -n "anchor_status|signature_status" schemas/audit_artifact.schema.json aegis/schemas/audit_artifact.schema.json
```

Expected:

- no whitespace errors;
- no raw exception forwarding or sensitive details;
- no provider, network, retry, or credential dependency;
- no persisted verification or anchor status;
- no engine-constructor or legacy-signing change.

- [ ] **Step 8: Run the complete suite once more after review fixes**

Run:

```bash
../../.venv/bin/python -m pytest -q
../../.venv/bin/python -m flake8 aegis
git status --short
```

Expected: tests and lint pass; status contains only intentional plan-checkbox or review-fix changes.

- [ ] **Step 9: Commit final review updates**

```bash
git add docs/superpowers/plans/2026-07-28-issue-44-trust-anchor-contracts.md
git commit -m "chore(signing): record issue 44 verification"
```

If review fixes changed implementation or tests, stage those exact files with the plan and use `fix(signing): close issue 44 verification gaps` instead.
