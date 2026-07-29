# Issue #45 AWS KMS and Google Cloud KMS Adapters Design

Date: 2026-07-29
Status: Approved for implementation planning
Parent issue: [#39](https://github.com/nealsolves/aegis/issues/39)
Prerequisite issue: [#44](https://github.com/nealsolves/aegis/issues/44)
Delivery issue: [#45](https://github.com/nealsolves/aegis/issues/45)

## Summary

Issue #45 adds two production-oriented, provider-specific implementations of
the external signing contracts delivered by #44:

- an AWS Key Management Service adapter; and
- a Google Cloud Key Management Service adapter.

Each provider gets a metadata-aware artifact signer and verifier. Both adapters
are optional extras in the main `aegis-ai-governance` distribution, are
importable without their provider dependencies installed, accept host-created
clients, and have fully offline fixture/conformance tests. The base dependency
set remains unchanged.

The adapters bind AEGIS signature metadata to a stable provider verification
identity, use SHA-256 digests, allow only a small closed set of asymmetric
algorithms, and fail closed when identity, algorithm, integrity, or provider
response checks do not agree. Google exposes and records an exact
CryptoKeyVersion. AWS exposes and records an immutable KMS key ARN, which is a
logical-key identity rather than an exposed backing-material version. Artifact
metadata is never treated as authority to select a provider resource:
verification requires a host-approved resolver for the exact
`(key_reference, key_version)` pair.

This design deliberately makes narrower claims than the provider products can
support. A valid KMS-backed signature is not an immutable audit log, trusted
timestamp, proof that the entire history is present, HSM/FIPS attestation, or
compliance certification.

## Goals

- Ship one tested AWS KMS signer/verifier pair.
- Ship one tested Google Cloud KMS signer/verifier pair.
- Bind every signature to an immutable provider verification resource:
  a Google CryptoKeyVersion or an AWS KMS key ARN.
- Prevent confused-deputy, mutable-alias, algorithm-confusion, and
  artifact-directed resource lookup failures.
- Preserve the atomic signing and structured verification contracts from #44.
- Keep all provider dependencies optional and keep the base dependency set
  unchanged.
- Let applications own provider clients, credentials, endpoints, retry policy,
  timeout policy, region/project configuration, authorization, and trust
  policy.
- Provide deterministic, offline fixtures that exercise provider request and
  response shapes while performing real local cryptographic verification.
- Correct the #44 conformance kit so randomized asymmetric signatures are
  tested correctly.
- Document least privilege, rotation, historical verification, compromise,
  outage, and evidence-retention behavior.

## Non-Goals

- Adding a mandatory AWS, Google Cloud, CRC32C, or cryptography dependency.
- Adding Azure Key Vault, HashiCorp Vault, PKCS#11, a generic remote-signer
  transport, or other providers.
- Creating cloud clients, finding credentials, refreshing credentials,
  selecting regions/projects, or configuring endpoints.
- Creating, importing, rotating, disabling, destroying, or scheduling
  destruction of provider keys.
- Automatically discovering trust from artifact-controlled provider resource
  names.
- Synchronous-to-asynchronous wrappers or asynchronous adapter APIs.
- Supporting raw-message KMS signing; both adapters submit SHA-256 digests.
- Supporting symmetric MAC keys, RSA PKCS#1 v1.5, SHA-384, SHA-512, or
  secp256k1.
- Providing a trusted timestamp, time-aware revocation, certificate PKI,
  timestamp-authority integration, transparency log, or immutable storage.
- Detecting complete replacement or truncation of an otherwise valid audit
  chain. That remains part of #46.
- Re-signing an already signed artifact or changing enforcement decisions when
  a signer or verifier is unavailable.
- Claiming a provider key's protection level, origin, HSM/FIPS boundary, or
  regulatory status from these adapters.

## Requirements Locked by Review

- Both AWS KMS and Google Cloud KMS ship in #45.
- Both providers include a signer and a verifier, with conformance coverage.
- They are optional extras of the existing distribution, not separate
  packages.
- There is one version and release path for the distribution.
- The base runtime dependency list does not change.
- The provider modules remain importable when their optional dependencies are
  absent.
- Provider clients are injected by the host; adapters do not instantiate
  clients.
- The implementation is test-driven.
- The written design receives a complete contradiction, ambiguity, dependency,
  failure-mode, security-boundary, and acceptance-coverage review before
  implementation planning.

## Options Considered

### Option A: Two explicit provider adapters in optional extras

Create small AWS and Google Cloud modules that implement the #44 protocols and
share only private provider-neutral validation helpers.

Advantages:

- Provider semantics stay visible instead of being hidden by a leaky generic
  abstraction.
- Consumers install only the dependencies they need.
- The public contracts and package release remain unified.
- Fixtures can match each SDK's real request and response shapes.

Costs:

- Some intentional duplication remains between provider implementations.
- Two dependency and packaging lanes must be maintained.

### Option B: One generic KMS adapter

Create one adapter driven by provider callbacks and configuration.

Advantages:

- Smaller nominal public API.
- Potentially reusable for future providers.

Costs:

- AWS alias resolution, AWS `Verify`, Google integrity fields, Google public
  key retrieval, and algorithm naming have materially different semantics.
- A broad callback surface moves security-sensitive provider checks into host
  code and makes conformance weaker.
- Provider errors and historical-verification behavior become ambiguous.

### Option C: Separate provider distributions

Publish `aegis-aws-kms` and `aegis-google-cloud-kms`.

Advantages:

- Strict dependency isolation.
- Independent provider release cadence.

Costs:

- Multiple version/release paths for two small adapters.
- Greater risk of provider packages drifting from the core signing contract.
- More packaging and compatibility machinery than #45 needs.

### Decision

Choose Option A. Provider-specific behavior is part of the security model and
should remain explicit. Optional extras provide dependency isolation without
fragmenting releases.

## Source and Version Baseline

Implementation must be checked against current official provider
documentation, not examples copied from third-party sources:

- [AWS KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [AWS KMS Verify](https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html)
- [AWS KMS DescribeKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html)
- [AWS KMS key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
- [Google Cloud KMS asymmetricSign](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
- [Google Cloud KMS data-integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines)
- [Google Cloud KMS getPublicKey](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey)
- [Google Cloud KMS algorithms](https://cloud.google.com/kms/docs/algorithms)
- [Google Cloud KMS resource hierarchy](https://cloud.google.com/kms/docs/resource-hierarchy)
- [Google Cloud KMS key states](https://cloud.google.com/kms/docs/key-states)
- [Google Cloud KMS key rotation](https://cloud.google.com/kms/docs/key-rotation)
- [Boto3 releases](https://pypi.org/project/boto3/)
- [Google Cloud KMS Python releases](https://pypi.org/project/google-cloud-kms/)
- [Google CRC32C releases](https://pypi.org/project/google-crc32c/)
- [cryptography releases](https://pypi.org/project/cryptography/)

The SDK surfaces and release availability were rechecked on 2026-07-29
against the published wheels as well as the product references. In particular,
Google `CryptoKeyVersion` exposes `name`, `state`, `protection_level`, and
`algorithm`, but not its parent `CryptoKey.purpose`; the signing algorithm
itself is restricted by Google to `ASYMMETRIC_SIGN` keys. Explicit
`GetPublicKeyRequest.public_key_format=PEM` returns the bytes and checksum
through `PublicKey.public_key`, not the legacy `PublicKey.pem` field.

The optional dependency floors are:

```toml
[project.optional-dependencies]
aws-kms = [
  "boto3>=1.43.0",
]
gcp-kms = [
  "google-cloud-kms>=3.15.0",
  "google-crc32c>=1.7.1",
  "cryptography>=45.0.1",
]
```

`google-cloud-kms` 3.15.0 was the current published release during review and
contains the explicit public-key-format and checksummed-data surfaces used by
this design. The `cryptography` floor avoids the yanked 45.0.0 release. These
floors are part of the #45 release review. They must be verified by
minimum-version and current-version clean-install tests before merge. No upper
bound is added without evidence of an incompatibility.

## Package and Import Design

The public provider modules are:

```text
aegis.integrations.kms
aegis.integrations.aws_kms
aegis.integrations.google_cloud_kms
```

They export:

```text
aegis.integrations.kms
└── KmsKeyDisposition

aegis.integrations.aws_kms
├── AwsKmsArtifactSigner
├── AwsKmsArtifactVerifier
└── AwsKmsVerificationTarget

aegis.integrations.google_cloud_kms
├── GoogleCloudKmsArtifactSigner
├── GoogleCloudKmsArtifactVerifier
└── GoogleCloudKmsVerificationTarget
```

Shared implementation details live in
`aegis.integrations._kms_common`. The private module may contain strict
built-in normalization, digest, canonical-base64, length, CRC32C, and
safe-error helpers. It must not become a public generic provider abstraction.

None of the new names is re-exported from `aegis`, `aegis.signing`, or
`aegis.integrations`. Importing `aegis` or any provider module must not require
an optional dependency. Provider SDK and cryptography imports are lazy and
occur only when a code path needs them. A missing dependency produces a
sanitized AEGIS contract error at use time, not an import-time traceback from
the provider library.

`__all__` in each provider module contains only its documented public names.
Private omission sentinels, normalized internal targets, SDK exception
classifiers, and algorithm descriptors remain private.

## Shared Trust-Policy Model

### Key disposition

```python
class KmsKeyDisposition(str, Enum):
    ANCHORED = "anchored"
    UNANCHORED = "unanchored"
    INVALID_ANCHOR = "invalid_anchor"
    REVOKED = "revoked"
```

The enum represents host trust policy, not provider lifecycle state.
Disabling, pending deletion, destruction scheduling, permission denial, or a
provider outage does not automatically mean `REVOKED`. Only the host resolver
can mark a version revoked.

Disposition maps to #44 verification results as follows:

| Disposition | Successful crypto result |
| --- | --- |
| `ANCHORED` | `VALID` / `ANCHORED` / `SIGNATURE_VALID_ANCHORED` |
| `UNANCHORED` | `VALID` / `UNANCHORED` / `SIGNATURE_VALID_UNANCHORED` |
| `INVALID_ANCHOR` | `VALID` / `INVALID` / `ANCHOR_INVALID` |
| `REVOKED` | no provider call; `REVOKED` / `NOT_EVALUATED` / `KEY_REVOKED` |

Cryptographic mismatch always takes the existing
`SIGNATURE_INVALID` outcome where a provider call or local verification was
performed. `INVALID_ANCHOR` does not turn an invalid signature into a valid
one.

### Exact resolver contract

Provider verifiers receive a host resolver:

```python
AwsKmsTargetResolver = Callable[
    [str, str],
    AwsKmsVerificationTarget | None,
]

GoogleCloudKmsTargetResolver = Callable[
    [str, str],
    GoogleCloudKmsVerificationTarget | None,
]
```

The two arguments are the artifact's already-validated `key_reference` and
`key_version`. The resolver is the only authority that maps them to a provider
resource. The adapter never constructs a resource name from metadata, treats a
metadata string as a client request target, scans provider keys, or falls back
to a mutable alias or primary version.

The `AwsKmsTargetResolver` and `GoogleCloudKmsTargetResolver` names in this
specification are notation for the two callable shapes, not additional public
exports.

A `None` result means `KEY_UNKNOWN` and causes no provider call.

The exact concrete target class is required. Subclasses, duck-typed objects,
mappings, mocks returned as targets, and lookalikes are rejected. On every
call, the verifier copies allowed fields into new trusted built-in values and
reconstructs a validated target. This prevents hostile properties, mutable
collections, or post-resolution target mutation from changing a request.

If the resolver raises, returns a malformed value, or produces an impossible
combination, the verifier raises a sanitized `VerificationContractError`.
Resolver exception text, representation, traceback linkage, and attached
provider payloads must not escape.

## Public AWS Model

### Verification target

```python
@dataclass(frozen=True)
class AwsKmsVerificationTarget:
    key_arn: str
    allowed_algorithms: frozenset[str]
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED
```

Validation rules:

- `key_arn` is an exact built-in `str`, is nonempty, fits the #44
  128-character `key_version` bound, and is an AWS KMS key ARN rather than an
  alias, key ID, or arbitrary URI.
- `allowed_algorithms` is an exact `frozenset` of exact built-in strings,
  is nonempty, and contains only algorithms supported by this adapter.
- `disposition` is an exact `KmsKeyDisposition`.

The resolved `key_arn` must equal the immutable ARN represented by metadata's
`key_version`. No resolver may redirect an old metadata identity to a new key.
The adapter intentionally rejects otherwise provider-valid selectors or ARNs
that exceed #44's metadata bounds.

### Signer construction

`AwsKmsArtifactSigner` is constructed with:

- a host-created KMS client;
- a configured key selector accepted by `DescribeKey`, preferably an alias
  ARN;
- one supported signing algorithm.

The signer does not accept credentials, a region string, endpoint URL, retry
dictionary, or an SDK factory. Those belong to the injected client.

The public constructor is:

```python
def __init__(
    self,
    client: object,
    *,
    key_id: str,
    signing_algorithm: str,
) -> None: ...
```

`key_id` uses AWS's API terminology but is the configured selector: a key ID,
key ARN, alias name, or alias ARN that also fits the #44 `key_reference`
contract. It and `signing_algorithm` must be exact built-in strings; invalid
configuration raises a sanitized `SigningContractError` before an SDK call.

### Verifier construction

`AwsKmsArtifactVerifier` is constructed with:

- a host-created KMS client; and
- an `AwsKmsTargetResolver`.

The verifier does not use a signer selector and never resolves an AWS alias.

The public constructor is:

```python
def __init__(
    self,
    client: object,
    *,
    resolver: Callable[
        [str, str],
        AwsKmsVerificationTarget | None,
    ],
) -> None: ...
```

## Public Google Cloud Model

### Verification target

```python
@dataclass(frozen=True)
class GoogleCloudKmsVerificationTarget:
    crypto_key_version_name: str
    algorithm: str
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED
    public_key_pem: bytes | None = None
```

Validation rules:

- `crypto_key_version_name` is an exact built-in string in the canonical
  `projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}`
  shape and contains a concrete terminal version. Its parent CryptoKey must fit
  the 512-character `key_reference` bound, its terminal version must fit the
  128-character `key_version` bound, and the derived complete name is therefore
  bounded at 659 characters.
- `algorithm` is one of the supported Google algorithms.
- `disposition` is an exact `KmsKeyDisposition`.
- `public_key_pem`, when supplied, is exact built-in `bytes`, nonempty, no
  larger than 65,536 bytes, parses as a public key of the algorithm's required
  type and curve/size, and contains no private key material.

The resolved version resource must reconstruct the metadata pair exactly:
the parent CryptoKey is `key_reference`, and the terminal version identifier
is `key_version`.

### Signer construction

`GoogleCloudKmsArtifactSigner` is constructed with:

- a host-created Key Management Service client;
- one exact CryptoKeyVersion resource name;
- optional provider `retry`; and
- optional provider `timeout`.

The private `_USE_PROVIDER_DEFAULT` sentinel distinguishes an omitted SDK
argument from an explicit `None`. If retry or timeout is omitted, the adapter
does not include that keyword in the SDK call. If explicitly `None`, it
forwards `None`. A supplied timeout must be an exact finite positive number;
booleans, NaN, infinities, zero, and negative values are rejected.

The public constructor is:

```python
def __init__(
    self,
    client: object,
    *,
    crypto_key_version_name: str,
    retry: object = _USE_PROVIDER_DEFAULT,
    timeout: object = _USE_PROVIDER_DEFAULT,
) -> None: ...
```

The private sentinel appears here only to define omission behavior and is not
exported.

### Verifier construction

`GoogleCloudKmsArtifactVerifier` is constructed with:

- a host-created client or `None`;
- a `GoogleCloudKmsTargetResolver`; and
- optional provider `retry` and `timeout` with the same omission semantics.

`client=None` is allowed for retained-key operation. Every resolved target must
then include a valid `public_key_pem`. A target without retained PEM and
without a client produces `VERIFIER_UNAVAILABLE`.

The public constructor is:

```python
def __init__(
    self,
    client: object | None,
    *,
    resolver: Callable[
        [str, str],
        GoogleCloudKmsVerificationTarget | None,
    ],
    retry: object = _USE_PROVIDER_DEFAULT,
    timeout: object = _USE_PROVIDER_DEFAULT,
) -> None: ...
```

## Supported Algorithms

The adapter algorithm string stored in metadata is exactly the provider's
closed canonical name.

| Provider algorithm | Digest | Signing or verification operation |
| --- | --- | --- |
| AWS `RSASSA_PSS_SHA_256` | SHA-256 | KMS digest sign/verify |
| AWS `ECDSA_SHA_256` | SHA-256 | KMS digest sign/verify |
| Google `RSA_SIGN_PSS_2048_SHA256` | SHA-256 | KMS sign; local RSA-PSS verify |
| Google `RSA_SIGN_PSS_3072_SHA256` | SHA-256 | KMS sign; local RSA-PSS verify |
| Google `RSA_SIGN_PSS_4096_SHA256` | SHA-256 | KMS sign; local RSA-PSS verify |
| Google `EC_SIGN_P256_SHA256` | SHA-256 | KMS sign; local ECDSA P-256 verify |

All other algorithms fail closed before signing or provider verification.
Provider enum-like return values are normalized through an explicit mapping of
documented names. The implementation must not use `str(enum_value)` as an
algorithm identity because SDK enum rendering is not the protocol.

AWS key-spec agreement is also closed:

| AWS algorithm | Permitted `KeySpec` values |
| --- | --- |
| `RSASSA_PSS_SHA_256` | `RSA_2048`, `RSA_3072`, `RSA_4096` |
| `ECDSA_SHA_256` | `ECC_NIST_P256`, `ECC_SECG_P256K1` |

For local Google verification:

- the original AEGIS payload is hashed once with SHA-256;
- `cryptography` verifies with `utils.Prehashed(hashes.SHA256())`;
- RSA uses PSS with MGF1-SHA256 and salt length equal to the SHA-256 digest
  size;
- ECDSA uses P-256 with prehashed SHA-256;
- the public key type, curve, and RSA key size must match the declared
  algorithm.

Signatures are canonical RFC 4648 base64 without whitespace. A decoded
signature may contain at most 12,288 bytes, which is the largest raw value that
fits #44's 16,384-character encoded-signature bound. AWS applies the stricter
provider limit of 6,144 raw bytes on both signing responses and verification
inputs. Oversized, noncanonical, or malformed signatures are rejected before
network or cryptographic work.

## AWS Signing Flow

`signer_identity()`:

1. Validate the configured selector and requested algorithm.
2. Call `DescribeKey(KeyId=configured_selector)`.
3. Normalize the response into trusted built-ins.
4. Require `KeyUsage="SIGN_VERIFY"`, `KeyState="Enabled"`, `Enabled is True`,
   a permitted `KeySpec`, the requested algorithm in
   `KeyMetadata.SigningAlgorithms`, and a concrete key ARN.
5. Return:
   - `algorithm`: configured supported AWS algorithm;
   - `signature_encoding`: `BASE64`;
   - `key_reference`: the configured selector exactly;
   - `key_version`: the resolved concrete key ARN.

`sign(payload, identity)`:

1. Require exact `bytes` payload and exact `SignerIdentity`.
2. Revalidate that the identity matches this signer configuration.
3. Call `DescribeKey` again with the configured selector.
4. Require the selector still resolves to the exact `identity.key_version` and
   still permits the exact algorithm. If an alias rotated between identity
   preparation and this check, fail before signing.
5. Compute SHA-256 over the exact payload.
6. Call `Sign` with the immutable concrete ARN, not the selector:
   - `KeyId=identity.key_version`;
   - `Message=digest`;
   - `MessageType="DIGEST"`;
   - `SigningAlgorithm=identity.algorithm`.
7. Normalize the response, require a nonempty byte signature no larger than
   6,144 bytes, and require returned `KeyId` and `SigningAlgorithm` to equal
   the requested concrete ARN and algorithm.
8. Return a `SigningReceipt` echoing the prepared identity and containing
   canonical base64.

Using the immutable ARN after the second lookup closes the remaining
alias-retargeting race. It does not pin AWS's internal backing material: AWS
KMS rotation retains the same key ID and ARN and does not expose the material
version used by `Sign`. AWS owns selection and historical verification of
rotated material behind that ARN. The AEGIS `key_version` field therefore
means stable KMS key resource identity for AWS, not backing-material version.
AWS's `CurrentKeyMaterialId` metadata does not solve this for #45: AWS
documents it for rotatable symmetric encryption keys, not asymmetric
`SIGN_VERIFY` keys, and `Sign`/`Verify` responses do not return it.

AWS may retry the `Sign` request according to the injected client's
configuration. Randomized algorithms can therefore create more than one valid
remote signing operation, but AEGIS applies only the one returned receipt and
applies it atomically.

## Google Cloud Signing Flow

`signer_identity()`:

1. Parse and validate the configured exact CryptoKeyVersion name locally.
2. Call `get_crypto_key_version` for that exact resource using the configured
   retry/timeout forwarding semantics.
3. Normalize the response into trusted built-ins.
4. Require the exact returned name, `state=ENABLED`, and one supported signing
   algorithm. `CryptoKeyVersion` does not expose the parent
   `CryptoKey.purpose`; the closed algorithm mapping and Google's enforcement
   that these algorithms belong to `ASYMMETRIC_SIGN` keys provide the relevant
   operation check without an extra `get_crypto_key` permission or call.
5. Return:
   - `algorithm`: normalized version algorithm;
   - `signature_encoding`: `BASE64`;
   - `key_reference`: the parent CryptoKey resource name;
   - `key_version`: the terminal version identifier.

`sign(payload, identity)`:

1. Require exact `bytes` payload and exact `SignerIdentity`.
2. Revalidate that metadata identity reconstructs this signer's exact
   CryptoKeyVersion and algorithm.
3. Call `get_crypto_key_version` again for the exact version and require its
   identity and algorithm still agree and its state is still exactly
   `ENABLED`.
4. Compute SHA-256 over the exact payload.
5. Compute CRC32C over the digest with `google-crc32c`.
6. Build an `AsymmetricSignRequest` for the exact version and call
   `asymmetric_sign`, sending:
   - `digest.sha256=digest`; and
   - `digest_crc32c=crc32c(digest)`.
7. Require `verified_digest_crc32c is True`.
8. Require a bounded exact-byte signature.
9. Require `signature_crc32c` to be a non-boolean exact integer from 0 through
   `2**32 - 1` and equal locally computed CRC32C over the signature.
10. Require response `name` to equal the exact CryptoKeyVersion. The response
    does not contain an algorithm field; algorithm agreement was established
    by the immediately preceding exact-version metadata check.
11. Return a matching `SigningReceipt` with canonical base64.

CRC disagreement, missing integrity confirmation, wrong resource identity,
wrong algorithm, impossible state, and malformed response all fail without
mutating the artifact.

`protection_level` may appear on version, signing, and public-key responses,
but it is not part of identity or trust evaluation and is not persisted. The
adapter does not turn that field into an HSM, FIPS, origin, residency, or
compliance claim.

## AWS Verification Flow

Given payload, signature, and validated metadata:

1. Decode and bound-check canonical base64.
2. Reject an unsupported metadata algorithm as `ALGORITHM_NOT_ALLOWED`
   without calling the resolver or provider.
3. Call the host resolver with the exact metadata pair.
4. Normalize and validate the exact returned `AwsKmsVerificationTarget`.
5. Require `target.key_arn == metadata.key_version`. The resolver's approval
   of the exact pair is authoritative; the verifier does not dereference or
   attempt to reconstruct `key_reference`.
6. If the disposition is `REVOKED`, return `KEY_REVOKED` without a provider
   call.
7. If the metadata algorithm is not in the target's allowed set, return
   `ALGORITHM_NOT_ALLOWED` without a provider call.
8. Hash the exact payload with SHA-256.
9. Call `Verify` using only the trusted target:
   - `KeyId=target.key_arn`;
   - `Message=digest`;
   - `MessageType="DIGEST"`;
   - `Signature=decoded_signature`;
   - `SigningAlgorithm=metadata.algorithm`.
10. Require returned `KeyId` and `SigningAlgorithm` to equal the trusted
    concrete ARN and metadata algorithm.
11. Require `SignatureValid` to be an exact boolean. Map `False` or
    `KMSInvalidSignatureException` to `SIGNATURE_INVALID`; map `True` through
    the target disposition.

Historical AWS verification after alias retargeting requires the old logical
KMS key ARN to remain available for `Verify`. AWS-managed or on-demand
material rotation inside one KMS key retains the same ARN, and AWS KMS manages
the old material needed to verify earlier signatures. Removing access,
scheduling deletion, or destroying the logical key makes provider-backed
historical verification unavailable; it does not prove revocation or
invalidity.

## Google Cloud Verification Flow

Given payload, signature, and validated metadata:

1. Decode and bound-check canonical base64.
2. Reject an unsupported metadata algorithm as `ALGORITHM_NOT_ALLOWED`
   without calling the resolver or provider.
3. Call the host resolver with the exact metadata pair.
4. Normalize and validate the exact
   `GoogleCloudKmsVerificationTarget`.
5. Require the target resource's parent and terminal version to equal the
   metadata pair exactly.
6. If the disposition is `REVOKED`, return `KEY_REVOKED` without a provider
   call.
7. If the target algorithm differs from metadata, return
   `ALGORITHM_NOT_ALLOWED`.
8. Obtain the public key:
   - use the resolver-approved retained PEM when present; otherwise
   - construct `GetPublicKeyRequest` with the exact trusted version and
     `public_key_format=PublicKey.PublicKeyFormat.PEM`, then call
     `get_public_key` using the configured retry/timeout forwarding semantics.
9. For a provider-fetched key, require:
   - `name` equals the exact trusted CryptoKeyVersion;
   - `algorithm` equals the target and metadata algorithm;
   - `public_key_format` is exactly `PEM`;
   - `public_key.data` is exact bytes, nonempty, and no larger than 65,536
     bytes; and
   - `public_key.crc32c_checksum` is an exact non-boolean integer in range and
     equals locally computed CRC32C over `public_key.data`.
   The explicitly requested format uses the checksummed `public_key` field;
   the legacy `pem` and `pem_crc32c` fields are not accepted on this path.
10. Parse the PEM, require the expected public key type/curve/size, hash the
    exact payload once, and verify locally using the closed algorithm mapping.
11. For ECDSA, parse the signature with `decode_dss_signature` before
    verification; a signature-specific DER parse failure is
    `SIGNATURE_INVALID`. Map `cryptography.exceptions.InvalidSignature` to the
    same result and map successful verification through the target
    disposition. Other cryptography exceptions are contract errors. A
    provider-fetched key with an impossible type/curve/size is a malformed
    response and raises a contract error, while an invalid retained PEM is
    rejected when its target is constructed.

A retained resolver-approved PEM permits historical verification without a
live Google client. The retained key is trust-policy data and must be protected
and versioned by the host. Artifact metadata never supplies or selects PEM.

## Error and Result Semantics

The adapter returns only valid #44 `ExternalVerificationOutcome` combinations
or raises a sanitized `VerificationContractError`.

| Condition | Result or exception |
| --- | --- |
| Unsupported metadata algorithm | `ALGORITHM_NOT_ALLOWED` |
| Resolver returns `None` | `KEY_UNKNOWN` |
| Resolver marks version revoked | `KEY_REVOKED` |
| Allowed-algorithm or target-algorithm mismatch | `ALGORITHM_NOT_ALLOWED` |
| Cryptographic mismatch | `SIGNATURE_INVALID` |
| Successful crypto check | disposition-derived valid result |
| Known timeout, throttling, permission, unavailable service, disabled/destroyed key, or required client absent | `VERIFIER_UNAVAILABLE` |
| Resolver failure, malformed SDK response, impossible identity/state, invalid configured target, or unexpected exception | sanitized `VerificationContractError` |

An exact target-resource mismatch is a resolver contract failure, not
`KEY_UNKNOWN`. A provider `NotFound` after the host approved a target is
`VERIFIER_UNAVAILABLE`, not evidence that artifact metadata was unknown.

Signing failures are surfaced through the #44 atomic signing helper as a safe
`ArtifactSigningError`. Provider exception text, request/response objects,
payloads, digests, signatures, credentials, endpoints, resource discovery
data, and traceback chaining do not escape into AEGIS error messages,
`details`, `repr`, or AEGIS-emitted logs.

Only documented provider exception types and response states are classified as
availability or cryptographic mismatch. Broadly catching every provider
exception as `VERIFIER_UNAVAILABLE` would hide contract bugs and is forbidden.
Unexpected exceptions become safe contract errors.

AEGIS does not enable SDK debug/wire logging and does not copy provider
diagnostics. The host owns provider logger configuration; applications that
enable SDK diagnostics are responsible for their provider's redaction policy.

Direct calls to adapter methods are safe as well: they never intentionally
propagate a raw resolver, SDK, CRC, serialization, or cryptography exception.
Every returned `ExternalVerificationOutcome.message` is a fixed,
provider-neutral sentence containing no resource identifier. When the #44
helper is used, core performs its own second normalization and redaction
boundary.

## Concurrency, Mutation, and Lifecycle

Signer and verifier instances hold immutable configuration and must be safe for
concurrent calls to the extent the injected client itself is safe. They do not
store a mutable "last identity," "last key," "last signature," or per-call
result cache.

Injected clients, retry objects, and resolver callables remain host-owned. The
host must not mutate their behavior concurrently with an adapter call. The
adapter's concurrency guarantee is freedom from its own cross-call state bleed,
not an assertion that arbitrary injected objects are thread-safe.

Every request uses local snapshots of normalized identity and target values.
Provider operations happen before the #44 helper commits signature metadata
and signature. Any provider, integrity, validation, resolver, or receipt
failure leaves the artifact byte-for-byte unchanged.

AWS mutable aliases are permitted only as signer selectors. The signed identity
records both the selector and exact concrete ARN. An alias retarget detected
between the two `DescribeKey` calls aborts atomically. An alias retarget after
the second lookup is safe because `Sign` targets the exact ARN.

Google signers accept only a concrete CryptoKeyVersion, never a CryptoKey's
primary version. Provider rotation therefore does not retarget an in-flight
signing operation.

AWS multi-Region replicas have distinct ARNs. #45 does not substitute a
replica ARN for the recorded ARN during verification, even when AWS associates
the replicas with the same multi-Region key. Cross-Region failover that changes
the verification ARN requires a future, separately reviewed trust mapping.

The adapter does not provide time-aware "valid before compromise" policy.
`signed_at` is host-observed and signed, but it is not a trusted timestamp.
Disposition applies to the entire recorded verification resource: the Google
version or the AWS logical key. A host needing time-bounded revocation requires
separately trusted time evidence outside #45.

## Optional Dependencies and Release Path

`pyproject.toml` gains only the two provider extras. The project version and
release artifact remain singular. The base `dependencies` array is unchanged.

Required packaging checks:

- base install: no provider packages installed;
- `.[aws-kms]` at the declared floor and current compatible versions;
- `.[gcp-kms]` at the declared floors and current compatible versions;
- `.[aws-kms,gcp-kms]` at the declared floors and current compatible versions;
- wheel metadata contains the two extras and correct dependency markers;
- sdist contains provider source, integration guides, and required package
  metadata;
- `import aegis`, `import aegis.integrations.aws_kms`, and
  `import aegis.integrations.google_cloud_kms` succeed in the base lane;
- constructing or using a code path that needs a missing extra fails with the
  documented sanitized error;
- installing either extra does not require the other;
- no provider names are added to the top-level public API.

The changelog and release documentation describe both extras under the same
AEGIS version. Issue #45 and parent #39 are referenced by the eventual pull
request. Issue state is changed only after merge.

## Test Strategy

All repository tests are offline. They use generated local RSA and P-256 keys,
recording fake clients, and fixtures shaped like documented SDK responses.
No cloud credentials, emulators, network calls, real KMS resources, or
recorded secret-bearing responses are required.

### Conformance-kit correction

`tests/signing_conformance.py` currently assumes:

- repeated signing of the same payload produces the same encoded signature;
  and
- signing a changed payload produces a different encoded signature.

Those assertions are invalid for randomized RSA-PSS and ECDSA. The conformance
kit must instead:

- assert the exact canonical payload forwarded to the signer;
- assert receipt/identity binding and artifact atomicity;
- cryptographically verify every produced signature;
- verify that a signature does not validate a changed payload; and
- never require two valid signatures to be byte-equal or byte-different.

A randomized-signer regression test must fail under the old equality rule and
pass under the corrected contract. Deterministic existing fixture behavior may
remain tested in fixture-specific tests, not as a universal protocol rule.

The conformance fixture change is explicit:

```python
@dataclass(frozen=True)
class SignerFixture:
    signer: object
    recorded_payloads: Callable[[], Sequence[bytes]]
    verify_signature: Callable[[bytes, SigningReceipt], bool]
```

For every successful receipt, conformance asserts
`verify_signature(original_payload, receipt) is True` and
`verify_signature(changed_payload, receipt) is False`. It separately verifies
the receipt identity fields. It does not compare signature bytes across calls.
Every existing deterministic fixture and both provider fixtures implement this
callback.

### Shared adapter assertions

Both adapters must cover:

- every supported algorithm and every unsupported algorithm family;
- exact forwarded payload and SHA-256 digest;
- canonical base64 and raw-signature bounds;
- identity and receipt binding;
- wrong metadata provider/algorithm/resource/key shape;
- artifact nonmutation on every failure point;
- exact resolver arguments;
- unknown, revoked, unanchored, invalid-anchor, and anchored targets;
- resolver bypass for pre-resolution failures and revoked targets;
- resolver exception and malformed-target handling;
- exact-class rejection and trusted built-in reconstruction;
- provider availability, permission, timeout, throttle, malformed-response,
  impossible-state, and unexpected-exception behavior;
- redaction of the established hostile corpus from errors, `details`, `repr`,
  chaining, and AEGIS logs;
- barrier-controlled concurrent calls proving no per-call state bleed;
- missing optional dependencies and lazy-import behavior;
- `__all__` and no top-level re-export;
- the existing #44 external-signing conformance suite.

### AWS-specific assertions

- selector `DescribeKey` produces configured selector plus concrete ARN.
- Sign uses the exact ARN and never the mutable selector.
- Both `DescribeKey` checkpoints are exercised.
- Alias retargeting before the second check fails without a Sign call.
- Alias retargeting after the second check cannot retarget Sign.
- Key usage, key spec, state, algorithms, response fields, and exact built-in
  types are validated.
- `MessageType="DIGEST"` and the exact digest are sent.
- Verify uses only resolver-approved concrete ARN.
- `SignatureValid` true/false and documented invalid-signature exceptions map
  correctly.
- Old-key availability and unavailable historical verification are covered.
- Client retry behavior does not lead to multiple artifact mutations.

### Google-specific assertions

- Only an exact CryptoKeyVersion can configure a signer.
- Parent CryptoKey and terminal version are split and reconstructed exactly.
- Version resource, state, algorithm, and response fields are validated on
  both checkpoints; tests assert that no nonexistent version-level `purpose`
  field is assumed and no unnecessary `get_crypto_key` call is made.
- SHA-256 digest and its exact CRC32C are sent.
- `verified_digest_crc32c` must be the exact boolean `True`.
- Signature CRC32C accepts only exact non-boolean integers in range and must
  match.
- Retry/timeout omission, explicit `None`, and explicit valid values produce
  the exact SDK call shape.
- Invalid finite-timeout cases fail before a client call.
- `get_public_key` uses an explicit request object with
  `public_key_format=PEM`.
- Public-key response `name`, `algorithm`, `public_key_format`,
  checksummed-data bytes, CRC, size, type, curve, and RSA size are validated.
- The explicit-format path reads `public_key.data` and
  `public_key.crc32c_checksum`; legacy `pem` fields are rejected.
- Every Google algorithm is verified with real local cryptography.
- Wrong-key, changed-payload, malformed DER signature, malformed PEM, private
  PEM, and mismatched algorithm/key shape fail safely.
- Retained-PEM verification works with `client=None`.
- Missing PEM plus `client=None` returns `VERIFIER_UNAVAILABLE`.

### Verification matrix

Before completion, run:

- the complete pytest suite;
- coverage at the repository's required threshold;
- lint/static checks used by CI;
- public API and documentation-parity checks;
- base, AWS-only, Google-only, and combined clean-install tests;
- wheel and sdist build/metadata inspection;
- tests from built artifacts rather than only the source checkout.

The worktree baseline on 2026-07-29 was 2,497 passed and 1 skipped. Nine
`test_demo_copy_policy.py` cases failed only because the isolated worktree did
not contain `demo-app-react/node_modules`; the failures were Node module
resolution errors, not Python assertion failures. Final verification must
either provision the documented frontend dependencies in the worktree or run
the same checks in an equivalent clean environment. They may not be waived as
product failures without reproducing them with dependencies present.

## Documentation and Operations

Deliver:

- one provider-specific architecture decision record covering trust boundary,
  key identity, algorithm restrictions, and historical verification;
- one maintained AWS KMS integration guide;
- one maintained Google Cloud KMS integration guide;
- usage examples that inject clients and resolvers;
- optional-extra installation instructions;
- changelog and public API documentation updates.

The AWS guide must cover:

- least-privilege permissions for `DescribeKey`, `Sign`, and `Verify`;
- alias ARN preference for signer configuration;
- why signatures record and use concrete ARNs;
- rotation races and old-key retention;
- regional/client ownership;
- disabled, deletion-pending, destroyed, and inaccessible key behavior;
- revocation as host policy rather than inferred provider state.

The Google guide must cover:

- least-privilege permissions for version metadata, asymmetric signing, and
  public-key retrieval;
- exact CryptoKeyVersion pinning;
- digest and signature CRC32C integrity checks;
- provider retry/timeout ownership;
- retaining version public keys for offline historical verification;
- version state, rotation, destruction, and resolver revocation policy;
- why primary-version lookup is not used.

Both guides must state:

- credentials, clients, networking, endpoint selection, retries, and trust
  stores are host-owned;
- provider SDK debug logging can expose data and is host-controlled;
- a valid signature alone does not provide storage immutability, chronology,
  trusted time, completeness, or non-repudiation;
- #46 is still required for complete-chain replacement/truncation defenses;
- AEGIS makes no HSM, FIPS, key-origin, residency, or compliance claim based
  on these adapters.

## Security Boundaries and Adversarial Review

The final design was reviewed from artifact, host, SDK, provider, concurrency,
packaging, and operator perspectives.

| Attack or failure | Required defense |
| --- | --- |
| Artifact supplies an arbitrary key URI | Exact-pair host resolver; metadata never becomes provider request authority |
| AWS alias changes during signing | Two `DescribeKey` checks, then Sign immutable logical-key ARN |
| AWS backing material rotates under one ARN | Do not claim material-version pinning; rely on AWS KMS verification history |
| AWS multi-Region failover offers a replica ARN | Reject substitution; exact recorded ARN remains authoritative |
| Google primary version rotates | Signer accepts only exact CryptoKeyVersion |
| Resolver returns hostile object | Exact-class check and reconstruction into trusted built-ins |
| Algorithm-confusion attempt | Closed mappings plus target/key-shape agreement |
| Oversized signature or public key | 12,288-byte signature and 65,536-byte PEM limits |
| Boolean accepted as CRC integer | Exact non-bool integer and range validation |
| Digest/signature corrupted in transit | Google CRC32C request and response checks |
| Provider response lies about identity | Exact name/ARN/algorithm comparison wherever returned |
| Provider or resolver exposes secrets in an exception | Sanitized error, no chaining, safe details, redaction tests |
| Concurrent calls overwrite identity | No mutable per-call instance state |
| Randomized signature violates fixture assumption | Cryptographic conformance, no signature equality requirement |
| Old provider key becomes inaccessible | Explicit unavailable result; retained Google PEM option |
| Disabled provider key treated as revoked | Only resolver disposition marks revoked |
| Forged `signed_at` used for pre-compromise trust | No time-aware trust claim; trusted time is out of scope |
| Optional SDK absent | Module still imports; use-time sanitized failure |
| Extra silently alters base installation | Four packaging lanes and artifact metadata inspection |
| SDK retries create multiple remote signatures | Documented possibility; only one receipt is atomically stored |

No unresolved critical or high-severity design finding remains. The principal
residual risks are explicitly accepted boundaries: host resolver correctness,
injected-client security, host logging configuration, provider availability,
old-key/public-key retention, and absence of trusted time and complete-chain
anchoring.

## Requirement Traceability

| Locked requirement | Design mechanism | Verification evidence |
| --- | --- | --- |
| Two tested providers | Explicit AWS and Google signer/verifier modules | Provider suites plus shared conformance |
| Optional extras | Two `pyproject.toml` extras and lazy imports | Base/AWS/Google/combined clean installs |
| One release path | One distribution version, wheel, sdist, and changelog | Built-artifact metadata inspection |
| No base dependency change | Provider packages only in extras | Base dependency diff assertion |
| Stable signing identity | AWS selector-to-ARN checkpoint; exact Google version | Rotation/race fixtures and receipt binding |
| Artifact cannot choose provider resource | Exact-pair host resolver and trusted target reconstruction | Forged-metadata/confused-deputy tests |
| Closed algorithms | Provider and key-shape maps | Every allowed and rejected family tested |
| Integrity and size bounds | Digest, canonical base64, Google CRC32C, PEM/signature caps | Boundary and corruption fixtures |
| Structured trust results | Disposition-to-#44 outcome mapping | Full disposition/error matrix |
| Safe failures | Classified availability plus sanitized contract errors | Redaction corpus and no-chaining assertions |
| Historical verification | AWS old logical key; Google retained PEM | Old-key unavailable and offline-PEM tests |
| Concurrency safety | No mutable per-call adapter state | Barrier-controlled interleaving tests |
| Correct randomized-signature conformance | Cryptographic callback, no byte equality rule | Randomized regression plus all signer fixtures |
| Accurate operational claims | Provider ADR and two bounded integration guides | Documentation parity and claim audit |

## Acceptance Criteria

Issue #45 is complete only when all of the following are true:

- AWS and Google signer/verifier adapters implement the #44 contracts.
- Every supported algorithm has a real cryptographic fixture test.
- No unsupported algorithm reaches a provider operation.
- Signing binds a stable provider verification resource and is atomic on every
  failure; documentation distinguishes Google version pinning from AWS logical
  key identity.
- Verification uses only a host-approved exact target and cannot be redirected
  by artifact metadata.
- AWS alias rotation and Google version pinning behave as specified.
- Google CRC32C request/response checks and public-key validation are complete.
- Revoked, unknown, unavailable, invalid, unanchored, invalid-anchor, and
  anchored outcomes map consistently to #44.
- The randomized-signature defect in the shared conformance kit is fixed and
  regression-tested.
- Provider modules import without extras, and missing dependencies fail only
  at use time with sanitized errors.
- The base dependency list is byte-for-byte unchanged.
- Base, AWS-only, Google-only, and combined installation lanes pass.
- Wheel and sdist contents and metadata pass inspection.
- The full repository test/lint/coverage/documentation/public-API matrix
  passes from a clean environment with frontend dependencies provisioned.
- AWS and Google integration guides and the provider ADR are complete and
  accurately bound the security claims.
- The pull request references #45 and #39; issues are updated only after merge.

## Implementation Boundaries

Implementation planning may split work by shared contract hardening, AWS,
Google, packaging, and documentation, but it must preserve one coherent
test-first sequence. A provider adapter is not considered complete in
isolation from the shared conformance correction and packaging lanes.

Any implementation discovery that changes a public name, dependency floor,
supported algorithm, key identity, resolver authority, failure classification,
or security claim requires returning to design review before proceeding.
