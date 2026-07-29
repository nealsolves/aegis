# Issue #45 AWS KMS and Google Cloud KMS Adapters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add production-oriented AWS KMS and Google Cloud KMS signer/verifier adapters as optional extras of the existing `aegis-ai-governance` distribution, with no base dependency changes and with offline cryptographic, conformance, packaging, and adversarial verification.

**Architecture:** Add a deliberately narrow `aegis.integrations` namespace containing one shared trust-disposition enum, one private normalization/outcome helper module, and two explicit provider modules. Both signers implement the issue #44 external-signing protocol and preserve atomic artifact mutation. Both verifiers require an exact-pair host resolver before using a provider resource. AWS delegates digest verification to an injected KMS client; Google retrieves or retains an exact-version public key and verifies locally. Provider SDK imports stay lazy, and one distribution/version/release workflow owns the base and both optional extras.

**Tech Stack:** Python 3.10+, AEGIS issue #44 external-signing contracts, `boto3>=1.43.0`, `google-cloud-kms>=3.15.0`, `google-crc32c>=1.7.1`, `cryptography>=45.0.1`, pytest, flake8, Python build metadata, GitHub Actions, generated local RSA/P-256 fixtures, and recording fake cloud clients.

## Global Constraints

- Treat the approved design at `docs/superpowers/specs/2026-07-29-issue-45-aws-google-kms-adapters-design.md` as authoritative.
- Ship exactly two provider adapters: AWS KMS and Google Cloud KMS. Each provider gets one signer and one verifier.
- Keep the distribution name, package version, wheel, sdist, changelog, and release workflow singular.
- Keep `[project].dependencies` exactly `PyYAML>=6.0` and `jsonschema>=4.0`.
- Put provider packages only in `aws-kms` and `gcp-kms` optional extras.
- Never create provider clients, discover credentials, select endpoints, regions, projects, aliases, or primary versions inside an adapter.
- Keep `aegis`, `aegis.signing`, `aegis.integrations`, and both provider modules importable without optional dependencies installed.
- Do not re-export provider adapter names from `aegis`, `aegis.signing`, or `aegis.integrations`.
- Import provider SDK, CRC32C, and cryptography modules only inside code paths that need them.
- Require exact built-in types at all trust boundaries; reject subclasses, mocks returned as targets, mappings, duck types, booleans-as-integers, mutable allowed-algorithm collections, and enum lookalikes.
- Treat artifact metadata only as input to the host resolver. Never use artifact strings directly as a provider request target.
- Permit only the six algorithms approved by the design and SHA-256 digest mode.
- Require canonical RFC 4648 base64. Cap generic raw signatures at 12,288 bytes, AWS signatures at 6,144 bytes, and Google PEM at 65,536 bytes.
- Treat an AWS KMS key ARN as the stable logical-key identity exposed by AWS, not as a backing-material version.
- Require an exact Google CryptoKeyVersion and the checksummed `PublicKey.public_key.data` PEM response path.
- Use retained host-approved Google PEM for offline historical verification when supplied.
- Map only documented provider availability and invalid-signature failures. Convert unexpected or malformed behavior into sanitized contract errors.
- Never place payloads, digests, signatures, PEM, credentials, provider response data, resource identifiers, raw exception text, or traceback chaining in AEGIS exceptions, results, details, reprs, or logs.
- Store no mutable per-call adapter state. Every call uses a local snapshot of normalized configuration, identity, and resolver output.
- Preserve issue #44 atomic signing: no failed provider or integrity operation may partially attach signature metadata or a signature.
- Use red-green-refactor for every implementation task. Observe each intended test failure before adding the minimal implementation.
- Run focused tests and flake8 for each task before its commit.
- Before finalization, perform a complete contradiction, ambiguity, SDK-surface, dependency, trust-boundary, failure-mapping, mutation, concurrency, documentation, packaging, and acceptance-traceability audit.

---

## File and Responsibility Map

### Runtime implementation

- `aegis/integrations/__init__.py` — documented namespace only; no re-exports.
- `aegis/integrations/kms.py` — public `KmsKeyDisposition`.
- `aegis/integrations/_kms_common.py` — private strict normalization, bounds, canonical base64, digest, CRC integer validation, safe outcomes, timeout handling, and sanitized exception helpers.
- `aegis/integrations/aws_kms.py` — AWS target, signer, verifier, key metadata normalization, and AWS exception classification.
- `aegis/integrations/google_cloud_kms.py` — Google target, signer, verifier, resource parsing, SDK request construction, CRC32C checks, public-key validation, and local cryptographic verification.

### Tests and fixtures

- `tests/signing_conformance.py` — provider-neutral randomized-signature-safe signer conformance.
- `tests/test_external_signing_conformance.py` — deterministic and randomized conformance regression.
- `tests/support/external_signing.py` — deterministic signer verification callback support.
- `tests/support/kms_fixtures.py` — generated RSA/P-256 keys, real local signing helpers, recording fake clients, enum-like SDK response doubles, barriers, and safe provider exceptions.
- `tests/test_kms_common.py` — strict shared helper and disposition tests.
- `tests/test_aws_kms.py` — AWS signer/verifier unit, conformance, failure, redaction, mutation, and concurrency tests.
- `tests/test_google_cloud_kms.py` — Google signer/verifier unit, conformance, integrity, retained-key, failure, redaction, mutation, and concurrency tests.
- `tests/test_public_api.py` — exact supported import surface and absence of top-level re-exports.
- `tests/test_v090_distribution_contract.py` — unchanged base requirements and exact optional-extra metadata.
- `tests/test_v090_publish_workflow.py` — built-artifact validation matrix and single publish path.
- `tests/test_kms_distribution_smoke.py` — smoke-script contract and lane coverage.

### Packaging and release proof

- `pyproject.toml` — two optional extras; unchanged base dependencies and version.
- `scripts/validate_v090_distribution_candidate.py` — exact wheel metadata/member checks including both extras.
- `scripts/validate_kms_optional_extras.py` — isolated installed-artifact smoke proof for base, provider-only, combined, minimum, current, wheel, and sdist lanes.
- `.github/workflows/publish.yml` — install both extras for full tests, build once, validate isolated artifact lanes, publish the same validated artifacts.

### Maintained documentation and audit evidence

- `docs/decisions/ADR-0013-aws-google-kms-adapters.md` — accepted provider and trust-boundary decision.
- `docs/reference/external/AWS_KMS_SIGNING.md` — injected-client usage, IAM, rotation, outages, and AWS identity limits.
- `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` — injected-client usage, IAM, CRC, retained PEM, rotation, and outages.
- `docs/reference/external/README.md` — provider guide index.
- `README.md` — concise optional-extra installation and capability statement.
- `docs/INTEGRATION_GUIDE.md` — end-to-end signer/verifier examples and operational ownership.
- `docs/PUBLIC_INTEGRATION_CONTRACT.md` — exact public classes, constructors, algorithms, outcome mappings, and non-goals.
- `CHANGELOG.md` — both adapters under the same release.
- `RELEASE_GATES.md` — optional-extra artifact lanes and adversarial gate.
- `docs/audits/2026-07-29-issue-45-aws-google-kms-adapters-adversarial-review.md` — final evidence-backed adversarial review.
- `doc_parity_manifest.yaml` — classification of the issue #45 design, plan, ADR, provider guides, and audit.

---

### Task 1: Correct signer conformance for randomized asymmetric signatures

**Files:**

- Modify: `tests/signing_conformance.py`
- Modify: `tests/test_external_signing_conformance.py`
- Modify: `tests/support/external_signing.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class SignerFixture:
    signer: object
    recorded_payloads: Callable[[], Sequence[bytes]]
    verify_signature: Callable[[bytes, SigningReceipt], bool]
```

- [ ] **Step 1: Add a randomized-signature regression that fails under the existing equality rule**

Create a local conformance-only signer in `tests/test_external_signing_conformance.py`. Use `secrets.token_bytes(16)` as a nonce, encode `nonce + HMAC-SHA256(nonce + payload)` as canonical base64, and return a normal `SigningReceipt`. Its fixture verification callback must decode the receipt, recompute the HMAC with `compare_digest`, and return `False` for malformed signatures.

```python
def test_randomized_external_signer_conforms_without_signature_equality() -> None:
    assert_external_signer_conformance(_randomized_signer_scenario)
```

The normal scenario must produce two different valid signatures for the same payload.

- [ ] **Step 2: Run the regression and confirm the intended failure**

Run:

```bash
../../.venv/bin/python -m pytest \
  tests/test_external_signing_conformance.py::test_randomized_external_signer_conforms_without_signature_equality \
  -v
```

Expected: failure at the current universal `receipt.signature == repeated_receipt.signature` assertion.

- [ ] **Step 3: Replace byte-equality assumptions with semantic verification**

Update `SignerFixture` and `assert_external_signer_conformance()` so it asserts:

```python
assert fixture.verify_signature(payload, receipt) is True
assert fixture.verify_signature(payload, repeated_receipt) is True
assert fixture.verify_signature(payload + b"!", receipt) is False
assert fixture.verify_signature(payload, changed_receipt) is False
assert fixture.verify_signature(payload + b"!", changed_receipt) is True
```

Keep receipt-to-identity equality, exact payload recording, log-redaction, error normalization, and artifact atomicity assertions unchanged.

Add a deterministic verification callback in `tests/support/external_signing.py` that validates the existing HMAC hex receipt without calling the signer again.

- [ ] **Step 4: Prove deterministic and randomized conformance**

Run:

```bash
../../.venv/bin/python -m pytest \
  tests/test_external_signing_conformance.py \
  tests/test_external_signing.py \
  -v
../../.venv/bin/python -m flake8 tests/signing_conformance.py \
  tests/test_external_signing_conformance.py tests/support/external_signing.py
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit the conformance correction**

```bash
git add tests/signing_conformance.py tests/test_external_signing_conformance.py \
  tests/support/external_signing.py
git commit -m "test: support randomized external signatures"
```

---

### Task 2: Add the shared KMS trust contract and strict private helpers

**Files:**

- Create: `aegis/integrations/__init__.py`
- Create: `aegis/integrations/kms.py`
- Create: `aegis/integrations/_kms_common.py`
- Create: `tests/test_kms_common.py`
- Modify: `tests/test_public_api.py`

**Public interface:**

```python
class KmsKeyDisposition(str, Enum):
    ANCHORED = "anchored"
    UNANCHORED = "unanchored"
    INVALID_ANCHOR = "invalid_anchor"
    REVOKED = "revoked"
```

**Private helper contract:**

```python
MAX_RAW_SIGNATURE_BYTES = 12_288
MAX_AWS_RAW_SIGNATURE_BYTES = 6_144
MAX_PUBLIC_KEY_PEM_BYTES = 65_536
MAX_CRC32C = 2**32 - 1

def _sha256_digest(payload: bytes) -> bytes:
    raise NotImplementedError

def _canonical_b64encode(value: bytes) -> str:
    raise NotImplementedError

def _canonical_b64decode(value: str, *, max_raw_bytes: int) -> bytes:
    raise NotImplementedError

def _normalize_timeout(value: object, *, error_type: type[Exception]) -> object:
    raise NotImplementedError

def _normalize_crc32c(value: object) -> int:
    raise NotImplementedError

def _outcome(reason_code: VerificationReasonCode) -> ExternalVerificationOutcome:
    raise NotImplementedError
```

The implementation may use private dataclasses for normalized snapshots, but may not expose a generic public KMS adapter or resolver alias.

- [ ] **Step 1: Write failing strict-boundary and public-surface tests**

Cover:

- exact enum values and frozen host-policy meaning;
- `aegis.integrations.__dict__` containing no provider classes;
- no new names in `aegis.__all__` or `aegis.signing.__all__`;
- provider-neutral outcome mappings for every disposition;
- unsupported algorithm, unknown key, revoked key, invalid signature, and unavailable outcomes;
- exact-byte payload hashing;
- canonical base64 round-trip;
- rejection of whitespace, alternate padding, invalid alphabet, empty input, subclasses, and decoded values at 12,289 bytes;
- acceptance at 12,288 bytes;
- rejection of boolean, negative, and `2**32` CRC values;
- timeout omission sentinel separation from explicit `None`;
- rejection of bool, zero, negative, NaN, and infinity timeout values;
- fixed provider-neutral messages with no identifier interpolation.

- [ ] **Step 2: Run tests and confirm missing-module failures**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_kms_common.py \
  tests/test_public_api.py -v
```

Expected: collection fails because `aegis.integrations` does not exist.

- [ ] **Step 3: Implement the enum and strict helpers**

Use exact-type checks such as `type(value) is bytes`, `type(value) is str`, and `type(value) is int`. Decode base64 with `base64.b64decode(value.encode("ascii"), validate=True)` and require `base64.b64encode(decoded).decode("ascii") == value`.

Construct outcomes only from this closed mapping:

```python
_OUTCOME_FIELDS = {
    VerificationReasonCode.SIGNATURE_VALID_ANCHORED: (
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        "Signature is valid and externally anchored",
    ),
    VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: (
        SignatureStatus.VALID,
        AnchorStatus.UNANCHORED,
        "Signature is valid but not externally anchored",
    ),
    VerificationReasonCode.ANCHOR_INVALID: (
        SignatureStatus.VALID,
        AnchorStatus.INVALID,
        "The external anchor is invalid",
    ),
    VerificationReasonCode.KEY_REVOKED: (
        SignatureStatus.REVOKED,
        AnchorStatus.NOT_EVALUATED,
        "The configured verifier reports the key version as revoked",
    ),
    VerificationReasonCode.KEY_UNKNOWN: (
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        "The configured verifier does not recognize the key version",
    ),
    VerificationReasonCode.ALGORITHM_NOT_ALLOWED: (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        "The configured key does not permit the declared algorithm",
    ),
    VerificationReasonCode.SIGNATURE_INVALID: (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        "Signature is invalid",
    ),
    VerificationReasonCode.VERIFIER_UNAVAILABLE: (
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        "External verification is unavailable",
    ),
}
```

Translate disposition to a reason only after cryptographic success.

- [ ] **Step 4: Prove the shared contract and import boundary**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_kms_common.py \
  tests/test_public_api.py -v
../../.venv/bin/python -m flake8 aegis/integrations tests/test_kms_common.py
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit the shared contract**

```bash
git add aegis/integrations tests/test_kms_common.py tests/test_public_api.py
git commit -m "feat: add shared KMS trust contract"
```

---

### Task 3: Implement the AWS KMS signer with immutable ARN binding

**Files:**

- Create: `aegis/integrations/aws_kms.py`
- Create: `tests/support/kms_fixtures.py`
- Create: `tests/test_aws_kms.py`

**Public interfaces:**

```python
@dataclass(frozen=True)
class AwsKmsVerificationTarget:
    key_arn: str
    allowed_algorithms: frozenset[str]
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED


class AwsKmsArtifactSigner:
    def __init__(
        self,
        client: object,
        *,
        key_id: str,
        signing_algorithm: str,
    ) -> None:
        raise NotImplementedError

    def signer_identity(self) -> SignerIdentity:
        raise NotImplementedError

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        raise NotImplementedError
```

`__all__` must contain exactly `AwsKmsArtifactSigner`, `AwsKmsArtifactVerifier`, and `AwsKmsVerificationTarget`; the verifier name may be defined in Task 4.

- [ ] **Step 1: Build generated-key and recording-client fixtures**

In `tests/support/kms_fixtures.py`, lazy-import cryptography inside factory functions and generate:

- RSA 2048, 3072, and 4096 private keys;
- P-256 and secp256k1 private keys;
- AWS fake responses with documented `KeyMetadata` and `Sign` shapes;
- a recording client exposing `describe_key`, `sign`, `verify`, and a concrete `exceptions.KMSInvalidSignatureException`;
- deterministic mode switches for alias retarget, disabled key, wrong usage, wrong spec, absent algorithm, malformed fields, wrong response echo, oversized signature, documented provider failures, and secret-bearing unexpected failures.

The fake `sign` method must cryptographically sign the supplied SHA-256 digest using the requested RSA-PSS or ECDSA operation and return DER ECDSA signatures.

- [ ] **Step 2: Write failing signer tests**

Cover:

- exact constructor types and supported algorithms;
- `signer_identity()` request `DescribeKey(KeyId=configured_selector)`;
- exact enabled, state, usage, key-spec, algorithm-list, ARN, and response-type checks;
- identity `key_reference` equals the configured selector and `key_version` equals the returned concrete ARN;
- second `DescribeKey` before every sign;
- alias retarget between identity and sign fails before `Sign`;
- `Sign` receives the exact ARN, SHA-256 digest, `MessageType="DIGEST"`, and algorithm;
- response `KeyId`, `SigningAlgorithm`, byte type, nonempty value, and 6,144-byte maximum;
- canonical base64 receipt echo;
- all permitted RSA key sizes and both permitted EC key specs;
- unsupported families and cross-family combinations fail before `Sign`;
- exact payload bytes are signed;
- direct adapter failures are sanitized and unchained;
- `sign_artifact_with_metadata()` leaves the artifact unchanged on every failure.

- [ ] **Step 3: Run the signer tests and confirm missing class failures**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_aws_kms.py \
  -k "signer or signing or identity" -v
```

Expected: failure because `AwsKmsArtifactSigner` does not exist.

- [ ] **Step 4: Implement strict AWS metadata normalization and signing**

Use a closed descriptor:

```python
_AWS_ALGORITHMS = {
    "RSASSA_PSS_SHA_256": frozenset(
        {"RSA_2048", "RSA_3072", "RSA_4096"}
    ),
    "ECDSA_SHA_256": frozenset(
        {"ECC_NIST_P256", "ECC_SECG_P256K1"}
    ),
}
```

Never use `str(enum_value)` as protocol identity. Accept only exact built-in strings already equal to documented values. Normalize `KeyMetadata` into local built-ins, repeat the full eligibility check on the second describe, and call `sign` with the ARN snapshot.

Wrap all public method failures using fixed `SigningContractError` or `ArtifactSigningError` messages and `raise safe_error from None`. Do not log provider objects.

- [ ] **Step 5: Run focused AWS signing, conformance, and lint checks**

Add an AWS `SignerFactory` backed by the fake client and run:

```bash
../../.venv/bin/python -m pytest tests/test_aws_kms.py \
  tests/test_external_signing_conformance.py -v
../../.venv/bin/python -m flake8 aegis/integrations/aws_kms.py \
  tests/test_aws_kms.py tests/support/kms_fixtures.py
```

Expected: AWS signer tests and shared signer conformance pass.

- [ ] **Step 6: Commit the AWS signer**

```bash
git add aegis/integrations/aws_kms.py tests/test_aws_kms.py \
  tests/support/kms_fixtures.py
git commit -m "feat: add AWS KMS artifact signer"
```

---

### Task 4: Implement the AWS KMS verifier and trust-policy resolver

**Files:**

- Modify: `aegis/integrations/aws_kms.py`
- Modify: `tests/test_aws_kms.py`
- Modify: `tests/support/kms_fixtures.py`

**Public interface:**

```python
class AwsKmsArtifactVerifier:
    def __init__(
        self,
        client: object,
        *,
        resolver: Callable[
            [str, str],
            AwsKmsVerificationTarget | None,
        ],
    ) -> None:
        raise NotImplementedError

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        raise NotImplementedError
```

- [ ] **Step 1: Write failing target, resolver, and verification tests**

Cover:

- target ARN syntax is `arn:{partition}:kms:{region}:{account}:key/{key-id}`, never alias syntax, and fits the 128-character metadata bound;
- exact frozen target class, exact `frozenset`, exact supported strings, nonempty allowed set, and exact disposition;
- unsupported metadata algorithm returns `ALGORITHM_NOT_ALLOWED` before resolver invocation;
- resolver receives the exact `(key_reference, key_version)` pair once;
- resolver `None` returns `KEY_UNKNOWN` without provider work;
- subclasses, mappings, mocks, hostile properties, mutable sets, malformed values, and resolver exceptions become sanitized `VerificationContractError`;
- normalized target fields are copied before provider work;
- target ARN must exactly equal metadata `key_version`;
- revoked returns `KEY_REVOKED` without provider work;
- target algorithm denial returns `ALGORITHM_NOT_ALLOWED` without provider work;
- malformed, noncanonical, empty, or decoded signatures over 6,144 bytes are rejected before resolver/provider work;
- `Verify` receives only the trusted ARN, exact digest, decoded signature, `DIGEST`, and metadata algorithm;
- exact response echo and exact-bool `SignatureValid`;
- `False` and exact `KMSInvalidSignatureException` map to `SIGNATURE_INVALID`;
- documented timeout, throttle, permission, unavailable, disabled/destroyed, and not-found failures map to `VERIFIER_UNAVAILABLE`;
- wrong echo, malformed response, and unexpected exception become sanitized contract errors;
- valid crypto maps through all three non-revoked dispositions;
- historical verification targets an old ARN after the signer alias points elsewhere;
- forged metadata cannot redirect the resolver-approved target;
- errors, results, reprs, details, and logs contain no secret fixture corpus.

- [ ] **Step 2: Run verifier tests and confirm the missing behavior**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_aws_kms.py \
  -k "target or verifier or verification or resolver" -v
```

Expected: failures because the verifier and complete target validation are absent.

- [ ] **Step 3: Implement exact target reconstruction and AWS verification**

Require `type(resolved) is AwsKmsVerificationTarget`, then reconstruct a fresh target from:

```python
normalized = AwsKmsVerificationTarget(
    key_arn=str.__new__(str, resolved.key_arn),
    allowed_algorithms=frozenset(
        str.__new__(str, item) for item in resolved.allowed_algorithms
    ),
    disposition=resolved.disposition,
)
```

Only perform this copy after exact-type validation of each field. Do not read a field more than once.

Classify invalid signatures only from the injected client's concrete `KMSInvalidSignatureException` type. Classify availability from documented concrete client exception types or a botocore `ClientError` with a closed error-code allowlist. Any other exception is a contract error. Use fixed outcomes from `_kms_common`.

- [ ] **Step 4: Add AWS shared verifier conformance and concurrency tests**

Create signed artifacts for current, historical, revoked, and invalid-anchor ARNs and a `VerifierFactory`. Add barrier-controlled interleaving where two calls resolve different targets and verify simultaneously. Assert request fields never cross and the verifier gains no per-call attributes.

Run:

```bash
../../.venv/bin/python -m pytest tests/test_aws_kms.py \
  tests/test_external_signing_conformance.py -v
../../.venv/bin/python -m flake8 aegis/integrations/aws_kms.py \
  tests/test_aws_kms.py tests/support/kms_fixtures.py
```

Expected: AWS provider suite and shared signer/verifier conformance pass.

- [ ] **Step 5: Commit the AWS verifier**

```bash
git add aegis/integrations/aws_kms.py tests/test_aws_kms.py \
  tests/support/kms_fixtures.py
git commit -m "feat: add AWS KMS artifact verifier"
```

---

### Task 5: Implement the Google Cloud KMS signer with CRC32C integrity

**Files:**

- Create: `aegis/integrations/google_cloud_kms.py`
- Create: `tests/test_google_cloud_kms.py`
- Modify: `tests/support/kms_fixtures.py`

**Public interfaces:**

```python
@dataclass(frozen=True)
class GoogleCloudKmsVerificationTarget:
    crypto_key_version_name: str
    algorithm: str
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED
    public_key_pem: bytes | None = None


class GoogleCloudKmsArtifactSigner:
    def __init__(
        self,
        client: object,
        *,
        crypto_key_version_name: str,
        retry: object = _USE_PROVIDER_DEFAULT,
        timeout: object = _USE_PROVIDER_DEFAULT,
    ) -> None:
        raise NotImplementedError

    def signer_identity(self) -> SignerIdentity:
        raise NotImplementedError

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        raise NotImplementedError
```

`_USE_PROVIDER_DEFAULT` is private and absent from `__all__`.

- [ ] **Step 1: Extend fixtures with documented Google request/response shapes**

Add fake Google clients and generated keys for:

- RSA-PSS 2048, 3072, and 4096 with SHA-256 digest-size salt;
- ECDSA P-256 with SHA-256;
- `CryptoKeyVersion` responses exposing `name`, `state`, `algorithm`, and optional irrelevant `protection_level`;
- `AsymmetricSignResponse` exposing `name`, `signature`, `signature_crc32c`, and `verified_digest_crc32c`;
- enum-like values with `.name` that test the explicit mapping without accepting arbitrary `str(value)`;
- mode switches for wrong state, wrong name, wrong algorithm, bad CRCs, boolean CRCs, missing verification, oversized signature, documented availability failures, and secret-bearing unexpected exceptions.

Use the installed SDK's real `GetCryptoKeyVersionRequest`, `Digest`, and `AsymmetricSignRequest` classes in assertions when the Google extra is present. Keep module collection safe with `pytest.importorskip` inside provider-dependent fixture construction rather than at test-module import time.

- [ ] **Step 2: Write failing resource, timeout, identity, and sign tests**

Cover:

- canonical concrete version parsing and rejection of missing/extra segments, empty terminal version, non-built-in strings, parent over 512 characters, terminal over 128, and complete name over 659;
- supported algorithm normalization without a `CryptoKey.purpose` read or `get_crypto_key` call;
- exact `get_crypto_key_version(request=request)` construction;
- retry/timeout omission omits both kwargs;
- explicit `None` forwards both kwargs;
- exact finite positive `int` and `float` timeout forwards unchanged;
- bool, NaN, infinity, zero, negative, and numeric subclasses fail before a call;
- identity parent CryptoKey and terminal version derivation;
- second exact-version lookup before signing;
- exact payload SHA-256 and CRC32C;
- real `AsymmetricSignRequest` with `digest.sha256` and `digest_crc32c`;
- exact `verified_digest_crc32c is True`;
- exact response name;
- exact-byte bounded signature;
- exact non-bool integer signature CRC in range and local equality;
- response has no assumed algorithm field;
- all four algorithms produce cryptographically valid signatures;
- safe direct errors and atomic artifact behavior.

- [ ] **Step 3: Run signer tests and confirm missing-module behavior**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_google_cloud_kms.py \
  -k "signer or signing or identity or timeout or version" -v
```

Expected: failure because the Google module does not exist.

- [ ] **Step 4: Implement lazy SDK loading, explicit enum mapping, and signing**

Use this closed map:

```python
_GOOGLE_ALGORITHMS = {
    "RSA_SIGN_PSS_2048_SHA256": ("rsa", 2048),
    "RSA_SIGN_PSS_3072_SHA256": ("rsa", 3072),
    "RSA_SIGN_PSS_4096_SHA256": ("rsa", 4096),
    "EC_SIGN_P256_SHA256": ("ec", 256),
}
```

Resolve Google enum values only by equality against the installed SDK constants and map them to the exact canonical names. Never persist or make claims from `protection_level`.

Build SDK request objects inside private lazy-import helpers. Compute CRC32C using `google_crc32c.Checksum`, convert its four digest bytes with `int.from_bytes(checksum.digest(), "big")`, and validate provider integers before comparison.

- [ ] **Step 5: Prove Google signer conformance, CRC boundaries, and lint**

Add a Google `SignerFactory` backed by the recording fake client and run:

```bash
../../.venv/bin/python -m pytest tests/test_google_cloud_kms.py \
  tests/test_external_signing_conformance.py -v
../../.venv/bin/python -m flake8 \
  aegis/integrations/google_cloud_kms.py \
  tests/test_google_cloud_kms.py tests/support/kms_fixtures.py
```

Expected: Google signer tests and shared randomized-signature-safe conformance pass.

- [ ] **Step 6: Commit the Google signer**

```bash
git add aegis/integrations/google_cloud_kms.py \
  tests/test_google_cloud_kms.py tests/support/kms_fixtures.py
git commit -m "feat: add Google Cloud KMS artifact signer"
```

---

### Task 6: Implement the Google verifier with exact-version or retained-key trust

**Files:**

- Modify: `aegis/integrations/google_cloud_kms.py`
- Modify: `tests/test_google_cloud_kms.py`
- Modify: `tests/support/kms_fixtures.py`

**Public interface:**

```python
class GoogleCloudKmsArtifactVerifier:
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
    ) -> None:
        raise NotImplementedError

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        raise NotImplementedError
```

- [ ] **Step 1: Write failing target and retained-PEM tests**

Cover:

- exact frozen target class, canonical resource, supported algorithm, exact disposition, and exact optional bytes;
- PEM nonempty and 65,536-byte maximum;
- reject private-key PEM, malformed PEM, wrong key type, wrong RSA size, P-384/P-521/secp256k1 for the P-256 algorithm, subclasses, and mutable/lookalike targets;
- valid retained RSA and P-256 PEM;
- target reconstructs metadata parent and terminal version exactly;
- retained PEM verifies with `client=None`;
- missing PEM with `client=None` returns `VERIFIER_UNAVAILABLE`;
- revoked returns before PEM parsing, provider access, or crypto work;
- invalid metadata algorithm returns before resolver;
- target algorithm mismatch returns `ALGORITHM_NOT_ALLOWED`;
- resolver `None`, resolver failure, hostile target, and target identity mismatch mappings.

- [ ] **Step 2: Write failing fetched-key and cryptographic verification tests**

Cover:

- `GetPublicKeyRequest(name=trusted_version, public_key_format=PEM)` uses the real SDK request type;
- exact retry/timeout omission and forwarding;
- response `name`, algorithm, and `public_key_format`;
- accept only `public_key.data`, never legacy `pem`;
- public-key data exact bytes, nonempty, and bounded;
- checksum exact non-bool integer, range, and local CRC32C equality;
- provider PEM key type, curve, and RSA size;
- all four algorithms verify the exact original payload;
- changed payload and changed signature return `SIGNATURE_INVALID`;
- ECDSA DER parse failure returns `SIGNATURE_INVALID`;
- `cryptography.exceptions.InvalidSignature` returns `SIGNATURE_INVALID`;
- other cryptography, parser, SDK-shape, and CRC failures become sanitized contract errors;
- documented timeout, throttle, permission, unavailable, failed-precondition, disabled/destroyed, and not-found provider errors return `VERIFIER_UNAVAILABLE`;
- no provider-controlled value reaches results, errors, details, reprs, or logs.

- [ ] **Step 3: Run verifier tests and confirm absent behavior**

Run:

```bash
../../.venv/bin/python -m pytest tests/test_google_cloud_kms.py \
  -k "target or verifier or verification or resolver or public_key or pem" -v
```

Expected: failures because the verifier and complete target validation are absent.

- [ ] **Step 4: Implement exact target reconstruction and public-key acquisition**

Require `type(resolved) is GoogleCloudKmsVerificationTarget`. Read each exact field once, copy the resource and algorithm into new built-in strings, copy PEM with `bytes(resolved.public_key_pem)` only after `type(resolved.public_key_pem) is bytes`, and reconstruct a new validated target.

If retained PEM is absent, explicitly construct:

```python
request = kms_v1.GetPublicKeyRequest(
    name=target.crypto_key_version_name,
    public_key_format=kms_v1.PublicKey.PublicKeyFormat.PEM,
)
```

Read checksummed bytes from `response.public_key.data` and `response.public_key.crc32c_checksum`. Reject the legacy fields for this explicit-format path.

- [ ] **Step 5: Implement local prehashed verification**

Hash the AEGIS payload once. For RSA use:

```python
public_key.verify(
    signature_bytes,
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    ),
    utils.Prehashed(hashes.SHA256()),
)
```

For P-256 use:

```python
decode_dss_signature(signature_bytes)
public_key.verify(
    signature_bytes,
    digest,
    ec.ECDSA(utils.Prehashed(hashes.SHA256())),
)
```

Validate the public-key class, RSA size, and exact curve class before verification.

- [ ] **Step 6: Add shared verifier conformance and concurrency tests**

Create current, historical, revoked, and invalid-anchor signed artifacts. Exercise both fetched and retained key paths. Add barrier-controlled calls using different resource versions and algorithms; assert each call keeps its resolver snapshot, request, PEM, digest, and outcome isolated.

Run:

```bash
../../.venv/bin/python -m pytest tests/test_google_cloud_kms.py \
  tests/test_external_signing_conformance.py -v
../../.venv/bin/python -m flake8 \
  aegis/integrations/google_cloud_kms.py \
  tests/test_google_cloud_kms.py tests/support/kms_fixtures.py
```

Expected: Google provider suite and shared signer/verifier conformance pass.

- [ ] **Step 7: Commit the Google verifier**

```bash
git add aegis/integrations/google_cloud_kms.py \
  tests/test_google_cloud_kms.py tests/support/kms_fixtures.py
git commit -m "feat: add Google Cloud KMS artifact verifier"
```

---

### Task 7: Add optional extras and built-artifact release lanes

**Files:**

- Modify: `pyproject.toml`
- Modify: `tests/test_v090_distribution_contract.py`
- Modify: `scripts/validate_v090_distribution_candidate.py`
- Create: `scripts/validate_kms_optional_extras.py`
- Create: `tests/test_kms_distribution_smoke.py`
- Modify: `.github/workflows/publish.yml`
- Modify: `tests/test_v090_publish_workflow.py`

**Exact optional metadata:**

```toml
aws-kms = [
  "boto3>=1.43.0",
]
gcp-kms = [
  "google-cloud-kms>=3.15.0",
  "google-crc32c>=1.7.1",
  "cryptography>=45.0.1",
]
```

- [ ] **Step 1: Write failing distribution and workflow contract tests**

Assert:

- base requirements remain exactly the existing two;
- optional extra names and lower bounds are exact;
- no upper bound is introduced;
- wheel metadata contains both extras and conditional requirements;
- wheel contains all five `aegis/integrations` modules;
- only the existing `aegis-ai-governance` distribution name and `0.9.0b1` version exist;
- publish full-test install uses `.[dev,aws-kms,gcp-kms]`;
- build still occurs once;
- artifact validation matrix contains exactly:
  `base-wheel`, `aws-min-wheel`, `aws-current-wheel`,
  `gcp-min-wheel`, `gcp-current-wheel`, `combined-current-wheel`,
  and `combined-current-sdist`;
- publish depends on both build and optional-extra validation;
- every lane downloads the same build artifact and never rebuilds provider-specific distributions.

- [ ] **Step 2: Run the distribution tests and confirm missing extras/lanes**

Run:

```bash
../../.venv/bin/python -m pytest \
  tests/test_v090_distribution_contract.py \
  tests/test_v090_publish_workflow.py \
  tests/test_kms_distribution_smoke.py -v
```

Expected: failures because the extras, smoke script, wheel members, and matrix do not exist.

- [ ] **Step 3: Add the extras without changing base dependencies**

Modify only `[project.optional-dependencies]`. Use `tomllib` in tests to compare parsed requirement strings rather than brittle substring extraction.

Update the candidate validator to separate unconditional `Requires-Dist` entries from `extra ==` marker entries and compare both sets exactly. Add these required wheel members:

```python
{
    "aegis/integrations/__init__.py",
    "aegis/integrations/kms.py",
    "aegis/integrations/_kms_common.py",
    "aegis/integrations/aws_kms.py",
    "aegis/integrations/google_cloud_kms.py",
}
```

- [ ] **Step 4: Implement the installed-artifact smoke script**

`scripts/validate_kms_optional_extras.py` accepts:

```text
--artifact PATH
--lane base|aws|gcp|combined
--expected-versions JSON
```

It must:

1. create a temporary venv;
2. install the exact wheel or sdist path, with the selected extras;
3. honor exact minimum pins supplied by the workflow before installing the artifact;
4. run `pip check`;
5. execute smoke code from a temporary directory with isolated Python so the source checkout cannot shadow the installed artifact;
6. inspect `importlib.metadata.requires("aegis-ai-governance")`;
7. import `aegis`, `aegis.integrations.kms`, and both provider modules in every lane;
8. assert base lane has no boto3, Google KMS, google-crc32c, or cryptography distribution;
9. assert AWS-only lacks all Google-extra distributions and can run an injected fake-client AWS identity/sign/verify cycle;
10. assert Google-only lacks boto3 and can run an injected fake-client Google identity/sign plus retained-PEM verify cycle;
11. assert combined can execute both smoke cycles;
12. print a JSON report with artifact hash, installed versions, lane, checks, and `PASS`.

The script must never contact AWS or Google and must remove provider credential environment variables before running smoke code.

- [ ] **Step 5: Wire the single-artifact GitHub Actions matrix**

Change the build install command to:

```yaml
run: >-
  python -m pip install "build==1.5.0" "setuptools"
  -e ".[dev,aws-kms,gcp-kms]"
```

Keep build and upload in the unprivileged `build` job. Add an unprivileged `validate-optional-extras` matrix job that checks out the exact release tag, downloads `python-package-distributions`, and invokes the smoke script with the built wheel or sdist. Pin minimum lanes to:

```text
boto3==1.43.0
google-cloud-kms==3.15.0
google-crc32c==1.7.1
cryptography==45.0.1
```

Current lanes leave provider versions unpinned. Set `publish.needs` to both `build` and `validate-optional-extras`. Do not add another publish job, distribution, version, or OIDC permission.

- [ ] **Step 6: Prove metadata, workflow, and local built artifacts**

Run:

```bash
../../.venv/bin/python -m pytest \
  tests/test_v090_distribution_contract.py \
  tests/test_v090_publish_workflow.py \
  tests/test_kms_distribution_smoke.py -v
../../.venv/bin/python -m build
../../.venv/bin/python scripts/validate_v090_distribution_candidate.py \
  --dist-dir dist --no-build
../../.venv/bin/python scripts/validate_kms_optional_extras.py \
  --artifact dist/aegis_ai_governance-0.9.0b1-py3-none-any.whl \
  --lane base --expected-versions '{}'
```

Expected: unit contracts pass, wheel/sdist metadata is exact, candidate proof passes, and the base artifact lane imports provider modules without provider packages.

- [ ] **Step 7: Run network-backed minimum/current lanes when network is available**

Run the seven matrix configurations locally or through the GitHub Actions workflow. Record exact installed versions in the smoke reports. A minimum or current incompatibility blocks completion; do not relax a lower bound or skip a lane without updating the design and rerunning its review.

- [ ] **Step 8: Commit packaging and release proof**

```bash
git add pyproject.toml scripts/validate_v090_distribution_candidate.py \
  scripts/validate_kms_optional_extras.py .github/workflows/publish.yml \
  tests/test_v090_distribution_contract.py tests/test_v090_publish_workflow.py \
  tests/test_kms_distribution_smoke.py
git commit -m "build: add KMS optional extra release lanes"
```

---

### Task 8: Document provider usage, trust limits, and the one release path

**Files:**

- Create: `docs/decisions/ADR-0013-aws-google-kms-adapters.md`
- Create: `docs/reference/external/AWS_KMS_SIGNING.md`
- Create: `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md`
- Modify: `docs/reference/external/README.md`
- Modify: `README.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `CHANGELOG.md`
- Modify: `RELEASE_GATES.md`
- Modify: `doc_parity_manifest.yaml`

- [ ] **Step 1: Add failing documentation truth tests**

Extend existing doc-parity or distribution tests to assert:

- both install commands use `aegis-ai-governance[aws-kms]` and `aegis-ai-governance[gcp-kms]`;
- public docs name all six supported algorithms and no excluded algorithms;
- AWS docs explicitly call ARN a logical-key identity rather than backing-material version;
- Google docs name `public_key.data`, CRC32C checks, retained PEM, and exact CryptoKeyVersion;
- docs state artifact metadata does not select provider resources;
- docs state host ownership of clients, credentials, retry/timeout, endpoints, regional/project configuration, IAM, trust policy, and retained evidence;
- docs do not claim immutable logging, trusted time, complete history, HSM/FIPS status, or certification;
- changelog describes both adapters under the same version;
- release gates enumerate all artifact lanes.

Run:

```bash
../../.venv/bin/python -m pytest tests/test_doc_parity_v090_truth.py \
  tests/test_v090_distribution_contract.py -v
python scripts/check_doc_parity.py
```

Expected: failures for missing provider documents and unclassified issue #45 files.

- [ ] **Step 2: Write the ADR and provider guides**

The ADR records:

- Option A selection over a generic KMS adapter and separate distributions;
- exact-pair resolver authority;
- AWS ARN semantic limitation;
- exact Google version and retained-key strategy;
- closed algorithms;
- failure semantics;
- no base dependency change;
- operational and compliance non-claims.

Each provider guide includes:

- optional-extra installation;
- host-created client code;
- resolver and target code;
- signing and detailed verification code;
- least-privilege operations;
- rotation and historical verification;
- compromise/revocation policy;
- outage behavior;
- redaction cautions for provider debug logs;
- retained evidence responsibilities;
- unsupported operations and claims.

- [ ] **Step 3: Update maintained public docs and release gates**

Use only public imports:

```python
from aegis.integrations.aws_kms import (
    AwsKmsArtifactSigner,
    AwsKmsArtifactVerifier,
    AwsKmsVerificationTarget,
)
from aegis.integrations.google_cloud_kms import (
    GoogleCloudKmsArtifactSigner,
    GoogleCloudKmsArtifactVerifier,
    GoogleCloudKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition
```

Do not re-export or document the notation-only resolver aliases or private omission sentinel.

Classify the issue #45 spec and plan under `documentation_inventory.historical`; the ADR and final audit already match existing historical globs, while provider guides match `docs/reference/**`.

- [ ] **Step 4: Run documentation and public-boundary checks**

Run:

```bash
python scripts/check_doc_parity.py
python scripts/check_public_docs_no_internal_imports.py
../../.venv/bin/python -m pytest \
  tests/test_doc_parity_v090_truth.py \
  tests/test_public_api.py \
  tests/test_v090_distribution_contract.py -v
```

Expected: all documentation inventory, link, API, semantic, and release truth checks pass.

- [ ] **Step 5: Commit maintained documentation**

```bash
git add README.md CHANGELOG.md RELEASE_GATES.md doc_parity_manifest.yaml \
  docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md \
  docs/decisions/ADR-0013-aws-google-kms-adapters.md \
  docs/reference/external
git commit -m "docs: document AWS and Google KMS adapters"
```

---

### Task 9: Run the full end-to-end adversarial review and close every gap

**Files:**

- Create: `docs/audits/2026-07-29-issue-45-aws-google-kms-adapters-adversarial-review.md`
- Modify only if a proven review finding requires a correction: issue #45 runtime, tests, packaging, workflow, or documentation files
- Modify: `doc_parity_manifest.yaml` only if the explicit audit path is not already covered

- [ ] **Step 1: Create an acceptance-to-evidence matrix**

The audit document must map every design requirement and acceptance row to:

- implementation file and public/private symbol;
- focused test name;
- full-suite or artifact-lane command;
- observed result;
- residual risk or explicit non-goal.

No row may use “covered elsewhere,” “same as above,” or an unverified assertion.

- [ ] **Step 2: Adversarially inspect implementation and test structure**

Run targeted searches and record findings:

```bash
rg -n "boto3|botocore|google\\.cloud|google_crc32c|cryptography" \
  aegis pyproject.toml
rg -n "except Exception|except BaseException|raise .* from|logging\\.|print\\(" \
  aegis/integrations
rg -n "alias|Primary|cryptoKeyVersions/[^\\\"]+$|KeyId=.*metadata|purpose" \
  aegis/integrations tests
rg -n "TODO|TBD|FIXME|XXX|pass$|NotImplemented" \
  aegis/integrations tests/test_aws_kms.py tests/test_google_cloud_kms.py \
  scripts/validate_kms_optional_extras.py docs/reference/external
```

Manually trace:

- every provider request field to a trusted source;
- every artifact-controlled field to the resolver boundary;
- every exception branch to one documented outcome/error;
- every signature/PEM/CRC bound at `limit - 1`, `limit`, and `limit + 1`;
- every optional import from base import through use-time failure;
- every constructor omission/explicit-`None` path;
- every mutation point from identity preparation to atomic artifact commit;
- every concurrently executed call for shared mutable state;
- every doc claim to implementation and provider-confirmed semantics.

- [ ] **Step 3: Run focused provider, conformance, and adversarial tests**

Run:

```bash
../../.venv/bin/python -m pytest \
  tests/test_kms_common.py \
  tests/test_aws_kms.py \
  tests/test_google_cloud_kms.py \
  tests/test_external_signing.py \
  tests/test_external_signing_conformance.py \
  tests/test_public_api.py \
  tests/test_v090_distribution_contract.py \
  tests/test_v090_publish_workflow.py \
  tests/test_kms_distribution_smoke.py -v
```

Expected: all selected tests pass with no skipped supported-algorithm case in an environment installed with both extras.

- [ ] **Step 4: Provision the demo frontend and run the complete repository gate**

The baseline worktree lacked `demo-app-react/node_modules`, which caused nine known `test_demo_copy_policy.py` failures. Install the locked frontend dependencies before judging the final suite:

```bash
cd demo-app-react
npm ci
cd ..
../../.venv/bin/python -m pytest --cov=aegis \
  --cov-report=term-missing --cov-fail-under=90
../../.venv/bin/python -m flake8 aegis
python scripts/check_doc_parity.py
python scripts/check_public_docs_no_internal_imports.py
python scripts/validate_v090_release_freeze.py
npm --prefix demo-app-react test
npm --prefix demo-app-react run build
```

Expected: Python suite passes at or above 90% coverage, lint and documentation gates pass, release freeze passes, and frontend test/build passes. If dependency installation is unavailable, do not call the whole suite complete; use the already-known baseline only as diagnostic evidence and run the missing gate in connected CI.

After the successful full Python run, update `doc_parity_manifest.yaml`,
`README.md`, `CHANGELOG.md`, and `implementation_status.md` from the stale
`1923 tests` baseline to the exact observed passed-test count, then rerun
`scripts/check_doc_parity.py`. Do not estimate or predeclare the final count.

- [ ] **Step 5: Build and validate all artifact lanes**

Build into a clean directory:

```bash
../../.venv/bin/python -m build
../../.venv/bin/python scripts/validate_v090_distribution_candidate.py \
  --dist-dir dist --no-build
```

Execute all seven optional-extra matrix lanes against the produced wheel/sdist, including the exact minimum versions and current resolver-selected versions. Record artifact SHA-256 hashes and installed versions in the audit. Run the workflow in GitHub Actions when local network or platform coverage is insufficient.

- [ ] **Step 6: Correct every substantiated finding test-first**

For each finding:

1. add or strengthen the smallest failing regression;
2. run it and capture the failure;
3. apply the minimal correction;
4. rerun the focused and adjacent suites;
5. update the evidence matrix;
6. commit a scoped fix.

Do not waive a requirement because the implementation is otherwise complete. If the design itself is contradicted by a provider SDK or product contract, stop implementation, amend the design, and obtain renewed design approval before proceeding.

- [ ] **Step 7: Finalize the audit with an explicit completeness verdict**

The audit ends with:

- contradictions found and their resolution;
- ambiguity review;
- dependency and installed-artifact evidence;
- exact provider request/response surface evidence;
- threat/failure mapping;
- bounds and redaction evidence;
- concurrency and atomicity evidence;
- acceptance traceability;
- full verification command results;
- residual risks/non-goals;
- a `PASS` or `BLOCKED` verdict.

Only `PASS` permits finalization.

- [ ] **Step 8: Commit final audit evidence**

```bash
git add docs/audits/2026-07-29-issue-45-aws-google-kms-adapters-adversarial-review.md \
  doc_parity_manifest.yaml
git commit -m "docs: record KMS adapter adversarial review"
```

If review fixes produced separate commits, keep those commits separate and list them in the audit.

---

## Final Verification Checklist

- [ ] AWS signer passes shared randomized-signature-safe conformance.
- [ ] AWS verifier passes shared exact-version and trust-disposition conformance.
- [ ] Google signer passes shared randomized-signature-safe conformance.
- [ ] Google verifier passes shared exact-version and trust-disposition conformance.
- [ ] All six approved algorithms have real cryptographic fixture coverage.
- [ ] Every disallowed algorithm family fails before provider/crypto work.
- [ ] AWS alias retargeting cannot change the prepared ARN.
- [ ] AWS docs and metadata make no backing-material-version claim.
- [ ] Google signer verifies digest and signature CRC32C.
- [ ] Google verifier validates checksummed `public_key.data`, not legacy PEM fields.
- [ ] Retained Google PEM verifies with no live client.
- [ ] Exact-pair resolver authorization precedes every provider resource use.
- [ ] Revoked targets produce no provider or crypto call.
- [ ] Provider availability and invalid-signature failures use only closed classifications.
- [ ] Unexpected provider/resolver/crypto failures are sanitized and unchained.
- [ ] Signature, PEM, CRC, resource, and timeout boundaries include below/at/above tests.
- [ ] Concurrent calls have no adapter-owned state bleed.
- [ ] Failed signing leaves the artifact byte-for-byte unchanged.
- [ ] Provider modules import in a base-only environment.
- [ ] Base `Requires-Dist` metadata is unchanged.
- [ ] AWS-only, Google-only, combined, minimum, current, wheel, and sdist lanes pass.
- [ ] One distribution version and one publish action remain.
- [ ] Public imports and docs match the implemented surface.
- [ ] Full pytest coverage, flake8, doc parity, public-doc import, release-freeze, frontend test, and frontend build gates pass.
- [ ] The final adversarial review contains evidence for every approved requirement and concludes `PASS`.
