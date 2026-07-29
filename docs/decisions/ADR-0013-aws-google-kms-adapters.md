# ADR-0013: AWS and Google Cloud KMS Signing Adapters

Date: 2026-07-29
Status: Accepted
Owners: Neal

---

## Context

ADR-0012 established provider-neutral metadata-aware signing and detailed
verification. Issue #45 supplies two optional adapters without moving provider
credentials, network policy, or trust-store authority into AEGIS.

The adapters must bind artifact metadata to a host-approved provider identity,
keep the base installation unchanged, fail closed on malformed or unexpected
provider data, and preserve historical verification across normal key
rotation. Artifact metadata is evidence presented for verification; it is not
authority to select a provider resource.

## Decision

Choose two explicit adapters—AWS KMS and Google Cloud KMS—over either a generic
KMS adapter or separate distributions. Both adapters remain submodules of the
single `aegis-ai-governance` distribution and are enabled with provider
extras. There is one version, build, validation, and publish path. The base
dependency set remains exactly `PyYAML >= 6.0` and `jsonschema >= 4.0`.

The host injects clients and an exact-pair resolver. For verification, the
resolver is authoritative over the exact artifact-declared
`(key_reference, key_version)` pair and either returns a provider-specific
target or rejects it. AEGIS does not discover keys or dereference artifact
metadata.

### AWS identity

The signer may begin with a host selector such as an alias, but `DescribeKey`
must resolve it to an eligible concrete KMS key ARN. Signing then uses that
concrete ARN. Verification accepts only a resolver-approved concrete ARN.

An AWS key ARN is a logical-key identity, not a backing-material version.
AWS KMS can rotate backing material while retaining the ARN. Consequently,
the adapter proves the KMS logical key that performed or verified the
operation, not which internal backing-material generation AWS used.

The ARN partition is a closed allowlist:
`aws`, `aws-cn`, `aws-us-gov`, `aws-iso`, `aws-iso-b`, `aws-iso-e`,
`aws-iso-f`, and `aws-eusc`. Invented partitions fail closed; a future AWS
partition requires an adapter update.

### Google identity and retained keys

The Google signer is configured with one exact fully qualified
`CryptoKeyVersion` name. The metadata pair is the parent `CryptoKey` resource
and the exact version segment. The signer rechecks that exact enabled version
and algorithm before `AsymmetricSign`.

Verification resolves the same exact pair. It either obtains a checksummed PEM
from that exact version with `GetPublicKey`, or verifies locally with a
resolver-supplied retained PEM. Retained PEM is the historical-verification
strategy when a provider version may later become unavailable. Retention,
provenance, disposition, and deletion policy remain host responsibilities.

### Closed algorithms

The complete supported set is:

- AWS: `RSASSA_PSS_SHA_256`, `ECDSA_SHA_256`
- Google Cloud: `RSA_SIGN_PSS_2048_SHA256`,
  `RSA_SIGN_PSS_3072_SHA256`, `RSA_SIGN_PSS_4096_SHA256`,
  `EC_SIGN_P256_SHA256`

No provider algorithm outside this set is accepted. Algorithm names in
artifact metadata are not authorization; the resolver target must also permit
the exact algorithm.

### Failure semantics

Invalid local configuration or malformed identity data raises a sanitized
signing or verification contract error. Signing refusal or inability raises a
sanitized artifact-signing error and does not partially attach a signature.
Known verifier availability failures return an indeterminate
`VERIFIER_UNAVAILABLE` outcome. Unknown keys, revoked keys, disallowed
algorithms, and invalid signatures retain their distinct closed outcomes.
Provider error text and raw responses are not propagated.

The adapters reject provider-controlled exception lookalikes in an intact
Python process. They do not claim protection after arbitrary local code has
replaced Python import or module trust anchors before the first lazy provider
load. That is an interpreter-integrity boundary requiring prior arbitrary
in-process code execution, not a provider vulnerability.

### Operational and compliance boundary

Hosts own client construction, credentials, retry and timeout policy,
endpoints, regional or project configuration, IAM, trust policy, provider
debug-log controls, retained evidence, rotation, revocation, compromise
response, and outage policy.

This feature does not claim immutable logging. It does not claim trusted time.
It does not claim complete history. It does not claim HSM/FIPS status. It does
not claim certification. Those properties require separately evaluated host
controls and provider configurations.

## Options Considered

### Option A: Explicit adapters in one distribution (chosen)

Pros:

- Makes each provider's identity, response validation, and availability model
  explicit.
- Preserves the exact-pair resolver boundary.
- Keeps one release and dependency-metadata authority.
- Allows independent least-privilege signer and verifier deployments.

Cons:

- Provider-specific code and documentation must evolve when provider contracts
  or accepted AWS partitions change.

### Option B: Generic KMS adapter

Rejected because a common abstraction would conceal materially different
identity semantics: AWS exposes a logical key ARN, while Google exposes an
exact immutable `CryptoKeyVersion` and checksummed public-key retrieval.
Provider-specific response validation and failure classification would still
exist behind the generic surface.

### Option C: Separate provider distributions

Rejected because multiple packages would create version, build, dependency,
and publish paths that can drift. Optional extras on the one distribution
provide isolation without splitting release authority.

## Consequences

- Base installs gain no provider dependency.
- AWS and Google extras install only their declared SDK/cryptography families.
- Artifact metadata never becomes resource-selection authority.
- Normal AWS rotation retains logical-key verification; Google historical
  verification depends on retaining exact-version PEM evidence when required.
- Provider availability cannot silently produce a valid or anchored result.
- Operational assurance remains bounded by the host's provider and evidence
  controls.
