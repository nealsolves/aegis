# Google Cloud KMS Artifact Signing

The Google Cloud KMS adapter is a source-only change after `0.9.0b1`. It is
included in the single `aegis-ai-governance` distribution and is not
re-exported from top-level `aegis`.

## Install

```bash
python -m pip install -e ".[gcp-kms]"
```

Run that command from the source checkout. The extra adds the Google Cloud
KMS, CRC32C, and local cryptography dependencies. The host owns clients,
credentials, networking, retry and timeout behavior, endpoint selection,
project configuration, IAM, trust policy, trust stores, provider debug
logging, and retained evidence.

## Supported algorithms and identity

The closed supported set is `RSA_SIGN_PSS_2048_SHA256`,
`RSA_SIGN_PSS_3072_SHA256`, `RSA_SIGN_PSS_4096_SHA256`, and
`EC_SIGN_P256_SHA256`.

The signer accepts an exact CryptoKeyVersion name:

```text
projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY/cryptoKeyVersions/VERSION
```

Artifact `key_reference` is the parent CryptoKey resource and `key_version` is
the exact final version segment. That segment must be a positive ASCII decimal
with no sign, leading zero, or provider alias. No primary-version alias or
provider lookup is accepted.

## Sign with a host-created client

The signer calls `GetCryptoKeyVersion` to confirm the exact enabled version and
algorithm, computes the SHA-256 digest and its CRC32C, then sends an
`AsymmetricSign` request. It accepts a response only when the exact version
name matches, `verified_digest_crc32c` is true, and `signature_crc32c` matches
the returned signature.

```python
import time

from google.cloud import kms_v1

from aegis import sign_artifact_with_metadata
from aegis.integrations.google_cloud_kms import (
    GoogleCloudKmsArtifactSigner,
)

client = kms_v1.KeyManagementServiceClient()
version_name = (
    "projects/example/locations/us-central1/keyRings/audit/"
    "cryptoKeys/artifact-signing/cryptoKeyVersions/7"
)
signer = GoogleCloudKmsArtifactSigner(
    client,
    crypto_key_version_name=version_name,
)

artifact = {
    "audit_schema_version": "1.4",
    "event": "approved",
    "signature": None,
}
sign_artifact_with_metadata(
    artifact,
    signer,
    signed_at=int(time.time()),
)
```

The host must construct the client with its chosen credential provider,
retry/timeout policy, endpoint, quota project, and regional/project
configuration. The public constructors also accept host-supplied `retry` and
`timeout` values; omission leaves provider defaults in force.

The injected SDK client may retry a signing request. With randomized
algorithms, retries can create multiple valid remote signing operations even
though AEGIS emits at most one atomic receipt into the artifact.

## Resolve and verify an exact pair

Artifact metadata does not select provider resources. The resolver is the
host's trust-policy lookup for the exact `(key_reference, key_version)` pair.

For online verification, the adapter calls `GetPublicKey` for the resolver's
exact CryptoKeyVersion, requests PEM format, and reads
`PublicKey.public_key.data`. It checks the exact version name, algorithm,
format, and CRC32C before locally verifying the signature. Google Cloud KMS has
no verification call in this adapter.

For historical or offline verification, retain the PEM obtained for that
exact version and return it as `public_key_pem`. This retained PEM path needs
no Google client. The PEM must contain exactly one `PUBLIC KEY` block; only
surrounding ASCII whitespace is accepted:

```python
from pathlib import Path

from aegis import verify_artifact_detailed
from aegis.integrations.google_cloud_kms import (
    GoogleCloudKmsArtifactVerifier,
    GoogleCloudKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition

key_reference = (
    "projects/example/locations/us-central1/keyRings/audit/"
    "cryptoKeys/artifact-signing"
)
key_version = "7"
trusted_targets = {
    (key_reference, key_version): GoogleCloudKmsVerificationTarget(
        crypto_key_version_name=(
            f"{key_reference}/cryptoKeyVersions/{key_version}"
        ),
        algorithm="RSA_SIGN_PSS_2048_SHA256",
        disposition=KmsKeyDisposition.ANCHORED,
        public_key_pem=Path("evidence/google-kms-version-7.pem").read_bytes(),
    )
}


def resolve_google_key(metadata_reference, metadata_version):
    return trusted_targets.get((metadata_reference, metadata_version))


verifier = GoogleCloudKmsArtifactVerifier(
    None,
    resolver=resolve_google_key,
)
result = verify_artifact_detailed(artifact, verifier=verifier)
accepted = result.is_signature_valid and result.is_anchored
```

To fetch the key online instead, omit `public_key_pem` from the target and
pass the host-created client as the first verifier argument.

Availability classification remains exact-type and fail-closed. In addition
to the closed Google API status exceptions, it covers exact
`InternalServerError`, `BadGateway`, Requests `ConnectionError` and `Timeout`,
and google-auth `TransportError`, plus one direct `RetryError.cause` hop for
those exact types. Subclasses, lookalikes, nested retry causes, and
unauthenticated module replacements are contract failures.

## Least privilege

Grant only permissions for methods the deployment actually calls:

- signer: `cloudkms.cryptoKeyVersions.get` and
  `cloudkms.cryptoKeyVersions.useToSign`;
- online verifier:
  `cloudkms.cryptoKeyVersions.viewPublicKey`;
- retained-PEM verifier: no Google Cloud KMS permission.

Scope IAM to the intended CryptoKey and deployment identity. The host owns all
credential and IAM-role construction; signer and verifier workloads may use
different service accounts.

## Rotation, revocation, and outages

Always configure signing with an exact CryptoKeyVersion, not a primary-key
selector. On rotation, create a signer for the new exact version and add its
exact pair to host trust policy. Keep the old pair and retained PEM for as long
as historical artifacts must remain verifiable.

For compromise or policy revocation, mark that exact target
`KmsKeyDisposition.REVOKED`; do not delete retained evidence merely to express
revocation. Retain the PEM, its exact version identity, acquisition evidence,
algorithm, disposition history, and the policy that decides whether signatures
created before compromise remain acceptable.

Provider unavailability never becomes success. Online public-key retrieval can
produce an indeterminate verifier-unavailable result. A validated retained PEM
permits local verification during an outage, but only if host policy already
approved that evidence.

The adapter rejects provider-controlled exception lookalikes while Python's
normal import/module trust anchors remain intact. It does not promise to
authenticate those classes after arbitrary local code has replaced the
interpreter's import or module trust anchors before the first lazy load. That
requires prior arbitrary in-process code execution and is not a provider
vulnerability.

For host-owned rotation, revocation, retention, checkpoint selection,
historical verification, backup, and recovery, see the
[Append-Only Evidence Operations Guide](../APPEND_ONLY_EVIDENCE_OPERATIONS.md).
That guide separates library-produced results from host retention, write
protection, and organizational assurance decisions.

## Logging and assurance limits

Do not enable unrestricted Google client debug logging in paths that handle
artifact payloads, digests, signatures, CRC values, request bodies,
credentials, tokens, provider errors, or raw provider responses. Apply host
redaction before logging returned artifact metadata or retained evidence.

The adapter does not create immutable logging, trusted time, complete history,
HSM/FIPS status, or certification. It does not create, rotate, disable,
destroy, attest, or certify keys. Encryption, decryption, MAC, raw private-key,
and certificate operations are outside this adapter.

Related provider-neutral assurance boundaries are defined in the
[Append-Only Evidence Operations Guide](../APPEND_ONLY_EVIDENCE_OPERATIONS.md).
This adapter guide does not prescribe retention configuration or legal
conclusions.
