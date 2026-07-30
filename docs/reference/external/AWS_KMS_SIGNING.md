# AWS KMS Artifact Signing

The AWS KMS adapter is a source-only change after `0.9.0b1`. It is included in
the single `aegis-ai-governance` distribution and is not re-exported from
top-level `aegis`.

## Install

```bash
python -m pip install -e ".[aws-kms]"
```

Run that command from the source checkout. The extra adds the AWS SDK; it does
not create clients or load credentials.
The host owns clients, credentials, networking, retry and timeout behavior,
endpoint selection, regional configuration, IAM, trust policy, trust stores,
provider debug logging, and retained evidence.

## Supported algorithms and identity

The closed supported set is `RSASSA_PSS_SHA_256` and `ECDSA_SHA_256`.

`key_reference` is the host's configured selector, such as an alias.
`key_version` is the concrete KMS key ARN returned by `DescribeKey`. That ARN
is a logical-key identity rather than a backing-material version: AWS-managed
rotation may change backing material without changing the ARN. Do not use this
adapter to claim a particular internal backing-material generation.

Concrete ARNs are accepted only in these partitions: `aws`, `aws-cn`,
`aws-us-gov`, `aws-iso`, `aws-iso-b`, `aws-iso-e`, `aws-iso-f`, and
`aws-eusc`. This is a closed allowlist.

This is strictly fail-closed and rejects invented aws-* partitions, but a newly introduced AWS partition would require an adapter update.

Each ARN must also use its partition's minimum-supported Region family:
commercial prefixes for `aws`, `cn-` for `aws-cn`, `us-gov-` for
`aws-us-gov`, `us-iso-`, `us-isob-`, `eu-isoe-`, `us-isof-`, or
`eusc-de-` for their corresponding isolated partitions. A partition/Region
mismatch is rejected before a provider call.

## Sign with a host-created client

The signer calls `DescribeKey` to prepare identity, rechecks `DescribeKey`
before signing, hashes the exact AEGIS signing payload with SHA-256, then calls
`Sign` with the concrete ARN, `MessageType="DIGEST"`, and the selected
algorithm.

```python
import time

import boto3

from aegis import sign_artifact_with_metadata
from aegis.integrations.aws_kms import AwsKmsArtifactSigner

client = boto3.client("kms", region_name="us-east-1")
signer = AwsKmsArtifactSigner(
    client,
    key_id="alias/aegis-audit-signing",
    signing_algorithm="RSASSA_PSS_SHA_256",
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
botocore retry/timeout configuration, endpoint policy, and region. AEGIS does
not override those settings.

The injected SDK client may retry a signing request. With randomized
algorithms, retries can create multiple valid remote signing operations even
though AEGIS emits at most one atomic receipt into the artifact.

## Resolve and verify an exact pair

Artifact metadata does not select provider resources. The resolver is a host
trust-policy function over the exact `(key_reference, key_version)` pair.
Return `None` for an unknown pair; never turn the artifact's ARN directly into
an allow decision.

The verifier hashes the exact AEGIS payload with SHA-256 and calls `Verify`
with the resolver-approved ARN, digest, signature, and algorithm. It requires
the response's `KeyId`, `SigningAlgorithm`, and `SignatureValid` fields to
match the request.

```python
from aegis import verify_artifact_detailed
from aegis.integrations.aws_kms import (
    AwsKmsArtifactVerifier,
    AwsKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition

trusted_pair = (
    "alias/aegis-audit-signing",
    "arn:aws:kms:us-east-1:111122223333:"
    "key/12345678-1234-4abc-8def-1234567890ab",
)
trusted_targets = {
    trusted_pair: AwsKmsVerificationTarget(
        key_arn=trusted_pair[1],
        allowed_algorithms=frozenset({"RSASSA_PSS_SHA_256"}),
        disposition=KmsKeyDisposition.ANCHORED,
    )
}


def resolve_aws_key(key_reference, key_version):
    return trusted_targets.get((key_reference, key_version))


verifier = AwsKmsArtifactVerifier(client, resolver=resolve_aws_key)
result = verify_artifact_detailed(artifact, verifier=verifier)
accepted = result.is_signature_valid and result.is_anchored
```

Check both result axes. Cryptographic validity alone does not establish the
host's anchor decision.

The verifier maps only the exact botocore HTTP-session failures that the
non-streaming KMS operations can raise directly: connect timeout, read
timeout, endpoint connection, SSL, proxy connection, connection closed, and
the exact base HTTP-client error. Subclasses are not widened into availability.
In particular, `ResponseStreamingError` remains a contract failure because
KMS `DescribeKey`, `Sign`, and `Verify` do not have streaming output.

## Least privilege

Grant only operations the deployment uses:

- signer: `kms:DescribeKey` and `kms:Sign`;
- online verifier: `kms:Verify`;
- retained artifact consumer with no online verification: no AWS KMS call.

Scope IAM and KMS key policy to the intended key and deployment identity. A
signing workload does not need verification permission merely because the
adapter package contains both classes; deploy signer and verifier roles
separately when that improves least privilege.

## Rotation, revocation, and outages

An alias may rotate to a new logical key ARN. New signatures record the newly
resolved ARN; historical verification succeeds only while the resolver retains
the old exact pair and the verifier is allowed to call that old key. Backing
material rotation under the same ARN is not exposed as a distinct artifact
version.

For compromise or policy revocation, mark the exact target
`KmsKeyDisposition.REVOKED`; a cryptographically valid signature then remains
revoked. Preserve the evidence and policy history needed to explain when and
why disposition changed. Decide separately whether prior signatures remain
acceptable under incident policy.

Provider unavailability never becomes success. Known availability failures
produce an indeterminate verifier-unavailable result; unexpected or malformed
responses fail with sanitized contract errors. The host decides whether to
queue verification, fail a workflow, or use previously retained evidence.

## Logging and assurance limits

Do not enable unrestricted botocore debug logging in paths that handle
artifact payloads, digests, signatures, request bodies, credentials, tokens,
provider errors, or raw provider responses. Apply host redaction before
retaining artifact metadata or verification evidence.

The adapter does not create immutable logging, trusted time, complete history,
HSM/FIPS status, or certification. It does not manage keys, aliases, grants,
rotation, deletion, compromise response, or evidence retention. It supports
asymmetric signing and verification only; encryption, decryption, MAC,
key-generation, and certificate workflows are outside this adapter.
