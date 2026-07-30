# Issue #45 final whole-branch fix-wave report

Date: 2026-07-30
Branch: `codex/issue-45-aws-google-kms-adapters`
Reviewed runtime/documentation source: `3b7fad0`
Starting source: `76b99f6`
Status: `PASS`

## Scope and result

This wave closed six Important findings and one Minor
evidence/documentation finding from the final independent whole-branch
review. It preserved the approved exact-type, provenance-authenticated,
fail-closed contract; the exact optional extras; the unchanged base
dependency set; one release path with seven installed-artifact lanes; and the
Technical Manual boundary.

Commits:

- `89adfea` — `fix: harden KMS identity and transport validation`
- `8cbb8ae` — `docs: correct source-only KMS installation evidence`
- `3b7fad0` — `docs: refresh current-source verification count`
- evidence closeout — final audit, Task 9 report, and this report

## RED-before-GREEN record

Regressions were added before runtime or guide corrections. The combined
defect set was RED at 34 failed and 52 passed in 4.28 seconds. It reproduced:

- noncanonical Google versions across signer, verification target, and
  metadata normalization;
- multiple PEM blocks and non-whitespace material outside the PEM block;
- five missing direct Google transport types;
- cross-partition AWS Regions;
- four missing exact botocore transport types; and
- stale checkout-install and released-history/current-source documentation.

Both newly added real AWS ECDSA verifier success cases passed during RED,
proving that finding was an evidence gap rather than a runtime defect.

After the scoped fixes, the same focused defect set was GREEN at 89 passed in
4.83 seconds. The final provider/conformance/distribution matrix then passed
1,051 tests in 9.50 seconds with no skips.

## Findings closed

### 1. Google transport provenance and exact classification

Google availability classification now authenticates the exact installed
module source for:

- `google-api-core`: direct `InternalServerError`, `BadGateway`, and the
  existing closed direct API-core types;
- `requests`: exact `ConnectionError` and `Timeout`; and
- `google-auth`: exact `TransportError`.

Authentication requires the exact module type/name/package/spec/loader,
canonical `sys.modules` identity, installed distribution identity, and the
matching RECORD entry, path, size, and SHA-256. The classifier uses exact type
identity, not broad subclass acceptance, and follows at most one exact
`RetryError` cause. Real exact types, subclasses, nested retry causes, and
spoofed-provenance cases passed.

### 2. AWS botocore transport surface

AWS classification now authenticates and recognizes exactly:

- `ConnectTimeoutError`;
- `ReadTimeoutError`;
- `EndpointConnectionError`;
- `SSLError`;
- `ProxyConnectionError`;
- `ConnectionClosedError`; and
- exact `HTTPClientError`.

`ResponseStreamingError` is deliberately excluded. Botocore emits it from
streaming-body paths, while KMS `DescribeKey`, `Sign`, and `Verify` responses
are non-streaming. Real installed-class tests and both AWS artifact lanes
proved that the seven direct types map to unavailable and
`ResponseStreamingError` maps to a sanitized contract failure.

### 3. Canonical Google version identities

The terminal `cryptoKeyVersions` component must now match `[1-9][0-9]*`.
Aliases, zero, leading-zero forms, dotted values, signs, non-ASCII digits,
and nonterminal forms fail before provider work. The same rule applies to
signer configuration, verification targets, and provider metadata.

### 4. Exact Google public-key PEM envelope

Retained and fetched public keys must contain exactly one
`-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` block. Only supported
surrounding ASCII whitespace (`space`, tab, CR, LF, vertical tab, form feed)
is accepted. Multiple blocks, private/certificate envelopes, and surrounding
junk fail closed before cryptographic acceptance.

### 5. AWS partition/Region coherence

ARN validation now uses one closed minimum-supported Region pattern for each
accepted partition:

- `aws`
- `aws-cn`
- `aws-eusc`
- `aws-iso`
- `aws-iso-b`
- `aws-iso-e`
- `aws-iso-f`
- `aws-us-gov`

Cross-partition Regions and invented partitions fail closed.

Required future pull-request carry-forward note:

> This is strictly fail-closed and rejects invented aws-* partitions, but a newly introduced AWS partition would require an adapter update.

### 6. Real AWS ECDSA verifier evidence

Successful real cryptographic verification now covers:

- `ECC_NIST_P256`; and
- `ECC_SECG_P256K1`.

The tests exercise actual EC keys and signatures through the AWS verifier
contract. No runtime change was needed.

### 7. Checkout installation and count history

The maintained source-checkout instructions now use:

```console
python -m pip install -e ".[aws-kms]"
python -m pip install -e ".[gcp-kms]"
```

The immutable released 0.9.0b1 changelog history remains at 1,923 tests.
Current-source truth is recorded separately as 3,138 tests in the maintained
count surfaces.

## Final source gates

| Gate | Result |
| --- | --- |
| Focused defect set | 89 passed |
| Provider/conformance/distribution matrix | 1,051 passed, no skips |
| Complete Python suite with coverage | 3,138 passed, 1 skipped, 14 warnings in 60.88s |
| Coverage | 7,269 statements, 641 missed, 91.18% |
| `flake8 aegis` | PASS |
| Documentation parity, sections 0A–O | PASS |
| Public docs internal-import boundary | PASS |
| Release-freeze validator | PASS |
| Documentation truth tests | 78 passed |
| React tests | 30 files / 298 tests passed in 10.77s |
| Vite 8.0.10 production build | PASS; 1,782 modules transformed |

The single skip is the documented non-KMS concurrent Phase-B beta non-goal.
The 14 warnings are the existing governed/migration/precondition warnings and
deprecations, not KMS warnings.

## Fresh artifacts and candidate proof

Fresh directory: `/private/tmp/aegis-issue45-final-fix.Eiquhy`

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `aegis_ai_governance-0.9.0b1-py3-none-any.whl` | 192,058 bytes | `eacc75737fd9f1ec90f7031da5b7f701345ecf2f479a7c765216227cc934cd04` |
| `aegis_ai_governance-0.9.0b1.tar.gz` | 3,609,059 bytes | `38e562ab73fa8297c73405169956c72ecc131c7cc81976736db5f2278c0ea7f1` |

The first sandboxed build attempt could not resolve the package index. The
immediate network-enabled rerun succeeded; this was an external execution
precondition, not a product failure.

Exact sdist inspection found both maintained guide members:

- `aegis_ai_governance-0.9.0b1/docs/reference/external/AWS_KMS_SIGNING.md`
- `aegis_ai_governance-0.9.0b1/docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md`

It found no `docs/audits` or `.superpowers` member, so the evidence-only
closeout cannot change the recorded artifact bytes or hashes.

Candidate validation passed artifact inspection in 0.023 seconds and the
fresh-wheel end-to-end proof in 8.544 seconds. Dependency checking, all three
profiles, trace, three exports, and isolated-virtualenv provenance passed.

## Seven installed-artifact lanes

| Lane | Resolved provider versions | Result |
| --- | --- | --- |
| Base wheel | no AWS or Google provider family | PASS |
| AWS minimum wheel | `boto3 1.43.0`, `botocore 1.43.59`, `s3transfer 0.17.1` | PASS |
| AWS current wheel | `boto3 1.43.59`, `botocore 1.43.59`, `s3transfer 0.19.2` | PASS |
| Google minimum wheel | KMS `3.15.0`, CRC32C `1.7.1`, cryptography `45.0.1`, API core `2.33.0`, auth `2.56.2`, requests `2.34.2` | PASS |
| Google current wheel | KMS `3.16.0`, CRC32C `1.8.0`, cryptography `49.0.0`, API core `2.33.0`, auth `2.56.2`, requests `2.34.2` | PASS |
| Combined current wheel | AWS and Google current stacks above | PASS |
| Combined current sdist | AWS and Google current stacks above | PASS |

All AWS lanes exercised the exact seven-type transport set and the excluded
`ResponseStreamingError`. All Google lanes exercised the five exact direct
transport types and a one-hop `RetryError` around each. No provider check
skipped.

## Boundaries and finalizer handoff

Host clients, credentials, networking, Region/project configuration,
retry/timeout policy, IAM/trust policy, provider logging, retained evidence,
rotation, revocation, and outage policy remain host-owned. Resolver
correctness, provider availability, historical-key/public-key retention,
interpreter integrity before first authenticated lazy load, and Issue #46
complete-chain defense remain explicit boundaries.

No Technical Manual file, base dependency, optional-extra definition, or
release workflow was changed. No push, pull request, merge, or issue-state
mutation was performed.

Final fix-wave verdict: `PASS`.
