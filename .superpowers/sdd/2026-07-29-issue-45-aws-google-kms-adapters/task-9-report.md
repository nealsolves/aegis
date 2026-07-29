# Task 9 implementer report

Task: final end-to-end adversarial review for issue #45 AWS and Google Cloud
KMS adapters.

Started: 2026-07-29 15:55:22 CDT
Final reviewed branch: `codex/issue-45-aws-google-kms-adapters`
Initial Task 9 base: `e285d39`

## Outcome

Task 9 completed with a `PASS` adversarial-review verdict.

- Final focused provider/conformance/distribution matrix: 1,010 passed, no
  skips.
- Final full Python gate: 3,095 passed, 1 documented non-KMS beta skip,
  14 warnings, 91.35% coverage.
- Lint, documentation parity, public-doc import, and release-freeze gates:
  PASS.
- Frontend: 30 files / 298 tests passed; production build passed.
- Fresh distribution candidate proof: PASS.
- Optional-extra artifact matrix: seven of seven lanes passed with no
  provider check skipped.

The final adversarial review is:
`docs/audits/2026-07-29-issue-45-aws-google-kms-adapters-adversarial-review.md`.

## Preflight and review inputs

Read completely before implementation action:

- Task 9 brief;
- approved design;
- ADR-0013;
- Task 6/7/8 completion, deferred-minor, and parked ledger entries;
- execution, worktree, TDD/good-test, and verification instructions.

The linked worktree started clean on the named feature branch:

```console
$ git status --short --branch
## codex/issue-45-aws-google-kms-adapters

$ git rev-parse --show-toplevel
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.worktrees/issue-45-aws-google-kms-adapters
```

The Task 6 parked identity case was retained as the ADR's explicit
interpreter-integrity non-goal: same-source canonical-module replacement
before the first lazy load requires prior arbitrary in-process execution and
cannot be distinguished without a pre-retained trust anchor.

The remaining Task 7/8 deferred items were treated as a concrete audit queue:

1. unstable artifact/import provenance fields;
2. untrusted requirement values in metadata diagnostics;
3. per-guide host-ownership masking;
4. uppercase identity constants misclassified as algorithms;
5. first-iterable comprehension walrus bypass.

## Toolchain and optional extras

Both provider extras were initially absent. They were installed with:

```console
$ ../../.venv/bin/python -m pip install -e '.[aws-kms,gcp-kms]' --no-build-isolation
Successfully installed aegis-ai-governance-0.9.0b1
  boto3-1.43.59 botocore-1.43.59
  google-cloud-kms-3.16.0 google-api-core-2.33.0
  google-crc32c-1.8.0 cryptography-49.0.0 ...
```

Review toolchain:

- Python 3.12.13;
- `pytest 9.1.1`, `pytest-cov 7.1.0`, `flake8 7.3.0`;
- `build 1.5.0`;
- Node `v26.3.0`, npm `11.17.0`.

Context7 resolved the official Boto3 and Google Cloud Python documentation
repositories. The AWS result was supplemented with the official KMS product
API references. The Google Context7 result described the legacy `pem` field,
so acceptance evidence instead used the official explicit-format product
reference and installed SDK descriptors. Installed descriptors confirmed:

- AWS `Sign` exact request fields `KeyId`, `Message`, `MessageType`,
  `SigningAlgorithm` and response `KeyId`, `Signature`,
  `SigningAlgorithm`;
- AWS `Verify` adds `Signature` and returns `SignatureValid`;
- Google `CryptoKeyVersion` has name/state/algorithm but no `purpose`;
- Google `AsymmetricSignRequest` has `name`, `digest`, `digest_crc32c`;
- Google sign response has `name`, `signature`, `signature_crc32c`,
  `verified_digest_crc32c`;
- explicit `GetPublicKeyRequest.public_key_format=PEM` returns checksummed
  bytes through `PublicKey.public_key.data` and
  `PublicKey.public_key.crc32c_checksum`.

## Required structural searches

All four Task 9 `rg` commands were run exactly.

- Provider imports are lazy inside use paths; `pyproject.toml` contains the
  exact optional extras.
- Broad adapter catches terminate in fixed sanitized contract errors or
  documented closed outcomes. No adapter print or AEGIS provider log path was
  found.
- AWS selectors are used only for the two identity checkpoints; `Sign` and
  `Verify` use copied concrete ARNs. Google uses exact terminal versions,
  performs no primary lookup, and does not assume version-level `purpose`.
- No unfinished provider or guide implementation marker was found. The
  production `pass` hit is the deliberate safe `client.exceptions` probe;
  test `pass` hits are helper/marker classes.

## Findings and scoped commits

### 1. Installed-artifact diagnostics and provenance

Commit: `7f47cee fix: stabilize KMS lane diagnostics`

Added regressions for a direct URL containing a token, a hostile marker,
malformed requirement text, and stable report equality across temporary
roots.

RED:

```text
4 failed
```

Correction:

- provider metadata failures now raise fixed messages `from None`;
- untrusted tuples/values are not rendered;
- JSON reports use stable filename, format, SHA-256, and
  `import_location: isolated-virtualenv`;
- random artifact/venv/import paths were removed.

GREEN:

```text
4 passed
33 adjacent distribution tests passed
```

### 2. Documentation algorithm and comprehension validation

Commit: `7994725 test: close KMS guide validator gaps`

RED:

- an unrelated `KEY_ID` inline token was treated as an algorithm;
- a named expression in a comprehension's first iterable was accepted.

```text
2 failed
```

Correction:

- algorithm extraction is scoped to the declaration paragraph;
- every comprehension first iterable is scanned for `NamedExpr`.

GREEN:

```text
2 passed
76 documentation truth tests passed
documentation parity passed
```

### 3. Per-guide host ownership

Commit: `53dcf98 docs: enforce KMS host ownership boundaries`

The strengthened per-guide check first failed because the AWS guide did not
say `networking` explicitly. Both guides now individually state host ownership
of clients, credentials, networking, endpoints, retries/timeouts, regional or
project configuration, IAM/trust policy, trust stores, provider logging, and
retained evidence.

```text
RED: 1 failed
GREEN: focused test passed; 76 documentation truth tests passed
```

### 4. Candidate import provenance

Commit: `dcd046b fix: stabilize candidate import provenance`

The first candidate proof exposed a random
`installed_workflow.import_path`. A stable-provenance regression failed with
the expected missing helper:

```text
1 failed: AttributeError for _installed_import_provenance
```

The validator still proves the imported module is inside the fresh venv and
outside the checkout, but reports only
`import_location: isolated-virtualenv`.

```text
GREEN: 1 passed
Adjacent: 34 passed
```

### 5. Explicit boundary triplets

Commit: `2bac76f test: complete KMS boundary triplets`

Manual trace found correct runtime comparisons but incomplete explicit
evidence at limit−1, limit, and limit+1. Tests now exercise:

- AWS sign responses at 6,143 / 6,144 / 6,145 bytes;
- Google sign responses at 12,287 / 12,288 / 12,289 bytes;
- retained PEM at 65,535 / 65,536 / 65,537 bytes;
- CRC32C at both edges and
  `2**32−2` / `2**32−1` / `2**32`.

```text
4 focused boundary tests passed
```

This was an evidence-only test strengthening; the reviewed runtime already
handled all triplets correctly.

### 6. Maintained guides omitted from the source distribution

Commit: `d88d942 fix: ship KMS guides in source distribution`

Final artifact self-review found that the source distribution omitted both
maintained KMS integration guides even though the approved design requires
them as public integration documentation.

```text
RED: test_sdist_contains_both_maintained_kms_integration_guides failed;
     both expected guide members were absent
GREEN: focused test passed; 35 adjacent distribution tests passed
```

`MANIFEST.in` now includes
`docs/reference/external/AWS_KMS_SIGNING.md` and
`docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` exactly. The final fresh
sdist was inspected independently and contains both paths.

### 7. Missing AWS signer concurrency evidence

Commit: `952e4cb test: prove AWS signer concurrency isolation`

The final literal design-row audit found that Google signer/verifier and AWS
verifier calls had barrier-controlled interleaving tests, but AWS signer
conformance was sequential.

```text
RED: rg for an AWS signer concurrency test returned no match (exit 1)
GREEN: test_aws_signer_isolates_concurrent_payload_state passed
Adjacent: 267 KMS-common/AWS/conformance tests passed
```

The new test forces two calls on one frozen signer through both DescribeKey
and Sign barriers, proves exact payload-digest/request/receipt isolation,
cryptographically verifies both randomized signatures, and confirms that
signer configuration remains unchanged. No runtime correction was required.

### 8. AWS verifier below-limit evidence

Commit: `b25d4f7 test: complete AWS verifier signature bounds`

The verifier had explicit 6,144-byte acceptance and 6,145-byte rejection, but
the audit could not substantiate a 6,143-byte verifier-input claim.
`test_aws_verifier_accepts_limit_minus_one_and_limit` now exercises 6,143 and
6,144 bytes, while the existing rejection matrix exercises 6,145.

```text
10 focused AWS signature-bound cases passed
```

This was test-only evidence strengthening; the runtime comparison was already
correct.

## Provider, authority, failure, mutation, and concurrency trace

The final audit records every design threat, locked requirement, and
acceptance row with an implementation symbol, focused test, concrete command,
observed result, and residual/non-goal.

Manual trace conclusions:

- Artifact metadata reaches a provider resource only through the exact-pair
  host resolver and reconstructed exact target.
- AWS performs two `DescribeKey` checks, then sends only the concrete ARN,
  SHA-256 digest, `DIGEST`, and closed algorithm to `Sign`.
- AWS `Verify` sends only the resolver-approved concrete ARN and exact digest,
  signature, and algorithm.
- Google performs two exact-version metadata checks, sends the SHA-256 digest
  plus its CRC32C, requires provider digest confirmation, validates signature
  CRC32C, and checks response identity.
- Google fetches public keys only with an explicit PEM format request and
  validates checksummed data, identity, algorithm, type, curve/size, and
  bounds before local prehashed RSA-PSS/ECDSA verification.
- Every known provider availability path maps to the closed unavailable
  outcome; invalid signatures remain distinct; malformed/unexpected
  provider, resolver, CRC, serialization, and crypto paths become sanitized
  unchained contract errors.
- All four barrier-controlled signer/verifier interleavings confirm that
  frozen adapter configuration and local copied snapshots prevent
  adapter-owned cross-call state bleed.
- Provider operations finish before the core atomic signature commit; every
  failure snapshot remains byte-for-byte unchanged.

The exact AWS partition set is:

`aws`, `aws-cn`, `aws-us-gov`, `aws-iso`, `aws-iso-b`, `aws-iso-e`,
`aws-iso-f`, and `aws-eusc`.

Required future pull-request carry-forward note:

> This is strictly fail-closed and rejects invented aws-* partitions, but a newly introduced AWS partition would require an adapter update.

No AEGIS Technical Manual file was created or edited.

## Frontend provisioning and repository gates

The ignored worktree `demo-app-react/node_modules` initially pointed by
symlink to the main checkout. Its link target was verified, the symlink itself
was unlinked without traversing or deleting the target, and a locked local
installation was created:

```console
$ npm --prefix demo-app-react ci
added 388 packages, audited 389 packages
```

`npm ci` reported 1 low and 7 high advisories and pending install scripts for
`@playwright/browser-chromium@1.61.0`, `fsevents@2.3.3`, and
`fsevents@2.3.2`. No automated audit fix or script authorization was applied.
The complete frontend test and production build gates passed.

Final gates from the final 3,095-count source state:

```console
$ ../../.venv/bin/python -m pytest \
    tests/test_kms_common.py tests/test_aws_kms.py \
    tests/test_google_cloud_kms.py tests/test_external_signing.py \
    tests/test_external_signing_conformance.py tests/test_public_api.py \
    tests/test_v090_distribution_contract.py \
    tests/test_v090_publish_workflow.py \
    tests/test_kms_distribution_smoke.py -v
1010 passed in 17.14s

$ ../../.venv/bin/python -m pytest --cov=aegis \
    --cov-report=term-missing --cov-fail-under=90
3095 passed, 1 skipped, 14 warnings in 106.61s
TOTAL 7142 statements, 618 missed, 91.35%

$ ../../.venv/bin/python -m flake8 aegis
exit 0

$ ../../.venv/bin/python scripts/check_doc_parity.py
PASSED: all documentation parity checks OK

$ ../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py
PASS: no public aegis._internal imports found

$ ../../.venv/bin/python scripts/validate_v090_release_freeze.py
PASS: brand/version parity and public-doc import checks passed

$ npm --prefix demo-app-react test
30 files passed; 298 tests passed

$ npm --prefix demo-app-react run build
vite v8.0.10; 1782 modules transformed; build passed
```

The single skip is
`tests/test_pr11_session_replay_concurrency.py:100`, the explicit v0.9.0 beta
non-goal for concurrent Phase-B calls. It is unrelated to KMS, and no focused
provider or artifact case skipped.

The 14 warnings are existing governed/migration/precondition warnings and
deprecations, not KMS warnings.

After the stable count was observed, all four public count surfaces were
changed together from the old value to exactly 3,095:

- `doc_parity_manifest.yaml`;
- `README.md`;
- `CHANGELOG.md`;
- `implementation_status.md`.

Documentation parity and the full suite were rerun after the final update.

## Final artifacts and candidate proof

Final fresh build directory:
`/private/tmp/aegis-task9-final-matrix2.oNDqGk`

```console
$ ../../.venv/bin/python -m build \
    --outdir /private/tmp/aegis-task9-final-matrix2.oNDqGk
Successfully built aegis_ai_governance-0.9.0b1.tar.gz and
aegis_ai_governance-0.9.0b1-py3-none-any.whl
```

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| wheel | 189,843 bytes | `05bbe1bc3988a1ae29acb80ba06c2db134e80c89ebc2fef3c32d2c9e1ed1c712` |
| sdist | 3,606,308 bytes | `c2a4bbaab5a2d0fda3623a4f26d3f5557c298c1b19ac0f8ebc65b54c8d6184b7` |

Direct final-sdist inspection:

```console
$ tar -tzf /private/tmp/aegis-task9-final-matrix2.oNDqGk/aegis_ai_governance-0.9.0b1.tar.gz \
    | rg '^aegis_ai_governance-0\.9\.0b1/docs/reference/external/(AWS_KMS_SIGNING|GOOGLE_CLOUD_KMS_SIGNING)\.md$'
aegis_ai_governance-0.9.0b1/docs/reference/external/AWS_KMS_SIGNING.md
aegis_ai_governance-0.9.0b1/docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md
```

Candidate proof:

```console
$ ../../.venv/bin/python scripts/validate_v090_distribution_candidate.py \
    --dist-dir /private/tmp/aegis-task9-final-matrix2.oNDqGk --no-build
status: PASS
inspect_artifacts: PASS (0.024s)
fresh_wheel_end_to_end: PASS (10.996s)
dependency_check: PASS
import_location: isolated-virtualenv
```

The proof exercised all workflow profiles, doctor/fix, trace, and
audit/operator/compliance-lineage exports with provider credentials removed.

Setuptools emitted nonblocking license-table/license-classifier deprecations
with a 2027-02-18 horizon and existing MANIFEST no-match/exclusion warnings.
Both artifacts built and passed inspection.

## Seven final installed-artifact lanes

Each lane ran the exact `scripts/validate_kms_optional_extras.py` command
declared by `.github/workflows/publish.yml` against the final hashes.

| Lane | Requested pins | Resolved provider versions | Result |
| --- | --- | --- | --- |
| base wheel | `{}` | no AWS/Google provider family | PASS |
| AWS minimum wheel | `boto3==1.43.0` | `boto3 1.43.0`, `botocore 1.43.59`, `s3transfer 0.17.1` | PASS |
| AWS current wheel | current | `boto3 1.43.59`, `botocore 1.43.59`, `s3transfer 0.19.2` | PASS |
| Google minimum wheel | KMS `3.15.0`, CRC32C `1.7.1`, cryptography `45.0.1` | exact floors; `google-api-core 2.33.0` | PASS |
| Google current wheel | current | KMS `3.16.0`, CRC32C `1.8.0`, cryptography `49.0.0`, API core `2.33.0` | PASS |
| combined current wheel | current | AWS and Google current versions above | PASS |
| combined current sdist | current | AWS and Google current versions above | PASS |

All reports used stable artifact filename/format/SHA-256 and
`import_location: isolated-virtualenv`. AWS lanes exercised real botocore
transport classes. Google lanes exercised real request/response/API classes,
signing, and retained-PEM verification. No provider check skipped.

## Residuals and non-goals

- Host clients, credentials, networking, endpoints, regional/project
  configuration, IAM/trust policy, trust stores, retries/timeouts, retained
  evidence, logging, rotation, revocation, compromise response, and outage
  policy remain host-owned.
- Resolver correctness, provider availability, AWS old-key access, and Google
  retained-key provenance/retention remain explicit operational boundaries.
- No immutable-log, complete-history, trusted-time, non-repudiation,
  HSM/FIPS, key-origin/residency, or compliance claim is made. Issue #46
  remains required for complete-chain replacement/truncation defense.
- The Task 6 interpreter-integrity boundary remains explicit and accepted.
- npm advisories/pending scripts and setuptools license metadata deprecations
  remain dependency/release-tooling maintenance; they did not fail acceptance
  gates.
- The live GitHub Actions run, PR references to #45/#39, and post-merge issue
  state changes are finalizer actions. Task 9 intentionally did not push,
  create a PR, or mutate issue state.

## Commits produced by Task 9

- `7f47cee` — `fix: stabilize KMS lane diagnostics`
- `7994725` — `test: close KMS guide validator gaps`
- `53dcf98` — `docs: enforce KMS host ownership boundaries`
- `dcd046b` — `fix: stabilize candidate import provenance`
- `2bac76f` — `test: complete KMS boundary triplets`
- `d88d942` — `fix: ship KMS guides in source distribution`
- `952e4cb` — `test: prove AWS signer concurrency isolation`
- `b25d4f7` — `test: complete AWS verifier signature bounds`
- final evidence commit — `docs: record KMS adapter adversarial review`
  (this commit)

## Self-review

- Every threat, locked requirement, and acceptance row is represented in the
  final audit with a concrete file/symbol, focused test, command/result, and
  residual/non-goal.
- The audit ends in `PASS`.
- Exact eight-partition runtime/docs behavior is preserved.
- The required future Technical Manual sentence appears verbatim in the audit
  and this report; no Technical Manual file was touched.
- No push, PR, merge, or issue-state mutation was performed.
- Final count, coverage, artifact hashes, resolved lane versions, warning
  classes, skip reason, and residuals are recorded.

Final Task 9 status: `PASS`.
