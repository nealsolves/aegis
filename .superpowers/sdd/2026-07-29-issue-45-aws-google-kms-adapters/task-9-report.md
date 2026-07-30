# Task 9 implementer report

Task: final end-to-end adversarial review for issue #45 AWS and Google Cloud
KMS adapters.

Started: 2026-07-29 15:55:22 CDT
Final reviewed branch: `codex/issue-45-aws-google-kms-adapters`
Initial Task 9 base: `e285d39`
Adversarial fix-round review base: `43eed14`

## Outcome

Task 9 completed with a `PASS` adversarial-review verdict.

- Final focused provider/conformance/distribution matrix: 1,015 passed, no
  skips.
- Final full Python gate: 3,101 passed, 1 documented non-KMS beta skip,
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

Final gates from the final 3,101-count source state:

```console
$ ../../.venv/bin/python -m pytest \
    tests/test_kms_common.py tests/test_aws_kms.py \
    tests/test_google_cloud_kms.py tests/test_external_signing.py \
    tests/test_external_signing_conformance.py tests/test_public_api.py \
    tests/test_v090_distribution_contract.py \
    tests/test_v090_publish_workflow.py \
    tests/test_kms_distribution_smoke.py -v
1015 passed in 8.47s

$ env PATH="../../.venv/bin:$PATH" ../../.venv/bin/python -m pytest --cov=aegis \
    --cov-report=term-missing --cov-fail-under=90
3101 passed, 1 skipped, 14 warnings in 58.47s
TOTAL 7142 statements, 618 missed, 91.35%

$ ../../.venv/bin/python -m flake8 aegis
exit 0

$ ../../.venv/bin/python scripts/check_doc_parity.py
PASSED: all documentation parity checks OK

$ ../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py
PASS: no public aegis._internal imports found

$ ../../.venv/bin/python scripts/validate_v090_release_freeze.py
PASS: brand/version parity and public-doc import checks passed

$ ../../.venv/bin/python -m pytest tests/test_doc_parity_v090_truth.py -v
77 passed in 1.12s

$ npm --prefix demo-app-react test
30 files passed; 298 tests passed

$ npm --prefix demo-app-react run build
vite v8.0.10; 1782 modules transformed; build passed
```

The first full-suite attempt used the same explicit interpreter but did not
prepend its directory to `PATH`. It reported 1 failed, 3,100 passed, 1 skipped,
and 14 warnings solely because
`test_pr11_public_api_boundary.py::test_public_import_boundary_script_passes`
intentionally launches literal `python`, for which that shell had no alias.
The exact successful rerun above supplied the virtual-environment bin
directory through `PATH`. This was an execution-environment precondition, not
a product failure.

The single skip is
`tests/test_pr11_session_replay_concurrency.py:100`, the explicit v0.9.0 beta
non-goal for concurrent Phase-B calls. It is unrelated to KMS, and no focused
provider or artifact case skipped.

The 14 warnings are existing governed/migration/precondition warnings and
deprecations, not KMS warnings.

After the stable count was observed, all four public count surfaces were
changed together from 3,095 to exactly 3,101:

- `doc_parity_manifest.yaml`;
- `README.md`;
- `CHANGELOG.md`;
- `implementation_status.md`.

Documentation parity and the full suite were rerun after the final update.

## Final artifacts and candidate proof

Final fresh build directory:
`/private/tmp/aegis-task9-fix1-final.OQ92ck`

```console
$ ../../.venv/bin/python -m build \
    --outdir /private/tmp/aegis-task9-fix1-final.OQ92ck
Successfully built aegis_ai_governance-0.9.0b1.tar.gz and
aegis_ai_governance-0.9.0b1-py3-none-any.whl
```

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| wheel | 189,843 bytes | `c0eaba907c38cb722cdc580fb0df16deceb3be65817a0f49c0a028473c02561e` |
| sdist | 3,606,357 bytes | `b5aa37ee631773c77012bb2d209042b3767fbca61688edace7eb9613c2698273` |

Direct final-sdist inspection:

```console
$ tar -tzf /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1.tar.gz \
    | rg '^aegis_ai_governance-0\.9\.0b1/docs/reference/external/(AWS_KMS_SIGNING|GOOGLE_CLOUD_KMS_SIGNING)\.md$'
aegis_ai_governance-0.9.0b1/docs/reference/external/AWS_KMS_SIGNING.md
aegis_ai_governance-0.9.0b1/docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md
```

Candidate proof:

```console
$ ../../.venv/bin/python scripts/validate_v090_distribution_candidate.py \
    --dist-dir /private/tmp/aegis-task9-fix1-final.OQ92ck --no-build
status: PASS
inspect_artifacts: PASS (0.023s)
fresh_wheel_end_to_end: PASS (8.686s)
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

## Task 9 adversarial fix round 1 (2026-07-30)

Fix-round review base: `43eed14`. Five independently verified findings were
corrected without changing the locked provider contract, the exact eight AWS
partitions, or any Technical Manual file.

1. **Tracked report missing from parity manifest.** RED:
   `../../.venv/bin/python scripts/check_doc_parity.py` failed section 0B only
   because
   `.superpowers/sdd/2026-07-29-issue-45-aws-google-kms-adapters/task-9-report.md`
   was an unclassified tracked document. GREEN after `d795a92`: every
   documentation-parity section 0A through O passed; release freeze also
   passed.
2. **Distribution-validator failure serialization exposed subprocess
   commands, stdout/stderr, random roots, and hostile values.** The two-root
   candidate and optional-extra regressions initially failed. GREEN after
   `3570aff`: both passed, followed by 29 adjacent distribution tests.
   Candidate failures retain fixed schema/distribution/version/status plus
   stable stage name, category, and optional return code. Optional-extra
   failures retain only schema, status, lane, stage, category, and optional
   return code. Neither report includes a command, stdout/stderr, secret,
   hostile URL/domain, or temporary path.
3. **Both guides omitted the retry-signature/atomic-receipt warning.** RED:
   the new per-guide truth test failed on the AWS guide. GREEN after
   `34e65ee`: the focused test and all 77 documentation truth tests passed.
   Each guide now warns that retries of randomized algorithms can create
   multiple valid remote signing operations although AEGIS emits at most one
   atomic receipt into the artifact.
4. **The audit/evidence matrix was not exact and self-contained enough.**
   The final audit names all seven exact optional-extra commands, the actual
   documentation test command, exact design-before-plan history, TDD evidence,
   host-injected/no-client-creation evidence, signer and verifier unsupported-
   algorithm paths, exact failure symbols, and the fetched-PEM boundary.
   `ef1e893` synchronized all four public count surfaces from 3,095 to 3,101;
   this evidence closeout records the corrected audit and report.
5. **Fetched Google public-key bounds lacked an explicit
   limit−1/limit/limit+1 triplet.** RED:
   `rg -n "test_google_fetched_pem_covers_limit_minus_one_limit_and_limit_plus_one" tests/test_google_cloud_kms.py`
   returned no match (exit 1). GREEN after `2b174ed`: 65,535- and 65,536-byte
   fetched PEM responses were accepted and cryptographically verified;
   65,537 bytes was rejected with the sanitized contract error. Every case
   made exactly one provider call; the three focused cases and all 278 Google
   tests passed.

The exact hostile-failure GREEN was:

```console
$ ../../.venv/bin/python -m pytest \
    tests/test_v090_distribution_contract.py::test_candidate_subprocess_failure_report_is_stable_and_redacted \
    tests/test_kms_distribution_smoke.py::test_smoke_subprocess_failure_report_is_stable_and_redacted -v
2 passed
```

The fresh artifacts and candidate result are the ones recorded above:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| wheel | 189,843 bytes | `c0eaba907c38cb722cdc580fb0df16deceb3be65817a0f49c0a028473c02561e` |
| sdist | 3,606,357 bytes | `b5aa37ee631773c77012bb2d209042b3767fbca61688edace7eb9613c2698273` |

The build command, exact sdist membership command, and candidate command used
`/private/tmp/aegis-task9-fix1-final.OQ92ck`. Candidate inspection passed in
0.023s and fresh-wheel end-to-end passed in 8.686s on Python 3.12 with
`dependency_check: PASS` and `import_location: isolated-virtualenv`. Minimal,
regulated doctor/fix, standard approval-checkpoint, trace, and
audit/operator/compliance-lineage flows completed with provider credentials
removed.

That fresh build followed every package, runtime, test, public count, and
provider-guide change. Exact tar inspection found neither `docs/audits` nor
the `.superpowers` Task 9 report in the sdist, so the later evidence-only
audit/report edits cannot change the recorded artifact bytes or hashes.

The seven installed-artifact commands and results were:

| ID | Exact command | Observed provider versions/result |
| --- | --- | --- |
| P1 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane base --expected-versions '{}'` | PASS; PyYAML 6.0.3, jsonschema 4.26.0; no AWS/Google provider family. |
| P2 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane aws --expected-versions '{"boto3":"1.43.0"}'` | PASS; boto3 1.43.0, botocore 1.43.59, s3transfer 0.17.1. |
| P3 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane aws --expected-versions '{}'` | PASS; boto3/botocore 1.43.59, s3transfer 0.19.2. |
| P4 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane gcp --expected-versions '{"google-cloud-kms":"3.15.0","google-crc32c":"1.7.1","cryptography":"45.0.1"}'` | PASS; exact floors and google-api-core 2.33.0. |
| P5 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane gcp --expected-versions '{}'` | PASS; google-cloud-kms 3.16.0, google-crc32c 1.8.0, cryptography 49.0.0, google-api-core 2.33.0. |
| P6 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1-py3-none-any.whl --lane combined --expected-versions '{}'` | PASS; AWS-current and Google-current stacks above. |
| P7 | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact /private/tmp/aegis-task9-fix1-final.OQ92ck/aegis_ai_governance-0.9.0b1.tar.gz --lane combined --expected-versions '{}'` | PASS; AWS-current and Google-current stacks above from the sdist. |

All seven lanes exercised installed metadata, provider isolation, credential
environment clearing, real SDK/request/response or botocore transport classes,
and the applicable AWS sign/verify or Google sign/retained-PEM verify checks.
No provider check skipped.

Final source verification observed 1,015 focused tests with no skips and 3,101
full-suite passes, 1 documented non-KMS beta skip, 14 warnings, and 91.35%
coverage (7,142 statements, 618 missed). The single skip and warning classes
remain those documented above. Build warnings remain the nonblocking
setuptools license-table/license-classifier deprecations (2027-02-18 horizon)
and existing MANIFEST no-match/prune/exclude warnings. Host ownership,
provider availability, resolver correctness, retention/provenance, Issue #46
complete-chain defense, interpreter integrity, npm advisories/pending scripts,
and live GitHub/PR/issue actions remain the documented residuals or finalizer
work.

## Commits produced by Task 9

- `7f47cee` — `fix: stabilize KMS lane diagnostics`
- `7994725` — `test: close KMS guide validator gaps`
- `53dcf98` — `docs: enforce KMS host ownership boundaries`
- `dcd046b` — `fix: stabilize candidate import provenance`
- `2bac76f` — `test: complete KMS boundary triplets`
- `d88d942` — `fix: ship KMS guides in source distribution`
- `952e4cb` — `test: prove AWS signer concurrency isolation`
- `b25d4f7` — `test: complete AWS verifier signature bounds`
- `43eed14` — `docs: record KMS adapter adversarial review`
- `3570aff` — `fix: redact distribution subprocess failures`
- `34e65ee` — `docs: warn about KMS retry signatures`
- `2b174ed` — `test: prove fetched Google KMS PEM bounds`
- `d795a92` — `docs: classify Task 9 evidence report`
- `ef1e893` — `docs: refresh Task 9 verification count`
- `5ccfe7a` — `docs: close KMS adapter adversarial fix round`
- round-2 evidence correction — accurate inventory-section label (this
  commit)

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

## Task 9 adversarial fix round 2 (2026-07-30)

Round 1 mislabeled the original unclassified-document failure. The checker
registry maps candidate identity to section 0A and documentation inventory to
section 0B; the exact tracked Task 9 report therefore failed section 0B.
Both stale claims were corrected without changing runtime, tests, artifacts,
hashes, counts, or provider evidence.

Narrow verification passed:

- exact search found the corrected section 0B failure claim in the audit and
  this report and found no remaining stale failure-section claim;
- documentation parity passed every section from 0A through O;
- the v0.9.0 release-freeze validator passed brand/version parity and the
  public-document import boundary;
- `git diff --check` reported no whitespace errors.

Round 2 status: `PASS`.
