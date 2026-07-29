# Issue #45 AWS and Google Cloud KMS Adapters: Final Adversarial Review

Date: 2026-07-29
Branch: `codex/issue-45-aws-google-kms-adapters`
Reviewed implementation range: `b62ce23..b25d4f7`
Design authority:
`docs/superpowers/specs/2026-07-29-issue-45-aws-google-kms-adapters-design.md`
Decision authority:
`docs/decisions/ADR-0013-aws-google-kms-adapters.md`

## Executive result

The implementation, provider contracts, failure classifications, test
structure, documentation, package metadata, built artifacts, and all seven
optional-extra lanes were reviewed adversarially. Every supported provider
case ran with both extras installed; the focused provider matrix had no skips.
The final repository state passed 3,095 Python tests at 91.35% coverage, all
lint/documentation/release gates, 298 frontend tests, the frontend production
build, the fresh-wheel end-to-end candidate proof, and all seven isolated
artifact lanes.

Eight substantiated whole-branch findings were corrected in scoped commits:

| Commit | Finding closed | Focused evidence |
| --- | --- | --- |
| `7f47cee` | Optional-extra diagnostics exposed untrusted requirement values and reports exposed random/absolute paths. | Four regressions failed before the fix and passed after it; 33 adjacent distribution tests passed. |
| `7994725` | The guide algorithm parser treated unrelated uppercase identity constants as algorithms, and a first-iterable walrus bypassed fail-closed validation. | Two regressions failed before the fix; both and all 76 truth tests passed after it. |
| `53dcf98` | Host-ownership assertions aggregated the guides and could let one guide mask omissions in the other. | The per-guide assertion failed on missing networking language, then passed for each guide; all 76 truth tests passed. |
| `dcd046b` | Candidate JSON still exposed a random temporary import path. | The new stable-provenance regression failed with a missing helper, then passed; 34 adjacent distribution tests passed. |
| `2bac76f` | Runtime bounds were correct, but provider-response/PEM/CRC evidence did not explicitly include every required limit−1/limit/limit+1 triplet. | Four explicit boundary tests passed; the final focused matrix passed 1,010 tests. |
| `d88d942` | The source distribution omitted both maintained KMS integration guides despite the approved public-documentation requirement. | `test_sdist_contains_both_maintained_kms_integration_guides` failed before the manifest fix, then passed; 35 adjacent distribution tests passed. |
| `952e4cb` | The design required barrier-controlled signer concurrency evidence for both adapters, but AWS had only sequential signer conformance. | The exact-test discovery check returned no match (exit 1) before the addition; `test_aws_signer_isolates_concurrent_payload_state` then passed and 267 adjacent tests passed. |
| `b25d4f7` | AWS verifier evidence exercised the 6,144-byte limit and 6,145-byte rejection but not an explicit 6,143-byte accepted request. | `test_aws_verifier_accepts_limit_minus_one_and_limit` plus the +1 rejection and sign-response triplet produced 10 passing focused cases. |

No contradiction required a design amendment. No unresolved critical or
high-severity implementation finding remains. The PR-reference and
post-merge issue-state row is explicitly pending direct finalizer evidence:
Task 9 was required not to push, create a PR, or mutate issue state.

## Evidence command index

Rows below cite these exact commands and their observed final results.

| ID | Command | Observed result |
| --- | --- | --- |
| `F` | `../../.venv/bin/python -m pytest tests/test_kms_common.py tests/test_aws_kms.py tests/test_google_cloud_kms.py tests/test_external_signing.py tests/test_external_signing_conformance.py tests/test_public_api.py tests/test_v090_distribution_contract.py tests/test_v090_publish_workflow.py tests/test_kms_distribution_smoke.py -v` | `1010 passed in 17.14s`; no skips. |
| `R` | `../../.venv/bin/python -m pytest --cov=aegis --cov-report=term-missing --cov-fail-under=90` | `3095 passed, 1 skipped, 14 warnings in 106.61s`; 7,142 statements, 618 missed, 91.35%. |
| `L` | `../../.venv/bin/python -m flake8 aegis` | Exit 0, no findings. |
| `D1` | `../../.venv/bin/python scripts/check_doc_parity.py` | All sections 0A through O passed. |
| `D2` | `../../.venv/bin/python scripts/check_public_docs_no_internal_imports.py` | `PASS: no public aegis._internal imports found`. |
| `D3` | `../../.venv/bin/python scripts/validate_v090_release_freeze.py` | Brand/version parity and public-doc import checks passed. |
| `UI1` | `npm --prefix demo-app-react test` | 30 files and 298 tests passed in 17.96s. |
| `UI2` | `npm --prefix demo-app-react run build` | TypeScript and Vite 8.0.10 build passed; 1,782 modules transformed. |
| `B` | `../../.venv/bin/python -m build --outdir /private/tmp/aegis-task9-final-matrix2.oNDqGk` | One wheel and one sdist built successfully in a fresh directory; direct tar inspection found both maintained KMS guides. |
| `C` | `../../.venv/bin/python scripts/validate_v090_distribution_candidate.py --dist-dir /private/tmp/aegis-task9-final-matrix2.oNDqGk --no-build` | Artifact inspection passed in 0.024s and the fresh-wheel end-to-end workflow passed in 10.996s; import provenance was `isolated-virtualenv`. |
| `P` | `../../.venv/bin/python scripts/validate_kms_optional_extras.py --artifact <final-artifact> --lane <lane> --expected-versions <json>` using the seven `.github/workflows/publish.yml` matrix rows | Seven of seven isolated lanes passed with no provider check skipped. |

The one full-suite skip is
`tests/test_pr11_session_replay_concurrency.py::test_concurrent_phase_b_completion_attempt_is_fail_closed`
(marker at line 100, test at line 101): concurrent Phase-B calls are an
explicit v0.9.0 beta non-goal.
It is unrelated to KMS. All KMS provider, conformance, real-SDK, and artifact
lane cases ran.

The 14 warnings are established repository warnings: missing
`pre_conditions.required` warnings in legacy/migration fixtures, one governed
legacy opt-out deprecation, and bare-string precondition deprecations. None
originates in the KMS adapters.

## Contradiction, ambiguity, and dependency review

### Trusted provider surface

Current official product references were checked for AWS `DescribeKey`,
`Sign`, and `Verify`, and Google `getCryptoKeyVersion`, `asymmetricSign`,
`getPublicKey`, algorithms, states, and data-integrity behavior. Context7 was
used for the official Boto3 and Google Cloud Python repositories. Its Google
search result described the legacy `PublicKey.pem` path, so it was not used as
acceptance evidence; the official explicit-format product reference and the
installed SDK descriptors were authoritative.

The review environment contained:

| Distribution | Installed review version |
| --- | --- |
| `aegis-ai-governance` | `0.9.0b1` |
| `boto3` / `botocore` | `1.43.59` / `1.43.59` |
| `google-cloud-kms` | `3.16.0` |
| `google-api-core` | `2.33.0` |
| `google-crc32c` | `1.8.0` |
| `cryptography` | `49.0.0` |
| `build` / `pytest` / `pytest-cov` / `flake8` | `1.5.0` / `9.1.1` / `7.1.0` / `7.3.0` |
| Node / npm | `v26.3.0` / `11.17.0` |

Installed SDK descriptor inspection established:

| Operation/type | Installed request/response fields used by the adapter | Conclusion |
| --- | --- | --- |
| AWS `DescribeKey` | Input `KeyId`; output `KeyMetadata`, including ARN, usage, state, enabled flag, key spec, and signing algorithms. | `AwsKmsArtifactSigner.signer_identity`, `sign`, and `_normalize_key_description` use only documented fields. |
| AWS `Sign` | Input `KeyId`, `Message`, `MessageType`, `SigningAlgorithm`; output `KeyId`, `Signature`, `SigningAlgorithm`. | Exact request and echo validation match `AwsKmsArtifactSigner.sign` and `_normalize_sign_response`; the 6,144-byte AWS response cap is enforced. |
| AWS `Verify` | The `Sign` inputs plus `Signature`; output `KeyId`, `SignatureValid`, `SigningAlgorithm`; documented `KMSInvalidSignatureException`. | `AwsKmsArtifactVerifier.verify` and `_classify_verify_error` distinguish mismatch, availability, and unexpected failures. |
| Google `CryptoKeyVersion` | `name`, `state`, `algorithm`, `protection_level`, and other metadata; no version-level `purpose`. | `_normalize_crypto_key_version` correctly avoids a nonexistent `purpose` field and no unnecessary `get_crypto_key` call occurs. |
| Google `AsymmetricSignRequest` / response | Request `name`, `digest`, `digest_crc32c`; response `name`, `signature`, `signature_crc32c`, `verified_digest_crc32c`. | `GoogleCloudKmsArtifactSigner.sign` and `_normalize_asymmetric_sign_response` validate every relied-on field. |
| Google `GetPublicKeyRequest` / `PublicKey` | Request `name`, `public_key_format`; response `name`, `algorithm`, `public_key_format`, checksummed `public_key`, plus legacy `pem` fields. `ChecksummedData` has `data` and `crc32c_checksum`. | `_fetch_public_key` explicitly requests PEM and accepts only `public_key.data` plus `public_key.crc32c_checksum`; legacy-only responses fail closed. |

### Resolutions and ambiguity rulings

| Question | Resolution and evidence |
| --- | --- |
| Does AWS expose the backing-material generation used by asymmetric `Sign`/`Verify`? | No. The implementation and both maintained documents claim only the stable logical-key ARN. `test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets` and `D1` passed. |
| Can any syntactically plausible `aws-*` partition be accepted? | No. `_AWS_KMS_PARTITIONS` is exactly `aws`, `aws-cn`, `aws-us-gov`, `aws-iso`, `aws-iso-b`, `aws-iso-e`, `aws-iso-f`, and `aws-eusc`; eight positive provider paths and invented-partition negatives passed in `F`. |
| Is a Google version's parent key purpose available on `CryptoKeyVersion`? | No. Closed signing algorithms and provider enforcement are used; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature` confirms no parent-key call. |
| Which Google public-key response field is authoritative after explicitly requesting PEM? | The checksummed `public_key` message. `test_google_verifier_fetches_checksummed_public_key_and_verifies`, `test_controlled_google_public_key_response_uses_exact_sdk_shapes`, and the real-SDK lane passed. |
| Does explicit `None` mean provider default for Google retry/timeout? | No. Omission suppresses the keyword; explicit `None` forwards it. `test_google_signer_omits_default_retry_and_timeout_from_every_sdk_call`, `test_google_signer_forwards_explicit_none_retry_and_timeout`, and verifier forwarding tests passed. |
| Can a lazy first load prove integrity after arbitrary same-source canonical-module replacement? | No under the approved no-preloaded-anchor architecture. The adapters reject provider-controlled exception lookalikes in an intact interpreter. Arbitrary in-process replacement before the first lazy load is an interpreter-integrity non-goal, now stated in ADR-0013. |

Required future pull-request carry-forward note:

> This is strictly fail-closed and rejects invented aws-* partitions, but a newly introduced AWS partition would require an adapter update.

No AEGIS Technical Manual file was created or edited by issue #45.

## Targeted structural searches

The four required searches were run exactly as specified in Task 9.

| Search | Observed finding |
| --- | --- |
| Optional imports and dependency names | `pyproject.toml` contains only the declared provider extras. Provider imports occur inside `_load_google_dependencies`, `_load_cryptography_dependencies`, `_botocore_client_error_code`, and `_is_botocore_transport_error`; no eager provider import was found. |
| Broad exception/error/logging paths | Broad catches are intentional adapter boundaries. They end in fixed-message, empty-details, `from None` contract errors or closed outcomes. No adapter `print` or AEGIS provider logging path was found. Redaction/no-chaining tests passed. |
| Alias/primary/resource/purpose paths | AWS uses the selector only for two `DescribeKey` calls and then signs/verifies with a copied concrete ARN. Google parses only terminal concrete versions, never primary lookup, and never reads version-level `purpose`. |
| TODO/pass/NotImplemented markers | No unfinished production/provider/documentation implementation marker was found. Production `pass` is only the deliberate safe failure while probing `client.exceptions`; test `pass` hits are marker/helper exception classes. |

## Manual authority and request trace

| Flow | Artifact-controlled input and resolver boundary | Provider/crypto request | Response validation | Focused evidence |
| --- | --- | --- | --- | --- |
| AWS identity | Host constructor owns `key_id`; artifact is not involved. | `DescribeKey(KeyId=configured selector)`. | Exact dicts/built-ins; concrete allowlisted ARN; `SIGN_VERIFY`; exact enabled state; allowed key spec and complete documented algorithm list. | `test_aws_signer_identity_and_signing_bind_exact_selector_arn_and_payload`; `F` passed. |
| AWS sign | Prepared `SignerIdentity` is copied and must match selector, algorithm, and ARN; second `DescribeKey` must return the same ARN. | `Sign(KeyId=identity.key_version, Message=sha256(payload), MessageType="DIGEST", SigningAlgorithm=identity.algorithm)`. | Exact returned ARN and algorithm; exact nonempty bytes; at most 6,144 bytes; canonical base64 receipt. | `test_aws_signer_identity_and_signing_bind_exact_selector_arn_and_payload`; `test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign`; `test_aws_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `F` passed. |
| AWS verify | Validated metadata supplies the exact pair only to the host resolver. Exact target reconstruction and ARN equality precede provider use. | `Verify(KeyId=target.key_arn, Message=sha256(payload), MessageType="DIGEST", Signature=decoded, SigningAlgorithm=metadata.algorithm)`. | Exact response dict, ARN, algorithm, and boolean; false or exact invalid-signature class maps to invalid; known exact availability types/codes map unavailable. | `test_aws_verifier_uses_exact_pair_once_and_exact_digest_request`; `test_aws_verifier_maps_only_documented_provider_failures`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `F` passed. |
| Google identity | Host constructor supplies one parsed exact CryptoKeyVersion; no primary version or artifact lookup. | `GetCryptoKeyVersionRequest(name=exact version)`. | Exact SDK version shape, exact name, canonical `ENABLED` singleton, closed algorithm enum mapping. | `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_signer_uses_real_sdk_request_types_when_extra_is_installed`; `F` passed. |
| Google sign | Copied prepared identity reconstructs the configured version; second exact-version checkpoint precedes signing. | `AsymmetricSignRequest(name=exact version, digest.sha256=sha256(payload), digest_crc32c=crc32c(digest))`. | Exact name; `verified_digest_crc32c is True`; exact bounded signature bytes; exact non-bool uint32 CRC matching the signature. | `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_signer_rejects_checkpoint_or_response_failures_safely`; `F` passed. |
| Google verify, retained | Exact metadata pair goes only to the host resolver. Target fields and retained PEM are copied before use. | No provider call. SHA-256 once, RSA-PSS or P-256 ECDSA with `Prehashed(SHA256)`. | PEM size/type/curve/RSA-size validation and closed disposition result. | `test_google_verifier_uses_retained_public_key_without_google_sdk` passed for all four algorithms in `F`. |
| Google verify, fetched | Exact reconstructed target version is the sole request authority. | `GetPublicKeyRequest(name=target version, public_key_format=PEM)` with exact retry/timeout semantics. | Exact SDK types; name, algorithm, format; checksummed-data exact bytes; 65,536-byte cap; exact uint32 CRC; local key-shape and signature validation. | `test_google_verifier_fetches_checksummed_public_key_and_verifies`; `test_google_verifier_rejects_malformed_or_unexpected_public_keys`; `test_google_verifier_uses_actual_checksumming_response_types_when_installed`; `F` passed. |

Every artifact-controlled provider field terminates at one of three boundaries:
core `SignatureMetadata` validation, provider-specific metadata-shape
validation, or the exact-pair resolver. No artifact string becomes an AWS
`KeyId`, Google `name`, retained PEM, client, retry, timeout, endpoint, region,
project, credential, or trust disposition.

## Failure, bounds, mutation, and concurrency trace

| Area | Implementation symbol | Focused test | Command/result | Residual or non-goal |
| --- | --- | --- | --- | --- |
| Closed trust outcomes | `aegis/integrations/_kms_common.py::_outcome`; `aegis/integrations/aws_kms.py::_successful_verification_outcome`; `aegis/integrations/google_cloud_kms.py::_successful_verification_outcome` | `test_outcome_uses_only_the_provider_neutral_closed_matrix`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `test_google_verifier_runs_shared_verifier_conformance` | `F`: all passed | Host resolver remains responsible for disposition truth. |
| Resolver `None` / revoked | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` | `test_aws_verifier_maps_unknown_revoked_and_denied_without_provider_work`; `test_google_verifier_returns_revoked_before_pem_parsing_or_provider` | `F`: both passed, no provider work | Revocation is host policy, not inferred provider lifecycle state. |
| Availability vs invalid vs contract failure | `aegis/integrations/aws_kms.py::_classify_verify_error`; `aegis/integrations/google_cloud_kms.py::{_is_google_availability_error,_verify_local_signature}` | `test_aws_verifier_keeps_transport_service_and_crypto_errors_distinct`; `test_google_verifier_maps_closed_provider_availability_errors`; `test_google_verifier_maps_malformed_ecdsa_der_to_signature_invalid` | `F`: all passed | Provider outage remains an indeterminate result, never valid/anchored. |
| Redaction and chaining | `aegis/integrations/aws_kms.py::{AwsKmsArtifactSigner.sign,AwsKmsArtifactVerifier.verify}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner.sign,GoogleCloudKmsArtifactVerifier.verify}`; `aegis/_internal/external_signing.py::sign_artifact_with_metadata` | `test_aws_signing_failures_are_sanitized_and_artifact_atomic`; `test_google_signing_failures_are_redacted_and_artifact_atomic`; `test_external_signing_boundary_redacts_adversarial_provider_data_and_logs` | `F`: all passed | Host-enabled SDK wire/debug logging remains host-owned. |
| General signature cap | `aegis/integrations/_kms_common.py::_canonical_b64decode`, 12,288 bytes | `test_canonical_base64_decode_accepts_one_byte_below_the_raw_signature_limit`; `test_canonical_base64_decode_accepts_the_raw_signature_limit`; `test_canonical_base64_decode_rejects_a_decoded_value_past_the_limit` | `F`: all passed at 12,287/12,288/12,289 | Canonical RFC 4648 base64 only. |
| AWS signature cap | `aegis/integrations/aws_kms.py::{_normalize_sign_response,AwsKmsArtifactVerifier.verify}`, 6,144 bytes | `test_aws_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `test_aws_verifier_accepts_limit_minus_one_and_limit`; `test_aws_verifier_rejects_noncanonical_or_oversized_signature_before_resolver` | `F`: PASS at 6,143/6,144/6,145 for both provider response and verifier input | Provider cap is stricter than the core metadata cap. |
| Google signature cap | `aegis/integrations/google_cloud_kms.py::_normalize_asymmetric_sign_response`, 12,288 bytes | `test_google_sign_response_covers_limit_minus_one_limit_and_limit_plus_one` | `F`: PASS at 12,287/12,288/12,289 | Response CRC must also match. |
| PEM cap | `GoogleCloudKmsVerificationTarget.__post_init__`; `GoogleCloudKmsArtifactVerifier._fetch_public_key`, 65,536 bytes | `test_google_retained_pem_covers_limit_minus_one_limit_and_limit_plus_one`; `test_google_verifier_rejects_malformed_or_unexpected_public_keys` | `F`: both passed at 65,535/65,536/65,537 | Retained-key provenance and storage remain host-owned. |
| CRC32C range | `aegis/integrations/_kms_common.py::_normalize_crc32c` | `test_normalize_crc32c_covers_both_edges_and_the_upper_boundary_triplet`; `test_normalize_crc32c_rejects_out_of_range_or_non_exact_integer`; `test_normalize_crc32c_rejects_an_int_subclass` | `F`: all passed at −1/0/1 and `2**32−2`/`2**32−1`/`2**32` | CRC is transport integrity, not authenticity. |
| Resource bounds | `aegis/integrations/aws_kms.py::_is_concrete_key_arn`; `aegis/integrations/google_cloud_kms.py::_parse_crypto_key_version_name` | `test_aws_verification_target_is_frozen_and_honors_metadata_arn_bound`; `test_google_signer_accepts_exact_resource_and_metadata_length_limits`; `test_google_signer_rejects_noncanonical_or_unbounded_versions_before_calls` | `F`: all passed | Valid provider identifiers exceeding #44 metadata limits are intentionally rejected. |
| Timeout bounds and omission | `aegis/integrations/_kms_common.py::_normalize_timeout`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner._call_kwargs,GoogleCloudKmsArtifactVerifier._call_kwargs}` | `test_normalize_timeout_rejects_nonpositive_or_nonfinite_values`; `test_google_signer_omits_default_retry_and_timeout_from_every_sdk_call`; `test_google_signer_forwards_explicit_none_retry_and_timeout`; `test_google_verifier_forwards_explicit_retry_and_timeout` | `F`: all passed | Retry object semantics are delegated unchanged to the injected SDK client. |
| Atomic mutation | `aegis/_internal/external_signing.py::sign_artifact_with_metadata`; provider signer `sign` methods | `test_sign_artifact_with_metadata_binds_identity_receipt_and_payload_atomically`; `test_aws_signing_failures_are_sanitized_and_artifact_atomic`; `test_google_signing_failures_are_redacted_and_artifact_atomic` | `F`: all passed, byte-for-byte snapshots unchanged | SDK retry may create multiple remote signatures; only one returned receipt can commit. |
| Signer concurrency | Frozen/slotted provider signer classes and local `sign` variables | `test_aws_signer_isolates_concurrent_payload_state`; `test_google_signer_has_no_per_call_mutable_state_under_concurrency` | `F`: both barrier-controlled tests passed | Injected client thread safety is outside the adapter guarantee. |
| Verifier concurrency | `AwsKmsArtifactVerifier.verify`; `GoogleCloudKmsArtifactVerifier.verify` local copied metadata/target/request state | `test_aws_verifier_concurrent_calls_keep_request_snapshots_isolated`; `test_google_verifier_isolates_concurrent_resolver_and_fetched_key_state` | `F`: both barrier-controlled tests passed | Host must not concurrently mutate resolver/client behavior. |
| Lazy dependencies | `aegis/integrations/aws_kms.py::_botocore_client_error_code`; `aegis/integrations/google_cloud_kms.py::{_load_google_dependencies,_load_cryptography_dependencies}` | `test_aws_verifier_missing_botocore_keeps_concrete_classification_safe`; `test_google_signer_constructor_does_not_import_optional_dependencies`; `test_google_signer_missing_optional_dependencies_fails_only_at_use_time` | `F` and `P/base-wheel`: all passed | Interpreter-integrity boundary described above remains explicit. |

## Threat and failure mapping

Every design threat row has concrete implementation, focused-test, command,
observed-result, and residual evidence.

| Attack or failure | Implementation file/symbol | Focused test | Command and observed result | Residual or explicit non-goal |
| --- | --- | --- | --- | --- |
| Artifact supplies arbitrary key URI | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` | `test_aws_verifier_forged_metadata_cannot_redirect_approved_target`; `test_detailed_metadata_artifact_hints_cannot_select_another_resolver` | `F`: both passed within 1,010 | Resolver correctness remains host-owned. |
| AWS alias changes during signing | `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign` | `test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign` | `F`: passed; no `Sign` on retarget | Alias may rotate after checkpoint, but immutable ARN remains the request target. |
| AWS backing material rotates under one ARN | `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign`; `docs/decisions/ADR-0013-aws-google-kms-adapters.md` “AWS identity” | `test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets` | `F` and `D1`: passed | No backing-material-version claim. |
| AWS multi-Region replica substitution | `aegis/integrations/aws_kms.py::{_is_concrete_key_arn,AwsKmsArtifactSigner.sign}` | `test_aws_signer_rejects_multi_region_replica_arn_substitution_before_sign` | `F`: passed | Cross-ARN failover requires separate trust design. |
| Google primary version rotates | `aegis/integrations/google_cloud_kms.py::{_parse_crypto_key_version_name,GoogleCloudKmsArtifactSigner.sign}` | `test_google_signer_rejects_noncanonical_or_unbounded_versions_before_calls`; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature` | `F`: both passed | Hosts must rotate signer configuration explicitly. |
| Resolver returns hostile object | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` exact-class reconstruction | `test_aws_verifier_rejects_target_subclass_without_reading_hostile_properties`; `test_google_verifier_rejects_lookalike_or_subclass_targets`; `test_google_verifier_reads_each_resolved_field_once` | `F`: all passed | Arbitrary pre-load interpreter replacement is excluded. |
| Algorithm confusion | `aegis/integrations/aws_kms.py::_AWS_ALGORITHMS`; `aegis/integrations/google_cloud_kms.py::_GOOGLE_ALGORITHMS` | `test_aws_verifier_rejects_unsupported_algorithm_before_resolver_or_provider`; `test_google_verifier_checks_unsupported_algorithm_before_resolver`; `test_google_verifier_returns_algorithm_denied_for_target_mismatch` | `F`: all passed | Adding an algorithm requires reviewed code/docs/tests. |
| Oversized signature or public key | `aegis/integrations/_kms_common.py::_canonical_b64decode`; `aegis/integrations/aws_kms.py::_normalize_sign_response`; `aegis/integrations/google_cloud_kms.py::{_normalize_asymmetric_sign_response,_load_validated_public_key}` | `test_aws_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `test_google_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `test_google_retained_pem_covers_limit_minus_one_limit_and_limit_plus_one` | `F`: all passed | Provider-valid identifiers/keys beyond #44 caps remain rejected. |
| Boolean accepted as CRC integer | `aegis/integrations/_kms_common.py::_normalize_crc32c` | `test_normalize_crc32c_rejects_out_of_range_or_non_exact_integer`; `test_normalize_crc32c_rejects_an_int_subclass` | `F`: both passed | None. |
| Digest/signature corrupted in transit | `aegis/integrations/google_cloud_kms.py::{_crc32c,_normalize_asymmetric_sign_response}` | `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_signer_rejects_checkpoint_or_response_failures_safely` | `F`: both passed | CRC is not a replacement for signature verification. |
| Provider lies about identity | Inline echo/type checks in `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::{_normalize_asymmetric_sign_response,GoogleCloudKmsArtifactVerifier._fetch_public_key}` | `test_aws_verifier_rejects_malformed_or_unexpected_provider_behavior`; `test_google_signer_rejects_checkpoint_or_response_failures_safely`; `test_google_verifier_rejects_malformed_or_unexpected_public_keys` | `F`: all passed | A fully compromised provider is outside local response-shape validation. |
| Provider/resolver exception exposes secrets | Both methods of `AwsKmsArtifactSigner`/`AwsKmsArtifactVerifier` and `GoogleCloudKmsArtifactSigner`/`GoogleCloudKmsArtifactVerifier`; `aegis/_internal/external_signing.py::sign_artifact_with_metadata` | `test_aws_signing_failures_are_sanitized_and_artifact_atomic`; `test_google_signing_failures_are_redacted_and_artifact_atomic`; `test_external_signing_boundary_redacts_adversarial_provider_data_and_logs` | `F`: all passed | Host SDK logging configuration remains host-owned. |
| Concurrent calls overwrite identity | `aegis/integrations/aws_kms.py::{AwsKmsArtifactSigner.sign,AwsKmsArtifactVerifier.verify}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner.sign,GoogleCloudKmsArtifactVerifier.verify}` | `test_aws_signer_isolates_concurrent_payload_state`; `test_aws_verifier_concurrent_calls_keep_request_snapshots_isolated`; `test_google_signer_has_no_per_call_mutable_state_under_concurrency`; `test_google_verifier_isolates_concurrent_resolver_and_fetched_key_state` | `F`: all four barrier-controlled tests passed | Injected-object concurrency is not asserted. |
| Randomized signature violates fixture assumption | `tests/signing_conformance.py::assert_external_signer_conformance` | `test_randomized_external_signer_conforms_without_signature_equality`; `test_aws_signer_runs_shared_external_signing_conformance`; `test_google_signer_runs_shared_randomized_signing_conformance` | `F`: all passed | Signature byte equality/difference is deliberately not asserted. |
| Old provider key inaccessible | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` retained-PEM branch | `test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets`; `test_aws_verifier_maps_only_documented_provider_failures`; `test_google_verifier_uses_retained_public_key_without_google_sdk` | `F`: all passed | Hosts must retain AWS access or Google PEM evidence. |
| Disabled provider key treated as revoked | `aegis/integrations/kms.py::KmsKeyDisposition`; `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` | `test_aws_verifier_maps_unknown_revoked_and_denied_without_provider_work`; `test_google_verifier_returns_revoked_before_pem_parsing_or_provider`; `test_google_verifier_maps_closed_provider_availability_errors` | `F`: all passed | Lifecycle-to-revocation policy is host-owned. |
| Forged `signed_at` used for pre-compromise trust | `aegis/_internal/external_signing.py::_metadata_signing_payload`; “Logging and assurance limits” in `docs/reference/external/AWS_KMS_SIGNING.md` and `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` | `test_metadata_aware_signature_payload_detects_signed_artifact_tampering`; `test_kms_docs_make_only_bounded_operational_and_compliance_claims` | `F` and `D1`: both passed | Trusted time and time-aware revocation are out of scope. |
| Optional SDK absent | `aegis/integrations/aws_kms.py::_botocore_client_error_code`; `aegis/integrations/google_cloud_kms.py::{_load_google_dependencies,_load_cryptography_dependencies}` | `test_aws_verifier_missing_botocore_keeps_concrete_classification_safe`; `test_google_signer_constructor_does_not_import_optional_dependencies`; `test_google_signer_missing_optional_dependencies_fails_only_at_use_time` | `F`: all passed; `P/base-wheel`: PASS with no provider distributions | Use-time operation fails closed with sanitized error. |
| Extra silently alters base installation | `pyproject.toml [project.optional-dependencies]`; `scripts/validate_kms_optional_extras.py::_validate_provider_family_isolation` | `test_distribution_rename_does_not_change_runtime_dependencies`; `test_lane_isolation_rejects_opposite_provider_transitive_stacks` | `F`: both passed; all seven `P` lanes passed | Transitive resolver versions will evolve within declared lower bounds. |
| SDK retries create multiple remote signatures | `aegis/_internal/external_signing.py::sign_artifact_with_metadata`; `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactSigner.sign` | `test_sign_artifact_with_metadata_binds_identity_receipt_and_payload_atomically`; `test_aws_signing_failures_are_sanitized_and_artifact_atomic`; `test_google_signing_failures_are_redacted_and_artifact_atomic`; `test_kms_docs_make_only_bounded_operational_and_compliance_claims` | `F`, `D1`: all passed | Remote duplicate signing is documented and host client retry policy is authoritative. |

## Locked requirement traceability

| Locked requirement | Implementation file/symbol | Focused test | Command and observed result | Residual or explicit non-goal |
| --- | --- | --- | --- | --- |
| Two tested providers | `aegis/integrations/aws_kms.py::{AwsKmsArtifactSigner,AwsKmsArtifactVerifier,AwsKmsVerificationTarget}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner,GoogleCloudKmsArtifactVerifier,GoogleCloudKmsVerificationTarget}` | `test_aws_signer_runs_shared_external_signing_conformance`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `test_google_signer_runs_shared_randomized_signing_conformance`; `test_google_verifier_runs_shared_verifier_conformance` | `F`: all 1,010 passed | No generic, Azure, Vault, or PKCS#11 provider. |
| Optional extras | `pyproject.toml [project.optional-dependencies].aws-kms/.gcp-kms`; `aegis/integrations/aws_kms.py::_botocore_client_error_code`; `aegis/integrations/google_cloud_kms.py::{_load_google_dependencies,_load_cryptography_dependencies}` | `test_kms_optional_extras_have_exact_unbounded_lower_bounds`; `test_google_signer_constructor_does_not_import_optional_dependencies`; `test_google_signer_missing_optional_dependencies_fails_only_at_use_time` | `F`: all passed; seven `P` lanes passed | Provider SDKs are required only when used. |
| One release path | `pyproject.toml [project].version`; `.github/workflows/publish.yml` jobs `build`, `validate-optional-extras`, and `publish` | `test_candidate_version_is_consistent_in_metadata_and_runtime`; `test_publish_workflow_separates_unprivileged_build_from_oidc_publish`; `test_every_optional_lane_downloads_the_build_once_and_never_rebuilds` | `F`: all passed; `C`: PASS | Actual publish is outside this task. |
| No base dependency change | `pyproject.toml [project].dependencies` | `test_distribution_rename_does_not_change_runtime_dependencies`; `test_lane_isolation_rejects_opposite_provider_transitive_stacks` | `F` and `P/base-wheel`: passed | Transitive base versions are resolver-selected. |
| Stable signing identity | `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactSigner.sign` | `test_aws_signer_identity_and_signing_bind_exact_selector_arn_and_payload`; `test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign`; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature` | `F`: all passed | AWS identity is logical key, not material generation. |
| Artifact cannot choose provider resource | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` | `test_aws_verifier_forged_metadata_cannot_redirect_approved_target`; `test_google_verifier_rejects_target_identity_mismatch`; `test_detailed_metadata_artifact_hints_cannot_select_another_resolver` | `F`: all passed | Resolver authorization is host-owned. |
| Closed algorithms | `aegis/integrations/aws_kms.py::_AWS_ALGORITHMS`; `aegis/integrations/google_cloud_kms.py::{_GOOGLE_ALGORITHMS,_load_validated_public_key}` | `test_aws_verifier_rejects_unsupported_algorithm_before_resolver_or_provider`; `test_google_verifier_checks_unsupported_algorithm_before_resolver`; `test_google_target_accepts_exact_algorithm_correct_public_pem` | `F`: all passed | Six algorithms only. |
| Integrity and size bounds | `aegis/integrations/_kms_common.py::{_canonical_b64decode,_normalize_crc32c,_normalize_timeout}`; `aegis/integrations/aws_kms.py::_normalize_sign_response`; `aegis/integrations/google_cloud_kms.py::{_normalize_asymmetric_sign_response,_load_validated_public_key}` | `test_aws_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `test_google_sign_response_covers_limit_minus_one_limit_and_limit_plus_one`; `test_google_retained_pem_covers_limit_minus_one_limit_and_limit_plus_one`; `test_normalize_crc32c_covers_both_edges_and_the_upper_boundary_triplet` | `F`: all passed | CRC provides transport corruption detection only. |
| Structured trust results | `aegis/integrations/kms.py::KmsKeyDisposition`; `aegis/integrations/_kms_common.py::{_OUTCOME_FIELDS,_outcome}` | `test_kms_dispositions_are_the_frozen_host_trust_policy_values`; `test_outcome_uses_only_the_provider_neutral_closed_matrix`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `test_google_verifier_runs_shared_verifier_conformance` | `F`: all passed | No time-aware trust result. |
| Safe failures | `aegis/integrations/aws_kms.py::{_classify_verify_error,AwsKmsArtifactSigner.sign,AwsKmsArtifactVerifier.verify}`; `aegis/integrations/google_cloud_kms.py::{_is_google_availability_error,GoogleCloudKmsArtifactSigner.sign,GoogleCloudKmsArtifactVerifier.verify}`; `aegis/_internal/external_signing.py::sign_artifact_with_metadata` | `test_aws_verifier_classifies_only_exact_client_exception_types`; `test_google_verifier_sanitizes_unprovenanced_spoof_without_chaining`; `test_external_signing_boundary_redacts_adversarial_provider_data_and_logs` | `F`: all passed | Host SDK diagnostics remain outside AEGIS control. |
| Historical verification | `aegis/integrations/aws_kms.py::AwsKmsArtifactVerifier.verify`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactVerifier.verify` retained-PEM branch | `test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets`; `test_google_verifier_uses_retained_public_key_without_google_sdk`; `test_google_verifier_reports_unavailable_when_no_retained_key_or_client` | `F`: all passed | Evidence retention and provider access are host responsibilities. |
| Concurrency safety | `aegis/integrations/aws_kms.py::{AwsKmsArtifactSigner.sign,AwsKmsArtifactVerifier.verify}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner.sign,GoogleCloudKmsArtifactVerifier.verify}` | `test_aws_signer_isolates_concurrent_payload_state`; `test_aws_verifier_concurrent_calls_keep_request_snapshots_isolated`; `test_google_signer_has_no_per_call_mutable_state_under_concurrency`; `test_google_verifier_isolates_concurrent_resolver_and_fetched_key_state` | `F`: all four barrier-controlled tests passed | Injected clients/resolvers must satisfy their own thread-safety contracts. |
| Correct randomized-signature conformance | `tests/signing_conformance.py::{SignerFixture,assert_external_signer_conformance}` | `test_randomized_external_signer_conforms_without_signature_equality`; `test_aws_signer_runs_shared_external_signing_conformance`; `test_google_signer_runs_shared_randomized_signing_conformance` | `F`: all passed | No deterministic-signature protocol claim. |
| Accurate operational claims | `docs/decisions/ADR-0013-aws-google-kms-adapters.md`; `docs/reference/external/AWS_KMS_SIGNING.md`; `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` | `test_kms_guides_preserve_provider_identity_and_verification_boundaries`; `test_kms_docs_make_only_bounded_operational_and_compliance_claims` | `D1`, `D2`, `D3`: passed | Host controls and #46 remain required. |

## Acceptance criteria

| Acceptance row | Implementation file/symbol | Focused test | Command and observed result | Residual or explicit non-goal |
| --- | --- | --- | --- | --- |
| AWS and Google signer/verifier adapters implement #44 contracts. | `aegis/integrations/aws_kms.py::{AwsKmsArtifactSigner,AwsKmsArtifactVerifier,AwsKmsVerificationTarget}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactSigner,GoogleCloudKmsArtifactVerifier,GoogleCloudKmsVerificationTarget}`; `aegis/_internal/external_signing.py::{ExternalArtifactSigner,ExternalArtifactVerifier}` | `test_aws_signer_runs_shared_external_signing_conformance`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `test_google_signer_runs_shared_randomized_signing_conformance`; `test_google_verifier_runs_shared_verifier_conformance` | `F`: all passed without skips | Synchronous APIs only. |
| Every supported algorithm has real cryptographic fixture coverage. | `aegis/integrations/aws_kms.py::_AWS_ALGORITHMS`; `aegis/integrations/google_cloud_kms.py::{_GOOGLE_ALGORITHMS,_verify_local_signature}` | `test_aws_signer_identity_and_signing_bind_exact_selector_arn_and_payload`; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_verifier_uses_retained_public_key_without_google_sdk`; `test_google_verifier_fetches_checksummed_public_key_and_verifies` | `F`: all six passed with real local RSA/ECDSA cryptography | No SHA-384/512, PKCS#1 v1.5, MAC, or secp256k1 Google support. |
| No unsupported algorithm reaches provider work. | `aegis/integrations/aws_kms.py::{AwsKmsArtifactVerifier.verify,AwsKmsVerificationTarget}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactVerifier.verify,GoogleCloudKmsVerificationTarget}` | `test_aws_verifier_rejects_unsupported_algorithm_before_resolver_or_provider`; `test_google_verifier_checks_unsupported_algorithm_before_resolver` | `F`: both passed with empty resolver/provider call logs | New algorithms require review. |
| Signing binds a stable provider resource and is atomic; docs distinguish identities. | `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign`; `aegis/integrations/google_cloud_kms.py::GoogleCloudKmsArtifactSigner.sign`; `aegis/_internal/external_signing.py::sign_artifact_with_metadata`; “AWS identity”/“Google identity” in `docs/decisions/ADR-0013-aws-google-kms-adapters.md`; “Supported algorithms and identity” in `docs/reference/external/AWS_KMS_SIGNING.md` and `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` | `test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign`; `test_aws_signing_failures_are_sanitized_and_artifact_atomic`; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_signing_failures_are_redacted_and_artifact_atomic`; `test_kms_guides_preserve_provider_identity_and_verification_boundaries` | `F` and `D1`: all passed | AWS does not pin backing material. |
| Verification uses only host-approved exact target and cannot be metadata-redirected. | `aegis/integrations/aws_kms.py::{AwsKmsArtifactVerifier.verify,AwsKmsVerificationTarget}`; `aegis/integrations/google_cloud_kms.py::{GoogleCloudKmsArtifactVerifier.verify,GoogleCloudKmsVerificationTarget}` | `test_aws_verifier_uses_exact_pair_once_and_exact_digest_request`; `test_aws_verifier_forged_metadata_cannot_redirect_approved_target`; `test_google_verifier_rejects_target_identity_mismatch`; `test_detailed_metadata_artifact_hints_cannot_select_another_resolver` | `F`: all passed | Host resolver is the trust authority. |
| AWS alias rotation and Google version pinning behave as specified. | `aegis/integrations/aws_kms.py::AwsKmsArtifactSigner.sign`; `aegis/integrations/google_cloud_kms.py::{_parse_crypto_key_version_name,GoogleCloudKmsArtifactSigner.sign}` | `test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign`; `test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets`; `test_google_signer_rejects_noncanonical_or_unbounded_versions_before_calls`; `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature` | `F`: all passed | Host updates signer configuration for Google rotation. |
| Google CRC request/response and public-key validation are complete. | `aegis/integrations/google_cloud_kms.py::{_crc32c,_normalize_asymmetric_sign_response,_load_validated_public_key,GoogleCloudKmsArtifactVerifier._fetch_public_key}` | `test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature`; `test_google_verifier_fetches_checksummed_public_key_and_verifies`; `test_controlled_google_public_key_response_uses_exact_sdk_shapes`; `test_google_verifier_rejects_malformed_or_unexpected_public_keys` | `F`: all passed; real SDK classes exercised | CRC is not authenticity. |
| Revoked, unknown, unavailable, invalid, unanchored, invalid-anchor, and anchored map to #44. | `aegis/integrations/_kms_common.py::{_OUTCOME_FIELDS,_outcome}`; `aegis/integrations/aws_kms.py::_successful_verification_outcome`; `aegis/integrations/google_cloud_kms.py::_successful_verification_outcome` | `test_outcome_uses_only_the_provider_neutral_closed_matrix`; `test_aws_verifier_runs_shared_external_verifier_conformance`; `test_google_verifier_runs_shared_verifier_conformance` | `F`: all passed | Only host marks revoked. |
| Randomized-signature conformance defect is fixed and regression-tested. | `tests/signing_conformance.py::assert_external_signer_conformance` | `test_randomized_external_signer_conforms_without_signature_equality`; `test_aws_signer_runs_shared_external_signing_conformance`; `test_google_signer_runs_shared_randomized_signing_conformance` | `F`: all passed | Fixture-specific deterministic behavior may still be asserted locally. |
| Provider modules import without extras; missing use fails safely. | `aegis/integrations/aws_kms.py::{_botocore_client_error_code,__all__}`; `aegis/integrations/google_cloud_kms.py::{_load_google_dependencies,_load_cryptography_dependencies,__all__}`; empty provider-neutral namespace in `aegis/integrations/__init__.py` | `test_aws_verifier_missing_botocore_keeps_concrete_classification_safe`; `test_google_signer_constructor_does_not_import_optional_dependencies`; `test_google_signer_missing_optional_dependencies_fails_only_at_use_time`; `test_kms_integration_contract_stays_out_of_existing_public_namespaces` | `F` and `P/base-wheel`: all passed | Arbitrary pre-load interpreter replacement is excluded. |
| Base dependency list is byte-for-byte unchanged. | `pyproject.toml [project].dependencies` | `test_distribution_rename_does_not_change_runtime_dependencies` | `F`: passed; base lane contained no provider family | None. |
| Base, AWS-only, Google-only, and combined lanes pass. | `scripts/validate_kms_optional_extras.py::{main,_validate_artifact}`; `.github/workflows/publish.yml` job `validate-optional-extras` strategy matrix | `test_optional_extra_matrix_proves_exact_single_artifact_release_lanes`; `test_release_gates_publish_the_exact_optional_extra_artifact_lanes`; `test_lane_isolation_rejects_opposite_provider_transitive_stacks` | `P`: seven of seven passed | Resolver-selected current versions can change over time. |
| Wheel and sdist contents/metadata pass inspection. | `pyproject.toml`; `MANIFEST.in`; `scripts/validate_v090_distribution_candidate.py::main`; `scripts/validate_kms_optional_extras.py::main` | `test_wheel_contains_every_kms_integration_module`; `test_sdist_contains_both_maintained_kms_integration_guides`; `test_wheel_metadata_exposes_one_distribution_with_conditional_kms_extras` | `B`, `C`, and combined wheel/sdist `P`: PASS; fresh tar inspection found both maintained guides | Setuptools license metadata deprecation is tracked below. |
| Full test/lint/coverage/docs/public-API/frontend matrix passes cleanly provisioned. | `scripts/check_doc_parity.py::main`; `scripts/check_public_docs_no_internal_imports.py::main`; `scripts/validate_v090_release_freeze.py::main`; `demo-app-react/package.json` scripts `test` and `build` | `test_release_gates_publish_the_exact_optional_extra_artifact_lanes`; `test_v090_release_truth_accepts_exact_row_mapping_and_coupled_freeze`; `test_kms_integration_contract_stays_out_of_existing_public_namespaces` | `R`, `L`, `D1`–`D3`, `UI1`, `UI2`: all passed | One documented non-KMS beta skip remains. |
| AWS/Google guides and provider ADR accurately bound security claims. | `docs/decisions/ADR-0013-aws-google-kms-adapters.md`; `docs/reference/external/AWS_KMS_SIGNING.md`; `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` | `test_kms_guides_publish_exact_extras_algorithms_and_compilable_examples`; `test_kms_guides_preserve_provider_identity_and_verification_boundaries`; `test_kms_docs_make_only_bounded_operational_and_compliance_claims` | `D1`–`D3`: all passed | No Technical Manual edit was made; future note retained above. |
| Pull request references #45/#39; issues update only after merge. | External finalizer action governed by `docs/superpowers/specs/2026-07-29-issue-45-aws-google-kms-adapters-design.md` “Optional Dependencies and Release Path”; no runtime symbol can perform it | No repository test can prove a future PR body or post-merge issue mutation; direct finalizer inspection is required | Task 9 observed no push, PR, or issue mutation, as explicitly required by its handoff scope; criterion remains pending | Finalizer must include both issue references and defer issue-state changes until merge; this external action is not part of the Task 9 implementation verdict. |

## Built artifacts and installed-artifact evidence

Fresh directory: `/private/tmp/aegis-task9-final-matrix2.oNDqGk`

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `aegis_ai_governance-0.9.0b1-py3-none-any.whl` | 189,843 bytes | `05bbe1bc3988a1ae29acb80ba06c2db134e80c89ebc2fef3c32d2c9e1ed1c712` |
| `aegis_ai_governance-0.9.0b1.tar.gz` | 3,606,308 bytes | `c2a4bbaab5a2d0fda3623a4f26d3f5557c298c1b19ac0f8ebc65b54c8d6184b7` |

Candidate validation installed the wheel into a fresh virtual environment,
removed provider credential variables, ran `pip check`, exercised the CLI
help, all three workflow profiles, doctor/fix, trace, and
audit/operator/compliance-lineage exports. It reported only stable artifact
filenames/hashes and `import_location: isolated-virtualenv`.

Direct `tar -tzf` inspection also found these exact final-sdist members:
`aegis_ai_governance-0.9.0b1/docs/reference/external/AWS_KMS_SIGNING.md`
and
`aegis_ai_governance-0.9.0b1/docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md`.

| Lane | Artifact | Exact pins requested | Provider versions observed | Result |
| --- | --- | --- | --- | --- |
| `base-wheel` | wheel | `{}` | No AWS or Google provider distribution installed; `PyYAML 6.0.3`, `jsonschema 4.26.0` | PASS |
| `aws-min-wheel` | wheel | `boto3==1.43.0` | `boto3 1.43.0`, `botocore 1.43.59`, `s3transfer 0.17.1` | PASS |
| `aws-current-wheel` | wheel | current resolver | `boto3 1.43.59`, `botocore 1.43.59`, `s3transfer 0.19.2` | PASS |
| `gcp-min-wheel` | wheel | `google-cloud-kms==3.15.0`, `google-crc32c==1.7.1`, `cryptography==45.0.1` | Exact requested floors; `google-api-core 2.33.0` | PASS |
| `gcp-current-wheel` | wheel | current resolver | `google-cloud-kms 3.16.0`, `google-crc32c 1.8.0`, `cryptography 49.0.0`, `google-api-core 2.33.0` | PASS |
| `combined-current-wheel` | wheel | current resolver | AWS current plus Google current versions above | PASS |
| `combined-current-sdist` | sdist | current resolver | AWS current plus Google current versions above | PASS |

Every provider lane exercised an identity/sign/verify cycle with real
transport/SDK classes. Google lanes also performed retained-PEM verification;
AWS lanes verified the exact botocore connect/read/endpoint transport classes.
No installed-extra check skipped.

## Residual risks and non-goals

- Host-created clients, credentials, networking, endpoint selection,
  region/project configuration, retries, timeouts, IAM, trust policy, trust
  stores, retained evidence, provider logging, rotation, revocation,
  compromise response, and outage policy remain host-owned.
- The exact-pair resolver is an explicit trust boundary. The adapters prevent
  artifact-directed lookup but cannot make a wrong host policy correct.
- Provider availability and historical key/public-key retention remain
  operational dependencies. Google retained PEM removes the live-client
  dependency only when the host has retained trustworthy version evidence.
- AWS identity is the immutable logical-key ARN exposed by KMS, not a
  backing-material generation. A future accepted partition or algorithm
  requires an adapter update and review.
- The adapter does not claim immutable logging, complete history, trusted
  time, non-repudiation, HSM/FIPS status, key origin/residency, or compliance
  certification. Issue #46 remains required for complete-chain
  replacement/truncation defense.
- The provider exception classifiers assume an intact interpreter until the
  first lazy load. Arbitrary local code that replaces canonical modules and
  cloned authentic code before that point is an interpreter-integrity
  boundary, not a provider-input guarantee.
- `npm ci` reported 1 low and 7 high dependency advisories and pending install
  scripts for `@playwright/browser-chromium@1.61.0`, `fsevents@2.3.3`, and
  `fsevents@2.3.2`. No automated audit fix was applied; all 298 frontend tests
  and the production build passed, so these are dependency-maintenance risks,
  not failed issue #45 acceptance behavior.
- Setuptools warned that the TOML license table/license classifier forms are
  deprecated, with a 2027-02-18 horizon, and emitted existing MANIFEST
  no-match/exclusion warnings. Both artifacts built and passed inspection;
  license metadata modernization is separate release-tooling maintenance.
- This review ran locally on macOS with Python 3.12.13. The pinned GitHub
  Actions workflow remains the cross-environment enforcement point; workflow
  shape, tag coupling, single-build provenance, and action pins passed static
  tests.

## Final verdict

All approved runtime, security-boundary, packaging, documentation, and
verification requirements have concrete passing evidence. Residuals are
explicit host or release-maintenance boundaries and do not contradict issue
#45. The pending external PR/issue action is a finalizer handoff; this `PASS`
permits that finalization and does not claim it already occurred.

**PASS**
