"""Strict offline coverage for the AWS KMS artifact signer and verifier."""

from __future__ import annotations

from base64 import b64decode, b64encode
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import logging
import sys
from threading import Barrier, Lock, Thread
from types import ModuleType

import pytest

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations.aws_kms import (
    AwsKmsArtifactSigner,
    AwsKmsArtifactVerifier,
    AwsKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    AnchorStatus,
    CANONICALIZATION_VERSION,
    EvidenceType,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
    sign_artifact_with_metadata,
)
from tests.signing_conformance import (
    SignedArtifactFixture,
    SignerFixture,
    SignerScenario,
    VerifierScenario,
    assert_external_signer_conformance,
    assert_external_verifier_conformance,
)
from tests.support.external_signing import SENSITIVE_CORPUS
from tests.support.kms_fixtures import (
    AWS_KEY_ARNS,
    RecordingAwsKmsClient,
    generate_aws_private_keys,
    verify_aws_signature,
)


@pytest.fixture(scope="module")
def aws_private_keys():
    return generate_aws_private_keys()


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


_VALID_AWS_KEY_ARNS = (
    "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-cn:kms:cn-north-1:111122223333:key/mrk-0123456789abcdef0123456789abcdef",
    (
        "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/"
        "abcdefab-cdef-abcd-efab-cdefabcdefab"
    ),
    (
        "arn:aws-iso:kms:us-iso-east-1:111122223333:key/"
        "01234567-89ab-cdef-0123-456789abcdef"
    ),
    (
        "arn:aws-iso-b:kms:us-isob-east-1:111122223333:key/"
        "mrk-fedcba9876543210fedcba9876543210"
    ),
    (
        "arn:aws-iso-e:kms:eu-isoe-west-1:111122223333:key/"
        "89abcdef-0123-4567-89ab-cdef01234567"
    ),
    (
        "arn:aws-iso-f:kms:us-isof-south-1:111122223333:key/"
        "mrk-abcdef0123456789abcdef0123456789"
    ),
    (
        "arn:aws-eusc:kms:eusc-de-east-1:111122223333:key/"
        "fedcba98-7654-3210-fedc-ba9876543210"
    ),
)

_MALFORMED_AWS_KEY_ARNS = (
    "arn:notaws:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:AWS:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws--gov:kms:us-gov-west-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:US-EAST-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:-:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:us--east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:us-east-1:11112222333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:us-east-1:1111222233333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:us-east-1:111122223333:alias/audit",
    "arn:aws:kms:us-east-1:111122223333:key/not-a-canonical-key-id",
    "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-4ABC-8def-1234567890ab",
    "arn:aws:kms:us-east-1:111122223333:key/1234567-1234-4abc-8def-1234567890ab",
    "arn:aws:kms:us-east-1:111122223333:key/mrk-0123456789abcdef0123456789abcde",
    "arn:aws:kms:us-east-1:111122223333:key/mrk-0123456789abcdef0123456789abcdeg",
    (
        "arn:aws-not-a-real-partition:kms:us-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
    "arn:aws-CN:kms:cn-north-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn::kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-cn-extra:kms:cn-north-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-euscx:kms:eusc-de-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-us-gov-2:kms:us-gov-west-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-iso-g:kms:us-iso-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab/extra"
    ),
    (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab?version=1"
    ),
)

_UNSUPPORTED_AWS_PROVIDER_PARTITION_ARNS = (
    "arn::kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    "arn:aws-CN:kms:cn-north-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
    (
        "arn:aws-not-a-real-partition:kms:us-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
    (
        "arn:aws-cn-extra:kms:cn-north-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
    (
        "arn:aws-euscx:kms:eusc-de-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
    (
        "arn:aws-us-gov-2:kms:us-gov-west-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
    (
        "arn:aws-iso-g:kms:us-iso-east-1:111122223333:key/"
        "12345678-1234-4abc-8def-1234567890ab"
    ),
)

_DOCUMENTED_AWS_SIGNING_ALGORITHMS = (
    "RSASSA_PSS_SHA_256",
    "RSASSA_PSS_SHA_384",
    "RSASSA_PSS_SHA_512",
    "RSASSA_PKCS1_V1_5_SHA_256",
    "RSASSA_PKCS1_V1_5_SHA_384",
    "RSASSA_PKCS1_V1_5_SHA_512",
    "ECDSA_SHA_256",
    "ECDSA_SHA_384",
    "ECDSA_SHA_512",
    "SM2DSA",
    "ML_DSA_SHAKE_256",
    "ED25519_SHA_512",
    "ED25519_PH_SHA_512",
)


def test_aws_signer_rejects_a_missing_injected_client():
    with pytest.raises(
        SigningContractError,
        match=r"^AWS KMS signer configuration is invalid$",
    ) as caught:
        AwsKmsArtifactSigner(
            None,
            key_id="alias/audit",
            signing_algorithm="RSASSA_PSS_SHA_256",
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    ("key_id", "algorithm"),
    [
        (b"alias/audit", "RSASSA_PSS_SHA_256"),
        (_StringSubclass("alias/audit"), "RSASSA_PSS_SHA_256"),
        ("alias/audit", b"RSASSA_PSS_SHA_256"),
        ("alias/audit", _StringSubclass("RSASSA_PSS_SHA_256")),
        ("", "RSASSA_PSS_SHA_256"),
        ("alias/audit", "RSASSA_PKCS1_V1_5_SHA_256"),
    ],
)
def test_aws_signer_rejects_invalid_constructor_values_without_provider_calls(
    aws_private_keys, key_id, algorithm
):
    client = RecordingAwsKmsClient(aws_private_keys)

    with pytest.raises(
        SigningContractError,
        match=r"^AWS KMS signer configuration is invalid$",
    ) as caught:
        AwsKmsArtifactSigner(client, key_id=key_id, signing_algorithm=algorithm)

    _assert_safe_error(caught.value)
    assert client.describe_calls == []
    assert client.sign_calls == []


def test_aws_module_exports_only_the_three_aws_adapter_types():
    import aegis.integrations.aws_kms as aws_kms

    assert aws_kms.__all__ == [
        "AwsKmsArtifactSigner",
        "AwsKmsArtifactVerifier",
        "AwsKmsVerificationTarget",
    ]


def test_aws_verification_target_reconstructs_only_exact_trusted_builtins():
    target = AwsKmsVerificationTarget(
        AWS_KEY_ARNS["RSA_2048"],
        frozenset({"RSASSA_PSS_SHA_256"}),
    )

    assert target.key_arn == AWS_KEY_ARNS["RSA_2048"]
    assert target.allowed_algorithms == frozenset({"RSASSA_PSS_SHA_256"})
    assert target.disposition is KmsKeyDisposition.ANCHORED


def test_aws_target_rejects_forged_exact_disposition_instances():
    for value in ("anchored", "revoked", "unknown"):
        forged = str.__new__(KmsKeyDisposition, value)

        with pytest.raises(
            VerificationContractError,
            match=r"^AWS KMS verification target is invalid$",
        ) as caught:
            AwsKmsVerificationTarget(
                AWS_KEY_ARNS["RSA_2048"],
                frozenset({"RSASSA_PSS_SHA_256"}),
                forged,
            )

        _assert_safe_error(caught.value)


def test_aws_verification_target_is_frozen_and_honors_metadata_arn_bound():
    maximum_arn = (
        "arn:aws:kms:"
        + "r" * 62
        + ":111122223333:key/12345678-1234-4abc-8def-1234567890ab"
    )
    assert len(maximum_arn) == 128

    target = AwsKmsVerificationTarget(
        maximum_arn,
        frozenset({"RSASSA_PSS_SHA_256"}),
    )

    assert target.key_arn == maximum_arn
    with pytest.raises(FrozenInstanceError):
        target.key_arn = AWS_KEY_ARNS["RSA_2048"]

    with pytest.raises(VerificationContractError) as caught:
        AwsKmsVerificationTarget(
            maximum_arn.replace("r" * 62, "r" * 63),
            frozenset({"RSASSA_PSS_SHA_256"}),
        )
    _assert_safe_error(caught.value)


@pytest.mark.parametrize("key_arn", _VALID_AWS_KEY_ARNS)
def test_aws_verification_target_accepts_all_supported_aws_partitions(key_arn):
    target = AwsKmsVerificationTarget(
        key_arn,
        frozenset({"RSASSA_PSS_SHA_256"}),
    )

    assert target.key_arn == key_arn


@pytest.mark.parametrize("key_arn", _MALFORMED_AWS_KEY_ARNS)
def test_aws_verification_target_rejects_noncanonical_key_arns(key_arn):
    with pytest.raises(VerificationContractError) as caught:
        AwsKmsVerificationTarget(
            key_arn,
            frozenset({"RSASSA_PSS_SHA_256"}),
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    ("key_arn", "allowed_algorithms", "disposition"),
    [
        ("alias/audit", frozenset({"RSASSA_PSS_SHA_256"}), KmsKeyDisposition.ANCHORED),
        (
            _StringSubclass(AWS_KEY_ARNS["RSA_2048"]),
            frozenset({"RSASSA_PSS_SHA_256"}),
            KmsKeyDisposition.ANCHORED,
        ),
        (AWS_KEY_ARNS["RSA_2048"], {"RSASSA_PSS_SHA_256"}, KmsKeyDisposition.ANCHORED),
        (AWS_KEY_ARNS["RSA_2048"], frozenset(), KmsKeyDisposition.ANCHORED),
        (
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"ED25519_SHA_512"}),
            KmsKeyDisposition.ANCHORED,
        ),
        (
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
            "anchored",
        ),
    ],
)
def test_aws_verification_target_rejects_malformed_trust_data(
    key_arn, allowed_algorithms, disposition
):
    with pytest.raises(VerificationContractError) as caught:
        AwsKmsVerificationTarget(key_arn, allowed_algorithms, disposition)

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    ("key_spec", "algorithm"),
    [
        ("RSA_2048", "RSASSA_PSS_SHA_256"),
        ("RSA_3072", "RSASSA_PSS_SHA_256"),
        ("RSA_4096", "RSASSA_PSS_SHA_256"),
        ("ECC_NIST_P256", "ECDSA_SHA_256"),
        ("ECC_SECG_P256K1", "ECDSA_SHA_256"),
    ],
)
def test_aws_signer_identity_and_signing_bind_exact_selector_arn_and_payload(
    aws_private_keys, key_spec, algorithm
):
    client = RecordingAwsKmsClient(aws_private_keys, key_spec=key_spec)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit-artifact",
        signing_algorithm=algorithm,
    )

    identity = signer.signer_identity()
    payload = b"\x00AWS KMS exact payload\xff\n"
    receipt = signer.sign(payload, identity)
    raw_signature = b64decode(receipt.signature, validate=True)

    assert identity == SignerIdentity(
        algorithm,
        SignatureEncoding.BASE64,
        "alias/audit-artifact",
        AWS_KEY_ARNS[key_spec],
    )
    assert client.describe_calls == [
        {"KeyId": "alias/audit-artifact"},
        {"KeyId": "alias/audit-artifact"},
    ]
    assert client.sign_calls == [
        {
            "KeyId": AWS_KEY_ARNS[key_spec],
            "Message": sha256(payload).digest(),
            "MessageType": "DIGEST",
            "SigningAlgorithm": algorithm,
        }
    ]
    assert receipt == SigningReceipt(
        b64encode(raw_signature).decode("ascii"),
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    assert verify_aws_signature(
        aws_private_keys[key_spec].public_key(),
        signing_algorithm=algorithm,
        payload=payload,
        signature=raw_signature,
    )


def test_aws_signer_binds_and_signs_with_a_canonical_mrk_arn(aws_private_keys):
    key_arn = (
        "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/"
        "mrk-0123456789abcdef0123456789abcdef"
    )
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=key_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    identity = signer.signer_identity()
    signer.sign(b"payload", identity)

    assert identity.key_version == key_arn
    assert client.sign_calls[0]["KeyId"] == key_arn


@pytest.mark.parametrize("key_arn", _VALID_AWS_KEY_ARNS)
def test_aws_signer_identity_accepts_all_supported_provider_partitions(
    aws_private_keys, key_arn
):
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=key_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    identity = signer.signer_identity()

    assert identity == SignerIdentity(
        "RSASSA_PSS_SHA_256",
        SignatureEncoding.BASE64,
        "alias/audit",
        key_arn,
    )
    assert client.describe_calls == [{"KeyId": "alias/audit"}]
    assert client.sign_calls == []


def test_aws_signer_rejects_multi_region_replica_arn_substitution_before_sign(
    aws_private_keys,
):
    east_arn = (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "mrk-0123456789abcdef0123456789abcdef"
    )
    west_arn = (
        "arn:aws:kms:us-west-2:111122223333:key/"
        "mrk-0123456789abcdef0123456789abcdef"
    )
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=east_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()
    client._key_arn = west_arn

    with pytest.raises(ArtifactSigningError) as caught:
        signer.sign(b"payload", identity)

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 2
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "key_arn",
    (
        "arn:notaws:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
        "arn:aws--gov:kms:us-east-1:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
        "arn:aws:kms:-:111122223333:key/12345678-1234-4abc-8def-1234567890ab",
        "arn:aws:kms:us-east-1:111122223333:key/not-a-canonical-key-id",
        "arn:aws:kms:us-east-1:111122223333:key/mrk-ABCDEF0123456789ABCDEF0123456789",
    ),
)
def test_aws_signer_identity_rejects_noncanonical_provider_arns(
    aws_private_keys, key_arn
):
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=key_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    with pytest.raises(SigningContractError) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "key_arn",
    _UNSUPPORTED_AWS_PROVIDER_PARTITION_ARNS,
)
def test_aws_signer_identity_rejects_unsupported_provider_partitions(
    aws_private_keys, key_arn
):
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=key_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    with pytest.raises(SigningContractError) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.describe_calls == [{"KeyId": "alias/audit"}]
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "signing_algorithms",
    [
        ["RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_256"],
        ["RSASSA_PSS_SHA_256", "FUTURE_PROVIDER_ALGORITHM"],
        ["RSASSA_PSS_SHA_256", _StringSubclass("ECDSA_SHA_256")],
    ],
)
def test_aws_signer_identity_rejects_noncanonical_complete_algorithm_arrays(
    aws_private_keys, signing_algorithms
):
    client = RecordingAwsKmsClient(
        aws_private_keys,
        signing_algorithms=signing_algorithms,
    )
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    with pytest.raises(SigningContractError) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "additional_algorithm",
    _DOCUMENTED_AWS_SIGNING_ALGORITHMS[1:],
)
def test_aws_signer_accepts_each_additional_documented_metadata_algorithm(
    aws_private_keys, additional_algorithm
):
    client = RecordingAwsKmsClient(
        aws_private_keys,
        signing_algorithms=[
            "RSASSA_PSS_SHA_256",
            additional_algorithm,
        ],
    )
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    identity = signer.signer_identity()

    assert identity.algorithm == "RSASSA_PSS_SHA_256"


@pytest.mark.parametrize(
    "signing_algorithms",
    [
        ["RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_256"],
        ["RSASSA_PSS_SHA_256", "FUTURE_PROVIDER_ALGORITHM"],
        ["RSASSA_PSS_SHA_256", _StringSubclass("ECDSA_SHA_256")],
    ],
)
def test_aws_signer_rejects_invalid_second_algorithm_array_before_sign(
    aws_private_keys, signing_algorithms
):
    client = RecordingAwsKmsClient(aws_private_keys)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()
    client.signing_algorithms = signing_algorithms

    with pytest.raises(ArtifactSigningError) as caught:
        signer.sign(b"payload", identity)

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 2
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "mode",
    [
        "disabled_key",
        "disabled_enabled_flag",
        "disabled_key_state",
        "wrong_usage",
        "wrong_spec",
        "absent_algorithm",
        "malformed_describe",
        "malformed_enabled",
        "malformed_algorithms",
        "enum_algorithm",
        "provider_describe_failure",
        "unexpected_describe_failure",
    ],
)
def test_aws_signer_identity_rejects_ineligible_or_malformed_metadata_safely(
    aws_private_keys, mode
):
    client = RecordingAwsKmsClient(aws_private_keys, mode=mode)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )

    with pytest.raises(
        SigningContractError,
        match=r"^AWS KMS signer could not prepare identity$",
    ) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.sign_calls == []


def test_aws_signer_rechecks_selector_and_aborts_alias_retarget_before_sign(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(aws_private_keys, mode="normal")
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()
    client.mode = "alias_retarget"

    with pytest.raises(
        ArtifactSigningError,
        match=r"^AWS KMS signer could not produce a signature$",
    ) as caught:
        signer.sign(b"payload", identity)

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 2
    assert client.sign_calls == []


@pytest.mark.parametrize(
    ("key_spec", "algorithm"),
    [
        ("RSA_2048", "ECDSA_SHA_256"),
        ("ECC_NIST_P256", "RSASSA_PSS_SHA_256"),
    ],
)
def test_aws_signer_rejects_cross_family_algorithm_and_key_spec_before_sign(
    aws_private_keys, key_spec, algorithm
):
    client = RecordingAwsKmsClient(
        aws_private_keys,
        key_spec=key_spec,
        signing_algorithms=[algorithm],
    )
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm=algorithm,
    )

    with pytest.raises(SigningContractError) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 1
    assert client.sign_calls == []


@pytest.mark.parametrize(
    "mode",
    [
        "alias_retarget",
        "disabled_key",
        "wrong_usage",
        "wrong_spec",
        "absent_algorithm",
        "malformed_describe",
        "provider_describe_failure",
        "unexpected_describe_failure",
        "malformed_sign",
        "empty_signature",
        "oversized_signature",
        "signature_subclass",
        "wrong_sign_key_id",
        "wrong_sign_algorithm",
        "provider_sign_failure",
        "unexpected_sign_failure",
    ],
)
def test_aws_signing_failures_are_sanitized_and_artifact_atomic(
    aws_private_keys, mode, caplog
):
    client = RecordingAwsKmsClient(aws_private_keys)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    artifact = {
        "audit_schema_version": "1.4",
        "private": SENSITIVE_CORPUS[4],
        "signature": None,
    }
    snapshot = deepcopy(artifact)
    client.mode = mode
    caplog.set_level(logging.DEBUG)

    with pytest.raises(ArtifactSigningError) as caught:
        sign_artifact_with_metadata(artifact, signer, signed_at=123)

    _assert_safe_error(caught.value, logs=caplog.text)
    assert artifact == snapshot


def test_aws_signer_accepts_the_inclusive_raw_signature_limit(aws_private_keys):
    client = RecordingAwsKmsClient(aws_private_keys)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()
    client.mode = "maximum_signature"

    receipt = signer.sign(b"payload", identity)

    assert b64decode(receipt.signature, validate=True) == b"x" * 6_144


@pytest.mark.parametrize(
    "payload",
    [bytearray(b"payload"), memoryview(b"payload"), "payload", _BytesSubclass(b"payload")],
)
def test_aws_signer_rejects_non_exact_payload_bytes_without_provider_calls(
    aws_private_keys, payload
):
    client = RecordingAwsKmsClient(aws_private_keys)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()

    with pytest.raises(ArtifactSigningError) as caught:
        signer.sign(payload, identity)

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 1
    assert client.sign_calls == []


def test_aws_signer_rejects_subclass_or_forged_identity_before_provider_calls(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    identity = signer.signer_identity()
    forged = SignerIdentity(
        identity.algorithm,
        identity.signature_encoding,
        "alias/forged",
        identity.key_version,
    )

    with pytest.raises(ArtifactSigningError) as caught:
        signer.sign(b"payload", forged)

    _assert_safe_error(caught.value)
    assert len(client.describe_calls) == 1
    assert client.sign_calls == []


def test_aws_signer_runs_shared_external_signing_conformance(aws_private_keys):
    class MalformedScenarioSigner:
        def __init__(self, signer, scenario):
            self.signer = signer
            self.scenario = scenario

        def signer_identity(self):
            if self.scenario is SignerScenario.MALFORMED_IDENTITY:
                return object()
            return self.signer.signer_identity()

        def sign(self, payload, identity):
            if self.scenario is SignerScenario.MALFORMED_RECEIPT:
                return object()
            return self.signer.sign(payload, identity)

    def signer_factory(scenario: SignerScenario) -> SignerFixture:
        modes = {
            SignerScenario.NORMAL: "normal",
            SignerScenario.IDENTITY_ERROR: "provider_describe_failure",
            SignerScenario.IDENTITY_UNEXPECTED: "unexpected_describe_failure",
            SignerScenario.MALFORMED_IDENTITY: "normal",
            SignerScenario.SIGNING_ERROR: "provider_sign_failure",
            SignerScenario.SIGNING_UNEXPECTED: "unexpected_sign_failure",
            SignerScenario.MALFORMED_RECEIPT: "normal",
        }
        client = RecordingAwsKmsClient(aws_private_keys, mode=modes[scenario])
        aws_signer = AwsKmsArtifactSigner(
            client,
            key_id="alias/audit",
            signing_algorithm="RSASSA_PSS_SHA_256",
        )
        signer = (
            MalformedScenarioSigner(aws_signer, scenario)
            if scenario in (
                SignerScenario.MALFORMED_IDENTITY,
                SignerScenario.MALFORMED_RECEIPT,
            )
            else aws_signer
        )

        def verify_signature(payload: bytes, receipt: SigningReceipt) -> bool:
            try:
                raw = b64decode(receipt.signature, validate=True)
            except Exception:
                return False
            return verify_aws_signature(
                aws_private_keys["RSA_2048"].public_key(),
                signing_algorithm=receipt.algorithm,
                payload=payload,
                signature=raw,
            )

        return SignerFixture(
            signer,
            lambda: tuple(
                call["Message"] for call in client.sign_calls
            ),
            verify_signature,
        )

    assert_external_signer_conformance(signer_factory)


def test_aws_verifier_rejects_invalid_constructor_values():
    client = object()

    for invalid_client, invalid_resolver in (
        (None, lambda _reference, _version: None),
        (client, None),
        (client, object()),
    ):
        with pytest.raises(
            VerificationContractError,
            match=r"^AWS KMS verifier configuration is invalid$",
        ) as caught:
            AwsKmsArtifactVerifier(
                invalid_client,
                resolver=invalid_resolver,
            )

        _assert_safe_error(caught.value)


def test_aws_verifier_uses_exact_pair_once_and_exact_digest_request(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    target = AwsKmsVerificationTarget(
        AWS_KEY_ARNS["RSA_2048"],
        frozenset({"RSASSA_PSS_SHA_256"}),
    )

    def resolver(key_reference, key_version):
        resolver_calls.append((key_reference, key_version))
        return target

    verifier = AwsKmsArtifactVerifier(client, resolver=resolver)
    payload = b"\x00AWS KMS verification payload\xff\n"
    signature = _aws_signature(client, payload)
    metadata = _aws_metadata()

    outcome = verifier.verify(payload, signature, metadata)

    _assert_outcome(outcome, VerificationReasonCode.SIGNATURE_VALID_ANCHORED)
    assert resolver_calls == [
        ("alias/audit-artifact", AWS_KEY_ARNS["RSA_2048"])
    ]
    assert client.verify_calls == [
        {
            "KeyId": AWS_KEY_ARNS["RSA_2048"],
            "Message": sha256(payload).digest(),
            "MessageType": "DIGEST",
            "Signature": b64decode(signature, validate=True),
            "SigningAlgorithm": "RSASSA_PSS_SHA_256",
        }
    ]


def test_aws_verifier_rejects_unsupported_algorithm_before_resolver_or_provider(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda *pair: resolver_calls.append(pair),
    )

    outcome = verifier.verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(algorithm="RSASSA_PKCS1_V1_5_SHA_256"),
    )

    _assert_outcome(outcome, VerificationReasonCode.ALGORITHM_NOT_ALLOWED)
    assert resolver_calls == []
    assert client.verify_calls == []


@pytest.mark.parametrize(
    "payload",
    (
        bytearray(b"payload"),
        memoryview(b"payload"),
        _BytesSubclass(b"payload"),
    ),
)
def test_aws_verifier_rejects_non_exact_direct_call_inputs_before_resolver(
    aws_private_keys,
    payload,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda *pair: resolver_calls.append(pair),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            payload,
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)
    assert resolver_calls == []
    assert client.verify_calls == []


def test_aws_verifier_rejects_metadata_subclass_without_property_reads(
    aws_private_keys,
):
    reads = []

    class HostileMetadata(SignatureMetadata):
        def __getattribute__(self, name):
            if name in (
                "algorithm",
                "signature_encoding",
                "key_reference",
                "key_version",
            ):
                reads.append(name)
                raise RuntimeError("metadata " + SENSITIVE_CORPUS[0])
            return super().__getattribute__(name)

    metadata = object.__new__(HostileMetadata)
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda *pair: resolver_calls.append(pair),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            metadata,
        )

    _assert_safe_error(caught.value)
    assert reads == []
    assert resolver_calls == []
    assert client.verify_calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("algorithm", _StringSubclass("RSASSA_PSS_SHA_256")),
        ("signature_encoding", "base64"),
        ("key_reference", _StringSubclass("alias/audit-artifact")),
        (
            "key_version",
            _StringSubclass(AWS_KEY_ARNS["RSA_2048"]),
        ),
    ),
)
def test_aws_verifier_rejects_forged_exact_metadata_fields_before_resolver(
    aws_private_keys,
    field,
    value,
):
    metadata = _aws_metadata()
    object.__setattr__(metadata, field, value)
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda *pair: resolver_calls.append(pair),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            metadata,
        )

    _assert_safe_error(caught.value)
    assert resolver_calls == []
    assert client.verify_calls == []


@pytest.mark.parametrize(
    "signature",
    (
        "",
        "YQ==\n",
        "YQ== ",
        "YQ",
        "YQ===",
        "YQ-_",
        _StringSubclass("YQ=="),
        b64encode(b"x" * 6_145).decode("ascii"),
    ),
)
def test_aws_verifier_rejects_noncanonical_or_oversized_signature_before_resolver(
    aws_private_keys,
    signature,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda *pair: resolver_calls.append(pair),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS verification request is invalid$",
    ) as caught:
        verifier.verify(b"payload", signature, _aws_metadata())

    _assert_safe_error(caught.value)
    assert resolver_calls == []
    assert client.verify_calls == []


def test_aws_verifier_accepts_the_inclusive_raw_signature_limit(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(aws_private_keys, mode="verify_false")
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )
    raw_signature = b"x" * 6_144

    outcome = verifier.verify(
        b"payload",
        b64encode(raw_signature).decode("ascii"),
        _aws_metadata(),
    )

    _assert_outcome(outcome, VerificationReasonCode.SIGNATURE_INVALID)
    assert client.verify_calls[0]["Signature"] == raw_signature


def test_aws_verifier_maps_unknown_revoked_and_denied_without_provider_work(
    aws_private_keys,
):
    cases = (
        (None, VerificationReasonCode.KEY_UNKNOWN),
        (
            AwsKmsVerificationTarget(
                AWS_KEY_ARNS["RSA_2048"],
                frozenset({"RSASSA_PSS_SHA_256"}),
                KmsKeyDisposition.REVOKED,
            ),
            VerificationReasonCode.KEY_REVOKED,
        ),
        (
            AwsKmsVerificationTarget(
                AWS_KEY_ARNS["RSA_2048"],
                frozenset({"ECDSA_SHA_256"}),
            ),
            VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
        ),
    )

    for target, reason in cases:
        client = RecordingAwsKmsClient(aws_private_keys)
        verifier = AwsKmsArtifactVerifier(
            client,
            resolver=lambda _reference, _version, value=target: value,
        )

        outcome = verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

        _assert_outcome(outcome, reason)
        assert client.verify_calls == []


@pytest.mark.parametrize(
    "resolved",
    (
        object(),
        {
            "key_arn": AWS_KEY_ARNS["RSA_2048"],
            "allowed_algorithms": frozenset({"RSASSA_PSS_SHA_256"}),
        },
        _StringSubclass(AWS_KEY_ARNS["RSA_2048"]),
    ),
)
def test_aws_verifier_rejects_non_exact_resolver_targets_safely(
    aws_private_keys,
    resolved,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS resolver returned an invalid target$",
    ) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)
    assert client.verify_calls == []


def test_aws_verifier_rejects_target_subclass_without_reading_hostile_properties(
    aws_private_keys,
):
    reads = []

    class HostileTarget(AwsKmsVerificationTarget):
        def __getattribute__(self, name):
            if name in ("key_arn", "allowed_algorithms", "disposition"):
                reads.append(name)
                raise RuntimeError("hostile " + SENSITIVE_CORPUS[0])
            return super().__getattribute__(name)

    resolved = object.__new__(HostileTarget)
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)
    assert reads == []
    assert client.verify_calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("key_arn", _StringSubclass(AWS_KEY_ARNS["RSA_2048"])),
        ("allowed_algorithms", {"RSASSA_PSS_SHA_256"}),
        (
            "allowed_algorithms",
            frozenset({_StringSubclass("RSASSA_PSS_SHA_256")}),
        ),
        ("allowed_algorithms", frozenset()),
        ("disposition", "anchored"),
    ),
)
def test_aws_verifier_rejects_forged_exact_target_fields(
    aws_private_keys,
    field,
    value,
):
    resolved = object.__new__(AwsKmsVerificationTarget)
    object.__setattr__(resolved, "key_arn", AWS_KEY_ARNS["RSA_2048"])
    object.__setattr__(
        resolved,
        "allowed_algorithms",
        frozenset({"RSASSA_PSS_SHA_256"}),
    )
    object.__setattr__(
        resolved,
        "disposition",
        KmsKeyDisposition.ANCHORED,
    )
    object.__setattr__(resolved, field, value)
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)
    assert client.verify_calls == []


def test_aws_verifier_rejects_forged_disposition_before_provider_work(
    aws_private_keys,
):
    resolved = object.__new__(AwsKmsVerificationTarget)
    object.__setattr__(resolved, "key_arn", AWS_KEY_ARNS["RSA_2048"])
    object.__setattr__(
        resolved,
        "allowed_algorithms",
        frozenset({"RSASSA_PSS_SHA_256"}),
    )
    object.__setattr__(
        resolved,
        "disposition",
        str.__new__(KmsKeyDisposition, "revoked"),
    )
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS resolver returned an invalid target$",
    ) as caught:
        verifier.verify(
            b"forged disposition",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)
    assert client.verify_calls == []


def test_aws_verifier_reads_each_resolved_target_field_once(
    aws_private_keys,
    monkeypatch,
):
    resolved = AwsKmsVerificationTarget(
        AWS_KEY_ARNS["RSA_2048"],
        frozenset({"RSASSA_PSS_SHA_256"}),
    )
    reads = {
        "key_arn": 0,
        "allowed_algorithms": 0,
        "disposition": 0,
    }
    original_getattribute = AwsKmsVerificationTarget.__getattribute__

    def tracked_getattribute(self, name):
        if self is resolved and name in reads:
            reads[name] += 1
        return original_getattribute(self, name)

    monkeypatch.setattr(
        AwsKmsVerificationTarget,
        "__getattribute__",
        tracked_getattribute,
    )
    client = RecordingAwsKmsClient(aws_private_keys, mode="verify_false")
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    verifier.verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )

    assert reads == {
        "key_arn": 1,
        "allowed_algorithms": 1,
        "disposition": 1,
    }


def test_aws_verifier_uses_copied_target_after_resolver_object_mutation(
    aws_private_keys,
):
    resolved = AwsKmsVerificationTarget(
        AWS_KEY_ARNS["RSA_2048"],
        frozenset({"RSASSA_PSS_SHA_256"}),
    )
    forged_arn = (
        "arn:aws:kms:us-west-2:111122223333:key/"
        "ffffffff-ffff-4fff-8fff-ffffffffffff"
    )

    class MutatingClient(RecordingAwsKmsClient):
        def verify(self, **kwargs):
            object.__setattr__(resolved, "key_arn", forged_arn)
            object.__setattr__(
                resolved,
                "allowed_algorithms",
                frozenset({"ECDSA_SHA_256"}),
            )
            object.__setattr__(
                resolved,
                "disposition",
                KmsKeyDisposition.REVOKED,
            )
            return super().verify(**kwargs)

    client = MutatingClient(aws_private_keys)
    payload = b"copied target payload"
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: resolved,
    )

    outcome = verifier.verify(
        payload,
        _aws_signature(client, payload),
        _aws_metadata(),
    )

    _assert_outcome(
        outcome,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
    )
    assert client.verify_calls[0]["KeyId"] == AWS_KEY_ARNS["RSA_2048"]
    assert client.verify_calls[0]["SigningAlgorithm"] == (
        "RSASSA_PSS_SHA_256"
    )


def test_aws_verifier_sanitizes_resolver_failure(aws_private_keys, caplog):
    client = RecordingAwsKmsClient(aws_private_keys)

    def resolver(_key_reference, _key_version):
        raise RuntimeError("resolver failure " + " | ".join(SENSITIVE_CORPUS))

    verifier = AwsKmsArtifactVerifier(client, resolver=resolver)
    caplog.set_level(logging.DEBUG)

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS resolver failed$",
    ) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value, logs=caplog.text)
    assert client.verify_calls == []


def test_aws_verifier_rejects_resolver_target_arn_substitution(
    aws_private_keys,
):
    approved_arn = AWS_KEY_ARNS["RSA_2048"]
    substituted_arn = (
        "arn:aws:kms:us-west-2:111122223333:key/"
        "00000000-0000-4000-8000-000000002048"
    )
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            substituted_arn,
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS resolver returned an invalid target$",
    ) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(key_version=approved_arn),
        )

    _assert_safe_error(caught.value)
    assert client.verify_calls == []


@pytest.mark.parametrize(
    ("mode", "reason"),
    (
        ("verify_false", VerificationReasonCode.SIGNATURE_INVALID),
        (
            "invalid_signature_exception",
            VerificationReasonCode.SIGNATURE_INVALID,
        ),
        ("dependency_timeout", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("disabled_verify", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("kms_internal", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("invalid_state", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("key_unavailable", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("not_found", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("access_denied", VerificationReasonCode.VERIFIER_UNAVAILABLE),
        ("throttled", VerificationReasonCode.VERIFIER_UNAVAILABLE),
    ),
)
def test_aws_verifier_maps_only_documented_provider_failures(
    aws_private_keys,
    mode,
    reason,
):
    client = RecordingAwsKmsClient(aws_private_keys, mode=mode)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    outcome = verifier.verify(
        b"payload",
        b64encode(b"wrong signature").decode("ascii"),
        _aws_metadata(),
    )

    _assert_outcome(outcome, reason)


@pytest.mark.parametrize(
    "mode",
    (
        "malformed_verify",
        "wrong_verify_key_id",
        "wrong_verify_algorithm",
        "malformed_verify_validity",
        "unexpected_verify_failure",
        "validation_verify_failure",
    ),
)
def test_aws_verifier_rejects_malformed_or_unexpected_provider_behavior(
    aws_private_keys,
    mode,
    caplog,
):
    client = RecordingAwsKmsClient(aws_private_keys, mode=mode)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )
    caplog.set_level(logging.DEBUG)

    with pytest.raises(
        VerificationContractError,
        match=r"^AWS KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"wrong signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value, logs=caplog.text)


@pytest.mark.parametrize(
    "mutation",
    (
        "mapping_subclass",
        "key_id_subclass",
        "algorithm_subclass",
    ),
)
def test_aws_verifier_rejects_response_and_echo_subclasses(
    aws_private_keys,
    mutation,
):
    class DictSubclass(dict):
        pass

    class ResponseSubclassClient(RecordingAwsKmsClient):
        def verify(self, **kwargs):
            response = super().verify(**kwargs)
            if mutation == "mapping_subclass":
                return DictSubclass(response)
            if mutation == "key_id_subclass":
                response["KeyId"] = _StringSubclass(response["KeyId"])
            else:
                response["SigningAlgorithm"] = _StringSubclass(
                    response["SigningAlgorithm"]
                )
            return response

    client = ResponseSubclassClient(aws_private_keys, mode="verify_false")
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    ("disposition", "reason"),
    (
        (
            KmsKeyDisposition.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        ),
        (
            KmsKeyDisposition.UNANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        ),
        (
            KmsKeyDisposition.INVALID_ANCHOR,
            VerificationReasonCode.ANCHOR_INVALID,
        ),
    ),
)
def test_aws_verifier_maps_valid_crypto_through_host_disposition(
    aws_private_keys,
    disposition,
    reason,
):
    client = RecordingAwsKmsClient(aws_private_keys)
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
            disposition,
        ),
    )
    payload = b"valid disposition payload"

    outcome = verifier.verify(
        payload,
        _aws_signature(client, payload),
        _aws_metadata(),
    )

    _assert_outcome(outcome, reason)


def test_aws_verifier_keeps_historical_arn_after_signer_alias_retargets(
    aws_private_keys,
):
    old_arn = AWS_KEY_ARNS["RSA_2048"]
    new_arn = (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "ffffffff-ffff-4fff-8fff-ffffffffffff"
    )
    client = RecordingAwsKmsClient(aws_private_keys, key_arn=old_arn)
    signer = AwsKmsArtifactSigner(
        client,
        key_id="alias/audit",
        signing_algorithm="RSASSA_PSS_SHA_256",
    )
    payload = b"historical payload"
    identity = signer.signer_identity()
    receipt = signer.sign(payload, identity)
    client._key_arn = new_arn
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda reference, version: (
            AwsKmsVerificationTarget(
                old_arn,
                frozenset({"RSASSA_PSS_SHA_256"}),
                KmsKeyDisposition.UNANCHORED,
            )
            if (reference, version) == ("alias/audit", old_arn)
            else None
        ),
    )

    outcome = verifier.verify(
        payload,
        receipt.signature,
        _aws_metadata(key_reference="alias/audit", key_version=old_arn),
    )

    _assert_outcome(
        outcome,
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
    )
    assert client.verify_calls[-1]["KeyId"] == old_arn
    assert client.verify_calls[-1]["KeyId"] != client.key_arn


def test_aws_verifier_forged_metadata_cannot_redirect_approved_target(
    aws_private_keys,
):
    approved_arn = AWS_KEY_ARNS["RSA_2048"]
    forged_arn = (
        "arn:aws:kms:us-west-2:111122223333:key/"
        "ffffffff-ffff-4fff-8fff-ffffffffffff"
    )
    client = RecordingAwsKmsClient(aws_private_keys)
    resolver_calls = []

    def resolver(reference, version):
        resolver_calls.append((reference, version))
        return AwsKmsVerificationTarget(
            approved_arn,
            frozenset({"RSASSA_PSS_SHA_256"}),
        )

    verifier = AwsKmsArtifactVerifier(client, resolver=resolver)

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(
                key_reference="alias/forged",
                key_version=forged_arn,
            ),
        )

    _assert_safe_error(caught.value)
    assert resolver_calls == [("alias/forged", forged_arn)]
    assert client.verify_calls == []


def test_aws_verifier_classifies_only_exact_client_exception_types(
    aws_private_keys,
):
    client = RecordingAwsKmsClient(
        aws_private_keys,
        mode="invalid_signature_subclass",
    )
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"wrong signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)


def test_aws_verifier_uses_closed_exact_botocore_client_error_codes(
    aws_private_keys,
    monkeypatch,
):
    class ClientError(Exception):
        def __init__(self, code):
            super().__init__("client error " + " | ".join(SENSITIVE_CORPUS))
            self.response = {"Error": {"Code": code}}

    botocore_module = ModuleType("botocore")
    exceptions_module = ModuleType("botocore.exceptions")
    exceptions_module.ClientError = ClientError
    botocore_module.exceptions = exceptions_module
    monkeypatch.setitem(sys.modules, "botocore", botocore_module)
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        exceptions_module,
    )

    for code in (
        "AccessDeniedException",
        "DependencyTimeoutException",
        "DisabledException",
        "InternalFailure",
        "KeyUnavailableException",
        "KMSInternalException",
        "KMSInvalidStateException",
        "NotFoundException",
        "NotAuthorized",
        "RequestTimeoutException",
        "ServiceUnavailable",
        "ThrottlingException",
    ):
        client = RecordingAwsKmsClient(aws_private_keys)
        client.verify_error = ClientError(code)
        verifier = AwsKmsArtifactVerifier(
            client,
            resolver=lambda _reference, _version: AwsKmsVerificationTarget(
                AWS_KEY_ARNS["RSA_2048"],
                frozenset({"RSASSA_PSS_SHA_256"}),
            ),
        )

        outcome = verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

        _assert_outcome(outcome, VerificationReasonCode.VERIFIER_UNAVAILABLE)

    for code in (
        "KMSInvalidSignatureException",
        "ValidationException",
        _StringSubclass("AccessDeniedException"),
    ):
        client = RecordingAwsKmsClient(aws_private_keys)
        client.verify_error = ClientError(code)
        verifier = AwsKmsArtifactVerifier(
            client,
            resolver=lambda _reference, _version: AwsKmsVerificationTarget(
                AWS_KEY_ARNS["RSA_2048"],
                frozenset({"RSASSA_PSS_SHA_256"}),
            ),
        )

        with pytest.raises(VerificationContractError) as caught:
            verifier.verify(
                b"payload",
                b64encode(b"signature").decode("ascii"),
                _aws_metadata(),
            )

        _assert_safe_error(caught.value)

    class NarrowClient:
        def __init__(self):
            self.verify_calls = []

        def verify(self, **kwargs):
            self.verify_calls.append(dict(kwargs))
            raise ClientError("ServiceUnavailable")

    client = NarrowClient()
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    outcome = verifier.verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )

    _assert_outcome(outcome, VerificationReasonCode.VERIFIER_UNAVAILABLE)
    assert len(client.verify_calls) == 1


def test_aws_verifier_rejects_a_spoofed_client_error_class(
    aws_private_keys,
):
    class ClientError(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}

    client = RecordingAwsKmsClient(aws_private_keys)
    client.verify_error = ClientError("spoofed " + SENSITIVE_CORPUS[0])
    verifier = AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )

    with pytest.raises(VerificationContractError) as caught:
        verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)


def test_aws_verifier_maps_only_exact_botocore_transport_types(
    aws_private_keys,
    monkeypatch,
):
    transport_types = _install_fake_botocore_transport(monkeypatch)
    endpoint = SENSITIVE_CORPUS[5]

    for exception_type in transport_types:
        client = RecordingAwsKmsClient(aws_private_keys)
        client.verify_error = exception_type(endpoint_url=endpoint)
        verifier = _aws_verifier_for_client(client)

        outcome = verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

        _assert_outcome(outcome, VerificationReasonCode.VERIFIER_UNAVAILABLE)
        assert outcome.message == "External verification is unavailable"
        assert endpoint not in str(outcome)
        assert endpoint not in repr(outcome)


def test_aws_verifier_rejects_botocore_transport_subclasses_and_lookalikes(
    aws_private_keys,
    monkeypatch,
):
    transport_types = _install_fake_botocore_transport(monkeypatch)
    exceptions_module = sys.modules["botocore.exceptions"]
    endpoint = SENSITIVE_CORPUS[5]
    failures = [
        type(
            exception_type.__name__,
            (exception_type,),
            {},
        )(endpoint_url=endpoint)
        for exception_type in transport_types
    ]
    failures.extend(
        (
            type(
                "ConnectTimeoutError",
                (Exception,),
                {},
            )("lookalike " + endpoint),
            exceptions_module.ConnectionError(
                endpoint_url=endpoint,
            ),
            exceptions_module.HTTPClientError(
                endpoint_url=endpoint,
            ),
            exceptions_module.ProxyConnectionError(
                endpoint_url=endpoint,
            ),
        )
    )

    for failure in failures:
        client = RecordingAwsKmsClient(aws_private_keys)
        client.verify_error = failure
        verifier = _aws_verifier_for_client(client)

        with pytest.raises(
            VerificationContractError,
            match=r"^AWS KMS verifier returned an invalid response$",
        ) as caught:
            verifier.verify(
                b"payload",
                b64encode(b"signature").decode("ascii"),
                _aws_metadata(),
            )

        _assert_safe_error(caught.value)


def test_aws_verifier_uses_real_botocore_transport_types_when_available(
    aws_private_keys,
):
    try:
        from botocore.exceptions import (
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        )
    except (ImportError, ModuleNotFoundError):
        pytest.skip("botocore is not installed in the base test environment")

    endpoint = SENSITIVE_CORPUS[5]
    for exception_type in (
        ConnectTimeoutError,
        ReadTimeoutError,
        EndpointConnectionError,
    ):
        client = RecordingAwsKmsClient(aws_private_keys)
        client.verify_error = exception_type(endpoint_url=endpoint)
        verifier = _aws_verifier_for_client(client)

        outcome = verifier.verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

        _assert_outcome(outcome, VerificationReasonCode.VERIFIER_UNAVAILABLE)


def test_aws_verifier_missing_botocore_keeps_concrete_classification_safe(
    aws_private_keys,
    monkeypatch,
):
    monkeypatch.setitem(sys.modules, "botocore", None)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", None)

    unavailable_client = RecordingAwsKmsClient(
        aws_private_keys,
        mode="dependency_timeout",
    )
    unavailable = _aws_verifier_for_client(unavailable_client).verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )

    _assert_outcome(
        unavailable,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
    )

    unexpected_client = RecordingAwsKmsClient(
        aws_private_keys,
        mode="unexpected_verify_failure",
    )
    with pytest.raises(VerificationContractError) as caught:
        _aws_verifier_for_client(unexpected_client).verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )

    _assert_safe_error(caught.value)


def test_aws_verifier_keeps_transport_service_and_crypto_errors_distinct(
    aws_private_keys,
    monkeypatch,
):
    transport_types = _install_fake_botocore_transport(monkeypatch)
    exceptions_module = sys.modules["botocore.exceptions"]

    transport_client = RecordingAwsKmsClient(aws_private_keys)
    transport_client.verify_error = transport_types[0](
        endpoint_url=SENSITIVE_CORPUS[5]
    )
    transport = _aws_verifier_for_client(transport_client).verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )
    _assert_outcome(transport, VerificationReasonCode.VERIFIER_UNAVAILABLE)

    service_client = RecordingAwsKmsClient(aws_private_keys)
    service_client.verify_error = exceptions_module.ClientError(
        "AccessDeniedException"
    )
    service = _aws_verifier_for_client(service_client).verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )
    _assert_outcome(service, VerificationReasonCode.VERIFIER_UNAVAILABLE)

    spoofed_crypto_client = RecordingAwsKmsClient(aws_private_keys)
    spoofed_crypto_client.verify_error = exceptions_module.ClientError(
        "KMSInvalidSignatureException"
    )
    with pytest.raises(VerificationContractError) as caught:
        _aws_verifier_for_client(spoofed_crypto_client).verify(
            b"payload",
            b64encode(b"signature").decode("ascii"),
            _aws_metadata(),
        )
    _assert_safe_error(caught.value)

    crypto_client = RecordingAwsKmsClient(
        aws_private_keys,
        mode="invalid_signature_exception",
    )
    crypto = _aws_verifier_for_client(crypto_client).verify(
        b"payload",
        b64encode(b"signature").decode("ascii"),
        _aws_metadata(),
    )
    _assert_outcome(crypto, VerificationReasonCode.SIGNATURE_INVALID)


def test_aws_verifier_runs_shared_external_verifier_conformance(
    aws_private_keys,
):
    arns = {
        "version/current": AWS_KEY_ARNS["RSA_2048"],
        "version/historical": (
            "arn:aws:kms:us-east-1:111122223333:key/"
            "11111111-1111-4111-8111-111111111111"
        ),
        "version/revoked": (
            "arn:aws:kms:us-east-1:111122223333:key/"
            "22222222-2222-4222-8222-222222222222"
        ),
        "version/invalid-anchor": (
            "arn:aws:kms:us-east-1:111122223333:key/"
            "33333333-3333-4333-8333-333333333333"
        ),
    }
    dispositions = {
        arns["version/current"]: KmsKeyDisposition.ANCHORED,
        arns["version/historical"]: KmsKeyDisposition.UNANCHORED,
        arns["version/revoked"]: KmsKeyDisposition.REVOKED,
        arns["version/invalid-anchor"]: KmsKeyDisposition.INVALID_ANCHOR,
    }

    def signed_artifact_factory(version):
        artifact = {
            "audit_schema_version": "1.4",
            "event": "AWS verifier conformance",
            "signature": None,
        }
        client = RecordingAwsKmsClient(
            aws_private_keys,
            key_arn=arns[version],
        )
        signer = _PayloadRecordingSigner(
            AwsKmsArtifactSigner(
                client,
                key_id="alias/audit",
                signing_algorithm="RSASSA_PSS_SHA_256",
            )
        )
        sign_artifact_with_metadata(artifact, signer, signed_at=123)
        return SignedArtifactFixture(artifact, signer.payloads[0])

    def verifier_factory(scenario):
        modes = {
            VerifierScenario.NORMAL: "normal",
            VerifierScenario.UNAVAILABLE: "dependency_timeout",
            VerifierScenario.MALFORMED: "malformed_verify",
            VerifierScenario.MALFORMED_COMBINATION: (
                "malformed_verify_validity"
            ),
            VerifierScenario.UNEXPECTED: "unexpected_verify_failure",
        }
        client = RecordingAwsKmsClient(
            aws_private_keys,
            mode=modes[scenario],
        )

        def resolver(reference, version):
            if reference != "alias/audit" or version not in dispositions:
                return None
            return AwsKmsVerificationTarget(
                version,
                frozenset({"RSASSA_PSS_SHA_256"}),
                dispositions[version],
            )

        return AwsKmsArtifactVerifier(client, resolver=resolver)

    assert_external_verifier_conformance(
        signed_artifact_factory,
        verifier_factory,
    )


def test_aws_verifier_concurrent_calls_keep_request_snapshots_isolated(
    aws_private_keys,
):
    first_arn = AWS_KEY_ARNS["RSA_2048"]
    second_arn = (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "44444444-4444-4444-8444-444444444444"
    )
    payloads = {
        first_arn: b"first concurrent payload",
        second_arn: b"second concurrent payload",
    }
    client = _BarrierAwsKmsClient(
        aws_private_keys,
        expected_payloads=payloads,
    )
    signatures = {
        key_arn: _aws_signature(client, payload)
        for key_arn, payload in payloads.items()
    }
    resolver_barrier = Barrier(2)

    def resolver(_reference, version):
        target = AwsKmsVerificationTarget(
            version,
            frozenset({"RSASSA_PSS_SHA_256"}),
            (
                KmsKeyDisposition.ANCHORED
                if version == first_arn
                else KmsKeyDisposition.UNANCHORED
            ),
        )
        resolver_barrier.wait()
        return target

    verifier = AwsKmsArtifactVerifier(client, resolver=resolver)
    original_state = (verifier._client, verifier._resolver)
    assert not hasattr(verifier, "__dict__")
    outcomes = {}
    failures = []
    lock = Lock()

    def verify_one(key_arn):
        try:
            outcome = verifier.verify(
                payloads[key_arn],
                signatures[key_arn],
                _aws_metadata(key_version=key_arn),
            )
            with lock:
                outcomes[key_arn] = outcome.reason_code
        except BaseException as error:
            with lock:
                failures.append(error)

    threads = [
        Thread(target=verify_one, args=(first_arn,)),
        Thread(target=verify_one, args=(second_arn,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert failures == []
    assert outcomes == {
        first_arn: VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        second_arn: VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
    }
    assert {
        (
            call["KeyId"],
            call["Message"],
            call["Signature"],
        )
        for call in client.verify_calls
    } == {
        (
            first_arn,
            sha256(payloads[first_arn]).digest(),
            b64decode(signatures[first_arn], validate=True),
        ),
        (
            second_arn,
            sha256(payloads[second_arn]).digest(),
            b64decode(signatures[second_arn], validate=True),
        ),
    }
    assert (verifier._client, verifier._resolver) == original_state
    assert not hasattr(verifier, "__dict__")


class _PayloadRecordingSigner:
    def __init__(self, signer):
        self.signer = signer
        self.payloads = []

    def signer_identity(self):
        return self.signer.signer_identity()

    def sign(self, payload, identity):
        self.payloads.append(payload)
        return self.signer.sign(payload, identity)


class _BarrierAwsKmsClient(RecordingAwsKmsClient):
    def __init__(self, private_keys, *, expected_payloads):
        super().__init__(private_keys)
        self.expected_payloads = dict(expected_payloads)
        self.verify_barrier = Barrier(2)

    def verify(self, **kwargs):
        self.verify_barrier.wait()
        return super().verify(**kwargs)


def _install_fake_botocore_transport(monkeypatch):
    class BotocoreError(Exception):
        def __init__(self, *, endpoint_url):
            self.endpoint_url = endpoint_url
            super().__init__(
                type(self).__name__ + " for " + endpoint_url
            )

    class ConnectionError(BotocoreError):
        pass

    class HTTPClientError(BotocoreError):
        pass

    class ConnectTimeoutError(ConnectionError):
        pass

    class ReadTimeoutError(HTTPClientError):
        pass

    class EndpointConnectionError(ConnectionError):
        pass

    class ProxyConnectionError(ConnectionError):
        pass

    class ClientError(Exception):
        def __init__(self, code):
            super().__init__("client error " + " | ".join(SENSITIVE_CORPUS))
            self.response = {"Error": {"Code": code}}

    botocore_module = ModuleType("botocore")
    exceptions_module = ModuleType("botocore.exceptions")
    exceptions_module.BotocoreError = BotocoreError
    exceptions_module.ConnectionError = ConnectionError
    exceptions_module.HTTPClientError = HTTPClientError
    exceptions_module.ConnectTimeoutError = ConnectTimeoutError
    exceptions_module.ReadTimeoutError = ReadTimeoutError
    exceptions_module.EndpointConnectionError = EndpointConnectionError
    exceptions_module.ProxyConnectionError = ProxyConnectionError
    exceptions_module.ClientError = ClientError
    botocore_module.exceptions = exceptions_module
    monkeypatch.setitem(sys.modules, "botocore", botocore_module)
    monkeypatch.setitem(
        sys.modules,
        "botocore.exceptions",
        exceptions_module,
    )
    return (
        ConnectTimeoutError,
        ReadTimeoutError,
        EndpointConnectionError,
    )


def _aws_verifier_for_client(client):
    return AwsKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: AwsKmsVerificationTarget(
            AWS_KEY_ARNS["RSA_2048"],
            frozenset({"RSASSA_PSS_SHA_256"}),
        ),
    )


def _aws_metadata(
    *,
    algorithm="RSASSA_PSS_SHA_256",
    key_reference="alias/audit-artifact",
    key_version=None,
):
    return SignatureMetadata(
        SIGNATURE_METADATA_SCHEMA_VERSION,
        SIGNING_PROFILE,
        CANONICALIZATION_VERSION,
        EvidenceType.AUDIT_ARTIFACT,
        algorithm,
        SignatureEncoding.BASE64,
        key_reference,
        AWS_KEY_ARNS["RSA_2048"] if key_version is None else key_version,
        123,
    )


def _aws_signature(client, payload):
    return b64encode(
        client._sign_digest(
            sha256(payload).digest(),
            "RSASSA_PSS_SHA_256",
        )
    ).decode("ascii")


def _assert_outcome(outcome, reason):
    expected = {
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
        ),
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
        ),
        VerificationReasonCode.ANCHOR_INVALID: (
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
        ),
        VerificationReasonCode.KEY_REVOKED: (
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
        ),
        VerificationReasonCode.KEY_UNKNOWN: (
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
        ),
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
        ),
        VerificationReasonCode.SIGNATURE_INVALID: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
        ),
        VerificationReasonCode.VERIFIER_UNAVAILABLE: (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
        ),
    }
    assert type(outcome) is ExternalVerificationOutcome
    assert (outcome.signature_status, outcome.anchor_status) == expected[reason]
    assert outcome.reason_code is reason
    rendered = "\n".join(
        (
            str(outcome),
            repr(outcome),
            outcome.message,
        )
    )
    for sensitive in SENSITIVE_CORPUS:
        assert sensitive not in rendered


def _assert_safe_error(error: BaseException, *, logs: str = "") -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert getattr(error, "details", {}) == {}
    rendered = "\n".join(
        (
            str(error),
            repr(error),
            repr(getattr(error, "details", {})),
            repr(error.__cause__),
            repr(error.__context__),
            logs,
        )
    )
    for sensitive in SENSITIVE_CORPUS:
        assert sensitive not in rendered
