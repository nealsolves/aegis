"""Strict offline coverage for the AWS KMS artifact signer."""

from __future__ import annotations

from base64 import b64decode, b64encode
from copy import deepcopy
from hashlib import sha256
import logging

import pytest

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations.aws_kms import (
    AwsKmsArtifactSigner,
    AwsKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    SignatureEncoding,
    SignerIdentity,
    SigningReceipt,
    sign_artifact_with_metadata,
)
from tests.signing_conformance import (
    SignerFixture,
    SignerScenario,
    assert_external_signer_conformance,
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


def test_aws_signer_exports_only_task_three_public_names():
    import aegis.integrations.aws_kms as aws_kms

    assert aws_kms.__all__ == [
        "AwsKmsArtifactSigner",
        "AwsKmsVerificationTarget",
    ]
    assert "AwsKmsArtifactVerifier" not in aws_kms.__dict__


def test_aws_verification_target_reconstructs_only_exact_trusted_builtins():
    target = AwsKmsVerificationTarget(
        AWS_KEY_ARNS["RSA_2048"],
        frozenset({"RSASSA_PSS_SHA_256"}),
    )

    assert target.key_arn == AWS_KEY_ARNS["RSA_2048"]
    assert target.allowed_algorithms == frozenset({"RSASSA_PSS_SHA_256"})
    assert target.disposition is KmsKeyDisposition.ANCHORED


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
