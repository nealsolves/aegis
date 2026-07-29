"""Strict offline coverage for Google Cloud KMS signing and verification."""

from __future__ import annotations

from base64 import b64decode, b64encode
import builtins
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
import logging
from threading import Barrier, Lock, Thread

import pytest

import tests.support.kms_fixtures as kms_fixtures
from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations.google_cloud_kms import (
    GoogleCloudKmsArtifactSigner,
    GoogleCloudKmsArtifactVerifier,
    GoogleCloudKmsVerificationTarget,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    EvidenceType,
    SignatureEncoding,
    SignatureMetadata,
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
    GOOGLE_ALGORITHMS,
    GOOGLE_KEY_VERSION_NAMES,
    RecordingGoogleCloudKmsClient,
    generate_google_private_keys,
    google_crc32c_value,
    install_copied_provenance_google_api_core,
    install_controlled_google_kms_modules,
    verify_google_signature,
)


@pytest.fixture(scope="module")
def google_private_keys():
    return generate_google_private_keys()


@pytest.fixture
def controlled_google_modules(monkeypatch):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    modules = install_controlled_google_kms_modules(monkeypatch)
    availability_types = google_cloud_kms._GoogleApiAvailabilityTypes(
        direct_types=(
            kms_fixtures.DeadlineExceeded,
            kms_fixtures.GatewayTimeout,
            kms_fixtures.ResourceExhausted,
            kms_fixtures.TooManyRequests,
            kms_fixtures.PermissionDenied,
            kms_fixtures.Forbidden,
            kms_fixtures.ServiceUnavailable,
            kms_fixtures.FailedPrecondition,
            kms_fixtures.NotFound,
        ),
        bad_request_type=kms_fixtures.BadRequest,
        retry_error_type=kms_fixtures.RetryError,
    )
    monkeypatch.setattr(
        google_cloud_kms,
        "_load_google_api_availability_types",
        lambda: availability_types,
    )
    modules.availability_types = availability_types
    return modules


class _StringSubclass(str):
    pass


class _BytesSubclass(bytes):
    pass


class _IntSubclass(int):
    pass


class _FloatSubclass(float):
    pass


class _SignerIdentitySubclass(SignerIdentity):
    pass


class _VerificationTargetSubclass(GoogleCloudKmsVerificationTarget):
    pass


def _parent_and_version(name):
    parent, version = name.rsplit("/cryptoKeyVersions/", 1)
    return parent, version


def _bounded_version_name(*, parent_length=512, version_length=128):
    parent_suffix = "/locations/l/keyRings/r/cryptoKeys/k"
    project = "p" * (parent_length - len("projects/") - len(parent_suffix))
    parent = "projects/" + project + parent_suffix
    name = parent + "/cryptoKeyVersions/" + "1" * version_length
    assert len(parent) == parent_length
    return name


def _version_name_with_segment(segment_index, segment):
    parts = [
        "projects",
        "p",
        "locations",
        "l",
        "keyRings",
        "r",
        "cryptoKeys",
        "k",
        "cryptoKeyVersions",
        "1",
    ]
    parts[segment_index] = segment
    return "/".join(parts)


def _assert_safe_error(error, *, logs=""):
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


def _google_metadata(algorithm, name):
    key_reference, key_version = _parent_and_version(name)
    return SignatureMetadata(
        SIGNATURE_METADATA_SCHEMA_VERSION,
        SIGNING_PROFILE,
        CANONICALIZATION_VERSION,
        EvidenceType.AUDIT_ARTIFACT,
        algorithm,
        SignatureEncoding.BASE64,
        key_reference,
        key_version,
        1_721_600_000,
    )


def _google_public_pem(private_key):
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _google_private_pem(private_key):
    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _google_signature(private_key, algorithm, payload):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    digest = sha256(payload).digest()
    if algorithm.startswith("RSA_SIGN_PSS_"):
        return private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
    return private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def _google_verifier(
    client,
    *,
    target,
    retry=kms_fixtures._GooglePublicKeyFormat,
    timeout=kms_fixtures._GooglePublicKeyFormat,
):
    kwargs = {}
    if retry is not kms_fixtures._GooglePublicKeyFormat:
        kwargs["retry"] = retry
    if timeout is not kms_fixtures._GooglePublicKeyFormat:
        kwargs["timeout"] = timeout
    return GoogleCloudKmsArtifactVerifier(
        client,
        resolver=lambda _reference, _version: target,
        **kwargs,
    )


def test_google_module_exports_only_currently_defined_public_types():
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    assert google_cloud_kms.__all__ == [
        "GoogleCloudKmsArtifactSigner",
        "GoogleCloudKmsArtifactVerifier",
        "GoogleCloudKmsVerificationTarget",
    ]
    assert "_USE_PROVIDER_DEFAULT" not in google_cloud_kms.__all__


def test_google_verification_target_is_a_frozen_public_value():
    name = GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
    target = GoogleCloudKmsVerificationTarget(
        name,
        "RSA_SIGN_PSS_2048_SHA256",
    )

    assert target.crypto_key_version_name == name
    assert target.algorithm == "RSA_SIGN_PSS_2048_SHA256"
    assert target.disposition is KmsKeyDisposition.ANCHORED
    assert target.public_key_pem is None
    with pytest.raises(FrozenInstanceError):
        target.algorithm = "EC_SIGN_P256_SHA256"


def test_google_signer_constructor_does_not_import_optional_dependencies(
    google_private_keys,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)

    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )

    assert client.get_version_calls == []
    assert client.asymmetric_sign_calls == []
    assert not hasattr(signer, "__dict__")


def test_google_signer_rejects_a_missing_injected_client():
    with pytest.raises(
        SigningContractError,
        match=r"^Google Cloud KMS signer configuration is invalid$",
    ) as caught:
        GoogleCloudKmsArtifactSigner(
            None,
            crypto_key_version_name=(
                GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
            ),
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    "name",
    [
        b"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        _StringSubclass(
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        ),
        "",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/extra",
        "project/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/location/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyrings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptokeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersion/1",
        "projects//locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations//keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings//cryptoKeys/k/cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptoKeys//cryptoKeyVersions/1",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/one two",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/unicodé",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1?x=2",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/..\\1",
        _bounded_version_name(parent_length=513, version_length=128),
        _bounded_version_name(parent_length=512, version_length=129),
    ],
)
def test_google_signer_rejects_noncanonical_or_unbounded_versions_before_calls(
    google_private_keys,
    name,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)

    with pytest.raises(
        SigningContractError,
        match=r"^Google Cloud KMS signer configuration is invalid$",
    ) as caught:
        GoogleCloudKmsArtifactSigner(
            client,
            crypto_key_version_name=name,
        )

    _assert_safe_error(caught.value)
    assert client.get_version_calls == []
    assert client.asymmetric_sign_calls == []


@pytest.mark.parametrize("segment_index", [1, 3, 5, 7, 9])
@pytest.mark.parametrize("segment", [".", ".."])
def test_google_signer_direct_constructor_rejects_standalone_dot_resource_segment(
    segment_index,
    segment,
):
    name = _version_name_with_segment(segment_index, segment)

    with pytest.raises(
        SigningContractError,
        match=r"^Google Cloud KMS signer configuration is invalid$",
    ) as caught:
        GoogleCloudKmsArtifactSigner(
            object(),
            crypto_key_version_name=name,
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize("segment_index", [1, 3, 5, 7, 9])
@pytest.mark.parametrize("segment", [".", ".."])
def test_google_signer_dot_resource_segment_fails_before_provider_calls(
    google_private_keys,
    segment_index,
    segment,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    name = _version_name_with_segment(segment_index, segment)

    with pytest.raises(SigningContractError) as caught:
        GoogleCloudKmsArtifactSigner(
            client,
            crypto_key_version_name=name,
        )

    _assert_safe_error(caught.value)
    assert client.get_version_calls == []
    assert client.asymmetric_sign_calls == []


@pytest.mark.parametrize("segment_index", [1, 3, 5, 7, 9])
@pytest.mark.parametrize("segment", [".a", "a.", "...", "a..b"])
def test_google_signer_preserves_permitted_dot_segment_near_misses_exactly(
    google_private_keys,
    controlled_google_modules,
    segment_index,
    segment,
):
    name = _version_name_with_segment(segment_index, segment)
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        crypto_key_version_name=name,
    )
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=name,
    )

    identity = signer.signer_identity()

    assert client.get_version_calls[0]["request"].name == name
    assert (
        identity.key_reference
        + "/cryptoKeyVersions/"
        + identity.key_version
        == name
    )


def test_controlled_google_version_states_match_the_audited_floor():
    assert {
        member.name: member.value
        for member in kms_fixtures._GoogleVersionState
    } == {
        "CRYPTO_KEY_VERSION_STATE_UNSPECIFIED": 0,
        "PENDING_GENERATION": 5,
        "ENABLED": 1,
        "DISABLED": 2,
        "DESTROYED": 3,
        "DESTROY_SCHEDULED": 4,
        "PENDING_IMPORT": 6,
        "IMPORT_FAILED": 7,
        "GENERATION_FAILED": 8,
        "PENDING_EXTERNAL_DESTRUCTION": 9,
        "EXTERNAL_DESTRUCTION_FAILED": 10,
    }


def test_controlled_google_version_states_match_actual_sdk_when_installed():
    kms_v1 = pytest.importorskip("google.cloud.kms_v1")
    actual_type = kms_v1.CryptoKeyVersion.CryptoKeyVersionState

    for controlled in kms_fixtures._GoogleVersionState:
        assert getattr(actual_type, controlled.name).value == controlled.value


def test_actual_google_enabled_state_forge_is_rejected_when_constructible():
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    kms_v1 = pytest.importorskip("google.cloud.kms_v1")
    version_type = kms_v1.CryptoKeyVersion
    enabled = version_type.CryptoKeyVersionState.ENABLED
    try:
        forged = int.__new__(type(enabled), int(enabled))
        forged._name_ = enabled.name
        forged._value_ = enabled.value
    except Exception:
        pytest.skip("installed SDK state enum does not permit forged instances")
    assert forged == enabled
    assert forged is not enabled

    with pytest.raises(ValueError):
        google_cloud_kms._normalize_crypto_key_version(
            kms_v1,
            type(
                "VersionResponse",
                (),
                {
                    "name": GOOGLE_KEY_VERSION_NAMES[
                        "RSA_SIGN_PSS_2048_SHA256"
                    ],
                    "state": forged,
                    "algorithm": (
                        version_type.CryptoKeyVersionAlgorithm
                        .RSA_SIGN_PSS_2048_SHA256
                    ),
                },
            )(),
            expected_name=GOOGLE_KEY_VERSION_NAMES[
                "RSA_SIGN_PSS_2048_SHA256"
            ],
        )


def test_google_signer_accepts_exact_resource_and_metadata_length_limits(
    google_private_keys,
    controlled_google_modules,
):
    name = _bounded_version_name(parent_length=512, version_length=128)
    assert len(name) == 659
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        crypto_key_version_name=name,
    )
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=name,
    )

    identity = signer.signer_identity()

    assert identity == SignerIdentity(
        "RSA_SIGN_PSS_2048_SHA256",
        SignatureEncoding.BASE64,
        name.rsplit("/cryptoKeyVersions/", 1)[0],
        "1" * 128,
    )


@pytest.mark.parametrize(
    "timeout",
    [
        True,
        False,
        0,
        -1,
        0.0,
        -0.5,
        float("nan"),
        float("inf"),
        float("-inf"),
        _IntSubclass(1),
        _FloatSubclass(1.0),
    ],
)
def test_google_signer_rejects_invalid_timeout_before_provider_calls(
    google_private_keys,
    timeout,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)

    with pytest.raises(SigningContractError, match=r"^timeout is invalid$") as caught:
        GoogleCloudKmsArtifactSigner(
            client,
            crypto_key_version_name=client.crypto_key_version_name,
            timeout=timeout,
        )

    _assert_safe_error(caught.value)
    assert client.get_version_calls == []
    assert client.asymmetric_sign_calls == []


@pytest.mark.parametrize("timeout", [1, 2.5])
def test_google_signer_forwards_exact_finite_positive_timeout_and_retry(
    google_private_keys,
    controlled_google_modules,
    timeout,
):
    retry = object()
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
        retry=retry,
        timeout=timeout,
    )

    identity = signer.signer_identity()
    signer.sign(b"payload", identity)

    for call in client.get_version_calls:
        assert call["retry"] is retry
        assert call["timeout"] is timeout
        assert set(call) == {"request", "retry", "timeout"}
    sign_call = client.asymmetric_sign_calls[0]
    assert sign_call["retry"] is retry
    assert sign_call["timeout"] is timeout
    assert set(sign_call) == {"request", "retry", "timeout"}


def test_google_signer_omits_default_retry_and_timeout_from_every_sdk_call(
    google_private_keys,
    controlled_google_modules,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )

    identity = signer.signer_identity()
    signer.sign(b"payload", identity)

    assert all(set(call) == {"request"} for call in client.get_version_calls)
    assert set(client.asymmetric_sign_calls[0]) == {"request"}


def test_google_signer_forwards_explicit_none_retry_and_timeout(
    google_private_keys,
    controlled_google_modules,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
        retry=None,
        timeout=None,
    )

    identity = signer.signer_identity()
    signer.sign(b"payload", identity)

    for call in client.get_version_calls + client.asymmetric_sign_calls:
        assert call["retry"] is None
        assert call["timeout"] is None
        assert set(call) == {"request", "retry", "timeout"}


@pytest.mark.parametrize("algorithm", GOOGLE_ALGORITHMS)
def test_google_signer_uses_exact_version_enum_digest_crc_and_valid_signature(
    google_private_keys,
    controlled_google_modules,
    algorithm,
):
    kms_v1 = controlled_google_modules.kms_v1
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        algorithm=algorithm,
    )
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    payload = b"\x00Google KMS exact payload\xff\n"

    identity = signer.signer_identity()
    receipt = signer.sign(payload, identity)

    parent, version = _parent_and_version(client.crypto_key_version_name)
    assert identity == SignerIdentity(
        algorithm,
        SignatureEncoding.BASE64,
        parent,
        version,
    )
    assert len(client.get_version_calls) == 2
    for call in client.get_version_calls:
        request = call["request"]
        assert type(request) is kms_v1.GetCryptoKeyVersionRequest
        assert request.name == client.crypto_key_version_name
        assert set(call) == {"request"}
    assert client.get_crypto_key_calls == []

    sign_call = client.asymmetric_sign_calls[0]
    request = sign_call["request"]
    expected_digest = sha256(payload).digest()
    assert type(request) is kms_v1.AsymmetricSignRequest
    assert request.name == client.crypto_key_version_name
    assert type(request.digest) is kms_v1.Digest
    assert request.digest.sha256 == expected_digest
    assert request.digest_crc32c == google_crc32c_value(expected_digest)
    assert set(sign_call) == {"request"}

    raw_signature = b64decode(receipt.signature, validate=True)
    assert receipt == SigningReceipt(
        b64encode(raw_signature).decode("ascii"),
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    assert verify_google_signature(
        google_private_keys[algorithm].public_key(),
        algorithm=algorithm,
        payload=payload,
        signature=raw_signature,
    )


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_name",
        "wrong_state",
        "forged_state",
        "wrong_algorithm",
        "algorithm_string",
        "algorithm_lookalike",
        "state_lookalike",
        "malformed_version",
        "provider_get_failure",
        "permission_get_failure",
        "unexpected_get_failure",
    ],
)
def test_google_signer_identity_rejects_malformed_or_unavailable_version_safely(
    google_private_keys,
    controlled_google_modules,
    mode,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys, mode=mode)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )

    with pytest.raises(
        SigningContractError,
        match=r"^Google Cloud KMS signer could not prepare identity$",
    ) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.get_crypto_key_calls == []
    assert client.asymmetric_sign_calls == []


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_name_second",
        "wrong_state_second",
        "forged_state_second",
        "wrong_algorithm_second",
        "changed_algorithm_second",
        "provider_sign_failure",
        "unexpected_sign_failure",
        "malformed_sign_response",
        "wrong_response_name",
        "unverified_digest",
        "nonbool_verified_digest",
        "missing_verified_digest",
        "empty_signature",
        "oversized_signature",
        "signature_subclass",
        "bad_signature_crc",
        "boolean_signature_crc",
        "negative_signature_crc",
        "oversized_signature_crc",
        "signature_crc_subclass",
        "missing_signature_crc",
    ],
)
def test_google_signer_rejects_checkpoint_or_response_failures_safely(
    google_private_keys,
    controlled_google_modules,
    mode,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    identity = signer.signer_identity()
    client.mode = mode

    with pytest.raises(
        ArtifactSigningError,
        match=r"^Google Cloud KMS signer could not produce a signature$",
    ) as caught:
        signer.sign(b"payload", identity)

    _assert_safe_error(caught.value)
    assert client.get_crypto_key_calls == []
    if mode in {
        "wrong_name_second",
        "wrong_state_second",
        "forged_state_second",
        "wrong_algorithm_second",
        "changed_algorithm_second",
    }:
        assert client.asymmetric_sign_calls == []


def test_google_signer_accepts_the_inclusive_raw_signature_limit(
    google_private_keys,
    controlled_google_modules,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    identity = signer.signer_identity()
    client.mode = "maximum_signature"

    receipt = signer.sign(b"payload", identity)

    assert b64decode(receipt.signature, validate=True) == b"x" * 12_288


@pytest.mark.parametrize(
    "payload",
    [
        bytearray(b"payload"),
        memoryview(b"payload"),
        "payload",
        _BytesSubclass(b"payload"),
    ],
)
def test_google_signer_rejects_non_exact_payload_before_second_lookup(
    google_private_keys,
    controlled_google_modules,
    payload,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    identity = signer.signer_identity()

    with pytest.raises(ArtifactSigningError) as caught:
        signer.sign(payload, identity)

    _assert_safe_error(caught.value)
    assert len(client.get_version_calls) == 1
    assert client.asymmetric_sign_calls == []


def test_google_signer_rejects_subclass_and_forged_identity_before_signing(
    google_private_keys,
    controlled_google_modules,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    identity = signer.signer_identity()
    forged_values = (
        _SignerIdentitySubclass(
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        ),
        SignerIdentity(
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference + "-forged",
            identity.key_version,
        ),
        SignerIdentity(
            "EC_SIGN_P256_SHA256",
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        ),
        SignerIdentity(
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version + "-forged",
        ),
    )

    for forged in forged_values:
        with pytest.raises(ArtifactSigningError) as caught:
            signer.sign(b"payload", forged)
        _assert_safe_error(caught.value)

    assert len(client.get_version_calls) == 2
    assert client.asymmetric_sign_calls == []


def test_google_signer_missing_optional_dependencies_fails_only_at_use_time(
    google_private_keys,
    monkeypatch,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    real_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"google.cloud", "google_crc32c"}:
            raise ModuleNotFoundError("secret provider import details")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)

    with pytest.raises(
        SigningContractError,
        match=r"^Google Cloud KMS signer could not prepare identity$",
    ) as caught:
        signer.signer_identity()

    _assert_safe_error(caught.value)
    assert client.get_version_calls == []


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_name",
        "wrong_state_second",
        "wrong_algorithm_second",
        "provider_get_failure",
        "unexpected_get_failure",
        "provider_sign_failure",
        "unexpected_sign_failure",
        "wrong_response_name",
        "unverified_digest",
        "bad_signature_crc",
        "missing_signature_crc",
        "oversized_signature",
    ],
)
def test_google_signing_failures_are_redacted_and_artifact_atomic(
    google_private_keys,
    controlled_google_modules,
    mode,
    caplog,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys, mode=mode)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    artifact = {
        "audit_schema_version": "1.4",
        "private": SENSITIVE_CORPUS[4],
        "signature": None,
    }
    snapshot = deepcopy(artifact)
    caplog.set_level(logging.DEBUG)

    with pytest.raises(ArtifactSigningError) as caught:
        sign_artifact_with_metadata(artifact, signer, signed_at=123)

    _assert_safe_error(caught.value, logs=caplog.text)
    assert artifact == snapshot


def test_google_signer_has_no_per_call_mutable_state_under_concurrency(
    google_private_keys,
    controlled_google_modules,
):
    class BarrierClient(RecordingGoogleCloudKmsClient):
        def __init__(self, private_keys):
            super().__init__(private_keys)
            self.barrier = Barrier(2)

        def asymmetric_sign(self, **kwargs):
            self.barrier.wait()
            return super().asymmetric_sign(**kwargs)

    client = BarrierClient(google_private_keys)
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=client.crypto_key_version_name,
    )
    identity = signer.signer_identity()
    payloads = (b"concurrent Google payload one", b"concurrent Google payload two")
    receipts = {}
    failures = []
    lock = Lock()

    def worker(payload):
        try:
            receipt = signer.sign(payload, identity)
            with lock:
                receipts[payload] = receipt
        except BaseException as error:
            with lock:
                failures.append(error)

    threads = [Thread(target=worker, args=(payload,)) for payload in payloads]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert set(receipts) == set(payloads)
    assert {
        call["request"].digest.sha256
        for call in client.asymmetric_sign_calls
    } == {sha256(payload).digest() for payload in payloads}
    for payload, receipt in receipts.items():
        assert verify_google_signature(
            google_private_keys["RSA_SIGN_PSS_2048_SHA256"].public_key(),
            algorithm=receipt.algorithm,
            payload=payload,
            signature=b64decode(receipt.signature, validate=True),
        )
    assert not hasattr(signer, "__dict__")


def test_google_signer_runs_shared_randomized_signing_conformance(
    google_private_keys,
    controlled_google_modules,
):
    class ScenarioSigner:
        def __init__(self, signer, scenario):
            self.signer = signer
            self.scenario = scenario
            self.payloads = []

        def signer_identity(self):
            if self.scenario is SignerScenario.MALFORMED_IDENTITY:
                return object()
            return self.signer.signer_identity()

        def sign(self, payload, identity):
            self.payloads.append(payload)
            if self.scenario is SignerScenario.MALFORMED_RECEIPT:
                return object()
            return self.signer.sign(payload, identity)

    def signer_factory(scenario):
        modes = {
            SignerScenario.NORMAL: "normal",
            SignerScenario.IDENTITY_ERROR: "provider_get_failure",
            SignerScenario.IDENTITY_UNEXPECTED: "unexpected_get_failure",
            SignerScenario.MALFORMED_IDENTITY: "normal",
            SignerScenario.SIGNING_ERROR: "provider_sign_failure",
            SignerScenario.SIGNING_UNEXPECTED: "unexpected_sign_failure",
            SignerScenario.MALFORMED_RECEIPT: "normal",
        }
        client = RecordingGoogleCloudKmsClient(
            google_private_keys,
            mode=modes[scenario],
        )
        google_signer = GoogleCloudKmsArtifactSigner(
            client,
            crypto_key_version_name=client.crypto_key_version_name,
        )
        signer = ScenarioSigner(google_signer, scenario)

        def verify_signature(payload, receipt):
            try:
                raw_signature = b64decode(receipt.signature, validate=True)
            except Exception:
                return False
            return verify_google_signature(
                google_private_keys["RSA_SIGN_PSS_2048_SHA256"].public_key(),
                algorithm=receipt.algorithm,
                payload=payload,
                signature=raw_signature,
            )

        return SignerFixture(
            signer,
            lambda: tuple(signer.payloads),
            verify_signature,
        )

    assert_external_signer_conformance(signer_factory)


def test_google_signer_uses_real_sdk_request_types_when_extra_is_installed(
    google_private_keys,
):
    kms_v1 = pytest.importorskip("google.cloud.kms_v1")
    google_crc32c = pytest.importorskip("google_crc32c")
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    private_key = google_private_keys[algorithm]

    class RealSdkShapeClient:
        def __init__(self):
            self.get_version_calls = []
            self.asymmetric_sign_calls = []

        def get_crypto_key_version(self, **kwargs):
            self.get_version_calls.append(dict(kwargs))
            return kms_v1.CryptoKeyVersion(
                name=name,
                state=kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED,
                algorithm=getattr(
                    kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm,
                    algorithm,
                ),
            )

        def asymmetric_sign(self, **kwargs):
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, utils

            self.asymmetric_sign_calls.append(dict(kwargs))
            request = kwargs["request"]
            signature = private_key.sign(
                request.digest.sha256,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
            checksum = google_crc32c.Checksum(signature)
            return kms_v1.AsymmetricSignResponse(
                name=name,
                signature=signature,
                signature_crc32c=int.from_bytes(checksum.digest(), "big"),
                verified_digest_crc32c=True,
            )

    client = RealSdkShapeClient()
    signer = GoogleCloudKmsArtifactSigner(
        client,
        crypto_key_version_name=name,
    )

    identity = signer.signer_identity()
    signer.sign(b"real SDK request surface", identity)

    assert all(
        type(call["request"]) is kms_v1.GetCryptoKeyVersionRequest
        for call in client.get_version_calls
    )
    request = client.asymmetric_sign_calls[0]["request"]
    assert type(request) is kms_v1.AsymmetricSignRequest
    assert type(request.digest) is kms_v1.Digest


def test_google_module_exports_signer_verifier_and_target_only():
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    assert google_cloud_kms.__all__ == [
        "GoogleCloudKmsArtifactSigner",
        "GoogleCloudKmsArtifactVerifier",
        "GoogleCloudKmsVerificationTarget",
    ]


@pytest.mark.parametrize("algorithm", GOOGLE_ALGORITHMS)
def test_google_target_accepts_exact_algorithm_correct_public_pem(
    google_private_keys,
    algorithm,
):
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    pem = _google_public_pem(google_private_keys[algorithm])

    target = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        KmsKeyDisposition.UNANCHORED,
        pem,
    )

    assert target == GoogleCloudKmsVerificationTarget(
        crypto_key_version_name=name,
        algorithm=algorithm,
        disposition=KmsKeyDisposition.UNANCHORED,
        public_key_pem=pem,
    )


def test_google_target_repr_does_not_expose_resource_or_retained_pem(
    google_private_keys,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    pem = _google_public_pem(google_private_keys[algorithm])
    target = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        public_key_pem=pem,
    )

    rendered = repr(target)

    assert name not in rendered
    assert pem.decode("ascii") not in rendered


def test_google_target_rejects_forged_exact_disposition_instances():
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]

    for value in ("anchored", "revoked", "unknown"):
        forged = str.__new__(KmsKeyDisposition, value)

        with pytest.raises(
            VerificationContractError,
            match=r"^Google Cloud KMS verification target is invalid$",
        ) as caught:
            GoogleCloudKmsVerificationTarget(
                name,
                algorithm,
                forged,
            )

        _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("crypto_key_version_name", _StringSubclass(
            GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
        )),
        ("crypto_key_version_name", "not-a-version"),
        ("algorithm", _StringSubclass("RSA_SIGN_PSS_2048_SHA256")),
        ("algorithm", "RSA_SIGN_PKCS1_2048_SHA256"),
        ("disposition", "anchored"),
        ("public_key_pem", b""),
        ("public_key_pem", b"x" * 65_537),
        ("public_key_pem", _BytesSubclass(b"public")),
        ("public_key_pem", "public"),
    ],
)
def test_google_target_rejects_nonexact_or_invalid_fields(
    field,
    value,
):
    fields = {
        "crypto_key_version_name": (
            GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
        ),
        "algorithm": "RSA_SIGN_PSS_2048_SHA256",
        "disposition": KmsKeyDisposition.ANCHORED,
        "public_key_pem": None,
    }
    fields[field] = value

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verification target is invalid$",
    ) as caught:
        GoogleCloudKmsVerificationTarget(**fields)

    _assert_safe_error(caught.value)


def test_google_target_rejects_private_malformed_and_wrong_key_pem(
    google_private_keys,
):
    rsa_name = GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
    invalid_pems = (
        _google_private_pem(
            google_private_keys["RSA_SIGN_PSS_2048_SHA256"]
        ),
        b"-----BEGIN PUBLIC KEY-----\nmalformed\n-----END PUBLIC KEY-----\n",
        _google_public_pem(
            google_private_keys["EC_SIGN_P256_SHA256"]
        ),
    )

    for pem in invalid_pems:
        with pytest.raises(VerificationContractError) as caught:
            GoogleCloudKmsVerificationTarget(
                rsa_name,
                "RSA_SIGN_PSS_2048_SHA256",
                public_key_pem=pem,
            )
        _assert_safe_error(caught.value)


def test_google_target_rejects_wrong_rsa_size_and_non_p256_curves():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    rsa_name = GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
    wrong_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    with pytest.raises(VerificationContractError):
        GoogleCloudKmsVerificationTarget(
            rsa_name,
            "RSA_SIGN_PSS_2048_SHA256",
            public_key_pem=_google_public_pem(wrong_rsa),
        )

    ec_name = GOOGLE_KEY_VERSION_NAMES["EC_SIGN_P256_SHA256"]
    for curve in (ec.SECP384R1(), ec.SECP521R1(), ec.SECP256K1()):
        wrong_ec = ec.generate_private_key(curve)
        with pytest.raises(VerificationContractError):
            GoogleCloudKmsVerificationTarget(
                ec_name,
                "EC_SIGN_P256_SHA256",
                public_key_pem=_google_public_pem(wrong_ec),
            )


def test_google_verifier_constructor_is_lazy_frozen_and_accepts_historical_only():
    verifier = GoogleCloudKmsArtifactVerifier(
        None,
        resolver=lambda _reference, _version: None,
    )

    assert not hasattr(verifier, "__dict__")
    with pytest.raises(FrozenInstanceError):
        verifier._client = object()


@pytest.mark.parametrize("resolver", [None, object()])
def test_google_verifier_rejects_noncallable_resolver(resolver):
    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier configuration is invalid$",
    ) as caught:
        GoogleCloudKmsArtifactVerifier(None, resolver=resolver)

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    "timeout",
    [
        True,
        False,
        0,
        -1,
        0.0,
        float("nan"),
        float("inf"),
        _IntSubclass(1),
        _FloatSubclass(1.0),
    ],
)
def test_google_verifier_rejects_invalid_timeout(timeout):
    with pytest.raises(VerificationContractError, match=r"^timeout is invalid$"):
        GoogleCloudKmsArtifactVerifier(
            None,
            resolver=lambda _reference, _version: None,
            timeout=timeout,
        )


@pytest.mark.parametrize("algorithm", GOOGLE_ALGORITHMS)
def test_google_verifier_uses_retained_public_key_without_google_sdk(
    google_private_keys,
    algorithm,
):
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"retained Google public key payload\x00exact"
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )
    target = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        public_key_pem=_google_public_pem(google_private_keys[algorithm]),
    )
    verifier = _google_verifier(None, target=target)

    outcome = verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED


def test_google_verifier_reports_unavailable_when_no_retained_key_or_client(
    google_private_keys,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"historical lookup unavailable"
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )
    verifier = _google_verifier(
        None,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    outcome = verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE


def test_google_verifier_returns_revoked_before_pem_parsing_or_provider(
    google_private_keys,
    monkeypatch,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    target = object.__new__(GoogleCloudKmsVerificationTarget)
    object.__setattr__(target, "crypto_key_version_name", name)
    object.__setattr__(target, "algorithm", algorithm)
    object.__setattr__(target, "disposition", KmsKeyDisposition.REVOKED)
    object.__setattr__(target, "public_key_pem", b"not public pem")
    client = RecordingGoogleCloudKmsClient(google_private_keys)

    def fail_if_parsed(*_args, **_kwargs):
        raise AssertionError("revoked PEM must not be parsed")

    from cryptography.hazmat.primitives import serialization

    monkeypatch.setattr(
        serialization,
        "load_pem_public_key",
        fail_if_parsed,
    )
    verifier = _google_verifier(client, target=target)

    outcome = verifier.verify(
        b"revoked payload",
        b64encode(b"signature").decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.KEY_REVOKED
    assert client.get_public_key_calls == []


def test_google_verifier_checks_unsupported_algorithm_before_resolver():
    calls = []
    algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES["RSA_SIGN_PSS_2048_SHA256"]
    verifier = GoogleCloudKmsArtifactVerifier(
        None,
        resolver=lambda reference, version: calls.append(
            (reference, version)
        ),
    )

    outcome = verifier.verify(
        b"unsupported algorithm",
        b64encode(b"signature").decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.ALGORITHM_NOT_ALLOWED
    assert calls == []


def test_google_verifier_rejects_noncanonical_signature_before_resolver():
    calls = []
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    verifier = GoogleCloudKmsArtifactVerifier(
        None,
        resolver=lambda reference, version: calls.append(
            (reference, version)
        ),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verification request is invalid$",
    ):
        verifier.verify(
            b"invalid signature",
            b64encode(b"x" * 12_289).decode("ascii"),
            _google_metadata(algorithm, name),
        )

    assert calls == []


def test_google_verifier_maps_none_resolver_to_unknown():
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    verifier = GoogleCloudKmsArtifactVerifier(
        None,
        resolver=lambda _reference, _version: None,
    )

    outcome = verifier.verify(
        b"unknown",
        b64encode(b"signature").decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.KEY_UNKNOWN


def test_google_verifier_sanitizes_resolver_failures():
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]

    def fail(_reference, _version):
        raise RuntimeError("resolver " + " | ".join(SENSITIVE_CORPUS))

    verifier = GoogleCloudKmsArtifactVerifier(None, resolver=fail)

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS resolver failed$",
    ) as caught:
        verifier.verify(
            b"resolver failure",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    "resolved_factory",
    [
        lambda target: object(),
        lambda target: _VerificationTargetSubclass(
            target.crypto_key_version_name,
            target.algorithm,
        ),
    ],
)
def test_google_verifier_rejects_lookalike_or_subclass_targets(
    resolved_factory,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    target = GoogleCloudKmsVerificationTarget(name, algorithm)
    verifier = _google_verifier(
        None,
        target=resolved_factory(target),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS resolver returned an invalid target$",
    ) as caught:
        verifier.verify(
            b"hostile target",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_rejects_forged_disposition_before_pem_or_provider(
    google_private_keys,
    monkeypatch,
):
    from cryptography.hazmat.primitives import serialization

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    resolved = object.__new__(GoogleCloudKmsVerificationTarget)
    object.__setattr__(resolved, "crypto_key_version_name", name)
    object.__setattr__(resolved, "algorithm", algorithm)
    object.__setattr__(
        resolved,
        "disposition",
        str.__new__(KmsKeyDisposition, "anchored"),
    )
    object.__setattr__(
        resolved,
        "public_key_pem",
        _google_public_pem(google_private_keys[algorithm]),
    )
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    real_load = serialization.load_pem_public_key
    parse_calls = []

    def record_parse(*args, **kwargs):
        parse_calls.append(args[0])
        return real_load(*args, **kwargs)

    monkeypatch.setattr(
        serialization,
        "load_pem_public_key",
        record_parse,
    )
    verifier = _google_verifier(client, target=resolved)

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS resolver returned an invalid target$",
    ) as caught:
        verifier.verify(
            b"forged disposition",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)
    assert parse_calls == []
    assert client.get_public_key_calls == []


@pytest.mark.parametrize("mismatch", ["parent", "version"])
def test_google_verifier_rejects_target_identity_mismatch(mismatch):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    metadata_name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    parts = metadata_name.split("/")
    if mismatch == "parent":
        parts[1] = "other-project"
    else:
        parts[-1] = "99"
    target = GoogleCloudKmsVerificationTarget("/".join(parts), algorithm)
    verifier = _google_verifier(None, target=target)

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS resolver returned an invalid target$",
    ):
        verifier.verify(
            b"identity mismatch",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, metadata_name),
        )


def test_google_verifier_returns_algorithm_denied_for_target_mismatch():
    metadata_algorithm = "RSA_SIGN_PSS_2048_SHA256"
    target_algorithm = "RSA_SIGN_PSS_3072_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[metadata_algorithm]
    target = GoogleCloudKmsVerificationTarget(name, target_algorithm)
    verifier = _google_verifier(None, target=target)

    outcome = verifier.verify(
        b"algorithm denied",
        b64encode(b"signature").decode("ascii"),
        _google_metadata(metadata_algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.ALGORITHM_NOT_ALLOWED


@pytest.mark.parametrize("algorithm", GOOGLE_ALGORITHMS)
def test_google_verifier_fetches_checksummed_public_key_and_verifies(
    google_private_keys,
    controlled_google_modules,
    algorithm,
):
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"fetched Google public key payload\x00exact"
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        algorithm=algorithm,
    )
    target = GoogleCloudKmsVerificationTarget(name, algorithm)
    verifier = _google_verifier(client, target=target)
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )

    outcome = verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED
    call = client.get_public_key_calls[0]
    assert set(call) == {"request"}
    request = call["request"]
    assert type(request) is controlled_google_modules.kms_v1.GetPublicKeyRequest
    assert request.name == name
    assert (
        request.public_key_format
        is controlled_google_modules.kms_v1.PublicKey.PublicKeyFormat.PEM
    )


def test_controlled_google_public_key_response_uses_exact_sdk_shapes(
    google_private_keys,
    controlled_google_modules,
):
    client = RecordingGoogleCloudKmsClient(google_private_keys)

    response = client.get_public_key(request=object())
    version_type = controlled_google_modules.kms_v1.CryptoKeyVersion
    algorithm_type = version_type.CryptoKeyVersionAlgorithm

    assert type(response) is controlled_google_modules.kms_v1.PublicKey
    assert (
        type(response.public_key)
        is controlled_google_modules.kms_v1.ChecksummedData
    )
    assert (
        response.algorithm
        is algorithm_type.RSA_SIGN_PSS_2048_SHA256
    )
    assert (
        response.public_key_format
        is controlled_google_modules.kms_v1.PublicKey.PublicKeyFormat.PEM
    )


@pytest.mark.parametrize("timeout", [None, 1, 2.5])
def test_google_verifier_forwards_explicit_retry_and_timeout(
    google_private_keys,
    controlled_google_modules,
    timeout,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(google_private_keys)
    retry = object()
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
        retry=retry,
        timeout=timeout,
    )
    payload = b"retry timeout"
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )

    verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    call = client.get_public_key_calls[0]
    assert set(call) == {"request", "retry", "timeout"}
    assert call["retry"] is retry
    assert call["timeout"] is timeout


@pytest.mark.parametrize(
    "mode",
    [
        "wrong_public_key_name",
        "wrong_public_key_algorithm",
        "public_key_algorithm_string",
        "public_key_algorithm_lookalike",
        "forged_public_key_algorithm",
        "wrong_public_key_format",
        "public_key_format_string",
        "public_key_format_lookalike",
        "forged_public_key_format",
        "public_key_response_duck",
        "public_key_response_subclass",
        "checksummed_data_duck",
        "checksummed_data_subclass",
        "empty_public_key",
        "oversized_public_key",
        "public_key_subclass",
        "bad_public_key_crc",
        "boolean_public_key_crc",
        "negative_public_key_crc",
        "oversized_public_key_crc",
        "public_key_crc_subclass",
        "legacy_public_key_only",
        "missing_public_key_crc",
        "wrong_public_key_type",
        "malformed_public_key_response",
        "unexpected_public_key",
    ],
)
def test_google_verifier_rejects_malformed_or_unexpected_public_keys(
    google_private_keys,
    controlled_google_modules,
    mode,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        mode=mode,
    )
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"malformed provider response " + SENSITIVE_CORPUS[4].encode(),
            b64encode(b"signature-" + SENSITIVE_CORPUS[3].encode()).decode(
                "ascii"
            ),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


@pytest.mark.parametrize(
    "mode",
    [
        "deadline_public_key",
        "gateway_timeout_public_key",
        "failed_precondition_public_key",
        "not_found_public_key",
        "permission_public_key",
        "forbidden_public_key",
        "resource_exhausted_public_key",
        "too_many_requests_public_key",
        "unavailable_public_key",
        "retry_deadline_public_key",
        "bad_request_failed_precondition",
    ],
)
def test_google_verifier_maps_closed_provider_availability_errors(
    google_private_keys,
    controlled_google_modules,
    mode,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        mode=mode,
    )
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    outcome = verifier.verify(
        b"provider unavailable",
        b64encode(b"signature").decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE


def test_controlled_google_api_errors_are_injected_as_canonical_loader_result(
    controlled_google_modules,
):
    exceptions = controlled_google_modules.api_exceptions
    availability_types = controlled_google_modules.availability_types
    names = (
        "DeadlineExceeded",
        "GatewayTimeout",
        "ResourceExhausted",
        "TooManyRequests",
        "PermissionDenied",
        "Forbidden",
        "ServiceUnavailable",
        "FailedPrecondition",
        "NotFound",
        "BadRequest",
        "RetryError",
    )

    for name in names:
        candidate = getattr(exceptions, name)
        assert candidate in (
            availability_types.direct_types
            + (
                availability_types.bad_request_type,
                availability_types.retry_error_type,
            )
        )
    assert type(exceptions.DeadlineExceeded) is not type


def test_google_api_exception_spoof_without_distribution_provenance_is_rejected(
    monkeypatch,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    install_controlled_google_kms_modules(
        monkeypatch,
        install_api_core_spoof=True,
    )

    assert google_cloud_kms._is_google_availability_error(
        kms_fixtures.DeadlineExceeded("spoofed " + SENSITIVE_CORPUS[0])
    ) is False


def test_google_api_exception_spoof_with_copied_provenance_is_rejected(
    monkeypatch,
    tmp_path,
):
    import importlib.metadata
    import importlib.util

    import aegis.integrations.google_cloud_kms as google_cloud_kms

    spoof = install_copied_provenance_google_api_core(
        monkeypatch,
        tmp_path,
    )
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda _name: spoof.spec,
    )
    monkeypatch.setattr(
        importlib.metadata,
        "distribution",
        lambda _name: spoof.distribution,
    )

    assert google_cloud_kms._is_google_availability_error(
        spoof.exceptions.DeadlineExceeded(
            "copied provenance " + SENSITIVE_CORPUS[0]
        )
    ) is False


@pytest.mark.parametrize("provider_error_kind", ["direct", "retry"])
def test_google_availability_classification_never_calls_class_equality(
    google_private_keys,
    controlled_google_modules,
    monkeypatch,
    provider_error_kind,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    equality_calls = []

    class EqualityBombMeta(type):
        def __eq__(cls, other):
            equality_calls.append((cls, other))
            raise AssertionError("class equality must not run")

        __hash__ = type.__hash__

    bomb_types = tuple(
        EqualityBombMeta(
            f"CanonicalAvailability{index}",
            (Exception,),
            {},
        )
        for index in range(11)
    )
    availability_types = google_cloud_kms._GoogleApiAvailabilityTypes(
        direct_types=bomb_types[:9],
        bad_request_type=bomb_types[9],
        retry_error_type=bomb_types[10],
    )
    monkeypatch.setattr(
        google_cloud_kms,
        "_load_google_api_availability_types",
        lambda: availability_types,
    )

    class UnexpectedProviderError(Exception):
        pass

    provider_error = UnexpectedProviderError(SENSITIVE_CORPUS[1])
    if provider_error_kind == "retry":
        provider_error = bomb_types[10]("retry " + SENSITIVE_CORPUS[1])
        provider_error.cause = UnexpectedProviderError(SENSITIVE_CORPUS[2])

    class Client:
        def get_public_key(self, **_kwargs):
            raise provider_error

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    verifier = _google_verifier(
        Client(),
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"equality bomb",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)
    assert equality_calls == []


def test_google_verifier_sanitizes_unprovenanced_spoof_without_chaining(
    google_private_keys,
    monkeypatch,
):
    install_controlled_google_kms_modules(
        monkeypatch,
        install_api_core_spoof=True,
    )
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        mode="deadline_public_key",
    )
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"unprovenanced provider exception",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "attribute",
    ["__spec__", "__file__", "GoogleAPICallError"],
)
def test_google_api_exception_loader_fails_closed_on_exploding_module_state(
    monkeypatch,
    attribute,
):
    import importlib.machinery
    import importlib.metadata
    import importlib.util
    from pathlib import Path
    from types import ModuleType

    import aegis.integrations.google_cloud_kms as google_cloud_kms

    module_path = Path(google_cloud_kms.__file__).resolve()
    loader = importlib.machinery.SourceFileLoader(
        "google.api_core.exceptions",
        str(module_path),
    )
    spec = importlib.util.spec_from_file_location(
        "google.api_core.exceptions",
        module_path,
        loader=loader,
    )
    assert spec is not None

    class ExplodingModule(ModuleType):
        def __getattribute__(self, name):
            if name == attribute:
                raise RuntimeError("exploding " + SENSITIVE_CORPUS[1])
            return super().__getattribute__(name)

    exceptions = ExplodingModule("google.api_core.exceptions")
    exceptions.__package__ = "google.api_core"
    exceptions.__file__ = str(module_path)
    exceptions.__spec__ = spec
    exceptions.__loader__ = loader

    class Distribution:
        metadata = {"Name": "google-api-core"}
        files = ("google/api_core/exceptions.py",)

        def locate_file(self, _entry):
            return module_path

    monkeypatch.setattr(
        google_cloud_kms,
        "_import_google_api_exceptions",
        lambda: exceptions,
    )
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: spec)
    monkeypatch.setattr(
        importlib.metadata,
        "distribution",
        lambda _name: Distribution(),
    )

    assert google_cloud_kms._is_google_availability_error(
        RuntimeError(SENSITIVE_CORPUS[2])
    ) is False


@pytest.mark.parametrize("stage", ["find_spec", "distribution"])
def test_google_api_exception_loader_fails_closed_on_exploding_provenance(
    monkeypatch,
    stage,
):
    import importlib.machinery
    import importlib.metadata
    import importlib.util
    from pathlib import Path
    from types import ModuleType

    import aegis.integrations.google_cloud_kms as google_cloud_kms

    module_path = Path(google_cloud_kms.__file__).resolve()
    loader = importlib.machinery.SourceFileLoader(
        "google.api_core.exceptions",
        str(module_path),
    )
    spec = importlib.util.spec_from_file_location(
        "google.api_core.exceptions",
        module_path,
        loader=loader,
    )
    assert spec is not None
    exceptions = ModuleType("google.api_core.exceptions")
    exceptions.__package__ = "google.api_core"
    exceptions.__file__ = str(module_path)
    exceptions.__spec__ = spec
    exceptions.__loader__ = loader
    monkeypatch.setattr(
        google_cloud_kms,
        "_import_google_api_exceptions",
        lambda: exceptions,
    )

    def explode(_name):
        raise RuntimeError("exploding provenance " + SENSITIVE_CORPUS[2])

    if stage == "find_spec":
        monkeypatch.setattr(importlib.util, "find_spec", explode)
    else:
        monkeypatch.setattr(importlib.util, "find_spec", lambda _name: spec)
        monkeypatch.setattr(importlib.metadata, "distribution", explode)

    assert google_cloud_kms._is_google_availability_error(
        RuntimeError(SENSITIVE_CORPUS[3])
    ) is False


def test_google_api_exception_loader_returns_empty_result_on_ordinary_failure(
    monkeypatch,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    def explode():
        raise RuntimeError("loader failure " + SENSITIVE_CORPUS[0])

    monkeypatch.setattr(
        google_cloud_kms,
        "_import_google_api_exceptions",
        explode,
    )

    assert google_cloud_kms._load_google_api_availability_types() is None


def test_google_api_exception_loader_rejects_malformed_canonical_classes(
    monkeypatch,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    monkeypatch.setattr(
        google_cloud_kms,
        "_load_google_api_availability_types",
        lambda: google_cloud_kms._GoogleApiAvailabilityTypes(
            direct_types=(object,),
            bad_request_type=object,
            retry_error_type=object,
        ),
    )

    assert google_cloud_kms._is_google_availability_error(
        RuntimeError(SENSITIVE_CORPUS[3])
    ) is False


@pytest.mark.parametrize(
    "mode",
    [
        "retry_unexpected_public_key",
        "bad_request_invalid_argument",
        "bad_request_missing_status",
        "bad_request_malformed_payload",
    ],
)
def test_google_verifier_rejects_unlisted_retry_and_bad_request_failures(
    google_private_keys,
    controlled_google_modules,
    mode,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        mode=mode,
    )
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"narrow Google API failure " + SENSITIVE_CORPUS[4].encode(),
            b64encode(b"signature-" + SENSITIVE_CORPUS[3].encode()).decode(
                "ascii"
            ),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_actual_google_api_exception_classes_have_audited_identity_when_installed():
    exceptions = pytest.importorskip("google.api_core.exceptions")

    for name in (
        "DeadlineExceeded",
        "GatewayTimeout",
        "ResourceExhausted",
        "TooManyRequests",
        "PermissionDenied",
        "Forbidden",
        "ServiceUnavailable",
        "FailedPrecondition",
        "NotFound",
        "BadRequest",
        "RetryError",
    ):
        candidate = getattr(exceptions, name)
        assert isinstance(candidate, type)
        assert candidate.__module__ == "google.api_core.exceptions"
        assert candidate.__name__ == name
    assert type(exceptions.FailedPrecondition) is not type


def test_actual_google_api_availability_classification_when_installed():
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    exceptions = pytest.importorskip("google.api_core.exceptions")
    direct_names = (
        "DeadlineExceeded",
        "GatewayTimeout",
        "ResourceExhausted",
        "TooManyRequests",
        "PermissionDenied",
        "Forbidden",
        "ServiceUnavailable",
        "FailedPrecondition",
        "NotFound",
    )
    for name in direct_names:
        error = getattr(exceptions, name)(
            "actual Google API " + SENSITIVE_CORPUS[0]
        )
        assert google_cloud_kms._is_google_availability_error(error) is True

    class Response:
        def __init__(self, status):
            self.status = status

        def json(self):
            return {
                "error": {
                    "status": self.status,
                    "message": SENSITIVE_CORPUS[1],
                },
            }

    failed_precondition = exceptions.BadRequest(
        "REST failed precondition " + SENSITIVE_CORPUS[2],
        response=Response("FAILED_PRECONDITION"),
    )
    invalid_argument = exceptions.BadRequest(
        "REST invalid argument " + SENSITIVE_CORPUS[2],
        response=Response("INVALID_ARGUMENT"),
    )
    retry_available = exceptions.RetryError(
        "retry " + SENSITIVE_CORPUS[3],
        exceptions.DeadlineExceeded(SENSITIVE_CORPUS[4]),
    )
    retry_unexpected = exceptions.RetryError(
        "retry " + SENSITIVE_CORPUS[3],
        RuntimeError(SENSITIVE_CORPUS[4]),
    )

    assert google_cloud_kms._is_google_availability_error(
        failed_precondition
    ) is True
    assert google_cloud_kms._is_google_availability_error(
        invalid_argument
    ) is False
    assert google_cloud_kms._is_google_availability_error(
        retry_available
    ) is True
    assert google_cloud_kms._is_google_availability_error(
        retry_unexpected
    ) is False


def test_actual_google_api_copied_provenance_spoof_is_rejected_when_installed(
    monkeypatch,
    tmp_path,
):
    import importlib.metadata
    import importlib.util

    import aegis.integrations.google_cloud_kms as google_cloud_kms

    exceptions = pytest.importorskip("google.api_core.exceptions")
    real_distribution = importlib.metadata.distribution("google-api-core")
    real_spec = exceptions.__spec__
    assert real_spec is not None
    spoof = install_copied_provenance_google_api_core(
        monkeypatch,
        tmp_path,
    )
    spoof.exceptions.__file__ = exceptions.__file__
    spoof.exceptions.__spec__ = real_spec
    spoof.exceptions.__loader__ = real_spec.loader
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda _name: real_spec,
    )
    monkeypatch.setattr(
        importlib.metadata,
        "distribution",
        lambda _name: real_distribution,
    )

    assert google_cloud_kms._is_google_availability_error(
        spoof.exceptions.DeadlineExceeded(SENSITIVE_CORPUS[0])
    ) is False


def test_actual_google_api_provenance_accepts_symlinked_module_path_when_installed(
    monkeypatch,
    tmp_path,
):
    import importlib.machinery
    import importlib.metadata
    import importlib.util
    from pathlib import Path
    from types import ModuleType

    import aegis.integrations.google_cloud_kms as google_cloud_kms

    exceptions = pytest.importorskip("google.api_core.exceptions")
    real_distribution = importlib.metadata.distribution("google-api-core")
    source_path = Path(exceptions.__file__).resolve()
    symlink_path = tmp_path / "google" / "api_core" / "exceptions.py"
    symlink_path.parent.mkdir(parents=True)
    symlink_path.symlink_to(source_path)
    loader = importlib.machinery.SourceFileLoader(
        "google.api_core.exceptions",
        str(symlink_path),
    )
    spec = importlib.util.spec_from_file_location(
        "google.api_core.exceptions",
        symlink_path,
        loader=loader,
    )
    assert spec is not None
    wrapper = ModuleType("google.api_core.exceptions")
    wrapper.__package__ = "google.api_core"
    wrapper.__file__ = str(symlink_path)
    wrapper.__spec__ = spec
    wrapper.__loader__ = loader
    for name in (
        "GoogleAPIError",
        "_GoogleAPICallErrorMeta",
        "GoogleAPICallError",
        "RetryError",
        "DeadlineExceeded",
        "GatewayTimeout",
        "ResourceExhausted",
        "TooManyRequests",
        "PermissionDenied",
        "Forbidden",
        "ServiceUnavailable",
        "FailedPrecondition",
        "NotFound",
        "BadRequest",
    ):
        setattr(wrapper, name, getattr(exceptions, name))
    monkeypatch.setattr(
        google_cloud_kms,
        "_import_google_api_exceptions",
        lambda: wrapper,
    )
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: spec)
    monkeypatch.setattr(
        importlib.metadata,
        "distribution",
        lambda _name: real_distribution,
    )

    loaded = google_cloud_kms._load_google_api_availability_types()

    assert loaded is not None
    assert loaded.direct_types[0] is exceptions.DeadlineExceeded


@pytest.mark.parametrize("algorithm", GOOGLE_ALGORITHMS)
def test_google_verifier_rejects_changed_payload_and_signature(
    google_private_keys,
    algorithm,
):
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"exact original Google payload"
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )
    verifier = _google_verifier(
        None,
        target=GoogleCloudKmsVerificationTarget(
            name,
            algorithm,
            public_key_pem=_google_public_pem(
                google_private_keys[algorithm]
            ),
        ),
    )
    metadata = _google_metadata(algorithm, name)

    changed_payload = verifier.verify(
        payload + b"!",
        b64encode(signature).decode("ascii"),
        metadata,
    )
    changed_signature_bytes = bytearray(signature)
    changed_signature_bytes[-1] ^= 1
    changed_signature = verifier.verify(
        payload,
        b64encode(changed_signature_bytes).decode("ascii"),
        metadata,
    )

    assert changed_payload.reason_code is VerificationReasonCode.SIGNATURE_INVALID
    assert changed_signature.reason_code is VerificationReasonCode.SIGNATURE_INVALID


def test_google_verifier_maps_malformed_ecdsa_der_to_signature_invalid(
    google_private_keys,
):
    algorithm = "EC_SIGN_P256_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    verifier = _google_verifier(
        None,
        target=GoogleCloudKmsVerificationTarget(
            name,
            algorithm,
            public_key_pem=_google_public_pem(
                google_private_keys[algorithm]
            ),
        ),
    )

    outcome = verifier.verify(
        b"malformed DER",
        b64encode(b"not DER").decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.SIGNATURE_INVALID


def test_google_verifier_does_not_swallow_unexpected_der_parser_errors(
    google_private_keys,
    monkeypatch,
):
    from cryptography.hazmat.primitives.asymmetric import utils

    class UnexpectedDerError(ValueError):
        pass

    algorithm = "EC_SIGN_P256_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    target = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        public_key_pem=_google_public_pem(google_private_keys[algorithm]),
    )

    def fail_decode(_signature):
        raise UnexpectedDerError("unexpected DER " + SENSITIVE_CORPUS[3])

    monkeypatch.setattr(utils, "decode_dss_signature", fail_decode)
    verifier = _google_verifier(None, target=target)

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier could not verify signature$",
    ) as caught:
        verifier.verify(
            b"unexpected DER parser error",
            b64encode(b"DER signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_does_not_classify_availability_error_subclasses(
    google_private_keys,
    controlled_google_modules,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]

    class DeadlineExceededSubclass(kms_fixtures.DeadlineExceeded):
        pass

    class Client:
        def get_public_key(self, **_kwargs):
            raise DeadlineExceededSubclass(
                "subclass timeout " + SENSITIVE_CORPUS[0]
            )

    verifier = _google_verifier(
        Client(),
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"provider exception subclass",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_rejects_availability_exception_class_lookalike(
    google_private_keys,
    controlled_google_modules,
):
    deadline_metaclass = type(kms_fixtures.DeadlineExceeded)
    DeadlineExceeded = deadline_metaclass(
        "DeadlineExceeded",
        (kms_fixtures.GoogleKmsFixtureError,),
        {"__module__": "google.api_core.exceptions"},
    )

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    assert type(DeadlineExceeded) is deadline_metaclass
    assert DeadlineExceeded.__module__ == "google.api_core.exceptions"
    assert DeadlineExceeded.__name__ == "DeadlineExceeded"
    assert DeadlineExceeded is not kms_fixtures.DeadlineExceeded

    class Client:
        def get_public_key(self, **_kwargs):
            raise DeadlineExceeded("lookalike " + SENSITIVE_CORPUS[0])

    verifier = _google_verifier(
        Client(),
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"exception lookalike",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_handles_missing_google_api_core_safely(
    google_private_keys,
    controlled_google_modules,
    monkeypatch,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    client = RecordingGoogleCloudKmsClient(
        google_private_keys,
        mode="deadline_public_key",
    )

    def missing_api_core():
        raise ModuleNotFoundError(
            "missing API core " + SENSITIVE_CORPUS[1]
        )

    monkeypatch.setattr(
        google_cloud_kms,
        "_load_google_api_availability_types",
        missing_api_core,
    )
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier returned an invalid response$",
    ) as caught:
        verifier.verify(
            b"missing Google API core",
            b64encode(b"signature").decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_reads_each_resolved_field_once(
    google_private_keys,
    monkeypatch,
):
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    resolved = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        public_key_pem=_google_public_pem(google_private_keys[algorithm]),
    )
    counts = {}
    original_getattribute = GoogleCloudKmsVerificationTarget.__getattribute__

    def counting_getattribute(self, field):
        if self is resolved and field in {
            "crypto_key_version_name",
            "algorithm",
            "disposition",
            "public_key_pem",
        }:
            counts[field] = counts.get(field, 0) + 1
        return original_getattribute(self, field)

    monkeypatch.setattr(
        GoogleCloudKmsVerificationTarget,
        "__getattribute__",
        counting_getattribute,
    )
    payload = b"single target property reads"
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )
    verifier = _google_verifier(None, target=resolved)

    outcome = verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED
    assert counts == {
        "crypto_key_version_name": 1,
        "algorithm": 1,
        "disposition": 1,
        "public_key_pem": 1,
    }


def test_google_verifier_sanitizes_late_crypto_dependency_failure(
    google_private_keys,
    monkeypatch,
):
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"late crypto dependency failure " + SENSITIVE_CORPUS[4].encode()
    target = GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        public_key_pem=_google_public_pem(google_private_keys[algorithm]),
    )
    real_loader = google_cloud_kms._load_cryptography_dependencies
    calls = 0

    def fail_third_load():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ModuleNotFoundError(
                "crypto dependency " + " | ".join(SENSITIVE_CORPUS)
            )
        return real_loader()

    monkeypatch.setattr(
        google_cloud_kms,
        "_load_cryptography_dependencies",
        fail_third_load,
    )
    verifier = _google_verifier(None, target=target)
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )

    with pytest.raises(
        VerificationContractError,
        match=r"^Google Cloud KMS verifier could not verify signature$",
    ) as caught:
        verifier.verify(
            payload,
            b64encode(signature).decode("ascii"),
            _google_metadata(algorithm, name),
        )

    _assert_safe_error(caught.value)


def test_google_verifier_isolates_concurrent_resolver_and_fetched_key_state(
    google_private_keys,
    controlled_google_modules,
):
    algorithms = (
        "RSA_SIGN_PSS_2048_SHA256",
        "EC_SIGN_P256_SHA256",
    )
    targets = {
        _parent_and_version(GOOGLE_KEY_VERSION_NAMES[algorithm]): (
            GoogleCloudKmsVerificationTarget(
                GOOGLE_KEY_VERSION_NAMES[algorithm],
                algorithm,
                (
                    KmsKeyDisposition.ANCHORED
                    if algorithm.startswith("RSA_")
                    else KmsKeyDisposition.UNANCHORED
                ),
            )
        )
        for algorithm in algorithms
    }
    resolver_barrier = Barrier(2)
    provider_barrier = Barrier(2)
    calls = []
    lock = Lock()

    def resolver(reference, version):
        target = targets.get((reference, version))
        resolver_barrier.wait()
        return target

    class BarrierPublicKeyClient:
        def get_public_key(self, **kwargs):
            request = kwargs["request"]
            algorithm = next(
                candidate
                for candidate in algorithms
                if GOOGLE_KEY_VERSION_NAMES[candidate] == request.name
            )
            provider_barrier.wait()
            child = RecordingGoogleCloudKmsClient(
                google_private_keys,
                algorithm=algorithm,
            )
            response = child.get_public_key(**kwargs)
            with lock:
                calls.append(dict(kwargs))
            return response

    verifier = GoogleCloudKmsArtifactVerifier(
        BarrierPublicKeyClient(),
        resolver=resolver,
    )
    payloads = {
        algorithm: (
            b"concurrent verifier payload "
            + algorithm.encode("ascii")
        )
        for algorithm in algorithms
    }
    outcomes = {}
    failures = []

    def worker(algorithm):
        try:
            payload = payloads[algorithm]
            signature = _google_signature(
                google_private_keys[algorithm],
                algorithm,
                payload,
            )
            outcome = verifier.verify(
                payload,
                b64encode(signature).decode("ascii"),
                _google_metadata(
                    algorithm,
                    GOOGLE_KEY_VERSION_NAMES[algorithm],
                ),
            )
            with lock:
                outcomes[algorithm] = outcome
        except BaseException as error:
            with lock:
                failures.append(error)

    threads = [
        Thread(target=worker, args=(algorithm,))
        for algorithm in algorithms
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert {
        algorithm: outcome.reason_code
        for algorithm, outcome in outcomes.items()
    } == {
        "RSA_SIGN_PSS_2048_SHA256": (
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED
        ),
        "EC_SIGN_P256_SHA256": (
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED
        ),
    }
    assert {
        call["request"].name
        for call in calls
    } == {
        GOOGLE_KEY_VERSION_NAMES[algorithm]
        for algorithm in algorithms
    }
    assert not hasattr(verifier, "__dict__")


def test_google_verifier_runs_shared_verifier_conformance(
    google_private_keys,
    controlled_google_modules,
):
    semantic_algorithms = {
        "version/current": "RSA_SIGN_PSS_2048_SHA256",
        "version/historical": "RSA_SIGN_PSS_3072_SHA256",
        "version/revoked": "RSA_SIGN_PSS_4096_SHA256",
        "version/invalid-anchor": "EC_SIGN_P256_SHA256",
    }
    dispositions = {
        "version/current": KmsKeyDisposition.ANCHORED,
        "version/historical": KmsKeyDisposition.UNANCHORED,
        "version/revoked": KmsKeyDisposition.REVOKED,
        "version/invalid-anchor": KmsKeyDisposition.INVALID_ANCHOR,
    }
    targets = {}

    def signed_artifact_factory(semantic_version):
        algorithm = semantic_algorithms[semantic_version]
        client = RecordingGoogleCloudKmsClient(
            google_private_keys,
            algorithm=algorithm,
        )
        signer = GoogleCloudKmsArtifactSigner(
            client,
            crypto_key_version_name=client.crypto_key_version_name,
        )
        payloads = []

        class PayloadRecordingSigner:
            def signer_identity(self):
                return signer.signer_identity()

            def sign(self, payload, identity):
                payloads.append(payload)
                return signer.sign(payload, identity)

        artifact = {
            "audit_schema_version": "1.4",
            "event": "Google verifier conformance",
            "signature": None,
        }
        sign_artifact_with_metadata(
            artifact,
            PayloadRecordingSigner(),
            signed_at=1_721_600_000,
        )
        targets[
            _parent_and_version(client.crypto_key_version_name)
        ] = GoogleCloudKmsVerificationTarget(
            client.crypto_key_version_name,
            algorithm,
            dispositions[semantic_version],
            _google_public_pem(google_private_keys[algorithm]),
        )
        return SignedArtifactFixture(artifact, payloads[0])

    def verifier_factory(scenario):
        def resolver(reference, version):
            if scenario in {
                VerifierScenario.MALFORMED,
                VerifierScenario.MALFORMED_COMBINATION,
                VerifierScenario.UNEXPECTED,
            }:
                raise RuntimeError("sanitized resolver scenario")
            target = targets.get((reference, version))
            if scenario is VerifierScenario.UNAVAILABLE and target is not None:
                return GoogleCloudKmsVerificationTarget(
                    target.crypto_key_version_name,
                    target.algorithm,
                    target.disposition,
                )
            return target

        return GoogleCloudKmsArtifactVerifier(None, resolver=resolver)

    assert_external_verifier_conformance(
        signed_artifact_factory,
        verifier_factory,
    )


def test_google_verifier_uses_actual_checksumming_response_types_when_installed(
    google_private_keys,
):
    kms_v1 = pytest.importorskip("google.cloud.kms_v1")
    google_crc32c = pytest.importorskip("google_crc32c")
    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = GOOGLE_KEY_VERSION_NAMES[algorithm]
    payload = b"actual Google KMS checksummed response"
    pem = _google_public_pem(google_private_keys[algorithm])
    checksum = google_crc32c.Checksum(pem)
    crc32c = int.from_bytes(checksum.digest(), "big")
    algorithm_member = getattr(
        kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm,
        algorithm,
    )
    pem_format = kms_v1.PublicKey.PublicKeyFormat.PEM
    response = kms_v1.PublicKey(
        name=name,
        algorithm=algorithm_member,
        public_key_format=pem_format,
        public_key=kms_v1.ChecksummedData(
            data=pem,
            crc32c_checksum=crc32c,
        ),
    )

    assert type(response) is kms_v1.PublicKey
    assert type(response.public_key) is kms_v1.ChecksummedData
    assert response.algorithm is algorithm_member
    assert response.public_key_format is pem_format

    class Client:
        def __init__(self):
            self.calls = []

        def get_public_key(self, **kwargs):
            self.calls.append(dict(kwargs))
            return response

    client = Client()
    verifier = _google_verifier(
        client,
        target=GoogleCloudKmsVerificationTarget(name, algorithm),
    )
    signature = _google_signature(
        google_private_keys[algorithm],
        algorithm,
        payload,
    )

    outcome = verifier.verify(
        payload,
        b64encode(signature).decode("ascii"),
        _google_metadata(algorithm, name),
    )

    assert outcome.reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED
    assert type(client.calls[0]["request"]) is kms_v1.GetPublicKeyRequest
