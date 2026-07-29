"""Strict offline coverage for the Google Cloud KMS artifact signer."""

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
from aegis.errors import ArtifactSigningError, SigningContractError
from aegis.integrations.google_cloud_kms import (
    GoogleCloudKmsArtifactSigner,
    GoogleCloudKmsVerificationTarget,
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
    GOOGLE_ALGORITHMS,
    GOOGLE_KEY_VERSION_NAMES,
    RecordingGoogleCloudKmsClient,
    generate_google_private_keys,
    google_crc32c_value,
    install_controlled_google_kms_modules,
    verify_google_signature,
)


@pytest.fixture(scope="module")
def google_private_keys():
    return generate_google_private_keys()


@pytest.fixture
def controlled_google_modules(monkeypatch):
    return install_controlled_google_kms_modules(monkeypatch)


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


def test_google_module_exports_only_currently_defined_public_types():
    import aegis.integrations.google_cloud_kms as google_cloud_kms

    assert google_cloud_kms.__all__ == [
        "GoogleCloudKmsArtifactSigner",
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
