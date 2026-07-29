"""Run the public external signing conformance kit against deterministic doubles."""

from base64 import b64decode, b64encode
import binascii
from copy import deepcopy
from hashlib import sha256
from hmac import compare_digest, new
import logging
from secrets import token_bytes

import pytest

from aegis.errors import ArtifactSigningError, SigningContractError
from aegis.signing import (
    SignatureEncoding,
    SignerIdentity,
    SigningReceipt,
    sign_artifact_with_metadata,
)
from tests.signing_conformance import (
    SignedArtifactFixture,
    SignerFixture,
    SignerScenario,
    VerifierScenario,
    _make_signed_artifact,
    assert_external_signer_conformance,
    assert_external_verifier_conformance,
)
from tests.support.external_signing import (
    DeterministicExternalSigner,
    DeterministicExternalVerifier,
    default_key_records,
    verify_deterministic_hmac_sha256_signature,
)


_RANDOMIZED_KEY_MATERIAL = b"randomized external signing test key material"
_RANDOMIZED_KEY_REFERENCE = "randomized-audit-key"
_RANDOMIZED_KEY_VERSION = "version/current"


class _RandomizedExternalSigner:
    """A conformance-only signer whose valid signatures are intentionally unique."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def signer_identity(self) -> SignerIdentity:
        return SignerIdentity(
            "HMAC-SHA256",
            SignatureEncoding.BASE64,
            _RANDOMIZED_KEY_REFERENCE,
            _RANDOMIZED_KEY_VERSION,
        )

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        self.payloads.append(payload)
        if identity != self.signer_identity():
            raise ArtifactSigningError("External signer does not recognize key identity")
        nonce = token_bytes(16)
        signature = b64encode(
            nonce + new(_RANDOMIZED_KEY_MATERIAL, nonce + payload, sha256).digest()
        ).decode("ascii")
        return SigningReceipt(
            signature,
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        )


def _verify_randomized_signature(payload: bytes, receipt: SigningReceipt) -> bool:
    """Validate a randomized receipt using the nonce carried by its signature."""
    if (
        not isinstance(receipt, SigningReceipt)
        or receipt.algorithm != "HMAC-SHA256"
        or receipt.signature_encoding is not SignatureEncoding.BASE64
        or receipt.key_reference != _RANDOMIZED_KEY_REFERENCE
        or receipt.key_version != _RANDOMIZED_KEY_VERSION
    ):
        return False
    try:
        decoded = b64decode(receipt.signature, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(decoded) != 48:
        return False
    nonce, signature = decoded[:16], decoded[16:]
    expected = new(_RANDOMIZED_KEY_MATERIAL, nonce + payload, sha256).digest()
    return compare_digest(expected, signature)


def _signer_scenario(scenario: SignerScenario) -> SignerFixture:
    modes = {
        SignerScenario.NORMAL: "normal",
        SignerScenario.IDENTITY_ERROR: "identity_error",
        SignerScenario.IDENTITY_UNEXPECTED: "identity_unexpected",
        SignerScenario.MALFORMED_IDENTITY: "malformed_identity",
        SignerScenario.SIGNING_ERROR: "signing_error",
        SignerScenario.SIGNING_UNEXPECTED: "signing_unexpected",
        SignerScenario.MALFORMED_RECEIPT: "malformed_receipt",
    }
    signer = DeterministicExternalSigner(mode=modes[scenario])
    return SignerFixture(
        signer,
        lambda: tuple(signer.payloads),
        verify_deterministic_hmac_sha256_signature,
    )


def _signed_artifact(key_version: str) -> SignedArtifactFixture:
    artifact: dict[str, object] = {
        "audit_schema_version": "1.4",
        "event": "deterministic external signing",
        "signature": None,
    }
    signer = DeterministicExternalSigner(
        key_records=default_key_records(), key_version=key_version
    )
    sign_artifact_with_metadata(artifact, signer, signed_at=1_721_600_000)
    return SignedArtifactFixture(artifact, signer.payloads[0])


def _verifier_scenario(scenario: VerifierScenario) -> object:
    modes = {
        VerifierScenario.NORMAL: "normal",
        VerifierScenario.UNAVAILABLE: "unavailable",
        VerifierScenario.MALFORMED: "malformed",
        VerifierScenario.MALFORMED_COMBINATION: "malformed_combination",
        VerifierScenario.UNEXPECTED: "unexpected",
    }
    return DeterministicExternalVerifier(mode=modes[scenario])


def test_deterministic_external_signer_conforms() -> None:
    assert_external_signer_conformance(_signer_scenario)


def _randomized_signer_scenario(scenario: SignerScenario) -> SignerFixture:
    if scenario is not SignerScenario.NORMAL:
        return _signer_scenario(scenario)
    signer = _RandomizedExternalSigner()
    return SignerFixture(
        signer,
        lambda: tuple(signer.payloads),
        _verify_randomized_signature,
    )


def test_randomized_external_signer_conforms_without_signature_equality() -> None:
    assert_external_signer_conformance(_randomized_signer_scenario)


def test_deterministic_external_verifier_conforms() -> None:
    assert_external_verifier_conformance(
        _signed_artifact,
        _verifier_scenario,
    )


def test_deterministic_signer_uses_exact_hmac_sha256_payload_bytes() -> None:
    signer = DeterministicExternalSigner()
    payload = b"\x00provider boundary\xffexact payload bytes"
    identity = signer.signer_identity()

    receipt = signer.sign(payload, identity)

    expected = new(
        default_key_records()["version/current"].key_material, payload, sha256
    ).hexdigest()
    assert receipt.signature == expected
    assert signer.payloads == [payload]


def test_deterministic_signer_rejects_a_forged_key_reference_for_a_known_version() -> None:
    signer = DeterministicExternalSigner()
    identity = SignerIdentity(
        "HMAC-SHA256",
        signer.signer_identity().signature_encoding,
        "forged-key-reference",
        "version/current",
    )

    with pytest.raises(ArtifactSigningError, match="does not recognize key identity"):
        signer.sign(b"exact payload", identity)


def test_signed_fixture_setup_rejects_an_original_signature_log_leak() -> None:
    def leaky_signed_artifact(key_version: str) -> SignedArtifactFixture:
        fixture = _signed_artifact(key_version)
        logging.getLogger(__name__).warning("original signature=%s", fixture.artifact["signature"])
        return fixture

    with pytest.raises(AssertionError):
        _make_signed_artifact(leaky_signed_artifact, "version/current")


def test_verifier_conformance_rejects_factory_time_credential_log_leak() -> None:
    def credential_logging_factory(scenario: VerifierScenario) -> object:
        logging.getLogger(__name__).warning("Bearer provider-token-123")
        return _verifier_scenario(scenario)

    with pytest.raises(AssertionError):
        assert_external_verifier_conformance(
            _signed_artifact,
            credential_logging_factory,
        )


def test_verifier_conformance_rejects_actual_mutated_metadata_payload_log_leak() -> None:
    class MutatedPayloadLeakingVerifier:
        def __init__(self, verifier: object) -> None:
            self.verifier = verifier

        def verify(self, payload: bytes, signature: str, metadata: object) -> object:
            if getattr(metadata, "algorithm") == "RSA-SHA256":
                logging.getLogger(__name__).warning(
                    "actual verifier payload=%s",
                    payload.decode("utf-8", "replace"),
                )
            return self.verifier.verify(  # type: ignore[attr-defined]
                payload,
                signature,
                metadata,
            )

    def verifier_factory(scenario: VerifierScenario) -> object:
        verifier = _verifier_scenario(scenario)
        if scenario is VerifierScenario.NORMAL:
            return MutatedPayloadLeakingVerifier(verifier)
        return verifier

    with pytest.raises(AssertionError):
        assert_external_verifier_conformance(
            _signed_artifact,
            verifier_factory,
        )


def test_receipt_alias_rotation_is_rejected_atomically() -> None:
    artifact: dict[str, object] = {
        "audit_schema_version": "1.4",
        "signature": None,
    }
    snapshot = deepcopy(artifact)

    with pytest.raises(SigningContractError) as caught:
        sign_artifact_with_metadata(
            artifact,
            DeterministicExternalSigner(mode="rotate_receipt"),
            signed_at=123,
        )

    assert str(caught.value) == "Signing receipt does not match prepared identity"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert artifact == snapshot
