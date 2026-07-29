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
        self.same_payload_signatures: list[str] = []

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
        if len(self.same_payload_signatures) < 2:
            self.same_payload_signatures.append(signature)
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
    if b64encode(decoded).decode("ascii") != receipt.signature:
        return False
    if len(decoded) != 48:
        return False
    nonce, signature = decoded[:16], decoded[16:]
    expected = new(_RANDOMIZED_KEY_MATERIAL, nonce + payload, sha256).digest()
    return compare_digest(expected, signature)


def _unchecked_randomized_receipt(signature: str) -> SigningReceipt:
    receipt = object.__new__(SigningReceipt)
    object.__setattr__(receipt, "signature", signature)
    object.__setattr__(receipt, "algorithm", "HMAC-SHA256")
    object.__setattr__(receipt, "signature_encoding", SignatureEncoding.BASE64)
    object.__setattr__(receipt, "key_reference", _RANDOMIZED_KEY_REFERENCE)
    object.__setattr__(receipt, "key_version", _RANDOMIZED_KEY_VERSION)
    return receipt


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


def test_randomized_external_signer_conforms_without_signature_equality() -> None:
    signer = _RandomizedExternalSigner()

    def randomized_signer_scenario(scenario: SignerScenario) -> SignerFixture:
        if scenario is not SignerScenario.NORMAL:
            return _signer_scenario(scenario)
        return SignerFixture(
            signer,
            lambda: tuple(signer.payloads),
            _verify_randomized_signature,
        )

    assert_external_signer_conformance(randomized_signer_scenario)
    assert len(signer.same_payload_signatures) == 2
    assert signer.same_payload_signatures[0] != signer.same_payload_signatures[1]


def test_randomized_signature_verification_rejects_malformed_or_forged_signatures() -> None:
    payload = b"randomized signature verification payload"
    signer = _RandomizedExternalSigner()
    valid_receipt = signer.sign(payload, signer.signer_identity())
    decoded = b64decode(valid_receipt.signature, validate=True)
    wrong_hmac = b64encode(decoded[:-1] + bytes([decoded[-1] ^ 1])).decode("ascii")

    assert _verify_randomized_signature(payload, valid_receipt) is True
    for signature in (
        b64encode(b"too short").decode("ascii"),
        "!" * 64,
        valid_receipt.signature + "==",
        wrong_hmac,
    ):
        assert _verify_randomized_signature(
            payload,
            _unchecked_randomized_receipt(signature),
        ) is False


def test_external_signer_conformance_rejects_repeated_receipt_payload_substitution() -> None:
    payload = b"external signing conformance payload\x00exact bytes"

    class RepeatedReceiptSigner:
        def __init__(self) -> None:
            self.calls = 0

        def signer_identity(self) -> SignerIdentity:
            return SignerIdentity(
                "HMAC-SHA256",
                SignatureEncoding.HEX,
                "repeated-receipt-key",
                "version/current",
            )

        def sign(self, signed_payload: bytes, identity: SignerIdentity) -> SigningReceipt:
            self.calls += 1
            return SigningReceipt(
                chr(96 + self.calls) * 64,
                identity.algorithm,
                identity.signature_encoding,
                identity.key_reference,
                identity.key_version,
            )

    signer = RepeatedReceiptSigner()

    def signer_factory(scenario: SignerScenario) -> SignerFixture:
        if scenario is not SignerScenario.NORMAL:
            return _signer_scenario(scenario)

        def verify_signature(
            verified_payload: bytes,
            receipt: SigningReceipt,
        ) -> bool:
            if receipt.signature == "a" * 64:
                return verified_payload == payload
            if receipt.signature == "b" * 64:
                return verified_payload in (payload, payload + b"!")
            return receipt.signature == "c" * 64 and verified_payload == payload + b"!"

        return SignerFixture(
            signer,
            lambda: tuple(),
            verify_signature,
        )

    with pytest.raises(AssertionError):
        assert_external_signer_conformance(signer_factory)


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
