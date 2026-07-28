"""Run the public external signing conformance kit against deterministic doubles."""

from copy import deepcopy
from hashlib import sha256
from hmac import new
import logging

import pytest

from aegis.errors import ArtifactSigningError, SigningContractError
from aegis.signing import SignerIdentity, sign_artifact_with_metadata
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
)


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
    return SignerFixture(signer, lambda: tuple(signer.payloads))


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
