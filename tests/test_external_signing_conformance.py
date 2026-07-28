"""Run the public external signing conformance kit against deterministic doubles."""

from copy import deepcopy
from hashlib import sha256
from hmac import new

import pytest

from aegis.errors import SigningContractError
from aegis.signing import sign_artifact_with_metadata
from tests.signing_conformance import (
    assert_external_signer_conformance,
    assert_external_verifier_conformance,
)
from tests.support.external_signing import (
    DeterministicExternalSigner,
    DeterministicExternalVerifier,
    default_key_records,
)


def _signed_artifact(key_version: str) -> dict[str, object]:
    artifact: dict[str, object] = {
        "audit_schema_version": "1.4",
        "event": "deterministic external signing",
        "signature": None,
    }
    sign_artifact_with_metadata(
        artifact,
        DeterministicExternalSigner(key_records=default_key_records(), key_version=key_version),
        signed_at=1_721_600_000,
    )
    return artifact


def test_deterministic_external_signer_conforms() -> None:
    assert_external_signer_conformance(DeterministicExternalSigner)


def test_deterministic_external_verifier_conforms() -> None:
    assert_external_verifier_conformance(
        _signed_artifact,
        lambda mode: DeterministicExternalVerifier(mode=mode),
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
