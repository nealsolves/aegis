"""Provider-agnostic public-contract checks for external signing recipes.

Factories intentionally describe scenarios rather than a provider.  A recipe
for another provider can adapt its own fixture setup to these two narrow
callable shapes while the assertions only import public Aegis contracts.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable

import pytest

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.signing import (
    AnchorStatus,
    SignatureStatus,
    VerificationReasonCode,
    sign_artifact_with_metadata,
    verify_artifact_detailed,
)


SignerFactory = Callable[..., object]
SignedArtifactFactory = Callable[[str], dict[str, Any]]
VerifierFactory = Callable[[str], object]

_REDACTION_CORPUS = (
    "AKIAIOSFODNN7EXAMPLE",
    "Bearer provider-token-123",
    "super-secret-key-material",
    "raw-signature-deadbeef",
    '{"audit_schema_version":"1.4","private":"payload-fragment"}',
    "https://provider.invalid/raw/response?id=credential",
)


def _artifact() -> dict[str, Any]:
    return {
        "audit_schema_version": "1.4",
        "event": "external signing conformance",
        "signature": None,
    }


def _assert_safe_error(error: BaseException) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert getattr(error, "details", {}) in ({}, {"field": "signature"})
    rendered = f"{error} {getattr(error, 'details', {})!r}"
    assert not any(value in rendered for value in _REDACTION_CORPUS)


def _assert_unchanged(artifact: dict[str, Any], snapshot: dict[str, Any]) -> None:
    assert artifact == snapshot


def _assert_safe_result(result: object, signature: object) -> None:
    rendered = repr(result)
    assert not any(value in rendered for value in _REDACTION_CORPUS)
    if isinstance(signature, str):
        assert signature not in rendered


def assert_external_signer_conformance(signer_factory: SignerFactory) -> None:
    """Assert signer identity, deterministic signing, errors, and atomicity."""
    signer = signer_factory()
    identity = signer.signer_identity()  # type: ignore[attr-defined]
    assert identity == signer.signer_identity()  # type: ignore[attr-defined]
    payload = b"external signing conformance payload\x00exact bytes"
    receipt = signer.sign(payload, identity)  # type: ignore[attr-defined]
    repeat_receipt = signer.sign(payload, identity)  # type: ignore[attr-defined]
    changed_receipt = signer.sign(payload + b"!", identity)  # type: ignore[attr-defined]
    assert receipt.signature == repeat_receipt.signature
    assert receipt.signature != changed_receipt.signature
    assert receipt.algorithm == identity.algorithm
    assert receipt.signature_encoding is identity.signature_encoding
    assert receipt.key_reference == identity.key_reference
    assert receipt.key_version == identity.key_version

    for mode, error_type in (
        ("identity_error", ArtifactSigningError),
        ("identity_unexpected", ArtifactSigningError),
        ("malformed_identity", SigningContractError),
        ("signing_error", ArtifactSigningError),
        ("signing_unexpected", ArtifactSigningError),
        ("malformed_receipt", SigningContractError),
        ("rotate_receipt", SigningContractError),
    ):
        artifact = _artifact()
        snapshot = deepcopy(artifact)
        with pytest.raises(error_type) as caught:
            sign_artifact_with_metadata(artifact, signer_factory(mode=mode), signed_at=123)
        _assert_safe_error(caught.value)
        _assert_unchanged(artifact, snapshot)


def assert_external_verifier_conformance(
    signed_artifact_factory: SignedArtifactFactory,
    verifier_factory: VerifierFactory,
) -> None:
    """Assert exact-version verification, closed outcomes, and safe failures."""
    unsigned = _artifact()
    snapshot = deepcopy(unsigned)
    result = verify_artifact_detailed(unsigned, verifier=verifier_factory("normal"))
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.UNSIGNED,
    )
    _assert_safe_result(result, unsigned["signature"])
    _assert_unchanged(unsigned, snapshot)

    cases = (
        ("version/current", SignatureStatus.VALID, AnchorStatus.ANCHORED,
         VerificationReasonCode.SIGNATURE_VALID_ANCHORED),
        ("version/historical", SignatureStatus.VALID, AnchorStatus.UNANCHORED,
         VerificationReasonCode.SIGNATURE_VALID_UNANCHORED),
        ("version/revoked", SignatureStatus.REVOKED, AnchorStatus.NOT_EVALUATED,
         VerificationReasonCode.KEY_REVOKED),
        ("version/invalid-anchor", SignatureStatus.VALID, AnchorStatus.INVALID,
         VerificationReasonCode.ANCHOR_INVALID),
    )
    for version, status, anchor, reason in cases:
        artifact = signed_artifact_factory(version)
        snapshot = deepcopy(artifact)
        result = verify_artifact_detailed(artifact, verifier=verifier_factory("normal"))
        assert (result.signature_status, result.anchor_status, result.reason_code) == (
            status,
            anchor,
            reason,
        )
        _assert_safe_result(result, artifact["signature"])
        _assert_unchanged(artifact, snapshot)

    unknown = signed_artifact_factory("version/current")
    unknown["signature_metadata"]["key_version"] = "version/unknown"
    snapshot = deepcopy(unknown)
    result = verify_artifact_detailed(unknown, verifier=verifier_factory("normal"))
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_UNKNOWN,
    )
    _assert_safe_result(result, unknown["signature"])
    _assert_unchanged(unknown, snapshot)

    invalid_signature = signed_artifact_factory("version/current")
    invalid_signature["signature"] = "00" * 32
    snapshot = deepcopy(invalid_signature)
    result = verify_artifact_detailed(
        invalid_signature, verifier=verifier_factory("normal")
    )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.SIGNATURE_INVALID,
    )
    _assert_safe_result(result, invalid_signature["signature"])
    _assert_unchanged(invalid_signature, snapshot)

    algorithm_denied = signed_artifact_factory("version/current")
    algorithm_denied["signature_metadata"]["algorithm"] = "RSA-SHA256"
    snapshot = deepcopy(algorithm_denied)
    result = verify_artifact_detailed(
        algorithm_denied, verifier=verifier_factory("normal")
    )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
    )
    _assert_safe_result(result, algorithm_denied["signature"])
    _assert_unchanged(algorithm_denied, snapshot)

    unavailable = signed_artifact_factory("version/current")
    snapshot = deepcopy(unavailable)
    result = verify_artifact_detailed(unavailable)
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
    )
    _assert_safe_result(result, unavailable["signature"])
    _assert_unchanged(unavailable, snapshot)

    for mode in ("unavailable", "malformed", "malformed_combination", "unexpected"):
        artifact = signed_artifact_factory("version/current")
        snapshot = deepcopy(artifact)
        if mode == "unavailable":
            result = verify_artifact_detailed(artifact, verifier=verifier_factory(mode))
            assert result.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE
            _assert_safe_result(result, artifact["signature"])
        else:
            with pytest.raises(VerificationContractError) as caught:
                verify_artifact_detailed(artifact, verifier=verifier_factory(mode))
            _assert_safe_error(caught.value)
        _assert_unchanged(artifact, snapshot)
