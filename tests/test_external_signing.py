"""Contract tests for external artifact signing boundaries."""

from __future__ import annotations

from copy import deepcopy

import pytest

from aegis._internal.errors import SignatureMetadataError, SigningContractError
from aegis._internal.external_signing import (
    ExternalArtifactSigner,
    ExternalArtifactVerifier,
    _metadata_from_identity,
    _metadata_signing_payload,
)
from aegis._internal.signature_models import (
    AnchorStatus,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
)


def _metadata(**changes: object) -> SignatureMetadata:
    values: dict[str, object] = {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": EvidenceType.AUDIT_ARTIFACT,
        "algorithm": "HSM-SHA256",
        "signature_encoding": SignatureEncoding.HEX,
        "key_reference": "audit-key",
        "key_version": "version/7",
        "signed_at": 123,
    }
    values.update(changes)
    return SignatureMetadata(**values)  # type: ignore[arg-type]


def test_metadata_signing_payload_matches_frozen_profile():
    artifact = {"audit_schema_version": "1.4", "signature": None}
    metadata = _metadata()
    expected_json = (
        b'{"audit_schema_version":"1.4","signature_metadata":{'
        b'"algorithm":"HSM-SHA256",'
        b'"canonicalization_version":"aegis-canonical-json-v1",'
        b'"key_reference":"audit-key","key_version":"version/7",'
        b'"payload_type":"audit_artifact","schema_version":"1",'
        b'"signature_encoding":"hex","signed_at":123,'
        b'"signing_profile":"aegis-signature-v1"}}'
    )
    expected = (
        b"AEGIS-SIGNATURE\x00"
        b"aegis-signature-v1\x00"
        b"audit_artifact\x00"
        + expected_json
    )
    assert _metadata_signing_payload(artifact, metadata) == expected


def test_metadata_signing_payload_preserves_artifact_and_replaces_temporary_metadata():
    artifact = {
        "audit_schema_version": "1.4",
        "signature": "deadbeef",
        "signature_metadata": {"temporary": True},
    }
    original = deepcopy(artifact)

    payload = _metadata_signing_payload(artifact, _metadata())

    assert artifact == original
    assert b'"signature":' not in payload
    assert b'"signature_metadata":{"algorithm":"HSM-SHA256"' in payload
    assert b'"temporary":true' not in payload


def test_metadata_signing_payload_rejects_unvalidated_metadata_objects():
    class FakeMetadata:
        def to_dict(self):
            return {
                "signing_profile": "attacker-profile",
                "payload_type": "attacker-payload",
            }

    with pytest.raises(SigningContractError):
        _metadata_signing_payload(
            {"audit_schema_version": "1.4", "signature": None}, FakeMetadata()
        )


@pytest.mark.parametrize(
    "artifact, metadata",
    [
        ({"audit_schema_version": "1.5", "signature": None}, _metadata()),
        (
            {"audit_schema_version": "1.4", "signature": None, "extra": "changed"},
            _metadata(),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(algorithm="RSA-SHA256"),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(signature_encoding=SignatureEncoding.BASE64),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(key_reference="other-key"),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(key_version="version/8"),
        ),
        ({"audit_schema_version": "1.4", "signature": None}, _metadata(signed_at=124)),
    ],
)
def test_metadata_signing_payload_changes_when_signed_inputs_change(artifact, metadata):
    baseline = _metadata_signing_payload(
        {"audit_schema_version": "1.4", "signature": None}, _metadata()
    )
    assert _metadata_signing_payload(artifact, metadata) != baseline


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema_version", "2"),
        ("signing_profile", "other-profile"),
        ("canonicalization_version", "other-canonicalization"),
        ("payload_type", None),
    ],
)
def test_unsupported_fixed_metadata_values_are_rejected_before_payload_construction(
    field, value
):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


def test_metadata_from_identity_uses_fixed_profile_and_identity_values():
    identity = SignerIdentity(
        algorithm="HSM-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="audit-key",
        key_version="version/7",
    )

    assert _metadata_from_identity(identity, 123) == _metadata()


@pytest.mark.parametrize(
    "identity, signed_at",
    [
        (object(), 123),
        (None, 123),
        (
            SignerIdentity(
                "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
            ),
            True,
        ),
    ],
)
def test_metadata_from_identity_rejects_invalid_inputs(identity, signed_at):
    with pytest.raises(SigningContractError):
        _metadata_from_identity(identity, signed_at)


def test_structural_signer_and_verifier_doubles_satisfy_runtime_protocols():
    class SignerDouble:
        def signer_identity(self) -> SignerIdentity:
            return SignerIdentity(
                "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
            )

        def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
            return SigningReceipt(
                "aa",
                identity.algorithm,
                identity.signature_encoding,
                identity.key_reference,
                identity.key_version,
            )

    class VerifierDouble:
        def verify(
            self, payload: bytes, signature: str, metadata: SignatureMetadata
        ) -> ExternalVerificationOutcome:
            return ExternalVerificationOutcome(
                SignatureStatus.UNSIGNED,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.UNSIGNED,
                "unsigned",
            )

    assert isinstance(SignerDouble(), ExternalArtifactSigner)
    assert isinstance(VerifierDouble(), ExternalArtifactVerifier)
