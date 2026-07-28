"""Contract tests for external artifact signing boundaries."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from aegis._internal.errors import (
    ArtifactSigningError,
    SignatureMetadataError,
    SigningContractError,
)
from aegis._internal.external_signing import (
    ExternalArtifactSigner,
    ExternalArtifactVerifier,
    _metadata_from_identity,
    _metadata_signing_payload,
    sign_artifact_with_metadata,
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


class RecordingSigner:
    def __init__(
        self, *, identity: SignerIdentity | None = None, receipt: object | None = None
    ) -> None:
        self.identity = identity or SignerIdentity(
            "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
        )
        self.receipt = receipt or SigningReceipt(
            "aa",
            self.identity.algorithm,
            self.identity.signature_encoding,
            self.identity.key_reference,
            self.identity.key_version,
        )
        self.payload: bytes | None = None

    def signer_identity(self) -> SignerIdentity:
        return self.identity

    def sign(self, payload: bytes, identity: SignerIdentity) -> object:
        self.payload = payload
        return self.receipt


class DigestSigner(RecordingSigner):
    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        self.payload = payload
        return SigningReceipt(
            sha256(payload).hexdigest(),
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        )


class DigestVerifier:
    def accepts(self, payload: bytes, signature: str) -> bool:
        return sha256(payload).hexdigest() == signature


def _unsigned_artifact() -> dict[str, object]:
    return {"audit_schema_version": "1.4", "signature": None}


def test_sign_artifact_with_metadata_binds_identity_receipt_and_payload_atomically():
    artifact = _unsigned_artifact()
    signer = RecordingSigner()

    result = sign_artifact_with_metadata(artifact, signer, signed_at=1_721_600_000)

    assert result is artifact
    assert artifact["signature_metadata"] == {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": "audit_artifact",
        "algorithm": "HSM-SHA256",
        "signature_encoding": "hex",
        "key_reference": "audit-key",
        "key_version": "version/7",
        "signed_at": 1_721_600_000,
    }
    assert artifact["signature"] == signer.receipt.signature  # type: ignore[union-attr]
    assert signer.payload == _metadata_signing_payload(
        {"audit_schema_version": "1.4", "signature": None},
        SignatureMetadata.from_dict(artifact["signature_metadata"]),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "artifact",
    [
        {"audit_schema_version": "1.4", "signature": "aa"},
        {
            "audit_schema_version": "1.4",
            "signature": None,
            "signature_metadata": {"stale": True},
        },
    ],
)
def test_sign_artifact_with_metadata_rejects_existing_signature_state_without_mutation(
    artifact,
):
    original = deepcopy(artifact)

    with pytest.raises(ArtifactSigningError):
        sign_artifact_with_metadata(artifact, RecordingSigner(), signed_at=1)

    assert artifact == original


def test_sign_artifact_with_metadata_rejects_invalid_timestamp_without_mutation():
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(SigningContractError):
        sign_artifact_with_metadata(artifact, RecordingSigner(), signed_at=True)

    assert artifact == original


def test_sign_artifact_with_metadata_redacts_identity_errors_without_mutation():
    class FailingIdentitySigner(RecordingSigner):
        def signer_identity(self) -> SignerIdentity:
            raise RuntimeError("credential=top-secret payload=do-not-disclose")

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="External signer could not prepare identity"
    ) as error:
        sign_artifact_with_metadata(artifact, FailingIdentitySigner(), signed_at=1)

    assert "top-secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_non_identity_without_mutation():
    class InvalidIdentitySigner(RecordingSigner):
        def signer_identity(self) -> object:
            return object()

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(SigningContractError, match="Signer returned an invalid identity"):
        sign_artifact_with_metadata(artifact, InvalidIdentitySigner(), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "exception",
    [
        ArtifactSigningError("provider credential=top-secret"),
        RuntimeError("credential=top-secret payload=do-not-disclose"),
    ],
)
def test_sign_artifact_with_metadata_redacts_signer_errors_without_mutation(exception):
    class FailingSigner(RecordingSigner):
        def sign(self, payload: bytes, identity: SignerIdentity) -> object:
            raise exception

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="External signer did not produce a signature"
    ) as error:
        sign_artifact_with_metadata(artifact, FailingSigner(), signed_at=1)

    assert "top-secret" not in str(error.value)
    assert "do-not-disclose" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_non_receipt_without_mutation():
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=object()), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "field, value",
    [
        ("algorithm", "RSA-SHA256"),
        ("signature_encoding", SignatureEncoding.BASE64),
        ("key_reference", "other-key"),
        ("key_version", "version/8"),
    ],
)
def test_sign_artifact_with_metadata_rejects_receipt_identity_mismatch_without_mutation(
    field, value
):
    signer = RecordingSigner()
    receipt = SigningReceipt(
        "aa",
        signer.identity.algorithm,
        signer.identity.signature_encoding,
        signer.identity.key_reference,
        signer.identity.key_version,
    )
    object.__setattr__(receipt, field, value)
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=receipt), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "signature, encoding",
    [
        ("", SignatureEncoding.HEX),
        ("a" * 16_385, SignatureEncoding.HEX),
        ("AA", SignatureEncoding.HEX),
        ("a", SignatureEncoding.HEX),
        ("0xaa", SignatureEncoding.HEX),
        ("Zm 9v", SignatureEncoding.BASE64),
        ("Zh==", SignatureEncoding.BASE64),
    ],
)
def test_sign_artifact_with_metadata_redacts_invalid_encoded_signature_without_mutation(
    signature, encoding
):
    identity = SignerIdentity(
        "HSM-SHA256", encoding, "audit-key", "version/7"
    )
    receipt = SigningReceipt(
        "aa" if encoding is SignatureEncoding.HEX else "YWE=",
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    object.__setattr__(receipt, "signature", signature)
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="Signer returned an invalid encoded signature"
    ) as error:
        sign_artifact_with_metadata(
            artifact, RecordingSigner(identity=identity, receipt=receipt), signed_at=1
        )

    assert error.value.details == {}
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_alias_rotation_without_mutation():
    signer = RecordingSigner()
    receipt = SigningReceipt(
        "aa",
        signer.identity.algorithm,
        signer.identity.signature_encoding,
        signer.identity.key_reference,
        "version/8",
    )
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=receipt), signed_at=1)

    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_identity_fields_without_mutation():
    class HostileAlgorithm(str):
        def __len__(self) -> int:
            raise ArtifactSigningError("provider secret from identity")

    signer = RecordingSigner()
    object.__setattr__(signer.identity, "algorithm", HostileAlgorithm("HSM-SHA256"))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signer returned an invalid identity"
    ) as error:
        sign_artifact_with_metadata(artifact, signer, signed_at=1)

    assert "provider secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_receipt_fields_without_mutation():
    class HostileKeyVersion(str):
        def __eq__(self, other: object) -> bool:
            raise ArtifactSigningError("provider secret from receipt")

    signer = RecordingSigner()
    receipt = signer.receipt
    object.__setattr__(receipt, "key_version", HostileKeyVersion("version/7"))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ) as error:
        sign_artifact_with_metadata(artifact, signer, signed_at=1)

    assert "provider secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_signature_without_mutation():
    class HostileBase64Signature(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise ArtifactSigningError("provider secret from signature")

    identity = SignerIdentity(
        "HSM-SHA256", SignatureEncoding.BASE64, "audit-key", "version/7"
    )
    receipt = SigningReceipt(
        "YWE=",
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    object.__setattr__(receipt, "signature", HostileBase64Signature("YWE="))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="Signer returned an invalid encoded signature"
    ) as error:
        sign_artifact_with_metadata(
            artifact, RecordingSigner(identity=identity, receipt=receipt), signed_at=1
        )

    assert "provider secret" not in str(error.value)
    assert artifact == original


@pytest.mark.parametrize(
    "mutate",
    [
        lambda artifact: artifact.update(audit_schema_version="1.5"),
        lambda artifact: artifact["signature_metadata"].update(algorithm="RSA-SHA256"),
        lambda artifact: artifact["signature_metadata"].update(key_reference="other-key"),
        lambda artifact: artifact["signature_metadata"].update(key_version="version/8"),
        lambda artifact: artifact["signature_metadata"].update(signed_at=1_721_600_001),
        lambda artifact: artifact["signature_metadata"].update(payload_type="other"),
        lambda artifact: artifact["signature_metadata"].update(signing_profile="other"),
        lambda artifact: artifact["signature_metadata"].update(canonicalization_version="other"),
    ],
)
def test_metadata_aware_signature_payload_detects_signed_artifact_tampering(mutate):
    artifact = _unsigned_artifact()
    signer = DigestSigner()
    sign_artifact_with_metadata(artifact, signer, signed_at=1_721_600_000)
    signed_payload = signer.payload
    verifier = DigestVerifier()

    assert verifier.accepts(signed_payload, artifact["signature"])

    mutate(artifact)
    try:
        tampered_payload = _metadata_signing_payload(
            artifact, SignatureMetadata.from_dict(artifact["signature_metadata"])
        )
    except SignatureMetadataError:
        tampered_payload = None

    assert not verifier.accepts(tampered_payload or b"", artifact["signature"])
