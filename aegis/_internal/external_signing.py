"""Provider-neutral protocols and payload construction for external signing."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from aegis._internal.errors import ArtifactSigningError, SigningContractError
from aegis._internal.signature_models import (
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureMetadata,
    SignerIdentity,
    SigningReceipt,
    validate_encoded_signature,
)
from aegis._internal.utils import canonical_json_bytes


_SIGNATURE_DOMAIN = b"AEGIS-SIGNATURE\x00"


@runtime_checkable
class ExternalArtifactSigner(Protocol):
    def signer_identity(self) -> SignerIdentity:
        raise NotImplementedError

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        raise NotImplementedError


@runtime_checkable
class ExternalArtifactVerifier(Protocol):
    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        raise NotImplementedError


def _metadata_from_identity(identity: SignerIdentity, signed_at: int) -> SignatureMetadata:
    """Bind immutable signer identity values to the fixed signature profile."""
    if not isinstance(identity, SignerIdentity):
        raise SigningContractError("identity must be a SignerIdentity", details={})
    if isinstance(signed_at, bool) or not isinstance(signed_at, int):
        raise SigningContractError("signed_at is invalid", details={"field": "signed_at"})
    return SignatureMetadata(
        schema_version=SIGNATURE_METADATA_SCHEMA_VERSION,
        signing_profile=SIGNING_PROFILE,
        canonicalization_version=CANONICALIZATION_VERSION,
        payload_type=EvidenceType.AUDIT_ARTIFACT,
        algorithm=identity.algorithm,
        signature_encoding=identity.signature_encoding,
        key_reference=identity.key_reference,
        key_version=identity.key_version,
        signed_at=signed_at,
    )


def _metadata_signing_payload(
    artifact: dict[str, Any], metadata: SignatureMetadata
) -> bytes:
    """Return the domain-separated canonical payload for an audit artifact."""
    if not isinstance(metadata, SignatureMetadata):
        raise SigningContractError("metadata must be a SignatureMetadata", details={})
    signable = artifact.copy()
    signable.pop("signature", None)
    signable["signature_metadata"] = metadata.to_dict()
    return (
        _SIGNATURE_DOMAIN
        + SIGNING_PROFILE.encode("utf-8")
        + b"\x00"
        + EvidenceType.AUDIT_ARTIFACT.value.encode("utf-8")
        + b"\x00"
        + canonical_json_bytes(signable)
    )


def _validate_receipt(receipt: object, identity: SignerIdentity) -> None:
    """Ensure a signing receipt echoes the identity prepared for this request."""
    if not isinstance(receipt, SigningReceipt) or (
        receipt.algorithm,
        receipt.signature_encoding,
        receipt.key_reference,
        receipt.key_version,
    ) != (
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    ):
        raise SigningContractError(
            "Signing receipt does not match prepared identity", details={}
        )


def sign_artifact_with_metadata(
    artifact: dict[str, Any],
    signer: ExternalArtifactSigner,
    *,
    signed_at: int,
) -> dict[str, Any]:
    """Atomically apply an externally-produced signature and its metadata."""
    if artifact.get("signature") is not None:
        raise ArtifactSigningError("Artifact is already signed")
    if "signature_metadata" in artifact:
        raise ArtifactSigningError("Artifact contains stale signature metadata")

    try:
        identity = signer.signer_identity()
    except Exception:
        raise ArtifactSigningError("External signer could not prepare identity") from None

    if not isinstance(identity, SignerIdentity):
        raise SigningContractError("Signer returned an invalid identity", details={})

    metadata = _metadata_from_identity(identity, signed_at)
    payload = _metadata_signing_payload(artifact, metadata)

    try:
        receipt = signer.sign(payload, identity)
    except Exception:
        raise ArtifactSigningError("External signer did not produce a signature") from None

    _validate_receipt(receipt, identity)
    try:
        validate_encoded_signature(receipt.signature, identity.signature_encoding)
    except SigningContractError:
        raise ArtifactSigningError("Signer returned an invalid encoded signature") from None

    artifact.update(
        signature_metadata=metadata.to_dict(),
        signature=receipt.signature,
    )
    return artifact
