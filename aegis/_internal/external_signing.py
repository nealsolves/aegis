"""Provider-neutral protocols and payload construction for external signing."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from aegis._internal.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis._internal.signature_models import (
    AnchorStatus,
    ArtifactVerificationResult,
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureStatus,
    SignatureMetadata,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
    validate_encoded_signature,
)
from aegis._internal.signing import ArtifactSigner, HMACSigner, _canonical_signing_payload
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


def _normalized_string(value: object) -> str:
    if type(value) is not str:
        raise TypeError
    return value


def _normalize_identity(identity: object) -> SignerIdentity:
    """Return a validated, provider-independent signer identity."""
    try:
        if not isinstance(identity, SignerIdentity):
            raise TypeError
        return SignerIdentity(
            algorithm=_normalized_string(identity.algorithm),
            signature_encoding=identity.signature_encoding,
            key_reference=_normalized_string(identity.key_reference),
            key_version=_normalized_string(identity.key_version),
        )
    except Exception:
        raise SigningContractError("Signer returned an invalid identity", details={}) from None


def _validate_receipt(receipt: object, identity: SignerIdentity) -> None:
    """Ensure a signing receipt echoes the identity prepared for this request."""
    try:
        if not isinstance(receipt, SigningReceipt):
            raise TypeError
        receipt_identity = SignerIdentity(
            algorithm=_normalized_string(receipt.algorithm),
            signature_encoding=receipt.signature_encoding,
            key_reference=_normalized_string(receipt.key_reference),
            key_version=_normalized_string(receipt.key_version),
        )
        if receipt_identity != identity:
            raise ValueError
    except Exception:
        raise SigningContractError(
            "Signing receipt does not match prepared identity", details={}
        ) from None


def _normalized_signature(receipt: SigningReceipt) -> str:
    try:
        return _normalized_string(receipt.signature)
    except Exception:
        raise ArtifactSigningError("Signer returned an invalid encoded signature") from None


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

    identity = _normalize_identity(identity)

    metadata = _metadata_from_identity(identity, signed_at)
    payload = _metadata_signing_payload(artifact, metadata)

    try:
        receipt = signer.sign(payload, identity)
    except Exception:
        raise ArtifactSigningError("External signer did not produce a signature") from None

    _validate_receipt(receipt, identity)
    signature = _normalized_signature(receipt)
    try:
        validate_encoded_signature(signature, identity.signature_encoding)
    except Exception:
        raise ArtifactSigningError("Signer returned an invalid encoded signature") from None

    artifact.update(
        signature_metadata=metadata.to_dict(),
        signature=signature,
    )
    return artifact


def _verify_legacy_artifact(
    artifact: Mapping[str, Any], signer: ArtifactSigner
) -> ArtifactVerificationResult:
    """Verify a pre-metadata artifact without inferring custom-signer anchors."""
    try:
        valid = signer.verify(
            _canonical_signing_payload(dict(artifact)), artifact["signature"]
        )
    except Exception:
        raise VerificationContractError(
            "Legacy signature verification failed", details={}
        ) from None

    if valid:
        anchor_status = (
            AnchorStatus.UNANCHORED
            if isinstance(signer, HMACSigner)
            else AnchorStatus.NOT_EVALUATED
        )
        return ArtifactVerificationResult(
            SignatureStatus.VALID,
            anchor_status,
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
            "Legacy signature is valid",
            None,
        )

    return ArtifactVerificationResult(
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
        "Legacy signature is invalid",
        None,
    )


def verify_artifact_detailed(
    artifact: Mapping[str, Any],
    *,
    legacy_signer: ArtifactSigner | None = None,
    verifier: ExternalArtifactVerifier | None = None,
) -> ArtifactVerificationResult:
    """Return a non-mutating detailed result for unsigned and legacy artifacts."""
    if artifact.get("signature") is None:
        return ArtifactVerificationResult(
            SignatureStatus.UNSIGNED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.UNSIGNED,
            "Artifact is unsigned",
            None,
        )

    if "signature_metadata" not in artifact:
        if legacy_signer is None:
            return ArtifactVerificationResult(
                SignatureStatus.INDETERMINATE,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.SIGNATURE_METADATA_MISSING,
                "Signature metadata and legacy verifier are unavailable",
                None,
            )
        return _verify_legacy_artifact(artifact, legacy_signer)

    raise VerificationContractError(
        "Metadata-aware verification is unavailable", details={}
    )
