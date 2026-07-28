"""Provider-neutral protocols and payload construction for external signing."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, runtime_checkable

from aegis._internal.errors import (
    ArtifactSigningError,
    SignatureMetadataError,
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
    validate_verification_outcome,
)
from aegis._internal.signing import ArtifactSigner, HMACSigner, _canonical_signing_payload
from aegis._internal.utils import canonical_json_bytes


_SIGNATURE_DOMAIN = b"AEGIS-SIGNATURE\x00"

_SAFE_REASON_MESSAGES = {
    VerificationReasonCode.UNSIGNED: "Artifact is unsigned",
    VerificationReasonCode.LEGACY_SIGNATURE_VALID: "Legacy signature is valid",
    VerificationReasonCode.LEGACY_SIGNATURE_INVALID: "Legacy signature is invalid",
    VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: (
        "Signature is valid but not externally anchored"
    ),
    VerificationReasonCode.SIGNATURE_VALID_ANCHORED: (
        "Signature is valid and externally anchored"
    ),
    VerificationReasonCode.SIGNATURE_INVALID: "Signature is invalid",
    VerificationReasonCode.SIGNATURE_METADATA_MISSING: (
        "Signature metadata is unavailable"
    ),
    VerificationReasonCode.ALGORITHM_NOT_ALLOWED: (
        "The configured key does not permit the declared algorithm"
    ),
    VerificationReasonCode.KEY_UNKNOWN: (
        "The configured verifier does not recognize the key version"
    ),
    VerificationReasonCode.KEY_REVOKED: (
        "The configured verifier reports the key version as revoked"
    ),
    VerificationReasonCode.VERIFIER_UNAVAILABLE: (
        "External verification is unavailable"
    ),
    VerificationReasonCode.ANCHOR_INVALID: "The external anchor is invalid",
}

_CONTEXTUALLY_IMPOSSIBLE_EXTERNAL_REASONS = {
    VerificationReasonCode.UNSIGNED,
    VerificationReasonCode.LEGACY_SIGNATURE_VALID,
    VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
    VerificationReasonCode.SIGNATURE_METADATA_MISSING,
}


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
    identity_invalid = False
    try:
        if not isinstance(identity, SignerIdentity):
            raise TypeError
        normalized_identity = SignerIdentity(
            algorithm=_normalized_string(identity.algorithm),
            signature_encoding=identity.signature_encoding,
            key_reference=_normalized_string(identity.key_reference),
            key_version=_normalized_string(identity.key_version),
        )
    except Exception:
        identity_invalid = True

    if identity_invalid:
        raise SigningContractError("Signer returned an invalid identity", details={})
    return normalized_identity


def _validate_receipt(receipt: object, identity: SignerIdentity) -> None:
    """Ensure a signing receipt echoes the identity prepared for this request."""
    receipt_invalid = False
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
        receipt_invalid = True

    if receipt_invalid:
        raise SigningContractError(
            "Signing receipt does not match prepared identity", details={}
        )


def _normalized_signature(receipt: SigningReceipt) -> str:
    signature_invalid = False
    try:
        signature = _normalized_string(receipt.signature)
    except Exception:
        signature_invalid = True

    if signature_invalid:
        raise ArtifactSigningError("Signer returned an invalid encoded signature")
    return signature


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

    identity_call_failed = False
    try:
        identity = signer.signer_identity()
    except Exception:
        identity_call_failed = True

    if identity_call_failed:
        raise ArtifactSigningError("External signer could not prepare identity")

    identity = _normalize_identity(identity)

    metadata = _metadata_from_identity(identity, signed_at)
    payload = _metadata_signing_payload(artifact, metadata)

    sign_call_failed = False
    try:
        receipt = signer.sign(payload, identity)
    except Exception:
        sign_call_failed = True

    if sign_call_failed:
        raise ArtifactSigningError("External signer did not produce a signature")

    _validate_receipt(receipt, identity)
    signature = _normalized_signature(receipt)
    signature_invalid = False
    try:
        validate_encoded_signature(signature, identity.signature_encoding)
    except Exception:
        signature_invalid = True

    if signature_invalid:
        raise ArtifactSigningError("Signer returned an invalid encoded signature")

    artifact.update(
        signature_metadata=metadata.to_dict(),
        signature=signature,
    )
    return artifact


def _verify_legacy_artifact(
    artifact: Mapping[str, Any], signer: ArtifactSigner
) -> ArtifactVerificationResult:
    """Verify a pre-metadata artifact without inferring custom-signer anchors."""
    verifier_failed = False
    try:
        valid = signer.verify(
            _canonical_signing_payload(dict(artifact)), artifact["signature"]
        )
    except Exception:
        verifier_failed = True

    if verifier_failed:
        raise VerificationContractError(
            "Legacy signature verification failed", details={}
        )

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


def _normalize_external_outcome(
    outcome: object,
    metadata: SignatureMetadata,
) -> ArtifactVerificationResult:
    """Validate and normalize a provider outcome at the core trust boundary."""
    if not isinstance(outcome, ExternalVerificationOutcome):
        raise VerificationContractError(
            "External verifier returned an invalid outcome", details={}
        )

    outcome_invalid = False
    try:
        signature_status = outcome.signature_status
        anchor_status = outcome.anchor_status
        reason_code = outcome.reason_code
    except Exception:
        outcome_invalid = True

    if outcome_invalid:
        raise VerificationContractError(
            "External verifier returned an invalid outcome", details={}
        )

    validate_verification_outcome(signature_status, anchor_status, reason_code)
    if reason_code in _CONTEXTUALLY_IMPOSSIBLE_EXTERNAL_REASONS:
        raise VerificationContractError(
            "External verifier returned an invalid outcome", details={}
        )
    message = _SAFE_REASON_MESSAGES[reason_code]

    return ArtifactVerificationResult(
        signature_status,
        anchor_status,
        reason_code,
        message,
        metadata,
    )


def verify_artifact_detailed(
    artifact: Mapping[str, Any],
    *,
    legacy_signer: ArtifactSigner | None = None,
    verifier: ExternalArtifactVerifier | None = None,
) -> ArtifactVerificationResult:
    """Return a non-mutating detailed artifact verification result."""
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

    signature = artifact["signature"]
    if type(signature) is not str:
        raise SignatureMetadataError(
            "signature is invalid", details={"field": "signature"}
        )

    metadata_error_message: str | None = None
    metadata_error_details: dict[str, Any] | None = None
    metadata_invalid = False
    try:
        metadata = SignatureMetadata.from_dict(artifact["signature_metadata"])
    except SignatureMetadataError as error:
        metadata_error_message = str(error)
        metadata_error_details = error.details.copy()
    except Exception:
        metadata_invalid = True

    if metadata_error_message is not None:
        raise SignatureMetadataError(
            metadata_error_message,
            details=metadata_error_details,
        )
    if metadata_invalid:
        raise SignatureMetadataError(
            "signature metadata is invalid", details={}
        )

    signature_invalid = False
    try:
        validate_encoded_signature(signature, metadata.signature_encoding)
    except Exception:
        signature_invalid = True

    if signature_invalid:
        raise SignatureMetadataError(
            "signature is invalid", details={"field": "signature"}
        )

    payload = _metadata_signing_payload(dict(artifact), metadata)
    if verifier is None:
        return ArtifactVerificationResult(
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
            _SAFE_REASON_MESSAGES[VerificationReasonCode.VERIFIER_UNAVAILABLE],
            metadata,
        )

    outcome: object = None
    verifier_failed = False
    try:
        outcome = verifier.verify(payload, signature, metadata)
    except Exception:
        verifier_failed = True

    if verifier_failed:
        raise VerificationContractError(
            "External verifier failed unexpectedly", details={}
        )

    return _normalize_external_outcome(outcome, metadata)
