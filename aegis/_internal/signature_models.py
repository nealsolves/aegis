"""Immutable value contracts for artifact signature verification."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, FrozenSet, TypeVar

from aegis._internal.errors import (
    SignatureMetadataError,
    SigningContractError,
    VerificationContractError,
)


SIGNATURE_METADATA_SCHEMA_VERSION = "1"
SIGNING_PROFILE = "aegis-signature-v1"
CANONICALIZATION_VERSION = "aegis-canonical-json-v1"
CHAIN_CHECKPOINT_SIGNING_PROFILE = "aegis-chain-checkpoint-v1"
WORKFLOW_CHECKPOINT_SIGNING_PROFILE = "aegis-workflow-checkpoint-v1"
CHECKPOINT_CANONICALIZATION_VERSION = "aegis-json-v2"
MAX_SIGNATURE_LENGTH = 16_384
MAX_VERIFICATION_MESSAGE_LENGTH = 1_024

_ALGORITHM_PATTERN = re.compile(r"[A-Za-z0-9._-]+\Z")
_KEY_REFERENCE_PATTERN = re.compile(r"[\x20-\x7e]+\Z")
_KEY_VERSION_PATTERN = re.compile(r"[A-Za-z0-9._:/-]+\Z")
_HEX_PATTERN = re.compile(r"[0-9a-f]+")


class EvidenceType(str, Enum):
    AUDIT_ARTIFACT = "audit_artifact"
    CHAIN_CHECKPOINT = "chain_checkpoint"
    WORKFLOW_CHECKPOINT = "workflow_checkpoint"


_SIGNATURE_METADATA_PROFILES: FrozenSet[tuple[EvidenceType, str, str]] = frozenset({
    (EvidenceType.AUDIT_ARTIFACT, SIGNING_PROFILE, CANONICALIZATION_VERSION),
    (
        EvidenceType.CHAIN_CHECKPOINT,
        CHAIN_CHECKPOINT_SIGNING_PROFILE,
        CHECKPOINT_CANONICALIZATION_VERSION,
    ),
    (
        EvidenceType.WORKFLOW_CHECKPOINT,
        WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
        CHECKPOINT_CANONICALIZATION_VERSION,
    ),
})


class SignatureEncoding(str, Enum):
    HEX = "hex"
    BASE64 = "base64"


class SignatureStatus(str, Enum):
    UNSIGNED = "unsigned"
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN_KEY = "unknown_key"
    REVOKED = "revoked"
    INDETERMINATE = "indeterminate"


class AnchorStatus(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    UNANCHORED = "unanchored"
    ANCHORED = "anchored"
    INVALID = "invalid"


class VerificationReasonCode(str, Enum):
    UNSIGNED = "unsigned"
    LEGACY_SIGNATURE_VALID = "legacy_signature_valid"
    LEGACY_SIGNATURE_INVALID = "legacy_signature_invalid"
    SIGNATURE_VALID_UNANCHORED = "signature_valid_unanchored"
    SIGNATURE_VALID_ANCHORED = "signature_valid_anchored"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNATURE_METADATA_MISSING = "signature_metadata_missing"
    ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
    KEY_UNKNOWN = "key_unknown"
    KEY_REVOKED = "key_revoked"
    VERIFIER_UNAVAILABLE = "verifier_unavailable"
    ANCHOR_INVALID = "anchor_invalid"


def _verification_outcome_is_allowed(
    signature_status: SignatureStatus,
    anchor_status: AnchorStatus,
    reason_code: VerificationReasonCode,
) -> bool:
    if signature_status is SignatureStatus.UNSIGNED:
        return (
            anchor_status is AnchorStatus.NOT_EVALUATED
            and reason_code is VerificationReasonCode.UNSIGNED
        )
    if signature_status is SignatureStatus.VALID:
        if anchor_status is AnchorStatus.NOT_EVALUATED:
            return reason_code is VerificationReasonCode.LEGACY_SIGNATURE_VALID
        if anchor_status is AnchorStatus.UNANCHORED:
            return reason_code in (
                VerificationReasonCode.LEGACY_SIGNATURE_VALID,
                VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
            )
        if anchor_status is AnchorStatus.ANCHORED:
            return reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED
        if anchor_status is AnchorStatus.INVALID:
            return reason_code is VerificationReasonCode.ANCHOR_INVALID
        return False
    if signature_status is SignatureStatus.INVALID:
        return (
            anchor_status is AnchorStatus.NOT_EVALUATED
            and reason_code
            in (
                VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
                VerificationReasonCode.SIGNATURE_INVALID,
                VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
            )
        )
    if signature_status is SignatureStatus.UNKNOWN_KEY:
        return (
            anchor_status is AnchorStatus.NOT_EVALUATED
            and reason_code is VerificationReasonCode.KEY_UNKNOWN
        )
    if signature_status is SignatureStatus.REVOKED:
        return (
            anchor_status is AnchorStatus.NOT_EVALUATED
            and reason_code is VerificationReasonCode.KEY_REVOKED
        )
    return (
        signature_status is SignatureStatus.INDETERMINATE
        and anchor_status is AnchorStatus.NOT_EVALUATED
        and reason_code
        in (
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
        )
    )


_EnumType = TypeVar("_EnumType", bound=Enum)


def _require_enum(
    value: object,
    enum_type: type[_EnumType],
    field: str,
    error_type: type[Exception],
) -> None:
    if not isinstance(value, enum_type):
        raise error_type(f"{field} must be a {enum_type.__name__}", details={"field": field})


def _validate_identity_fields(
    algorithm: object,
    signature_encoding: object,
    key_reference: object,
    key_version: object,
    error_type: type[Exception],
) -> None:
    _require_enum(
        signature_encoding, SignatureEncoding, "signature_encoding", error_type
    )
    if (
        not isinstance(algorithm, str)
        or not 1 <= len(algorithm) <= 128
        or not _ALGORITHM_PATTERN.fullmatch(algorithm)
    ):
        raise error_type("algorithm is invalid", details={"field": "algorithm"})
    if (
        not isinstance(key_reference, str)
        or not 1 <= len(key_reference) <= 512
        or not _KEY_REFERENCE_PATTERN.fullmatch(key_reference)
    ):
        raise error_type("key_reference is invalid", details={"field": "key_reference"})
    if (
        not isinstance(key_version, str)
        or not 1 <= len(key_version) <= 128
        or not _KEY_VERSION_PATTERN.fullmatch(key_version)
    ):
        raise error_type("key_version is invalid", details={"field": "key_version"})


def _validate_message(message: object) -> None:
    if not isinstance(message, str) or len(message) > MAX_VERIFICATION_MESSAGE_LENGTH:
        raise VerificationContractError("message is invalid", details={"field": "message"})


def validate_encoded_signature(signature: object, encoding: object) -> None:
    """Validate a bounded signature using the declared encoding."""
    _require_enum(encoding, SignatureEncoding, "signature_encoding", SigningContractError)
    if not isinstance(signature, str) or not 1 <= len(signature) <= MAX_SIGNATURE_LENGTH:
        raise SigningContractError("signature is invalid", details={"field": "signature"})

    if encoding is SignatureEncoding.HEX:
        if len(signature) % 2 or not _HEX_PATTERN.fullmatch(signature):
            raise SigningContractError("signature is invalid", details={"field": "signature"})
        return

    if any(character.isspace() for character in signature):
        raise SigningContractError("signature is invalid", details={"field": "signature"})
    try:
        decoded = base64.b64decode(signature.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise SigningContractError("signature is invalid", details={"field": "signature"}) from None
    if base64.b64encode(decoded).decode("ascii") != signature:
        raise SigningContractError("signature is invalid", details={"field": "signature"})


def validate_verification_outcome(
    signature_status: object,
    anchor_status: object,
    reason_code: object,
) -> None:
    """Ensure a verification outcome is one of the closed contract states."""
    _require_enum(signature_status, SignatureStatus, "signature_status", VerificationContractError)
    _require_enum(anchor_status, AnchorStatus, "anchor_status", VerificationContractError)
    _require_enum(reason_code, VerificationReasonCode, "reason_code", VerificationContractError)
    if not _verification_outcome_is_allowed(
        signature_status,
        anchor_status,
        reason_code,
    ):
        raise VerificationContractError("verification outcome is invalid", details={})


@dataclass(frozen=True)
class SignerIdentity:
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str

    def __post_init__(self) -> None:
        _validate_identity_fields(
            self.algorithm,
            self.signature_encoding,
            self.key_reference,
            self.key_version,
            SigningContractError,
        )


@dataclass(frozen=True)
class SignatureMetadata:
    schema_version: str
    signing_profile: str
    canonicalization_version: str
    payload_type: EvidenceType
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str
    signed_at: int

    def __post_init__(self) -> None:
        _require_enum(self.payload_type, EvidenceType, "payload_type", SignatureMetadataError)
        if not any(self.payload_type is evidence_type for evidence_type in EvidenceType):
            raise SignatureMetadataError(
                "payload_type must be a EvidenceType", details={"field": "payload_type"}
            )
        _validate_identity_fields(
            self.algorithm,
            self.signature_encoding,
            self.key_reference,
            self.key_version,
            SignatureMetadataError,
        )
        if self.schema_version != SIGNATURE_METADATA_SCHEMA_VERSION:
            raise SignatureMetadataError(
                "schema_version is unsupported", details={"field": "schema_version"}
            )
        if type(self.signing_profile) is not str:
            raise SignatureMetadataError(
                "signing_profile is invalid", details={"field": "signing_profile"}
            )
        if type(self.canonicalization_version) is not str:
            raise SignatureMetadataError(
                "canonicalization_version is invalid",
                details={"field": "canonicalization_version"},
            )
        if (
            self.payload_type,
            self.signing_profile,
            self.canonicalization_version,
        ) not in _SIGNATURE_METADATA_PROFILES:
            raise SignatureMetadataError(
                "signature metadata profile is unsupported",
                details={},
            )
        if (
            isinstance(self.signed_at, bool)
            or not isinstance(self.signed_at, int)
            or self.signed_at < 0
        ):
            raise SignatureMetadataError("signed_at is invalid", details={"field": "signed_at"})

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-native metadata representation in field order."""
        return {
            "schema_version": self.schema_version,
            "signing_profile": self.signing_profile,
            "canonicalization_version": self.canonicalization_version,
            "payload_type": self.payload_type.value,
            "algorithm": self.algorithm,
            "signature_encoding": self.signature_encoding.value,
            "key_reference": self.key_reference,
            "key_version": self.key_version,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, value: object) -> SignatureMetadata:
        """Parse exact, JSON-native signature metadata without mutating input."""
        if not isinstance(value, dict):
            raise SignatureMetadataError("metadata must be a dictionary", details={})
        expected_keys = {
            "schema_version",
            "signing_profile",
            "canonicalization_version",
            "payload_type",
            "algorithm",
            "signature_encoding",
            "key_reference",
            "key_version",
            "signed_at",
        }
        missing = expected_keys - value.keys()
        extra = value.keys() - expected_keys
        if missing or extra:
            raise SignatureMetadataError(
                "metadata keys are invalid",
                details={
                    "field": "signature_metadata",
                    "missing_count": len(missing),
                    "extra_count": len(extra),
                },
            )
        try:
            payload_type = (
                EvidenceType(value["payload_type"])
                if isinstance(value["payload_type"], str)
                else None
            )
            signature_encoding = (
                SignatureEncoding(value["signature_encoding"])
                if isinstance(value["signature_encoding"], str)
                else None
            )
        except ValueError:
            invalid_field = (
                "payload_type"
                if (
                    not isinstance(value["payload_type"], str)
                    or value["payload_type"] not in EvidenceType._value2member_map_
                )
                else "signature_encoding"
            )
            raise SignatureMetadataError(
                "metadata enum is invalid", details={"field": invalid_field}
            ) from None
        if payload_type is None:
            raise SignatureMetadataError(
                "metadata enum is invalid", details={"field": "payload_type"}
            )
        if signature_encoding is None:
            raise SignatureMetadataError(
                "metadata enum is invalid",
                details={"field": "signature_encoding"},
            )
        return cls(
            schema_version=value["schema_version"],
            signing_profile=value["signing_profile"],
            canonicalization_version=value["canonicalization_version"],
            payload_type=payload_type,
            algorithm=value["algorithm"],
            signature_encoding=signature_encoding,
            key_reference=value["key_reference"],
            key_version=value["key_version"],
            signed_at=value["signed_at"],
        )


@dataclass(frozen=True)
class SigningReceipt:
    signature: str
    algorithm: str
    signature_encoding: SignatureEncoding
    key_reference: str
    key_version: str

    def __post_init__(self) -> None:
        _validate_identity_fields(
            self.algorithm,
            self.signature_encoding,
            self.key_reference,
            self.key_version,
            SigningContractError,
        )
        validate_encoded_signature(self.signature, self.signature_encoding)


@dataclass(frozen=True)
class ExternalVerificationOutcome:
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    reason_code: VerificationReasonCode
    message: str

    def __post_init__(self) -> None:
        _validate_message(self.message)
        validate_verification_outcome(
            self.signature_status, self.anchor_status, self.reason_code
        )


@dataclass(frozen=True)
class ArtifactVerificationResult:
    signature_status: SignatureStatus
    anchor_status: AnchorStatus
    reason_code: VerificationReasonCode
    message: str
    signature_metadata: SignatureMetadata | None

    def __post_init__(self) -> None:
        _validate_message(self.message)
        validate_verification_outcome(
            self.signature_status, self.anchor_status, self.reason_code
        )
        if self.signature_metadata is not None and not isinstance(
            self.signature_metadata, SignatureMetadata
        ):
            raise VerificationContractError(
                "signature_metadata is invalid", details={"field": "signature_metadata"}
            )

    @property
    def is_signature_valid(self) -> bool:
        return self.signature_status is SignatureStatus.VALID

    @property
    def is_anchored(self) -> bool:
        return self.anchor_status is AnchorStatus.ANCHORED
