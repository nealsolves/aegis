"""Private strict helpers shared by optional KMS provider modules."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
from types import MappingProxyType

from aegis.signing import (
    AnchorStatus,
    ExternalVerificationOutcome,
    SignatureStatus,
    VerificationReasonCode,
)


MAX_RAW_SIGNATURE_BYTES = 12_288
MAX_AWS_RAW_SIGNATURE_BYTES = 6_144
MAX_PUBLIC_KEY_PEM_BYTES = 65_536
MAX_CRC32C = 2**32 - 1

_USE_PROVIDER_DEFAULT = object()

_OUTCOME_FIELDS = MappingProxyType(
    {
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            "Signature is valid and externally anchored",
        ),
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            "Signature is valid but not externally anchored",
        ),
        VerificationReasonCode.ANCHOR_INVALID: (
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            "The external anchor is invalid",
        ),
        VerificationReasonCode.KEY_REVOKED: (
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier reports the key version as revoked",
        ),
        VerificationReasonCode.KEY_UNKNOWN: (
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier does not recognize the key version",
        ),
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "The configured key does not permit the declared algorithm",
        ),
        VerificationReasonCode.SIGNATURE_INVALID: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "Signature is invalid",
        ),
        VerificationReasonCode.VERIFIER_UNAVAILABLE: (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            "External verification is unavailable",
        ),
    }
)

__all__: list[str] = []


def _sha256_digest(payload: bytes) -> bytes:
    """Hash one exact artifact byte sequence."""
    if type(payload) is not bytes:
        raise ValueError("payload is invalid")
    return hashlib.sha256(payload).digest()


def _canonical_b64encode(value: bytes) -> str:
    """Encode a nonempty exact byte sequence as canonical RFC 4648 base64."""
    if type(value) is not bytes or not value:
        raise ValueError("base64 value is invalid")
    return base64.b64encode(value).decode("ascii")


def _canonical_b64decode(value: str, *, max_raw_bytes: int) -> bytes:
    """Decode bounded canonical RFC 4648 base64 without accepting aliases."""
    if (
        type(value) is not str
        or type(max_raw_bytes) is not int
        or max_raw_bytes < 1
        or not value
        or len(value) > ((max_raw_bytes + 2) // 3) * 4
    ):
        raise ValueError("base64 value is invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise ValueError("base64 value is invalid") from None
    if not decoded or len(decoded) > max_raw_bytes:
        raise ValueError("base64 value is invalid")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 value is invalid")
    return decoded


def _normalize_timeout(value: object, *, error_type: type[Exception]) -> object:
    """Keep explicit SDK timeout values distinct from omitted arguments."""
    if value is _USE_PROVIDER_DEFAULT or value is None:
        return value
    if type(value) is int:
        if value > 0:
            return value
    elif type(value) is float and math.isfinite(value) and value > 0:
        return value
    raise error_type("timeout is invalid") from None


def _normalize_crc32c(value: object) -> int:
    """Require an exact unsigned 32-bit CRC32C value."""
    if type(value) is not int or not 0 <= value <= MAX_CRC32C:
        raise ValueError("crc32c is invalid")
    return value


def _outcome(reason_code: VerificationReasonCode) -> ExternalVerificationOutcome:
    """Construct a safe verification result from the closed KMS outcome set."""
    if type(reason_code) is not VerificationReasonCode:
        raise ValueError("verification outcome reason is invalid")
    fields = _OUTCOME_FIELDS.get(reason_code)
    if fields is None:
        raise ValueError("verification outcome reason is invalid")
    signature_status, anchor_status, message = fields
    return ExternalVerificationOutcome(
        signature_status,
        anchor_status,
        reason_code,
        message,
    )
