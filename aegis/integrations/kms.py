"""Provider-neutral KMS trust-policy declarations."""

from enum import Enum


class KmsKeyDisposition(str, Enum):
    """Host policy applied only after successful KMS signature verification."""

    ANCHORED = "anchored"
    UNANCHORED = "unanchored"
    INVALID_ANCHOR = "invalid_anchor"
    REVOKED = "revoked"


__all__ = ["KmsKeyDisposition"]
