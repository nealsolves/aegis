"""Unforgeable host capabilities for narrowly scoped legacy behavior."""

from __future__ import annotations

from enum import Enum


_HOST_LEGACY_CAPABILITY = object()


class LegacyFeature(str, Enum):
    BARE_STRING_PRECONDITIONS = "bare_string_preconditions"
    CHECKSUM_FREE_CHAIN_VERIFICATION = "checksum_free_chain_verification"
    AUDIT_SCHEMA_1X_VERIFICATION = "audit_schema_1x_verification"
    WORKFLOW_SCHEMA_1X_VERIFICATION = "workflow_schema_1x_verification"
    SINK_FAILURE_LOG = "sink_failure_log"


class LegacyAuthorization:
    """A host-created, immutable grant for an explicit set of legacy features."""

    __slots__ = ("_capability", "features")

    def __init__(self, capability: object, features: frozenset[str]) -> None:
        if capability is not _HOST_LEGACY_CAPABILITY:
            raise TypeError("LegacyAuthorization is host-created only")
        object.__setattr__(self, "_capability", capability)
        object.__setattr__(self, "features", features)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("LegacyAuthorization is immutable")


def create_legacy_authorization(
    *features: LegacyFeature,
) -> LegacyAuthorization:
    """Create a trusted host grant for only the enumerated compatibility paths."""
    if not features or any(not isinstance(feature, LegacyFeature) for feature in features):
        raise TypeError("features must be one or more LegacyFeature values")
    return LegacyAuthorization(
        _HOST_LEGACY_CAPABILITY,
        frozenset(feature.value for feature in features),
    )


def is_legacy_authorized(value: object, feature: LegacyFeature) -> bool:
    """Check an exact, authentic capability without duck-typing lookalikes."""
    return (
        type(value) is LegacyAuthorization
        and value._capability is _HOST_LEGACY_CAPABILITY
        and feature.value in value.features
    )
