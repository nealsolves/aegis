"""Shared prepared-checkpoint verification primitives."""

from __future__ import annotations

from dataclasses import dataclass

from aegis._internal.checkpoint_models import (
    CheckpointRecord,
    TrustedChainCheckpoint,
    TrustedWorkflowCheckpoint,
)
from aegis._internal.checkpoint_signing import _checkpoint_payload
from aegis._internal.external_signing import (
    ExternalArtifactVerifier,
    _verify_prepared_payload_detailed,
)
from aegis._internal.signature_models import ArtifactVerificationResult


@dataclass(frozen=True, slots=True)
class PreparedCheckpoint:
    """One core-owned checkpoint snapshot and its caller positions."""

    input_indexes: tuple[int, ...]
    checkpoint: CheckpointRecord
    canonical_record: bytes


def _checkpoint_dict(checkpoint: CheckpointRecord) -> dict[str, object]:
    if type(checkpoint) is TrustedChainCheckpoint:
        return TrustedChainCheckpoint.to_dict(checkpoint)
    if type(checkpoint) is TrustedWorkflowCheckpoint:
        return TrustedWorkflowCheckpoint.to_dict(checkpoint)
    raise TypeError("Unsupported checkpoint record")


def verify_prepared_checkpoint(
    prepared: PreparedCheckpoint,
    verifier: ExternalArtifactVerifier | None,
) -> ArtifactVerificationResult:
    """Verify one reparsed checkpoint through the prepared-payload boundary."""
    checkpoint = prepared.checkpoint
    snapshot = _checkpoint_dict(checkpoint)
    payload = _checkpoint_payload(snapshot, checkpoint.signature_metadata)
    return _verify_prepared_payload_detailed(
        payload,
        checkpoint.signature,
        checkpoint.signature_metadata,
        verifier,
    )


def unavailable_checkpoint_result(
    prepared: PreparedCheckpoint,
) -> ArtifactVerificationResult:
    """Return the fixed unavailable result after a caught provider failure."""
    checkpoint = prepared.checkpoint
    snapshot = _checkpoint_dict(checkpoint)
    payload = _checkpoint_payload(snapshot, checkpoint.signature_metadata)
    return _verify_prepared_payload_detailed(
        payload,
        checkpoint.signature,
        checkpoint.signature_metadata,
        None,
    )
