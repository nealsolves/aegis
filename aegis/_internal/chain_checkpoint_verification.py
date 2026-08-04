"""Bounded preparation and binding for trusted chain checkpoints."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from aegis._internal.canonicalization import canonicalize_v2
from aegis._internal.checkpoint_models import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
    TrustedChainCheckpoint,
)
from aegis._internal.checkpoint_verification import (
    PreparedCheckpoint,
    unavailable_checkpoint_result,
    verify_prepared_checkpoint,
)
from aegis._internal.external_signing import ExternalArtifactVerifier
from aegis._internal.signature_models import (
    AnchorStatus,
    ArtifactVerificationResult,
    SignatureStatus,
)
from aegis._internal.verification_contracts import Completeness, VerificationError
from aegis._internal.verification_limits import (
    BoundedVerificationErrors,
    VerificationBudget,
    VerificationInputError,
    _IterableConsumptionError,
    materialize_bounded_iterable,
)


_MAX_CHAIN_ARTIFACTS = 1_024
_MAX_CHAIN_CHECKPOINTS = 64
_MAX_SCOPE_ID_LENGTH = 512


@dataclass(frozen=True, slots=True)
class PreparedChainCheckpoints:
    artifacts: list[object]
    records: tuple[PreparedCheckpoint, ...]
    expected_chain_id: str | None
    invalid_record_count: int = 0


@dataclass(frozen=True, slots=True)
class CheckpointEvaluation:
    signature_status: CheckpointSignatureStatus
    anchor_status: AnchorStatus
    completeness: Completeness
    results: tuple[CheckpointVerificationResult, ...]


def _error(code: str, message: str, index: int | None = None) -> VerificationError:
    return VerificationError(code=code, message=message, index=index)


def _valid_scope_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_SCOPE_ID_LENGTH
        and bool(value.strip())
        and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    )


def _snapshot_for_measurement(value: object) -> object:
    if type(value) is TrustedChainCheckpoint:
        try:
            return TrustedChainCheckpoint.to_dict(value)
        except Exception:
            return None
    if type(value) is dict:
        return value
    return None


def _parse_chain_checkpoints(
    raw_checkpoints: list[object],
    measured: list[object],
    errors: BoundedVerificationErrors,
) -> tuple[tuple[PreparedCheckpoint, ...], int]:
    ordered: list[tuple[bytes, TrustedChainCheckpoint, list[int]]] = []
    positions: dict[bytes, int] = {}
    invalid_count = 0
    for index, (raw, snapshot) in enumerate(zip(raw_checkpoints, measured)):
        try:
            if type(raw) is TrustedChainCheckpoint:
                if type(snapshot) is not dict:
                    raise ValueError
                checkpoint = TrustedChainCheckpoint.from_dict(snapshot)
            elif type(raw) is dict:
                checkpoint = TrustedChainCheckpoint.from_dict(raw)
            else:
                raise ValueError
            canonical_record = canonicalize_v2(
                TrustedChainCheckpoint.to_dict(checkpoint)
            ).data
        except Exception:
            invalid_count += 1
            errors.append(
                _error(
                    "CHECKPOINT_RECORD_INVALID",
                    "Checkpoint record is invalid",
                    index,
                )
            )
            continue

        existing = positions.get(canonical_record)
        if existing is None:
            positions[canonical_record] = len(ordered)
            ordered.append((canonical_record, checkpoint, [index]))
        else:
            ordered[existing][2].append(index)

    return (
        tuple(
            PreparedCheckpoint(tuple(indexes), checkpoint, canonical_record)
            for canonical_record, checkpoint, indexes in ordered
        ),
        invalid_count,
    )


def prepare_chain_checkpoint_input(
    artifacts: list[object],
    checkpoints: object,
    expected_chain_id: object,
    budget: VerificationBudget,
    errors: BoundedVerificationErrors,
) -> PreparedChainCheckpoints | None:
    """Consume, snapshot, and measure every input before verification work."""
    if type(artifacts) is not list or len(artifacts) > _MAX_CHAIN_ARTIFACTS:
        return None
    if expected_chain_id is not None and not _valid_scope_id(expected_chain_id):
        errors.append(
            _error(
                "CHECKPOINT_SCOPE_INVALID",
                "Expected checkpoint chain scope is invalid",
            )
        )
        return None

    try:
        budget.measure(artifacts)
        artifacts_snapshot = deepcopy(artifacts)
    except VerificationInputError:
        errors.append(
            _error(
                "CHAIN_VERIFICATION_LIMIT_EXCEEDED",
                "Chain verification input exceeds a configured limit",
            )
        )
        return None
    except Exception:
        errors.append(
            _error(
                "CHAIN_VERIFICATION_LIMIT_EXCEEDED",
                "Chain verification input exceeds a configured limit",
            )
        )
        return None

    try:
        raw_checkpoints = materialize_bounded_iterable(
            checkpoints,
            max_items=_MAX_CHAIN_CHECKPOINTS,
        )
    except _IterableConsumptionError:
        errors.append(
            _error(
                "CHECKPOINT_INPUT_INVALID",
                "Checkpoint input is invalid",
            )
        )
        return None
    except VerificationInputError:
        errors.append(
            _error(
                "CHECKPOINT_LIMIT_EXCEEDED",
                "Checkpoint verification input exceeds a configured limit",
            )
        )
        return None

    measured = [_snapshot_for_measurement(value) for value in raw_checkpoints]
    try:
        if measured:
            budget.measure(measured)
    except VerificationInputError:
        errors.append(
            _error(
                "CHECKPOINT_LIMIT_EXCEEDED",
                "Checkpoint verification input exceeds a configured limit",
            )
        )
        return None

    records, invalid_count = _parse_chain_checkpoints(
        raw_checkpoints,
        measured,
        errors,
    )
    return PreparedChainCheckpoints(
        artifacts=artifacts_snapshot,
        records=records,
        expected_chain_id=expected_chain_id,
        invalid_record_count=invalid_count,
    )


def _derived_chain_id(
    artifacts: list[object],
    content_valid: bool,
    continuity_valid: bool,
) -> str | None:
    if not content_valid or not continuity_valid or not artifacts:
        return None
    first = artifacts[0]
    if type(first) is not dict:
        return None
    scope_id = first.get("chain_id")
    return scope_id if _valid_scope_id(scope_id) else None


def _binding_status(
    checkpoint: TrustedChainCheckpoint,
    artifacts: list[object],
) -> CheckpointBindingStatus:
    if (
        not artifacts
        or type(artifacts[0]) is not dict
        or type(artifacts[-1]) is not dict
    ):
        return CheckpointBindingStatus.AHEAD
    first_index = artifacts[0].get("chain_index")
    last_index = artifacts[-1].get("chain_index")
    if type(first_index) is not int or type(last_index) is not int:
        return CheckpointBindingStatus.AHEAD
    if checkpoint.chain_index < first_index:
        return CheckpointBindingStatus.OUTSIDE
    if checkpoint.chain_index > last_index:
        return CheckpointBindingStatus.AHEAD
    offset = checkpoint.chain_index - first_index
    if not 0 <= offset < len(artifacts):
        return CheckpointBindingStatus.CONFLICT
    artifact = artifacts[offset]
    if (
        type(artifact) is not dict
        or artifact.get("checksum") != checkpoint.artifact_checksum
    ):
        return CheckpointBindingStatus.CONFLICT
    if first_index > 0:
        return CheckpointBindingStatus.PARTIAL
    if checkpoint.chain_index == last_index:
        return CheckpointBindingStatus.MATCHED
    return CheckpointBindingStatus.HISTORICAL


def _checkpoint_signature_status(
    result: ArtifactVerificationResult,
) -> CheckpointSignatureStatus:
    mapping = {
        SignatureStatus.VALID: CheckpointSignatureStatus.VALID,
        SignatureStatus.INVALID: CheckpointSignatureStatus.INVALID,
        SignatureStatus.UNKNOWN_KEY: CheckpointSignatureStatus.UNKNOWN_KEY,
        SignatureStatus.REVOKED: CheckpointSignatureStatus.REVOKED,
        SignatureStatus.INDETERMINATE: CheckpointSignatureStatus.INDETERMINATE,
    }
    return mapping.get(
        result.signature_status,
        CheckpointSignatureStatus.INDETERMINATE,
    )


def _result(
    prepared: PreparedCheckpoint,
    binding_status: CheckpointBindingStatus,
    signature_result: ArtifactVerificationResult | None,
) -> CheckpointVerificationResult:
    checkpoint = prepared.checkpoint
    return CheckpointVerificationResult(
        input_indexes=prepared.input_indexes,
        checkpoint=checkpoint,
        scope_id=checkpoint.chain_id,
        chain_index=checkpoint.chain_index,
        signature_result=signature_result,
        binding_status=binding_status,
    )


def evaluate_chain_checkpoints(
    prepared: PreparedChainCheckpoints,
    artifacts: list[object],
    *,
    content_valid: bool,
    continuity_valid: bool,
    verifier: ExternalArtifactVerifier | None,
    errors: BoundedVerificationErrors,
) -> CheckpointEvaluation:
    """Verify and structurally bind prepared checkpoints to supplied evidence."""
    scope_id = prepared.expected_chain_id or _derived_chain_id(
        artifacts,
        content_valid,
        continuity_valid,
    )
    if scope_id is None:
        results = tuple(
            _result(record, CheckpointBindingStatus.NOT_EVALUATED, None)
            for record in prepared.records
        )
        return CheckpointEvaluation(
            signature_status=(
                CheckpointSignatureStatus.INDETERMINATE
                if prepared.invalid_record_count
                else CheckpointSignatureStatus.NOT_EVALUATED
            ),
            anchor_status=(
                AnchorStatus.INVALID
                if prepared.invalid_record_count
                else AnchorStatus.NOT_EVALUATED
            ),
            completeness=Completeness.UNPROVEN,
            results=results,
        )

    results: list[CheckpointVerificationResult] = []
    evaluated: list[tuple[ArtifactVerificationResult, CheckpointBindingStatus]] = []
    for record in prepared.records:
        checkpoint = record.checkpoint
        if checkpoint.chain_id != scope_id:
            results.append(
                _result(record, CheckpointBindingStatus.OUT_OF_SCOPE, None)
            )
            continue
        binding_status = _binding_status(checkpoint, artifacts)
        try:
            signature_result = verify_prepared_checkpoint(record, verifier)
        except Exception:
            errors.append(
                _error(
                    "CHECKPOINT_VERIFICATION_ERROR",
                    "Checkpoint verification could not be evaluated",
                    record.input_indexes[0],
                )
            )
            signature_result = unavailable_checkpoint_result(record)
        results.append(_result(record, binding_status, signature_result))
        evaluated.append((signature_result, binding_status))

    if prepared.invalid_record_count or len(evaluated) > 1:
        return CheckpointEvaluation(
            signature_status=CheckpointSignatureStatus.INDETERMINATE,
            anchor_status=AnchorStatus.INVALID,
            completeness=Completeness.UNPROVEN,
            results=tuple(results),
        )
    if not evaluated:
        return CheckpointEvaluation(
            signature_status=CheckpointSignatureStatus.NOT_EVALUATED,
            anchor_status=AnchorStatus.NOT_EVALUATED,
            completeness=Completeness.UNPROVEN,
            results=tuple(results),
        )

    signature_result, binding_status = evaluated[0]
    signature_status = _checkpoint_signature_status(signature_result)
    anchor_status = signature_result.anchor_status
    trusted = (
        signature_result.signature_status is SignatureStatus.VALID
        and signature_result.anchor_status is AnchorStatus.ANCHORED
    )
    first_index = (
        artifacts[0].get("chain_index")
        if artifacts and type(artifacts[0]) is dict
        else None
    )
    full_chain = (
        content_valid
        and continuity_valid
        and type(first_index) is int
        and first_index == 0
    )
    trusted_conflict = trusted and binding_status is CheckpointBindingStatus.CONFLICT
    trusted_ahead = trusted and binding_status is CheckpointBindingStatus.AHEAD
    terminal_trusted_match = (
        trusted
        and full_chain
        and binding_status is CheckpointBindingStatus.MATCHED
    )
    if trusted_conflict:
        errors.append(
            _error(
                "CHECKPOINT_BINDING_CONFLICT",
                "Trusted checkpoint conflicts with supplied chain evidence",
                prepared.records[0].input_indexes[0],
            )
        )
    if trusted_conflict or (trusted_ahead and full_chain):
        completeness = Completeness.CONTRADICTED
        anchor_status = AnchorStatus.INVALID
    elif terminal_trusted_match:
        completeness = Completeness.CHECKPOINT_PROVEN
    else:
        completeness = Completeness.UNPROVEN
    return CheckpointEvaluation(
        signature_status=signature_status,
        anchor_status=anchor_status,
        completeness=completeness,
        results=tuple(results),
    )
