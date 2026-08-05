"""Bounded preparation and binding for trusted chain checkpoints."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType

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
)


_MAX_CHAIN_ARTIFACTS = 1_024
_MAX_CHAIN_CHECKPOINTS = 64
_MAX_SCOPE_ID_LENGTH = 512

_SIGNATURE_PRECEDENCE = MappingProxyType({
    CheckpointSignatureStatus.NOT_EVALUATED: 0,
    CheckpointSignatureStatus.VALID: 1,
    CheckpointSignatureStatus.UNKNOWN_KEY: 2,
    CheckpointSignatureStatus.REVOKED: 3,
    CheckpointSignatureStatus.INVALID: 4,
    CheckpointSignatureStatus.INDETERMINATE: 5,
})
_ANCHOR_PRECEDENCE = MappingProxyType({
    AnchorStatus.ANCHORED: 0,
    AnchorStatus.UNANCHORED: 1,
    AnchorStatus.NOT_EVALUATED: 2,
    AnchorStatus.INVALID: 3,
})


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


@dataclass(slots=True)
class _EvaluatedCheckpoint:
    prepared: PreparedCheckpoint
    binding_status: CheckpointBindingStatus
    signature_result: ArtifactVerificationResult
    provider_contract_failed: bool = False


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


def _materialize_checkpoint_snapshots(
    value: object,
    budget: VerificationBudget,
) -> list[object]:
    """Read one bounded element ahead while snapshotting accepted occurrences."""
    try:
        if isinstance(value, (str, bytes, bytearray)) or isinstance(
            value, Mapping
        ):
            raise TypeError
        iterator = iter(value)
    except Exception:
        raise _IterableConsumptionError from None

    snapshots: list[object] = []
    while True:
        try:
            raw = next(iterator)
        except StopIteration:
            return snapshots
        except Exception:
            raise _IterableConsumptionError from None
        if len(snapshots) >= _MAX_CHAIN_CHECKPOINTS:
            raise VerificationInputError

        source = _snapshot_for_measurement(raw)
        try:
            budget.measure(source)
            snapshot = deepcopy(source)
        except VerificationInputError:
            raise
        except Exception:
            raise VerificationInputError from None
        snapshots.append(snapshot)


def _parse_chain_checkpoints(
    measured: list[object],
    errors: BoundedVerificationErrors,
) -> tuple[tuple[PreparedCheckpoint, ...], int]:
    ordered: list[tuple[bytes, TrustedChainCheckpoint, list[int]]] = []
    positions: dict[bytes, int] = {}
    invalid_count = 0
    for index, snapshot in enumerate(measured):
        try:
            if type(snapshot) is not dict:
                raise ValueError
            checkpoint = TrustedChainCheckpoint.from_dict(snapshot)
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
        measured = _materialize_checkpoint_snapshots(
            checkpoints,
            budget,
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

    records, invalid_count = _parse_chain_checkpoints(
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


def _aggregate_checkpoint_signature_status(
    statuses: Iterable[CheckpointSignatureStatus],
) -> CheckpointSignatureStatus:
    return max(
        statuses,
        key=_SIGNATURE_PRECEDENCE.__getitem__,
        default=CheckpointSignatureStatus.NOT_EVALUATED,
    )


def _aggregate_checkpoint_anchor_status(
    statuses: Iterable[AnchorStatus],
) -> AnchorStatus:
    return max(
        statuses,
        key=_ANCHOR_PRECEDENCE.__getitem__,
        default=AnchorStatus.NOT_EVALUATED,
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
    derived_scope_id = _derived_chain_id(
        artifacts,
        content_valid,
        continuity_valid,
    )
    scope_id = prepared.expected_chain_id or derived_scope_id
    if scope_id is None:
        results = tuple(
            _result(record, CheckpointBindingStatus.NOT_EVALUATED, None)
            for record in prepared.records
        )
        signature_statuses = (
            (CheckpointSignatureStatus.INDETERMINATE,)
            if prepared.invalid_record_count
            else ()
        )
        anchor_statuses = (
            (AnchorStatus.INVALID,) if prepared.invalid_record_count else ()
        )
        return CheckpointEvaluation(
            signature_status=_aggregate_checkpoint_signature_status(
                signature_statuses
            ),
            anchor_status=_aggregate_checkpoint_anchor_status(anchor_statuses),
            completeness=Completeness.UNPROVEN,
            results=results,
        )

    states: list[_EvaluatedCheckpoint | None] = []
    for record in prepared.records:
        checkpoint = record.checkpoint
        if checkpoint.chain_id != scope_id:
            states.append(None)
            errors.append(
                _error(
                    "CHECKPOINT_SCOPE_MISMATCH",
                    "Checkpoint is out of scope",
                    record.input_indexes[0],
                )
            )
            continue
        binding_status = _binding_status(checkpoint, artifacts)
        provider_contract_failed = False
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
            provider_contract_failed = True
        states.append(
            _EvaluatedCheckpoint(
                prepared=record,
                binding_status=binding_status,
                signature_result=signature_result,
                provider_contract_failed=provider_contract_failed,
            )
        )

    in_scope = [state for state in states if state is not None]
    anchored_in_scope = [
        state
        for state in in_scope
        if state.signature_result.signature_status is SignatureStatus.VALID
        and state.signature_result.anchor_status is AnchorStatus.ANCHORED
    ]
    explicit_scope_conflict = (
        prepared.expected_chain_id is not None
        and derived_scope_id is not None
        and prepared.expected_chain_id != derived_scope_id
        and bool(anchored_in_scope)
    )
    if explicit_scope_conflict:
        for state in in_scope:
            state.binding_status = CheckpointBindingStatus.CONFLICT

    trusted_by_coordinate: dict[
        tuple[str, int], dict[str, list[_EvaluatedCheckpoint]]
    ] = {}
    for state in anchored_in_scope:
        checkpoint = state.prepared.checkpoint
        coordinate = (checkpoint.chain_id, checkpoint.chain_index)
        claims = trusted_by_coordinate.setdefault(coordinate, {})
        claims.setdefault(checkpoint.artifact_checksum, []).append(state)
    trusted_authority_conflicts = [
        tuple(
            state
            for same_checksum_claims in claims.values()
            for state in same_checksum_claims
        )
        for claims in trusted_by_coordinate.values()
        if len(claims) > 1
    ]

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
    contradictions = [
        state
        for state in anchored_in_scope
        if state.binding_status is CheckpointBindingStatus.CONFLICT
        or (
            full_chain
            and state.binding_status is CheckpointBindingStatus.AHEAD
        )
    ]
    for state in contradictions:
        errors.append(
            _error(
                "CHECKPOINT_BINDING_CONFLICT",
                "Trusted checkpoint conflicts with supplied chain evidence",
                state.prepared.input_indexes[0],
            )
        )
    for conflicting_claims in trusted_authority_conflicts:
        if any(
            state.binding_status is CheckpointBindingStatus.CONFLICT
            or (
                full_chain
                and state.binding_status is CheckpointBindingStatus.AHEAD
            )
            for state in conflicting_claims
        ):
            continue
        errors.append(
            _error(
                "CHECKPOINT_BINDING_CONFLICT",
                "Trusted checkpoints conflict at the same chain coordinate",
                min(
                    state.prepared.input_indexes[0]
                    for state in conflicting_claims
                ),
            )
        )

    provider_contract_failed = any(
        state.provider_contract_failed for state in in_scope
    )
    signature_statuses = [
        _checkpoint_signature_status(state.signature_result)
        for state in in_scope
    ]
    anchor_statuses = [
        state.signature_result.anchor_status for state in in_scope
    ]
    if prepared.invalid_record_count or provider_contract_failed:
        signature_statuses.append(CheckpointSignatureStatus.INDETERMINATE)
        anchor_statuses.append(AnchorStatus.INVALID)
    signature_status = _aggregate_checkpoint_signature_status(
        signature_statuses
    )
    anchor_status = _aggregate_checkpoint_anchor_status(anchor_statuses)
    if contradictions or trusted_authority_conflicts:
        completeness = Completeness.CONTRADICTED
        anchor_status = AnchorStatus.INVALID
    elif (
        in_scope
        and not prepared.invalid_record_count
        and len(anchored_in_scope) == len(in_scope)
        and any(
            state.binding_status is CheckpointBindingStatus.MATCHED
            for state in anchored_in_scope
        )
        and full_chain
    ):
        completeness = Completeness.CHECKPOINT_PROVEN
    else:
        completeness = Completeness.UNPROVEN

    results = tuple(
        _result(record, CheckpointBindingStatus.OUT_OF_SCOPE, None)
        if state is None
        else _result(
            state.prepared,
            state.binding_status,
            state.signature_result,
        )
        for record, state in zip(prepared.records, states)
    )
    return CheckpointEvaluation(
        signature_status=signature_status,
        anchor_status=anchor_status,
        completeness=completeness,
        results=results,
    )
