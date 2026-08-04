"""Shared verification resource and trust-boundary contracts."""

from __future__ import annotations

from copy import deepcopy
from importlib import import_module

import pytest

import aegis
import aegis._internal.verification as chain_verification
import aegis._internal.workflow_verification as workflow_verification
import aegis.audit_chain as audit_chain
from aegis._internal.checkpoint_models import TrustedChainCheckpoint
from aegis._internal.errors import CheckpointError, VerificationContractError
from aegis._internal.signature_models import (
    AnchorStatus,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    VerificationReasonCode,
)


def _chain_record_dict() -> dict[str, object]:
    return {
        "checkpoint_schema_version": "1",
        "checkpoint_profile": "aegis-chain-checkpoint-v1",
        "canonicalization_profile": "aegis-json-v2",
        "chain_id": "chain-123",
        "chain_index": 2,
        "chain_length": 3,
        "artifact_schema_version": "2.0",
        "artifact_checksum": "a" * 64,
        "checkpointed_at": 1_725_000_000,
        "signature_metadata": {
            "schema_version": "1",
            "signing_profile": "aegis-chain-checkpoint-v1",
            "canonicalization_version": "aegis-json-v2",
            "payload_type": "chain_checkpoint",
            "algorithm": "ed25519",
            "signature_encoding": "hex",
            "key_reference": "kms://checkpoint-key",
            "key_version": "7",
            "signed_at": 1_725_000_000,
        },
        "signature": "ab" * 32,
    }


def _checkpoint_metadata() -> SignatureMetadata:
    return SignatureMetadata(
        schema_version="1",
        signing_profile="aegis-chain-checkpoint-v1",
        canonicalization_version="aegis-json-v2",
        payload_type=EvidenceType.CHAIN_CHECKPOINT,
        algorithm="ed25519",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="kms://checkpoint-key",
        key_version="7",
        signed_at=1_725_000_000,
    )


def test_extracted_verification_contracts_preserve_every_existing_identity():
    contracts = import_module("aegis._internal.verification_contracts")

    assert contracts.Completeness is chain_verification.Completeness
    assert contracts.Completeness is workflow_verification.Completeness
    assert contracts.Completeness is audit_chain.Completeness
    assert contracts.Completeness is aegis.Completeness
    assert contracts.VerificationError is chain_verification.VerificationError
    assert contracts.VerificationError is workflow_verification.VerificationError
    assert contracts.VerificationError is audit_chain.VerificationError
    assert contracts.VerificationError is aegis.VerificationError


def test_verification_budget_counts_bytes_and_nodes_across_documents():
    limits = import_module("aegis._internal.verification_limits")
    budget = limits.VerificationBudget(remaining_bytes=12, remaining_nodes=4)

    assert budget.measure(["x"]) == 6
    assert budget.measure(["y"]) == 6
    assert budget.remaining_bytes == 0
    assert budget.remaining_nodes == 0
    with pytest.raises(limits.VerificationInputError):
        budget.measure(None)
    assert budget.remaining_bytes == 0
    assert budget.remaining_nodes == 0


def test_verification_depth_limit_resets_for_each_document():
    limits = import_module("aegis._internal.verification_limits")
    allowed: object = None
    for _ in range(32):
        allowed = [allowed]
    budget = limits.VerificationBudget(remaining_bytes=256, remaining_nodes=66)

    budget.measure(allowed)
    budget.measure(allowed)

    too_deep: object = None
    for _ in range(33):
        too_deep = [too_deep]
    with pytest.raises(limits.VerificationInputError):
        limits.VerificationBudget().measure(too_deep)


def test_verification_alias_tracking_resets_for_each_supplied_document():
    limits = import_module("aegis._internal.verification_limits")
    repeated_occurrence = {"nested": []}
    budget = limits.VerificationBudget(remaining_bytes=128, remaining_nodes=8)

    budget.measure(repeated_occurrence)
    budget.measure(repeated_occurrence)

    assert budget.remaining_nodes == 4


def test_verification_budget_rejects_aliases_cycles_custom_containers_and_keys():
    limits = import_module("aegis._internal.verification_limits")

    shared: list[object] = []
    aliased = [shared, shared]
    cyclic: list[object] = []
    cyclic.append(cyclic)

    class CustomContainer(list):
        def __bool__(self) -> bool:
            raise AssertionError("caller truthiness must not be used")

        def __repr__(self) -> str:
            raise AssertionError("caller repr must not be used")

    for rejected in (aliased, cyclic, CustomContainer(), {1: "value"}):
        with pytest.raises(limits.VerificationInputError):
            limits.VerificationBudget().measure(rejected)


def test_bounded_materialization_reads_only_one_element_past_the_limit():
    limits = import_module("aegis._internal.verification_limits")

    class HostileSizedIterator:
        def __init__(self, count: int) -> None:
            self._count = count
            self._next_value = 0
            self.next_calls = 0

        def __iter__(self):
            return self

        def __next__(self):
            self.next_calls += 1
            if self._next_value >= self._count:
                raise StopIteration
            value = self._next_value
            self._next_value += 1
            return value

        def __bool__(self) -> bool:
            raise AssertionError("caller truthiness must not be used")

        def __len__(self) -> int:
            raise AssertionError("caller len must not be used")

        def __length_hint__(self) -> int:
            raise AssertionError("caller length hint must not be used")

        def __repr__(self) -> str:
            raise AssertionError("caller repr must not be used")

    exact = HostileSizedIterator(3)
    assert limits.materialize_bounded_iterable(exact, max_items=3) == [0, 1, 2]
    assert exact.next_calls == 4

    over_limit = HostileSizedIterator(100)
    with pytest.raises(limits.VerificationInputError):
        limits.materialize_bounded_iterable(over_limit, max_items=3)
    assert over_limit.next_calls == 4


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(
            import_module(
                "aegis._internal.verification_limits"
            ).VerificationInputError,
            id="forged-limit-error",
        ),
        pytest.param(UnicodeError, id="unicode-error"),
        pytest.param(MemoryError, id="memory-error"),
    ],
)
def test_bounded_materialization_sanitizes_hostile_classification(failure):
    limits = import_module("aegis._internal.verification_limits")

    class HostileClassification:
        @property
        def __class__(self):
            raise failure("secret-marker-from-classification")

        def __iter__(self):
            return iter(())

    with pytest.raises(limits.VerificationInputError) as raised:
        limits.materialize_bounded_iterable(
            HostileClassification(),
            max_items=3,
        )

    assert str(raised.value) == ""
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "secret-marker" not in repr(raised.value)


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_bounded_materialization_preserves_noncatchable_classification(failure):
    limits = import_module("aegis._internal.verification_limits")

    class HostileClassification:
        @property
        def __class__(self):
            raise failure("noncatchable-marker")

        def __iter__(self):
            return iter(())

    with pytest.raises(failure, match="noncatchable-marker"):
        limits.materialize_bounded_iterable(
            HostileClassification(),
            max_items=3,
        )


def test_bounded_verification_errors_drop_every_error_after_the_hundredth():
    contracts = import_module("aegis._internal.verification_contracts")
    limits = import_module("aegis._internal.verification_limits")
    errors = limits.BoundedVerificationErrors()

    for index in range(105):
        errors.append(contracts.VerificationError("CODE", "safe", index))

    assert len(errors) == 100
    assert tuple(error.index for error in errors) == tuple(range(100))


def test_checkpoint_parser_rejects_direct_aliased_graph_with_sanitized_error():
    source = _chain_record_dict()
    shared: list[object] = []
    source["signature_metadata"] = shared
    source["signature"] = shared

    with pytest.raises(CheckpointError) as raised:
        TrustedChainCheckpoint.from_dict(source)

    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


def test_checkpoint_parser_rejects_document_over_aggregate_byte_limit():
    source = deepcopy(_chain_record_dict())
    source["signature_metadata"] = "x" * (4 * 1024 * 1024 + 1)

    with pytest.raises(CheckpointError) as raised:
        TrustedChainCheckpoint.from_dict(source)

    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


def test_prepared_payload_boundary_calls_provider_once_with_disposable_metadata():
    external_signing = import_module("aegis._internal.external_signing")
    verify_prepared = external_signing._verify_prepared_payload_detailed
    metadata = _checkpoint_metadata()

    class MutatingVerifier:
        def __init__(self) -> None:
            self.calls: list[tuple[bytes, str, dict[str, object]]] = []

        def verify(self, payload, signature, disposable_metadata):
            self.calls.append(
                (payload, signature, disposable_metadata.to_dict())
            )
            object.__setattr__(
                disposable_metadata,
                "key_reference",
                "provider-mutated-reference",
            )
            return ExternalVerificationOutcome(
                SignatureStatus.VALID,
                AnchorStatus.ANCHORED,
                VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
                "provider-controlled message",
            )

    verifier = MutatingVerifier()

    result = verify_prepared(b"prepared-checkpoint-payload", "ab" * 32, metadata, verifier)

    assert verifier.calls == [
        (
            b"prepared-checkpoint-payload",
            "ab" * 32,
            metadata.to_dict(),
        )
    ]
    assert result.signature_status is SignatureStatus.VALID
    assert result.anchor_status is AnchorStatus.ANCHORED
    assert result.reason_code is VerificationReasonCode.SIGNATURE_VALID_ANCHORED
    assert result.message == "Signature is valid and externally anchored"
    assert result.signature_metadata is metadata
    assert metadata.key_reference == "kms://checkpoint-key"


def test_prepared_payload_boundary_returns_fixed_unavailable_result_without_provider():
    external_signing = import_module("aegis._internal.external_signing")
    verify_prepared = external_signing._verify_prepared_payload_detailed
    metadata = _checkpoint_metadata()

    result = verify_prepared(b"payload", "ab", metadata, None)

    assert result.signature_status is SignatureStatus.INDETERMINATE
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE
    assert result.message == "External verification is unavailable"
    assert result.signature_metadata is metadata


@pytest.mark.parametrize(
    ("signature_status", "reason_code"),
    [
        (SignatureStatus.UNSIGNED, VerificationReasonCode.UNSIGNED),
        (SignatureStatus.VALID, VerificationReasonCode.LEGACY_SIGNATURE_VALID),
        (SignatureStatus.INVALID, VerificationReasonCode.LEGACY_SIGNATURE_INVALID),
        (
            SignatureStatus.INDETERMINATE,
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
        ),
    ],
)
def test_prepared_payload_boundary_rejects_audit_context_only_outcomes(
    signature_status,
    reason_code,
):
    external_signing = import_module("aegis._internal.external_signing")
    verify_prepared = external_signing._verify_prepared_payload_detailed
    metadata = _checkpoint_metadata()

    class ContextConfusedVerifier:
        def verify(self, _payload, _signature, _metadata):
            return ExternalVerificationOutcome(
                signature_status,
                AnchorStatus.NOT_EVALUATED,
                reason_code,
                "provider-controlled message",
            )

    with pytest.raises(VerificationContractError):
        verify_prepared(b"payload", "ab", metadata, ContextConfusedVerifier())


def test_prepared_payload_boundary_sanitizes_provider_exceptions():
    external_signing = import_module("aegis._internal.external_signing")
    verify_prepared = external_signing._verify_prepared_payload_detailed
    metadata = _checkpoint_metadata()

    class FailingVerifier:
        def verify(self, _payload, _signature, _metadata):
            raise RuntimeError("credential=provider-secret")

    with pytest.raises(
        VerificationContractError,
        match="External verifier failed unexpectedly",
    ) as raised:
        verify_prepared(b"payload", "ab", metadata, FailingVerifier())

    assert raised.value.details == {}
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert "provider-secret" not in str(raised.value)
