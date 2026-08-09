"""Exact and adversarial tests for immutable checkpoint record contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

import aegis._internal.checkpoint_models as checkpoint_models_module
import aegis._internal.verification_limits as verification_limits_module
from aegis._internal.canonicalization import SAFE_INTEGER_MAX
from aegis._internal.checkpoint_models import (
    CheckpointBindingStatus,
    CheckpointSignatureStatus,
    CheckpointVerificationResult,
    TrustedChainCheckpoint,
    TrustedWorkflowCheckpoint,
    _is_exact_enum_member,
)
from aegis._internal.errors import CheckpointError
from aegis._internal.signature_models import (
    AnchorStatus,
    ArtifactVerificationResult,
    SignatureMetadata,
    SignatureStatus,
    VerificationReasonCode,
)
from aegis._internal.verification_limits import (
    VerificationBudget,
    VerificationInputError,
)


@pytest.mark.parametrize(
    ("enum_type", "canonical"),
    (
        (CheckpointSignatureStatus, CheckpointSignatureStatus.VALID),
        (CheckpointBindingStatus, CheckpointBindingStatus.MATCHED),
    ),
)
def test_checkpoint_enum_authenticity_ignores_mutable_enum_registries(
    enum_type,
    canonical,
):
    member_map = enum_type._member_map_
    member_names = enum_type._member_names_
    value_map = enum_type._value2member_map_
    original_map = member_map.copy()
    original_names = list(member_names)
    original_values = value_map.copy()
    forged = str.__new__(enum_type, canonical.value)
    object.__setattr__(forged, "_name_", "FORGED")
    object.__setattr__(forged, "_value_", canonical.value)
    try:
        member_map["FORGED"] = forged
        member_names.append("FORGED")
        value_map[canonical.value] = forged
        assert _is_exact_enum_member(forged, enum_type) is False
        member_map.clear()
        member_names.clear()
        value_map.clear()
        assert _is_exact_enum_member(canonical, enum_type) is True
    finally:
        member_map.clear()
        member_map.update(original_map)
        member_names[:] = original_names
        value_map.clear()
        value_map.update(original_values)


@pytest.fixture
def chain_record_dict() -> dict[str, object]:
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


@pytest.fixture
def workflow_record_dict() -> dict[str, object]:
    return {
        "checkpoint_schema_version": "1",
        "checkpoint_profile": "aegis-workflow-checkpoint-v1",
        "canonicalization_profile": "aegis-json-v2",
        "workflow_schema_version": "2.0",
        "session_id": "session-123",
        "final_status": "COMPLETED",
        "step_count": 2,
        "invocations": [
            {"step_index": 0, "checksum": "b" * 64},
            {"step_index": 1, "checksum": "c" * 64},
        ],
        "workflow_checksum": "d" * 64,
        "checkpointed_at": 1_725_000_001,
        "signature_metadata": {
            "schema_version": "1",
            "signing_profile": "aegis-workflow-checkpoint-v1",
            "canonicalization_version": "aegis-json-v2",
            "payload_type": "workflow_checkpoint",
            "algorithm": "ed25519",
            "signature_encoding": "base64",
            "key_reference": "kms://workflow-key",
            "key_version": "8",
            "signed_at": 1_725_000_001,
        },
        "signature": "Zm9v",
    }


def _assert_sanitized_input_error(value: object, parser: object) -> None:
    with pytest.raises(CheckpointError) as raised:
        parser(value)  # type: ignore[operator]
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}
    assert "secret-marker" not in str(raised.value)
    assert "secret-marker" not in repr(raised.value.details)


def _constructor_values(record: object) -> dict[str, object]:
    return {
        field: getattr(record, field)
        for field in record.__dataclass_fields__  # type: ignore[attr-defined]
    }


def test_checkpoint_status_values_are_closed_contracts():
    assert [status.value for status in CheckpointSignatureStatus] == [
        "not_evaluated",
        "valid",
        "invalid",
        "unknown_key",
        "revoked",
        "indeterminate",
    ]
    assert [status.value for status in CheckpointBindingStatus] == [
        "not_evaluated",
        "matched",
        "historical",
        "partial",
        "outside",
        "ahead",
        "conflict",
        "out_of_scope",
    ]


def test_chain_checkpoint_round_trip_is_exact_and_immutable(chain_record_dict):
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    assert record.to_dict() == chain_record_dict
    assert TrustedChainCheckpoint.from_dict(record.to_dict()) == record
    with pytest.raises(FrozenInstanceError):
        record.chain_index = 9


def test_workflow_checkpoint_round_trip_is_exact_and_immutable(workflow_record_dict):
    record = TrustedWorkflowCheckpoint.from_dict(workflow_record_dict)
    assert record.to_dict() == workflow_record_dict
    assert TrustedWorkflowCheckpoint.from_dict(record.to_dict()) == record
    with pytest.raises(FrozenInstanceError):
        record.step_count = 9


def test_workflow_checkpoint_detaches_nested_claim(workflow_record_dict):
    source = deepcopy(workflow_record_dict)
    record = TrustedWorkflowCheckpoint.from_dict(source)
    source["invocations"][0]["checksum"] = "f" * 64  # type: ignore[index]
    assert record.invocations[0][1] != "f" * 64


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
@pytest.mark.parametrize("key_change", ["missing", "extra"])
def test_checkpoint_parsers_reject_non_exact_key_sets(
    chain_record_dict, workflow_record_dict, record_kind, key_change
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    if key_change == "missing":
        source.pop("signature")
    else:
        source["secret-marker"] = "secret-marker"
    before = deepcopy(source)
    _assert_sanitized_input_error(source, parser)
    assert source == before


@pytest.mark.parametrize(
    ("record_kind", "field", "bad_value"),
    [
        ("chain", "chain_index", True),
        ("chain", "chain_length", False),
        ("chain", "checkpointed_at", True),
        ("chain", "chain_index", SAFE_INTEGER_MAX + 1),
        ("chain", "artifact_checksum", "A" * 64),
        ("chain", "artifact_checksum", "a" * 63),
        ("chain", "chain_id", ""),
        ("chain", "chain_id", "x" * 513),
        ("chain", "artifact_schema_version", "2.1"),
        ("workflow", "step_count", True),
        ("workflow", "checkpointed_at", False),
        ("workflow", "step_count", SAFE_INTEGER_MAX + 1),
        ("workflow", "workflow_checksum", "G" * 64),
        ("workflow", "session_id", ""),
        ("workflow", "session_id", "x" * 513),
        ("workflow", "workflow_schema_version", "2.1"),
        ("workflow", "final_status", "RUNNING"),
    ],
)
def test_checkpoint_parsers_reject_malformed_scalar_fields(
    chain_record_dict, workflow_record_dict, record_kind, field, bad_value
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source[field] = bad_value
    before = deepcopy(source)
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)
    assert source == before


def test_chain_checkpoint_requires_terminal_coordinate(chain_record_dict):
    chain_record_dict["chain_length"] = 4
    _assert_sanitized_input_error(chain_record_dict, TrustedChainCheckpoint.from_dict)


@pytest.mark.parametrize(
    "claim",
    [
        [{"step_index": 1, "checksum": "b" * 64}],
        [
            {"step_index": 0, "checksum": "b" * 64},
            {"step_index": 2, "checksum": "c" * 64},
        ],
        [{"step_index": True, "checksum": "b" * 64}],
        [{"step_index": 0, "checksum": "B" * 64}],
        [{"step_index": 0, "checksum": "b" * 64, "extra": 1}],
    ],
)
def test_workflow_checkpoint_requires_exact_gapless_claim(workflow_record_dict, claim):
    workflow_record_dict["invocations"] = claim
    workflow_record_dict["step_count"] = len(claim)
    _assert_sanitized_input_error(
        workflow_record_dict, TrustedWorkflowCheckpoint.from_dict
    )


def test_workflow_checkpoint_rejects_claim_count_mismatch(workflow_record_dict):
    workflow_record_dict["step_count"] = 1
    _assert_sanitized_input_error(
        workflow_record_dict, TrustedWorkflowCheckpoint.from_dict
    )


def test_workflow_checkpoint_rejects_more_than_1024_claims(workflow_record_dict):
    workflow_record_dict["step_count"] = 1_025
    workflow_record_dict["invocations"] = [
        {"step_index": index, "checksum": "b" * 64}
        for index in range(1_025)
    ]
    _assert_sanitized_input_error(
        workflow_record_dict, TrustedWorkflowCheckpoint.from_dict
    )


@pytest.mark.parametrize(
    ("record_kind", "field", "bad_value", "expected_code"),
    [
        ("chain", "checkpoint_schema_version", "2", "CHECKPOINT_VERSION_UNSUPPORTED"),
        ("workflow", "checkpoint_schema_version", "2", "CHECKPOINT_VERSION_UNSUPPORTED"),
        (
            "chain",
            "checkpoint_profile",
            "aegis-workflow-checkpoint-v1",
            "CHECKPOINT_PROFILE_INVALID",
        ),
        (
            "workflow",
            "checkpoint_profile",
            "aegis-chain-checkpoint-v1",
            "CHECKPOINT_PROFILE_INVALID",
        ),
        (
            "chain",
            "canonicalization_profile",
            "aegis-canonical-json-v1",
            "CHECKPOINT_PROFILE_INVALID",
        ),
        (
            "workflow",
            "canonicalization_profile",
            "aegis-canonical-json-v1",
            "CHECKPOINT_PROFILE_INVALID",
        ),
    ],
)
def test_checkpoint_discriminator_failures_have_stable_codes(
    chain_record_dict,
    workflow_record_dict,
    record_kind,
    field,
    bad_value,
    expected_code,
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source[field] = bad_value
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    with pytest.raises(CheckpointError) as raised:
        parser(source)
    assert raised.value.code == expected_code
    assert raised.value.details == {}


@pytest.mark.parametrize(
    ("record_kind", "metadata_field", "bad_value"),
    [
        ("chain", "payload_type", "workflow_checkpoint"),
        ("chain", "signing_profile", "aegis-workflow-checkpoint-v1"),
        ("chain", "canonicalization_version", "aegis-canonical-json-v1"),
        ("workflow", "payload_type", "chain_checkpoint"),
        ("workflow", "signing_profile", "aegis-chain-checkpoint-v1"),
        ("workflow", "canonicalization_version", "aegis-canonical-json-v1"),
    ],
)
def test_checkpoint_metadata_profile_mismatches_are_sanitized(
    chain_record_dict,
    workflow_record_dict,
    record_kind,
    metadata_field,
    bad_value,
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["signature_metadata"][metadata_field] = bad_value  # type: ignore[index]
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    with pytest.raises(CheckpointError) as raised:
        parser(source)
    assert raised.value.code == "CHECKPOINT_PROFILE_INVALID"
    assert raised.value.details == {}


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_metadata_discriminator_type_confusion_is_input_invalid(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["signature_metadata"]["payload_type"] = 1  # type: ignore[index]
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    with pytest.raises(CheckpointError) as raised:
        parser(source)
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_timestamp_must_equal_metadata_timestamp(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["checkpointed_at"] = 1
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_rejects_invalid_encoded_signature(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["signature"] = "not valid!"
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_parser_rejects_plain_dict_subclasses(
    chain_record_dict, workflow_record_dict, record_kind
):
    class DictSubclass(dict):
        pass

    source = DictSubclass(
        deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    )
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_parser_rejects_cross_record_replay(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = workflow_record_dict if record_kind == "chain" else chain_record_dict
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_parser_rejects_cycles_without_mutation(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["signature_metadata"]["secret-marker"] = source  # type: ignore[index]
    with pytest.raises(CheckpointError) as raised:
        (
            TrustedChainCheckpoint.from_dict(source)
            if record_kind == "chain"
            else TrustedWorkflowCheckpoint.from_dict(source)
        )
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}
    assert source["signature_metadata"]["secret-marker"] is source  # type: ignore[index]


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_checkpoint_parser_rejects_deeply_nested_input(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    nested: object = "secret-marker"
    for _ in range(33):
        nested = [nested]
    source["signature_metadata"] = nested
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
@pytest.mark.parametrize("bad_value", [{1: "secret-marker"}, float("inf"), "\ud800"])
def test_checkpoint_preflight_rejects_values_outside_plain_json_domain(
    chain_record_dict, workflow_record_dict, record_kind, bad_value
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    source["signature_metadata"] = bad_value
    parser = (
        TrustedChainCheckpoint.from_dict
        if record_kind == "chain"
        else TrustedWorkflowCheckpoint.from_dict
    )
    _assert_sanitized_input_error(source, parser)


def test_verification_budget_retains_aggregate_counters_but_resets_cycle_state():
    shared = ["x"]
    budget = VerificationBudget(remaining_bytes=100, remaining_nodes=10)
    first = budget.measure(shared)
    second = budget.measure(shared)
    assert first == 5
    assert second == 5
    assert budget.remaining_bytes == 90
    assert budget.remaining_nodes == 6


@pytest.mark.parametrize(
    "bad_value",
    [SAFE_INTEGER_MAX + 1, float("nan"), float("-inf"), "\udfff", {1: "x"}],
)
def test_verification_budget_rejects_values_outside_strict_v2_json(bad_value):
    with pytest.raises(VerificationInputError):
        VerificationBudget().measure(bad_value)


def test_verification_budget_rejects_scalar_and_container_subclasses_without_hooks():
    class HostileString(str):
        def __str__(self):
            raise AssertionError("must not dispatch")

    class HostileList(list):
        def __bool__(self):
            raise AssertionError("must not dispatch")

        def __repr__(self):
            raise AssertionError("must not dispatch")

    with pytest.raises(VerificationInputError):
        VerificationBudget().measure(HostileString("secret-marker"))
    with pytest.raises(VerificationInputError):
        VerificationBudget().measure(HostileList([1]))


def test_verification_budget_enforces_exact_default_byte_ceiling():
    budget = VerificationBudget()
    assert budget.measure("x" * (4 * 1024 * 1024 - 2)) == 4 * 1024 * 1024
    assert budget.remaining_bytes == 0
    with pytest.raises(VerificationInputError):
        budget.measure(None)


@pytest.mark.parametrize(
    ("value", "canonical_bytes"),
    (
        ("\x00", 8),
        ("\b\t\n\f\r\x01", 18),
        ('"\\', 6),
        ("A雪😀", 10),
        ({"\x00": '"\\雪😀'}, 24),
    ),
)
def test_verification_budget_counts_canonical_escaped_string_bytes_exactly(
    value,
    canonical_bytes,
):
    budget = VerificationBudget(
        remaining_bytes=canonical_bytes,
        remaining_nodes=2,
    )

    assert budget.measure(value) == canonical_bytes
    assert budget.remaining_bytes == 0
    with pytest.raises(VerificationInputError):
        VerificationBudget(
            remaining_bytes=canonical_bytes - 1,
            remaining_nodes=2,
        ).measure(value)


def test_verification_budget_enforces_exact_default_node_ceiling():
    budget = VerificationBudget()
    assert budget.measure([None] * 65_535) > 0
    assert budget.remaining_nodes == 0
    with pytest.raises(VerificationInputError):
        budget.measure(None)


def test_verification_budget_failure_does_not_consume_aggregate_counters():
    budget = VerificationBudget(remaining_bytes=4, remaining_nodes=2)
    with pytest.raises(VerificationInputError):
        budget.measure("abc")
    assert budget.remaining_bytes == 4
    assert budget.remaining_nodes == 2


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_direct_construction_revalidates_nested_metadata_and_rejects_forgery(
    chain_record_dict, workflow_record_dict, record_kind
):
    source = deepcopy(chain_record_dict if record_kind == "chain" else workflow_record_dict)
    metadata = SignatureMetadata.from_dict(source.pop("signature_metadata"))
    object.__setattr__(metadata, "signed_at", True)
    record_type = TrustedChainCheckpoint if record_kind == "chain" else TrustedWorkflowCheckpoint
    kwargs = {
        **source,
        "signature_metadata": metadata,
        **(
            {}
            if record_kind == "chain"
            else {
                "invocations": tuple(
                    (entry["step_index"], entry["checksum"])
                    for entry in source["invocations"]
                )
            }
        ),
    }
    with pytest.raises(CheckpointError) as raised:
        record_type(**kwargs)
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


def test_direct_chain_construction_rejects_lone_surrogate_scope(chain_record_dict):
    parsed = TrustedChainCheckpoint.from_dict(chain_record_dict)
    values = {
        field: getattr(parsed, field)
        for field in TrustedChainCheckpoint.__dataclass_fields__
    }
    values["chain_id"] = "\ud800"
    with pytest.raises(CheckpointError) as raised:
        TrustedChainCheckpoint(**values)
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


def test_direct_construction_detaches_valid_metadata_snapshot(chain_record_dict):
    parsed = TrustedChainCheckpoint.from_dict(chain_record_dict)
    metadata = parsed.signature_metadata
    values = {
        field: getattr(parsed, field)
        for field in TrustedChainCheckpoint.__dataclass_fields__
    }
    record = TrustedChainCheckpoint(**values)
    object.__setattr__(metadata, "key_version", "secret-marker")
    assert record.signature_metadata.key_version == "7"


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_fix1_valid_record_subclasses_remain_instantiable_for_boundary_tests(
    chain_record_dict, workflow_record_dict, record_kind
):
    base_type = TrustedChainCheckpoint if record_kind == "chain" else TrustedWorkflowCheckpoint

    class RecordSubclass(base_type):
        pass

    parsed = base_type.from_dict(
        chain_record_dict if record_kind == "chain" else workflow_record_dict
    )
    subclass_record = RecordSubclass(**_constructor_values(parsed))
    assert isinstance(subclass_record, RecordSubclass)


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_subclass_parser_is_rejected_without_dynamic_constructor_dispatch(
    chain_record_dict, workflow_record_dict, record_kind
):
    base_type = TrustedChainCheckpoint if record_kind == "chain" else TrustedWorkflowCheckpoint
    constructor_called = False

    class HostileRecord(base_type):
        def __init__(self, *args, **kwargs):
            nonlocal constructor_called
            constructor_called = True

    with pytest.raises(CheckpointError):
        HostileRecord.from_dict(
            chain_record_dict if record_kind == "chain" else workflow_record_dict
        )
    assert constructor_called is False


def test_record_serialization_rejects_nested_metadata_subclass_without_dispatch(
    chain_record_dict,
):
    class HostileMetadata(SignatureMetadata):
        def to_dict(self):
            raise AssertionError("must use the core-owned implementation")

    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    hostile = object.__new__(HostileMetadata)
    for field in SignatureMetadata.__dataclass_fields__:
        object.__setattr__(hostile, field, getattr(record.signature_metadata, field))
    forged = object.__new__(TrustedChainCheckpoint)
    for field in TrustedChainCheckpoint.__dataclass_fields__:
        object.__setattr__(
            forged,
            field,
            hostile if field == "signature_metadata" else getattr(record, field),
        )
    with pytest.raises(CheckpointError):
        TrustedChainCheckpoint.to_dict(forged)


def test_forged_typed_record_fails_core_snapshot_reparse(chain_record_dict):
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    forged = object.__new__(TrustedChainCheckpoint)
    for field in TrustedChainCheckpoint.__dataclass_fields__:
        object.__setattr__(forged, field, getattr(record, field))
    object.__setattr__(forged, "chain_length", 99)
    with pytest.raises(CheckpointError):
        TrustedChainCheckpoint.from_dict(TrustedChainCheckpoint.to_dict(forged))


@pytest.fixture
def verification_result(chain_record_dict):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    signature_result = ArtifactVerificationResult(
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        "Signature is valid and externally anchored",
        checkpoint.signature_metadata,
    )
    return CheckpointVerificationResult(
        input_indexes=(0, 2),
        checkpoint=checkpoint,
        scope_id="chain-123",
        chain_index=2,
        signature_result=signature_result,
        binding_status=CheckpointBindingStatus.MATCHED,
    )


def test_checkpoint_verification_result_accepts_exact_valid_contract(verification_result):
    assert verification_result.input_indexes == (0, 2)
    assert verification_result.scope_id == "chain-123"


@pytest.mark.parametrize("bad_indexes", [(), [0], (True,), (-1,), ("0",)])
def test_checkpoint_verification_result_rejects_invalid_input_indexes(
    verification_result, bad_indexes
):
    values = {
        field: getattr(verification_result, field)
        for field in verification_result.__dataclass_fields__
    }
    values["input_indexes"] = bad_indexes
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(**values)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("checkpoint", object()),
        ("scope_id", "other-chain"),
        ("chain_index", None),
        ("signature_result", object()),
        ("binding_status", "matched"),
    ],
)
def test_checkpoint_verification_result_rejects_type_and_scope_mismatches(
    verification_result, field, bad_value
):
    values = {
        name: getattr(verification_result, name)
        for name in verification_result.__dataclass_fields__
    }
    values[field] = bad_value
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(**values)


def test_workflow_verification_result_forbids_chain_index(workflow_record_dict):
    checkpoint = TrustedWorkflowCheckpoint.from_dict(workflow_record_dict)
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(
            input_indexes=(0,),
            checkpoint=checkpoint,
            scope_id="session-123",
            chain_index=0,
            signature_result=None,
            binding_status=CheckpointBindingStatus.NOT_EVALUATED,
        )


def test_evaluated_verification_result_requires_signature_result(chain_record_dict):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(
            input_indexes=(0,),
            checkpoint=checkpoint,
            scope_id="chain-123",
            chain_index=2,
            signature_result=None,
            binding_status=CheckpointBindingStatus.CONFLICT,
        )


# ---------------------------------------------------------------------------
# Task 2 review hardening regressions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("record_kind", ["chain", "workflow"])
def test_fix1_record_base_constructor_cannot_be_bypassed_by_post_init_override(
    chain_record_dict, workflow_record_dict, record_kind
):
    base_type = TrustedChainCheckpoint if record_kind == "chain" else TrustedWorkflowCheckpoint
    parsed = base_type.from_dict(
        chain_record_dict if record_kind == "chain" else workflow_record_dict
    )

    class HostileRecord(base_type):
        def __post_init__(self):
            pass

    values = _constructor_values(parsed)
    values["chain_length" if record_kind == "chain" else "step_count"] = 99
    with pytest.raises(CheckpointError):
        HostileRecord(**values)


def test_fix1_result_base_constructor_cannot_be_bypassed_by_post_init_override(
    verification_result,
):
    class HostileResult(CheckpointVerificationResult):
        def __post_init__(self):
            pass

    values = _constructor_values(verification_result)
    values["input_indexes"] = ()
    with pytest.raises(CheckpointError):
        HostileResult(**values)


def test_fix1_valid_result_subclass_remains_instantiable(verification_result):
    class ResultSubclass(CheckpointVerificationResult):
        pass

    result = ResultSubclass(**_constructor_values(verification_result))
    assert isinstance(result, ResultSubclass)


@pytest.mark.parametrize(
    "value",
    ["x" * 5, {"x" * 5: None}],
    ids=["scalar", "dictionary-key"],
)
def test_fix2_budget_rejects_over_limit_length_before_surrogate_scan(
    monkeypatch, value
):
    # Instrumentation is necessary because both orders raise the same public
    # error; this proves the linear scan is never entered for an O(1)-rejectable
    # length.
    def unexpected_scan(_value):
        raise AssertionError("surrogate scan ran before byte bound")

    monkeypatch.setattr(
        verification_limits_module,
        "ord",
        unexpected_scan,
        raising=False,
    )
    with pytest.raises(VerificationInputError):
        VerificationBudget(remaining_bytes=4).measure(value)


def test_fix2_direct_scope_length_precedes_unicode_scan(monkeypatch, chain_record_dict):
    # A public exception cannot reveal validation order, so intercept only the
    # character that belongs to the oversized field under test.
    real_ord = ord

    def guarded_ord(character):
        if character == "z":
            raise AssertionError("scope Unicode scan ran before length bound")
        return real_ord(character)

    monkeypatch.setattr(checkpoint_models_module, "ord", guarded_ord, raising=False)
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    values = _constructor_values(record)
    values["chain_id"] = "z" * 513
    with pytest.raises(CheckpointError):
        TrustedChainCheckpoint(**values)


class _HostileEnumValue:
    @property
    def value(self):
        raise RuntimeError("secret-marker-enum-value")


def _forged_metadata(metadata: SignatureMetadata, field: str) -> SignatureMetadata:
    forged = object.__new__(SignatureMetadata)
    for name in SignatureMetadata.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(metadata, name))
    object.__setattr__(forged, field, _HostileEnumValue())
    return forged


@pytest.mark.parametrize("field", ["payload_type", "signature_encoding"])
def test_fix3_direct_record_sanitizes_hostile_metadata_value_access(
    chain_record_dict, field
):
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    values = _constructor_values(record)
    values["signature_metadata"] = _forged_metadata(record.signature_metadata, field)
    with pytest.raises(CheckpointError) as raised:
        TrustedChainCheckpoint(**values)
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert "secret-marker" not in str(raised.value)
    assert raised.value.details == {}


@pytest.mark.parametrize("field", ["payload_type", "signature_encoding"])
def test_fix3_to_dict_sanitizes_hostile_metadata_value_access(
    chain_record_dict, field
):
    record = TrustedChainCheckpoint.from_dict(chain_record_dict)
    forged = object.__new__(TrustedChainCheckpoint)
    for name in TrustedChainCheckpoint.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(record, name))
    object.__setattr__(
        forged,
        "signature_metadata",
        _forged_metadata(record.signature_metadata, field),
    )
    with pytest.raises(CheckpointError) as raised:
        TrustedChainCheckpoint.to_dict(forged)
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert "secret-marker" not in str(raised.value)
    assert raised.value.details == {}


def test_fix3_workflow_to_dict_rejects_hostile_claim_before_iteration(
    workflow_record_dict,
):
    class HostileClaim:
        iteration_count = 0

        def __iter__(self):
            self.iteration_count += 1
            raise RuntimeError("secret-marker-claim")

    record = TrustedWorkflowCheckpoint.from_dict(workflow_record_dict)
    forged = object.__new__(TrustedWorkflowCheckpoint)
    for name in TrustedWorkflowCheckpoint.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(record, name))
    claim = HostileClaim()
    object.__setattr__(forged, "invocations", claim)
    with pytest.raises(CheckpointError) as raised:
        TrustedWorkflowCheckpoint.to_dict(forged)
    assert claim.iteration_count == 0
    assert "secret-marker" not in str(raised.value)
    assert raised.value.details == {}


def test_fix4_result_rejects_forged_exact_checkpoint(verification_result):
    checkpoint = verification_result.checkpoint
    forged = object.__new__(TrustedChainCheckpoint)
    for name in TrustedChainCheckpoint.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(checkpoint, name))
    object.__setattr__(forged, "chain_length", 99)
    values = _constructor_values(verification_result)
    values["checkpoint"] = forged
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(**values)


def test_fix4_result_rejects_forged_exact_provider_result(verification_result):
    provider_result = verification_result.signature_result
    forged = object.__new__(ArtifactVerificationResult)
    for name in ArtifactVerificationResult.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(provider_result, name))
    object.__setattr__(forged, "signature_status", _HostileEnumValue())
    values = _constructor_values(verification_result)
    values["signature_result"] = forged
    with pytest.raises(CheckpointError) as raised:
        CheckpointVerificationResult(**values)
    assert "secret-marker" not in str(raised.value)
    assert raised.value.details == {}


def test_fix4_result_rejects_provider_metadata_mismatch(verification_result):
    checkpoint = verification_result.checkpoint
    metadata_dict = SignatureMetadata.to_dict(checkpoint.signature_metadata)
    metadata_dict["key_version"] = "different-version"
    other_metadata = SignatureMetadata.from_dict(metadata_dict)
    provider_result = ArtifactVerificationResult(
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        "safe",
        other_metadata,
    )
    values = _constructor_values(verification_result)
    values["signature_result"] = provider_result
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(**values)


def test_fix4_result_detaches_checkpoint_and_provider_result(verification_result):
    source_checkpoint = verification_result.checkpoint
    source_provider_result = verification_result.signature_result
    detached = CheckpointVerificationResult(**_constructor_values(verification_result))
    assert detached.checkpoint is not source_checkpoint
    assert detached.signature_result is not source_provider_result
    object.__setattr__(source_checkpoint, "chain_id", "secret-marker")
    object.__setattr__(source_provider_result, "message", "secret-marker")
    assert detached.checkpoint.chain_id == "chain-123"
    assert detached.signature_result.message == "Signature is valid and externally anchored"


@pytest.mark.parametrize(
    ("signature_status", "anchor_status", "reason_code"),
    [
        (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_INVALID,
        ),
    ],
)
def test_fix4_result_preserves_valid_unavailable_and_invalid_outcomes(
    chain_record_dict, signature_status, anchor_status, reason_code
):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    provider_result = ArtifactVerificationResult(
        signature_status,
        anchor_status,
        reason_code,
        "safe",
        checkpoint.signature_metadata,
    )
    result = CheckpointVerificationResult(
        input_indexes=(0,),
        checkpoint=checkpoint,
        scope_id="chain-123",
        chain_index=2,
        signature_result=provider_result,
        binding_status=CheckpointBindingStatus.MATCHED,
    )
    assert result.signature_result.signature_status is signature_status


@pytest.mark.parametrize(
    "binding_status",
    [CheckpointBindingStatus.NOT_EVALUATED, CheckpointBindingStatus.OUT_OF_SCOPE],
)
def test_fix5_unevaluated_bindings_forbid_provider_results(
    verification_result, binding_status
):
    values = _constructor_values(verification_result)
    values["binding_status"] = binding_status
    with pytest.raises(CheckpointError):
        CheckpointVerificationResult(**values)


def _checkpoint_result_for_outcome(
    checkpoint: TrustedChainCheckpoint,
    signature_status: SignatureStatus,
    anchor_status: AnchorStatus,
    reason_code: VerificationReasonCode,
    metadata: SignatureMetadata | None,
) -> CheckpointVerificationResult:
    provider_result = ArtifactVerificationResult(
        signature_status,
        anchor_status,
        reason_code,
        "safe",
        metadata,
    )
    return CheckpointVerificationResult(
        input_indexes=(0,),
        checkpoint=checkpoint,
        scope_id="chain-123",
        chain_index=2,
        signature_result=provider_result,
        binding_status=CheckpointBindingStatus.MATCHED,
    )


def test_fix_round2_anchored_valid_result_requires_metadata(chain_record_dict):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    with pytest.raises(CheckpointError) as raised:
        _checkpoint_result_for_outcome(
            checkpoint,
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
            None,
        )
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


@pytest.mark.parametrize(
    ("signature_status", "anchor_status", "reason_code"),
    [
        (
            SignatureStatus.UNSIGNED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.UNSIGNED,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
        ),
        (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
        ),
    ],
)
def test_fix_round2_rejects_checkpoint_context_impossible_outcomes(
    chain_record_dict, signature_status, anchor_status, reason_code
):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    with pytest.raises(CheckpointError) as raised:
        _checkpoint_result_for_outcome(
            checkpoint,
            signature_status,
            anchor_status,
            reason_code,
            checkpoint.signature_metadata,
        )
    assert raised.value.code == "CHECKPOINT_INPUT_INVALID"
    assert raised.value.details == {}


@pytest.mark.parametrize(
    ("signature_status", "anchor_status", "reason_code"),
    [
        (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_INVALID,
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
        ),
        (
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.KEY_UNKNOWN,
        ),
        (
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.KEY_REVOKED,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            VerificationReasonCode.ANCHOR_INVALID,
        ),
    ],
)
def test_fix_round2_accepts_checkpoint_applicable_outcomes_with_matching_metadata(
    chain_record_dict, signature_status, anchor_status, reason_code
):
    checkpoint = TrustedChainCheckpoint.from_dict(chain_record_dict)
    result = _checkpoint_result_for_outcome(
        checkpoint,
        signature_status,
        anchor_status,
        reason_code,
        checkpoint.signature_metadata,
    )
    assert result.signature_result.signature_status is signature_status
    assert result.signature_result.anchor_status is anchor_status
    assert result.signature_result.reason_code is reason_code
    assert result.signature_result.signature_metadata == checkpoint.signature_metadata
    assert result.signature_result.signature_metadata is not checkpoint.signature_metadata
