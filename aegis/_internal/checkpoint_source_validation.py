"""Pure structural validation for finalized v2 checkpoint sources."""

from __future__ import annotations


_HEX_CHARACTERS = frozenset("0123456789abcdef")
_IDENTITY_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
_KEY_VERSION_CHARACTERS = _IDENTITY_CHARACTERS | frozenset(":/")

_AUDIT_REQUIRED_KEYS = frozenset(
    {
        "audit_schema_version",
        "canonicalization_profile",
        "policy_file",
        "policy_schema_version",
        "policy_version",
        "model_provider",
        "model_identifier",
        "role",
        "enforcement_result",
        "failures",
        "input_checksum",
        "output_checksum",
        "timestamp",
        "context",
        "metadata",
        "checksum",
        "signature_status",
        "signature",
    }
)
_AUDIT_OPTIONAL_KEYS = frozenset(
    {
        "failure_gate",
        "failure_reason",
        "risk_score",
        "signature_metadata",
        "provenance",
        "chain_id",
        "chain_index",
        "previous_audit_checksum",
        "reservation_id",
    }
)
_FAILURE_GATES = frozenset(
    {
        "invocation_validation",
        "role_validation",
        "precondition_validation",
        "schema_validation",
        "postcondition_validation",
        "feature_not_implemented",
        "tool_validation",
        "guard_evaluation",
        "condition_resolution",
        "sink_emission",
        "risk_scoring",
        "custom_gate_violation",
        "wrapped_function_error",
    }
)
_CHAIN_KEYS = frozenset(
    {"chain_id", "chain_index", "previous_audit_checksum", "reservation_id"}
)
_CORRELATION_KEYS = frozenset(
    {"session_id", "step_id", "step_index", "workflow_policy_digest"}
)
_SIGNATURE_METADATA_REQUIRED_KEYS = frozenset(
    {
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
)
_SIGNATURE_METADATA_KEYS = _SIGNATURE_METADATA_REQUIRED_KEYS | frozenset(
    {"canonicalization_profile"}
)
_PROVENANCE_KEYS = frozenset(
    {
        "source_ids",
        "derived_from_audit_checksums",
        "compilation_source_hash",
    }
)

_WORKFLOW_REQUIRED_KEYS = frozenset(
    {
        "workflow_schema_version",
        "canonicalization_profile",
        "checksum",
        "signature_status",
        "signature",
        "artifact_type",
        "session_id",
        "status",
        "started_at",
        "steps",
        "invocation_audit_checksums",
        "step_count",
        "invocations",
    }
)
_WORKFLOW_OPTIONAL_KEYS = frozenset(
    {
        "signature_metadata",
        "policy_file",
        "finalized_at",
        "failure_summary",
        "approval_checkpoints",
        "validator_hook_evidence",
        "metadata",
    }
)
_WORKFLOW_STATUSES = frozenset(
    {"COMPLETED", "FAILED", "CANCELED", "INCOMPLETE"}
)
_APPROVAL_KEYS = frozenset(
    {
        "checkpoint_id",
        "paused_at",
        "approver_id",
        "reason",
        "status",
        "resumed_at",
        "approval_note",
        "denial_reason",
    }
)


def _is_int(value: object) -> bool:
    return type(value) is int or (
        type(value) is float and value.is_integer()
    )


def _is_string(value: object, *, minimum: int = 0, maximum: int | None = None) -> bool:
    return (
        type(value) is str
        and len(value) >= minimum
        and (maximum is None or len(value) <= maximum)
    )


def _is_nullable_string(value: object) -> bool:
    return value is None or type(value) is str


def _is_hex64(value: object) -> bool:
    if type(value) is not str:
        return False
    matched = value[:-1] if len(value) == 65 and value.endswith("\n") else value
    return len(matched) == 64 and all(
        character in _HEX_CHARACTERS for character in matched
    )


def _has_exact_object_keys(
    value: object,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> bool:
    return (
        type(value) is dict
        and required <= frozenset(value)
        and frozenset(value) <= required | optional
    )


def _valid_failures(value: object) -> bool:
    if type(value) is not list or len(value) > 1_000:
        return False
    for failure in value:
        if not _has_exact_object_keys(
            failure,
            frozenset({"code", "message", "field"}),
        ):
            return False
        if (
            type(failure["code"]) is not str
            or type(failure["message"]) is not str
            or not _is_nullable_string(failure["field"])
        ):
            return False
    return True


def _valid_context(value: object) -> bool:
    if type(value) is not dict or len(value) > 100:
        return False
    bounded_strings = ("session_id", "step_id", "participant_id")
    for field in bounded_strings:
        if field in value and not _is_string(value[field], minimum=1, maximum=512):
            return False
    if "step_index" in value and (
        not _is_int(value["step_index"])
        or not 0 <= value["step_index"] <= 9_007_199_254_740_991
    ):
        return False
    if "workflow_policy_digest" in value and not _is_hex64(
        value["workflow_policy_digest"]
    ):
        return False
    if ("step_index" in value or "workflow_policy_digest" in value) and not (
        _CORRELATION_KEYS <= frozenset(value)
    ):
        return False
    return True


def _valid_metadata(value: object) -> bool:
    if type(value) is not dict or len(value) > 100:
        return False
    if "enforcement_mode" in value and value["enforcement_mode"] not in (
        "unified",
        "split",
        "split_pre_call_only",
    ):
        return False
    for field in ("pre_call_gates_evaluated", "post_call_gates_evaluated"):
        if field in value and (
            type(value[field]) is not list
            or len(value[field]) > 1_000
            or any(type(item) is not str for item in value[field])
        ):
            return False
    for field in ("pre_call_timestamp", "post_call_timestamp"):
        if field in value and (
            not _is_int(value[field]) or value[field] < 0
        ):
            return False
    return True


def _valid_signature_metadata(value: object) -> bool:
    if not _has_exact_object_keys(
        value,
        _SIGNATURE_METADATA_REQUIRED_KEYS,
        frozenset({"canonicalization_profile"}),
    ):
        return False
    if (
        value["schema_version"] != "1"
        or value["signing_profile"] != "aegis-signature-v1"
        or value["canonicalization_version"] != "aegis-canonical-json-v1"
        or value["payload_type"] != "audit_artifact"
        or value["signature_encoding"] not in ("hex", "base64")
        or not _is_int(value["signed_at"])
        or value["signed_at"] < 0
    ):
        return False
    if (
        "canonicalization_profile" in value
        and value["canonicalization_profile"] != "aegis-json-v2"
    ):
        return False
    algorithm = value["algorithm"]
    key_reference = value["key_reference"]
    key_version = value["key_version"]
    return (
        _is_string(algorithm, minimum=1, maximum=128)
        and all(character in _IDENTITY_CHARACTERS for character in algorithm)
        and _is_string(key_reference, minimum=1, maximum=512)
        and all(0x20 <= ord(character) <= 0x7E for character in key_reference)
        and _is_string(key_version, minimum=1, maximum=128)
        and all(character in _KEY_VERSION_CHARACTERS for character in key_version)
    )


def _valid_provenance(value: object) -> bool:
    if value is None:
        return True
    if (
        type(value) is not dict
        or not 1 <= len(value)
        or not frozenset(value) <= _PROVENANCE_KEYS
    ):
        return False
    if "source_ids" in value:
        source_ids = value["source_ids"]
        if (
            type(source_ids) is not list
            or not 1 <= len(source_ids) <= 1_000
            or any(not _is_string(item, minimum=1) for item in source_ids)
            or len(frozenset(source_ids)) != len(source_ids)
        ):
            return False
    if "derived_from_audit_checksums" in value:
        checksums = value["derived_from_audit_checksums"]
        if (
            type(checksums) is not list
            or not 1 <= len(checksums) <= 1_000
            or any(not _is_hex64(item) for item in checksums)
            or len(frozenset(checksums)) != len(checksums)
        ):
            return False
    return "compilation_source_hash" not in value or _is_hex64(
        value["compilation_source_hash"]
    )


def _valid_chain_fields(value: dict[str, object]) -> bool:
    present = _CHAIN_KEYS.intersection(value)
    if present and present != _CHAIN_KEYS:
        return False
    if not present:
        return True
    index = value["chain_index"]
    if (
        not _is_string(value["chain_id"], minimum=1, maximum=512)
        or not _is_int(index)
        or index < 0
        or not _is_string(value["reservation_id"], minimum=1, maximum=512)
    ):
        return False
    previous = value["previous_audit_checksum"]
    return previous is None if index == 0 else _is_hex64(previous)


def is_valid_audit_artifact_v2(value: object) -> bool:
    """Return whether one measured JSON object matches the audit v2 schema."""
    if not _has_exact_object_keys(value, _AUDIT_REQUIRED_KEYS, _AUDIT_OPTIONAL_KEYS):
        return False
    if (
        value["audit_schema_version"] != "2.0"
        or value["canonicalization_profile"] != "aegis-json-v2"
        or not _is_string(value["policy_file"], minimum=1)
        or type(value["policy_schema_version"]) is not str
        or type(value["policy_version"]) is not str
        or not _is_string(value["model_provider"], minimum=1)
        or not _is_string(value["model_identifier"], minimum=1)
        or not _is_string(value["role"], minimum=1)
        or value["enforcement_result"] not in ("PASS", "FAIL")
        or not _valid_failures(value["failures"])
        or not _is_hex64(value["input_checksum"])
        or not _is_hex64(value["output_checksum"])
        or not _is_int(value["timestamp"])
        or value["timestamp"] < 0
        or not _valid_context(value["context"])
        or not _valid_metadata(value["metadata"])
        or not _is_hex64(value["checksum"])
        or value["signature_status"] not in ("signed", "unsigned")
        or not (value["signature"] is None or type(value["signature"]) is str)
    ):
        return False
    if "failure_gate" in value and not (
        value["failure_gate"] is None
        or (
            type(value["failure_gate"]) is str
            and value["failure_gate"] in _FAILURE_GATES
        )
    ):
        return False
    if "failure_reason" in value and not _is_nullable_string(
        value["failure_reason"]
    ):
        return False
    if "risk_score" in value and not (
        value["risk_score"] is None
        or type(value["risk_score"]) in (int, float)
    ):
        return False
    if "signature_metadata" in value and not _valid_signature_metadata(
        value["signature_metadata"]
    ):
        return False
    if "provenance" in value and not _valid_provenance(value["provenance"]):
        return False
    return _valid_chain_fields(value)


def _valid_workflow_invocations(value: object) -> bool:
    if type(value) is not list or len(value) > 1_024:
        return False
    for invocation in value:
        if not _has_exact_object_keys(
            invocation,
            frozenset({"step_index", "checksum"}),
        ):
            return False
        if (
            not _is_int(invocation["step_index"])
            or invocation["step_index"] < 0
            or not _is_hex64(invocation["checksum"])
        ):
            return False
    return True


def _valid_approval_checkpoints(value: object) -> bool:
    if type(value) is not list:
        return False
    for checkpoint in value:
        if type(checkpoint) is not dict:
            return False
        for field in ("checkpoint_id",):
            if field in checkpoint and type(checkpoint[field]) is not str:
                return False
        for field in ("paused_at",):
            if field in checkpoint and not _is_int(checkpoint[field]):
                return False
        for field in (
            "approver_id",
            "reason",
            "approval_note",
            "denial_reason",
        ):
            if field in checkpoint and not _is_nullable_string(checkpoint[field]):
                return False
        if "status" in checkpoint and checkpoint["status"] not in (
            "pending",
            "approved",
            "denied",
        ):
            return False
        if "resumed_at" in checkpoint and not (
            checkpoint["resumed_at"] is None
            or _is_int(checkpoint["resumed_at"])
        ):
            return False
    return True


def is_valid_workflow_artifact_v2(value: object) -> bool:
    """Return whether one measured JSON object matches the workflow v2 schema."""
    if not _has_exact_object_keys(
        value,
        _WORKFLOW_REQUIRED_KEYS,
        _WORKFLOW_OPTIONAL_KEYS,
    ):
        return False
    if (
        value["workflow_schema_version"] != "2.0"
        or value["canonicalization_profile"] != "aegis-json-v2"
        or not _is_hex64(value["checksum"])
        or value["signature_status"] not in ("signed", "unsigned")
        or not (value["signature"] is None or type(value["signature"]) is str)
        or value["artifact_type"] != "workflow"
        or type(value["session_id"]) is not str
        or type(value["status"]) is not str
        or value["status"] not in _WORKFLOW_STATUSES
        or not _is_int(value["started_at"])
        or type(value["steps"]) is not list
        or any(type(step) is not dict for step in value["steps"])
        or type(value["invocation_audit_checksums"]) is not list
        or any(
            type(checksum) is not str
            for checksum in value["invocation_audit_checksums"]
        )
        or not _is_int(value["step_count"])
        or not 0 <= value["step_count"] <= 1_024
        or not _valid_workflow_invocations(value["invocations"])
    ):
        return False
    if "signature_metadata" in value and type(value["signature_metadata"]) is not dict:
        return False
    if "policy_file" in value and not _is_nullable_string(value["policy_file"]):
        return False
    if "finalized_at" in value and not (
        value["finalized_at"] is None or _is_int(value["finalized_at"])
    ):
        return False
    if "failure_summary" in value and not (
        value["failure_summary"] is None
        or type(value["failure_summary"]) is dict
    ):
        return False
    if "approval_checkpoints" in value and not _valid_approval_checkpoints(
        value["approval_checkpoints"]
    ):
        return False
    if "validator_hook_evidence" in value and (
        type(value["validator_hook_evidence"]) is not list
        or any(
            type(item) is not dict for item in value["validator_hook_evidence"]
        )
    ):
        return False
    return "metadata" not in value or type(value["metadata"]) is dict
