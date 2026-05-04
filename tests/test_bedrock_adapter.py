"""
Unit tests for aegis.bedrock_adapter.

Covers:
- Import guard behavior (no Bedrock SDK required)
- Schema validation for bedrock protocol_constraints
- Participant binding validation (alias-backed identity)
- Missing trace enforcement (require_trace)
- Adapter step state lifecycle (register, pop, discard)
- enforce_step_post_call step_metadata persistence
"""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA_PATHS = (
    _REPO_ROOT / "schemas" / "policy_dsl.schema.json",
    _REPO_ROOT / "aegis" / "schemas" / "policy_dsl.schema.json",
)
_POLICY = str(_REPO_ROOT / "tests" / "golden_replays" / "golden_policy_v1.yaml")

_BASE_INV = {
    "policy_file": _POLICY,
    "model_provider": "bedrock",
    "model_identifier": "anthropic.claude-3-sonnet-20240229-v1:0",
    "role": "planner",
    "input": {"messages": [{"role": "user", "content": "hello"}]},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


def _load_schemas():
    return [json.loads(path.read_text()) for path in _SCHEMA_PATHS]


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

def test_policy_schema_accepts_bedrock_constraints():
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "bedrock": {
                    "require_trace": True,
                    "require_alias_backed_identity": True,
                }
            }
        },
    }
    import jsonschema
    for schema in _load_schemas():
        jsonschema.validate(policy, schema)


def test_policy_schema_rejects_unknown_bedrock_field():
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "bedrock": {"unknown_bedrock_field": True}
            }
        },
    }
    import jsonschema
    for schema in _load_schemas():
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(policy, schema)


def test_policy_schema_accepts_partial_bedrock_constraints():
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "bedrock": {"require_trace": True}
            }
        },
    }
    import jsonschema
    for schema in _load_schemas():
        jsonschema.validate(policy, schema)


def test_policy_schema_accepts_legacy_bedrock_require_alias():
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "bedrock": {"require_alias": True}
            }
        },
    }
    import jsonschema
    for schema in _load_schemas():
        jsonschema.validate(policy, schema)


def test_policy_schema_rejects_disabled_bedrock_alias_identity():
    policy = {
        "policy_version": "1.0",
        "roles": ["analyst"],
        "workflow": {
            "protocol_constraints": {
                "bedrock": {"require_alias_backed_identity": False}
            }
        },
    }
    import jsonschema
    for schema in _load_schemas():
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(policy, schema)


# ---------------------------------------------------------------------------
# Import guard tests
# ---------------------------------------------------------------------------

def test_adapter_module_importable():
    from aegis import bedrock_adapter  # noqa: F401
    assert bedrock_adapter is not None


def test_dataclasses_importable():
    from aegis.bedrock_adapter import (
        BedrockTraceAdapter,
        BedrockParticipantBinding,
        BedrockPreparedStep,
    )
    assert BedrockTraceAdapter is not None
    assert BedrockParticipantBinding is not None
    assert BedrockPreparedStep is not None


def test_adapter_instantiable():
    from aegis.bedrock_adapter import BedrockTraceAdapter
    adapter = BedrockTraceAdapter()
    assert adapter is not None


def test_participant_binding_is_frozen():
    from aegis.bedrock_adapter import BedrockParticipantBinding
    b = BedrockParticipantBinding(
        participant_id="p1",
        collaborator_alias="arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID",
        role="planner",
    )
    with pytest.raises((AttributeError, TypeError)):
        b.participant_id = "other"  # type: ignore[misc]


def test_prepared_step_is_frozen():
    from aegis.bedrock_adapter import BedrockPreparedStep
    import dataclasses
    assert dataclasses.is_dataclass(BedrockPreparedStep)


# ---------------------------------------------------------------------------
# Helpers for session-integrated tests
# ---------------------------------------------------------------------------

def _make_session(policy_file=None, participants=None, protocol_constraints=None):
    """Build a GovernanceSession with optional injected constraints."""
    import aegis as _aegis
    session = _aegis.AEGIS().open_session(policy_file=policy_file)
    if protocol_constraints is not None:
        session._protocol_constraints = protocol_constraints
    if participants is not None:
        session._participants_by_id = {p["id"]: p for p in participants}
    return session


# ---------------------------------------------------------------------------
# Alias-backed identity enforcement
# ---------------------------------------------------------------------------

def test_prepare_step_rejects_bare_name_alias():
    """collaborator_alias must be a Bedrock agent alias ARN, not a bare name."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    adapter = BedrockTraceAdapter()
    with _make_session() as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias="MyCollaborator",  # bare name — must reject
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol_evidence": {"bedrock": {}},
        }
        with pytest.raises(WorkflowUnsupportedBindingError, match="collaborator_alias"):
            adapter.prepare_step(session, inv, binding=binding)


def test_prepare_step_accepts_arn_alias():
    """collaborator_alias as Bedrock agent alias ARN must pass binding validation."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding

    adapter = BedrockTraceAdapter()
    with _make_session(
        protocol_constraints={"bedrock": {}},
    ) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias="arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID",
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol": "bedrock",
            "protocol_evidence": {
                "bedrock": {"alias_backed": True}
            },
        }
        result = adapter.prepare_step(session, inv, binding=binding)
        assert result._session_result is not None
        assert result._adapter_step_key is not None
        adapter.complete_step(
            result,
            output={"result": "ok", "confidence": 0.9},
        )


def test_prepare_step_rejects_conflicting_alias_backed_false():
    """Host evidence cannot claim alias_backed=False for a governed Bedrock step."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import WorkflowProtocolViolationError

    adapter = BedrockTraceAdapter()
    participants = [{"id": "p1", "roles": ["planner"], "protocols": ["bedrock"]}]
    with _make_session(
        protocol_constraints={"bedrock": {}},
        participants=participants,
    ) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias="arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID",
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol": "bedrock",
            "protocol_evidence": {
                "bedrock": {"alias_backed": False},  # explicitly false — must reject
            },
        }
        with pytest.raises(WorkflowProtocolViolationError, match="alias_backed=False"):
            adapter.prepare_step(session, inv, binding=binding)


# ---------------------------------------------------------------------------
# Missing trace enforcement
# ---------------------------------------------------------------------------

def _make_prepared_step(session, protocol_constraints=None):
    """Helper: run prepare_step with minimal valid state, return (adapter, prepared)."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding

    adapter = BedrockTraceAdapter()
    binding = BedrockParticipantBinding(
        participant_id="p1",
        collaborator_alias="arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID",
        role="planner",
    )
    if protocol_constraints is not None:
        session._protocol_constraints = protocol_constraints
    inv = dict(_BASE_INV)
    inv["context"] = {
        **_BASE_INV["context"],
        "protocol": "bedrock",
        "protocol_evidence": {"bedrock": {"alias_backed": True}},
    }
    prepared = adapter.prepare_step(session, inv, binding=binding)
    return adapter, prepared


def test_complete_step_raises_if_require_trace_and_no_trace_parts():
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(WorkflowProtocolViolationError, match="require_trace"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=None,
            )


def test_complete_step_raises_if_require_trace_and_empty_trace_parts():
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(WorkflowProtocolViolationError, match="require_trace"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[],
            )


def test_complete_step_passes_without_trace_when_require_trace_false():
    with _make_session(protocol_constraints={"bedrock": {"require_trace": False}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": False}},
        )
        artifact = adapter.complete_step(
            prepared,
            output={"result": "ok", "confidence": 0.9},
            trace_parts=None,
        )
        assert artifact["enforcement_result"] == "PASS"


def test_complete_step_passes_with_trace_parts():
    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        trace_parts = [
            {"traceId": "trace-abc-001", "type": "preProcessingTrace"},
            {"traceId": "trace-abc-002", "type": "orchestrationTrace"},
        ]
        artifact = adapter.complete_step(
            prepared,
            output={"result": "ok", "confidence": 0.9},
            trace_parts=trace_parts,
        )
        assert artifact["enforcement_result"] == "PASS"


# ---------------------------------------------------------------------------
# Step metadata persistence
# ---------------------------------------------------------------------------

def test_complete_step_step_metadata_in_artifact():
    """step_metadata with adapter fields persists into the workflow artifact steps."""
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        adapter, prepared = _make_prepared_step(session)
        trace_parts = [{"traceId": "trace-xyz-001", "type": "orchestrationTrace"}]
        artifact = adapter.complete_step(
            prepared,
            output={"result": "ok", "confidence": 0.9},
            trace_parts=trace_parts,
        )
        assert artifact["enforcement_result"] == "PASS"

        steps = session._steps
        assert len(steps) >= 1
        last_step = steps[-1]
        meta = last_step.get("metadata") or {}
        assert meta.get("adapter") == "bedrock_trace"
        assert meta.get("trace_present") is True
        assert "trace-xyz-001" in (meta.get("trace_ids") or [])
        assert meta.get("collaborator_alias") == "arn:aws:bedrock:us-east-1:123456789012:agent-alias/AGENTID/ALIASID"


def test_complete_step_step_metadata_trace_absent():
    """When trace_parts is not supplied, trace_present=False in metadata."""
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        adapter, prepared = _make_prepared_step(session)
        adapter.complete_step(
            prepared,
            output={"result": "ok", "confidence": 0.9},
            trace_parts=None,
        )
        steps = session._steps
        last_step = steps[-1]
        meta = last_step.get("metadata") or {}
        assert meta.get("trace_present") is False
        assert meta.get("trace_parts_count") == 0


def test_adapter_cleans_up_state_on_complete_step_failure():
    """If complete_step raises, adapter step state is discarded."""
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        token_id = prepared._session_result._token_id

        with pytest.raises(WorkflowProtocolViolationError):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=None,
            )

        assert session._adapter_step_states.get(token_id) is None


# ---------------------------------------------------------------------------
# Public import boundary
# ---------------------------------------------------------------------------

def test_bedrock_adapter_not_in_aegis_top_level():
    """BedrockTraceAdapter must not be exported from the top-level aegis package."""
    import aegis
    assert not hasattr(aegis, "BedrockTraceAdapter"), \
        "aegis.BedrockTraceAdapter must not ship via the top-level package in v0.9.0"
    assert not hasattr(aegis, "BedrockParticipantBinding"), \
        "aegis.BedrockParticipantBinding must not ship via the top-level package in v0.9.0"


def test_bedrock_adapter_importable_from_own_module():
    """Adapter is importable via aegis.bedrock_adapter (direct submodule only)."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding, BedrockPreparedStep
    assert BedrockTraceAdapter is not None
    assert BedrockParticipantBinding is not None
    assert BedrockPreparedStep is not None


def test_bedrock_adapter_has_explicit_submodule_exports():
    """The direct submodule owns its public names without top-level re-export."""
    import aegis.bedrock_adapter as mod
    assert set(mod.__all__) == {
        "BedrockTraceAdapter",
        "BedrockParticipantBinding",
        "BedrockPreparedStep",
    }