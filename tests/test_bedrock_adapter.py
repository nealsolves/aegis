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

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA_PATHS = (
    _REPO_ROOT / "schemas" / "policy_dsl.schema.json",
    _REPO_ROOT / "aegis" / "schemas" / "policy_dsl.schema.json",
)
_POLICY = str(_REPO_ROOT / "tests" / "golden_replays" / "golden_policy_v1.yaml")
_AGENT_ID = "AGENTID12A"
_ALIAS_ID = "ALIASID12B"
_VALID_ALIAS_ARN = (
    f"arn:aws:bedrock:us-east-1:123456789012:agent-alias/{_AGENT_ID}/{_ALIAS_ID}"
)
_VALID_GOV_ALIAS_ARN = (
    f"arn:aws-us-gov:bedrock:us-gov-west-1:123456789012:"
    f"agent-alias/{_AGENT_ID}/{_ALIAS_ID}"
)
_OTHER_ALIAS_ARN = (
    "arn:aws:bedrock:us-east-1:123456789012:"
    "agent-alias/OTHERID12A/OTHALIAS1B"
)

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


def _ids_from_alias(alias_arn):
    return alias_arn.rsplit("/", 2)[-2:]


def _bedrock_trace_part(trace_id="trace-abc-001", alias_arn=_VALID_ALIAS_ARN):
    agent_id, alias_id = _ids_from_alias(alias_arn)
    return {
        "agentAliasId": alias_id,
        "agentId": agent_id,
        "agentVersion": "1",
        "callerChain": [{"agentAliasArn": alias_arn}],
        "collaboratorName": "CollaboratorA",
        "sessionId": "session-1",
        "trace": {
            "orchestrationTrace": {
                "invocationInput": {
                    "agentCollaboratorInvocationInput": {
                        "agentCollaboratorAliasArn": alias_arn,
                        "agentCollaboratorName": "CollaboratorA",
                    },
                    "invocationType": "AGENT_COLLABORATOR",
                    "traceId": trace_id,
                }
            }
        },
    }


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
        collaborator_alias=_VALID_ALIAS_ARN,
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


def test_prepare_step_rejects_malformed_agent_alias_arn():
    """collaborator_alias must match the Bedrock agent-alias ARN pattern."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import WorkflowUnsupportedBindingError

    adapter = BedrockTraceAdapter()
    with _make_session() as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=(
                "arn:aws:bedrock:us-east-1:123456789012:"
                "agent-alias/SHORT/ALIAS"
            ),
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol_evidence": {"bedrock": {}},
        }
        with pytest.raises(WorkflowUnsupportedBindingError, match="agent alias ARN"):
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
            collaborator_alias=_VALID_ALIAS_ARN,
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


def test_prepare_step_accepts_partitioned_arn_alias():
    """GovCloud/China-style AWS partitions are valid Bedrock alias ARNs."""
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding

    adapter = BedrockTraceAdapter()
    with _make_session(
        protocol_constraints={"bedrock": {}},
    ) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_GOV_ALIAS_ARN,
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
            collaborator_alias=_VALID_ALIAS_ARN,
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
        collaborator_alias=_VALID_ALIAS_ARN,
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


def test_complete_step_rejects_malformed_trace_part_when_trace_required():
    from aegis._internal.errors import InvocationValidationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(InvocationValidationError, match="TracePart"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[{}],
            )


def test_complete_step_rejects_trace_parts_for_other_alias():
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(WorkflowProtocolViolationError, match="collaborator_alias"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[_bedrock_trace_part(alias_arn=_OTHER_ALIAS_ARN)],
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
            _bedrock_trace_part("trace-abc-001"),
            _bedrock_trace_part("trace-abc-002"),
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
        trace_parts = [_bedrock_trace_part("trace-xyz-001")]
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
        assert meta.get("collaborator_alias") == _VALID_ALIAS_ARN
        assert meta.get("trace_alias_matched") is True


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
    from aegis.bedrock_adapter import (
        BedrockTraceAdapter,
        BedrockParticipantBinding,
        BedrockPreparedStep,
    )
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


# ---------------------------------------------------------------------------
# P1 Bug fixes: alias correlation correctness
# ---------------------------------------------------------------------------

def test_complete_step_rejects_trace_part_with_alias_only_in_caller_chain():
    """callerChain contains upstream forwarders, not emitter identity.

    A trace part where the bound alias appears only in callerChain (i.e. it was
    the calling agent, not the emitting agent) must be rejected. Accepting it
    would let a downstream agent's trace part pass correlation checks just
    because the bound collaborator called it.
    """
    from aegis._internal.errors import WorkflowProtocolViolationError

    # A trace part where _VALID_ALIAS_ARN appears ONLY in callerChain.
    # The emitting agent is _OTHER_ALIAS_ARN (agentId/agentAliasId and
    # agentCollaboratorAliasArn inside trace content).
    other_agent_id, other_alias_id = _ids_from_alias(_OTHER_ALIAS_ARN)
    caller_chain_only_part = {
        "agentAliasId": other_alias_id,          # emitter is OTHER
        "agentId": other_agent_id,               # emitter is OTHER
        "agentVersion": "1",
        "callerChain": [{"agentAliasArn": _VALID_ALIAS_ARN}],  # bound alias here only
        "collaboratorName": "DownstreamAgent",
        "sessionId": "session-1",
        "trace": {
            "orchestrationTrace": {
                "invocationInput": {
                    "agentCollaboratorInvocationInput": {
                        "agentCollaboratorAliasArn": _OTHER_ALIAS_ARN,  # emitter is OTHER
                        "agentCollaboratorName": "DownstreamAgent",
                    },
                    "invocationType": "AGENT_COLLABORATOR",
                    "traceId": "trace-downstream-001",
                }
            }
        },
    }

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(WorkflowProtocolViolationError, match="collaborator_alias"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[caller_chain_only_part],
            )


def test_complete_step_rejects_mixed_list_with_one_matching_part():
    """A mixed trace_parts list must be rejected even if one part matches.

    Accepting a mixed list allows unrelated trace parts (and their traceIds)
    to be ingested into step metadata, corrupting workflow evidence. Every
    supplied trace part must correlate to the bound collaborator alias.
    """
    from aegis._internal.errors import WorkflowProtocolViolationError

    matching_part = _bedrock_trace_part("trace-match-001", alias_arn=_VALID_ALIAS_ARN)
    mismatched_part = _bedrock_trace_part("trace-other-001", alias_arn=_OTHER_ALIAS_ARN)

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        with pytest.raises(WorkflowProtocolViolationError, match="collaborator_alias"):
            adapter.complete_step(
                prepared,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[matching_part, mismatched_part],
            )
