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
        pending = session._pending_results[result._session_result.operation_id]
        assert "inner" not in pending
        assert inv["output"] == {"result": "ok", "confidence": 0.9}
        assert result._session_result is not None
        assert result._adapter_step_key is not None
        adapter.complete_step(
            result,
            output={"result": "ok", "confidence": 0.9},
        )


def test_prepare_step_rejects_malformed_broad_invocation_output():
    """A broad adapter input validates output before projecting Phase A."""
    from aegis.bedrock_adapter import (
        BedrockParticipantBinding,
        BedrockTraceAdapter,
    )
    from aegis._internal.errors import InvocationValidationError

    adapter = BedrockTraceAdapter()
    invocation = dict(_BASE_INV)
    invocation["output"] = "not-an-object"
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        with pytest.raises(
            InvocationValidationError,
            match="Adapter invocation field 'output' must be an object",
        ) as raised:
            adapter.prepare_step(session, invocation, binding=binding)

    assert raised.value.details == {"field": "output"}
    assert invocation["output"] == "not-an-object"


@pytest.mark.parametrize(
    "output",
    [
        {"blob": "x" * (5 * 1024 * 1024)},
        None,
    ],
    ids=["five-megabytes", "depth-10000"],
)
def test_prepare_step_rejects_adversarial_output_with_stable_error(output):
    """The real adapter rejects hostile output before Phase A."""
    from aegis.bedrock_adapter import (
        BedrockParticipantBinding,
        BedrockTraceAdapter,
    )
    from aegis._internal.errors import InvocationValidationError

    if output is None:
        nested = None
        for _ in range(10_000):
            nested = [nested]
        output = {"deep": nested}

    adapter = BedrockTraceAdapter()
    invocation = dict(_BASE_INV)
    invocation["output"] = output
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        with pytest.raises(InvocationValidationError) as raised:
            adapter.prepare_step(session, invocation, binding=binding)

    assert raised.value.code == "INVOCATION_VALIDATION_ERROR"
    assert invocation["output"] is output


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


@pytest.mark.parametrize("falsey_non_dict", [[], "", 0, False])
def test_prepare_step_rejects_falsey_non_dict_protocol_evidence(falsey_non_dict):
    """Falsey non-dict protocol_evidence must raise InvocationValidationError.

    A bare ``or {}`` coerces falsey values to an empty mapping before the type
    check, silently accepting malformed evidence.  An explicit None-check must
    be used instead so that callers supplying e.g. [] get a hard error.
    """
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import InvocationValidationError

    adapter = BedrockTraceAdapter()
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol_evidence": falsey_non_dict,
        }
        with pytest.raises(InvocationValidationError, match="protocol_evidence"):
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
        token_id = prepared._session_result.operation_id

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


def test_complete_step_rejects_trace_part_with_bound_alias_as_invocation_target():
    """agentCollaboratorAliasArn identifies an invocation target, not the emitter.

    An orchestrator agent (different from the bound collaborator) emits a trace
    part whose agentCollaboratorAliasArn equals the bound alias because it is
    calling the bound collaborator. The emitter envelope (agentId/agentAliasId)
    belongs to the orchestrator. This part must be rejected — the bound alias
    appearing as an invocation target inside trace content is not emitter
    identity and must never satisfy alias correlation.
    """
    from aegis._internal.errors import WorkflowProtocolViolationError

    other_agent_id, other_alias_id = _ids_from_alias(_OTHER_ALIAS_ARN)
    # Orchestrator emitting a trace that calls the bound collaborator.
    # Emitter envelope is _OTHER_ALIAS_ARN. Bound alias appears only in
    # agentCollaboratorAliasArn (the invocation target), not as emitter.
    orchestrator_emits_call_to_bound = {
        "agentAliasId": other_alias_id,    # emitter is OTHER (the orchestrator)
        "agentId": other_agent_id,         # emitter is OTHER (the orchestrator)
        "agentVersion": "1",
        "collaboratorName": "OrchestratorAgent",
        "sessionId": "session-1",
        "trace": {
            "orchestrationTrace": {
                "invocationInput": {
                    "agentCollaboratorInvocationInput": {
                        # Bound alias here — but this is the TARGET of the call,
                        # not the emitter of this trace part.
                        "agentCollaboratorAliasArn": _VALID_ALIAS_ARN,
                        "agentCollaboratorName": "BoundCollaborator",
                    },
                    "invocationType": "AGENT_COLLABORATOR",
                    "traceId": "trace-orchestrator-001",
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
                trace_parts=[orchestrator_emits_call_to_bound],
            )


# ---------------------------------------------------------------------------
# P1/P2 fixes: state integrity and context type validation
# ---------------------------------------------------------------------------

def test_complete_step_rejects_absent_adapter_state():
    """complete_step must reject a BedrockPreparedStep whose adapter state was
    never registered (or was already consumed), not silently bypass Bedrock
    controls. Without this guard, require_trace and alias correlation are
    both skipped because adapter_state defaults to an empty dict.
    """
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        # Consume the adapter state as the first complete_step call would.
        # A second call to complete_step on the same prepared step must be
        # rejected because the state is absent, not silently pass.
        adapter.complete_step(
            prepared,
            output={"result": "ok", "confidence": 0.9},
            trace_parts=[_bedrock_trace_part()],
        )

    # Outside the context manager, attempt to forge a second completion using
    # a reconstructed BedrockPreparedStep that has no registered adapter state.
    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as fresh_session:
        adapter2, prepared2 = _make_prepared_step(
            fresh_session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        # Pop the state so that the next call has an empty-dict default.
        fresh_session.pop_adapter_step_state(prepared2._session_result)

        with pytest.raises(WorkflowProtocolViolationError, match="adapter state"):
            adapter2.complete_step(
                prepared2,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[_bedrock_trace_part()],
            )


def test_complete_step_discards_token_on_key_mismatch():
    """P2: complete_step must discard the pre-call token on adapter_step_key mismatch.

    Before the fix, pop_adapter_step_state removed the state before the key
    check, leaving an unconsumed session token in _pending_results.  A caller
    that caught the error could then call enforce_step_post_call directly and
    bypass all Bedrock trace/alias checks.  After the fix the token must be
    consumed (not completable) on the error path.
    """
    from aegis.bedrock_adapter import BedrockPreparedStep
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"bedrock": {"require_trace": True}}) as session:
        adapter, prepared = _make_prepared_step(
            session,
            protocol_constraints={"bedrock": {"require_trace": True}},
        )
        session_result = prepared._session_result
        token_id = session_result.operation_id

        # Forge a prepared step with a mismatched adapter_step_key.
        forged = BedrockPreparedStep(
            _session_result=prepared._session_result,
            _adapter_step_key="00000000-0000-0000-0000-000000000000",
            _session=session,
        )

        with pytest.raises(WorkflowProtocolViolationError, match="adapter state"):
            adapter.complete_step(
                forged,
                output={"result": "ok", "confidence": 0.9},
                trace_parts=[_bedrock_trace_part()],
            )

        # Token must be consumed — the bypass window is closed.
        assert token_id not in session._pending_results, (
            "pending token still present after key-mismatch rejection — "
            "bypass window is open"
        )


def test_prepare_step_rejects_conflicting_top_level_protocol():
    """A caller-supplied invocation['protocol'] != 'bedrock' must be rejected.

    Without this guard, GovernanceSession prefers the top-level value and the
    step can pass under a different protocol's constraints entirely (P1).
    """
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import WorkflowProtocolViolationError

    adapter = BedrockTraceAdapter()
    with _make_session(protocol_constraints={"local": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["protocol"] = "local"  # conflicting top-level protocol
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol_evidence": {"bedrock": {"alias_backed": True}},
        }
        with pytest.raises(WorkflowProtocolViolationError, match="conflicts with BedrockTraceAdapter"):
            adapter.prepare_step(session, inv, binding=binding)


def test_prepare_step_stamps_top_level_protocol_bedrock():
    """Adapter must write enriched['protocol'] = 'bedrock' so GovernanceSession
    uses the correct protocol key regardless of context-only stamping (P1).
    """
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding

    adapter = BedrockTraceAdapter()
    captured: list[dict] = []

    class _CapturingSession:
        session_id = "test-session"
        _protocol_constraints = {"bedrock": {}}
        _participants_by_id: dict = {}

        def protocol_constraints_for(self, protocol):
            return self._protocol_constraints.get(protocol, {})

        def participant_for(self, pid):
            return None

        def enforce_step_pre_call(self, inv, *, step_id, participant_id):
            captured.append(dict(inv))
            raise RuntimeError("stop after capture")

    inv = dict(_BASE_INV)
    inv["context"] = {
        **_BASE_INV["context"],
        "protocol_evidence": {"bedrock": {"alias_backed": True}},
    }
    binding = BedrockParticipantBinding(
        participant_id="p1",
        collaborator_alias=_VALID_ALIAS_ARN,
        role="planner",
    )
    session = _CapturingSession()
    with pytest.raises(RuntimeError, match="stop after capture"):
        adapter.prepare_step(session, inv, binding=binding)  # type: ignore[arg-type]

    assert len(captured) == 1
    assert captured[0].get("protocol") == "bedrock"


def test_prepare_step_rejects_invocation_role_differing_from_binding():
    """An explicit invocation['role'] that differs from binding.role must raise.

    Without this guard a caller can bind 'planner' but govern the step as
    'verifier', bypassing role enforcement (P2).
    """
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import WorkflowParticipantMismatchError

    adapter = BedrockTraceAdapter()
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["role"] = "verifier"  # differs from binding.role
        inv["context"] = {
            **_BASE_INV["context"],
            "protocol_evidence": {"bedrock": {"alias_backed": True}},
        }
        with pytest.raises(WorkflowParticipantMismatchError, match="conflicts with binding\\.role"):
            adapter.prepare_step(session, inv, binding=binding)


def test_prepare_step_raises_structured_error_when_context_is_non_dict():
    """If invocation['context'] is a truthy non-dict (e.g. a string), the
    adapter must raise InvocationValidationError — not AttributeError — before
    any .get() call is attempted on the non-mapping value.
    """
    from aegis.bedrock_adapter import BedrockTraceAdapter, BedrockParticipantBinding
    from aegis._internal.errors import InvocationValidationError

    adapter = BedrockTraceAdapter()
    with _make_session(protocol_constraints={"bedrock": {}}) as session:
        binding = BedrockParticipantBinding(
            participant_id="p1",
            collaborator_alias=_VALID_ALIAS_ARN,
            role="planner",
        )
        inv = dict(_BASE_INV)
        inv["context"] = "bedrock"  # truthy non-dict — the crash scenario
        with pytest.raises(InvocationValidationError, match="context"):
            adapter.prepare_step(session, inv, binding=binding)
