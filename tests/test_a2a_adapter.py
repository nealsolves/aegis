"""Unit tests for aegis.a2a_adapter.

Covers:
- Import boundary and no required A2A SDK dependency
- Strict policy schema for workflow.protocol_constraints.a2a
- Agent Card compatibility from supportedInterfaces[].protocolVersion
- gRPC rejection and binding checks
- Normative TASK_STATE_* validation
- Adapter state lifecycle and redacted workflow step metadata
"""
from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import jsonschema
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA_PATHS = (
    _REPO_ROOT / "schemas" / "policy_dsl.schema.json",
    _REPO_ROOT / "aegis" / "schemas" / "policy_dsl.schema.json",
)
_POLICY = str(_REPO_ROOT / "tests" / "golden_replays" / "golden_policy_v1.yaml")

_BASE_INV = {
    "policy_file": _POLICY,
    "model_provider": "a2a",
    "model_identifier": "remote-agent-card",
    "role": "planner",
    "input": {"messages": [{"role": "user", "content": "hello"}]},
    "context": {"role_declared": True, "schema_exists": True},
}
_GOOD_OUTPUT = {"result": "ok", "confidence": 0.9}

_AGENT_CARD_JSONRPC = {
    "name": "RemotePlanner",
    "version": "1.0.0",
    "capabilities": {"streaming": True, "nested": {"drop": "me"}},
    "supportedInterfaces": [
        {
            "url": "https://example.test/a2a",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "skills": [
        {
            "id": "plan",
            "name": "Plan",
            "tags": ["planning"],
            "inputModes": ["text/plain"],
            "outputModes": ["application/json"],
            "examples": ["do not persist"],
        }
    ],
}
_AGENT_CARD_HTTP_JSON = {
    **_AGENT_CARD_JSONRPC,
    "supportedInterfaces": [
        {
            "url": "https://example.test/a2a/tasks",
            "protocolBinding": "HTTP+JSON",
            "protocolVersion": "1.0",
        }
    ],
}
_TASK_COMPLETED = {
    "id": "task-1",
    "contextId": "ctx-1",
    "status": {"state": "TASK_STATE_COMPLETED"},
    "artifacts": [{"artifactId": "a1"}],
    "history": [],
}


def _load_schemas():
    return [json.loads(path.read_text()) for path in _SCHEMA_PATHS]


def _policy_with_a2a_constraints(a2a_constraints):
    return {
        "policy_version": "1.0",
        "roles": ["planner"],
        "workflow": {"protocol_constraints": {"a2a": a2a_constraints}},
    }


def _make_session(participants=None, protocol_constraints=None):
    import aegis as _aegis

    session = _aegis.AEGIS().open_session(policy_file=None)
    if protocol_constraints is not None:
        session._protocol_constraints = protocol_constraints
    if participants is not None:
        session._participants = participants
        session._participants_by_id = {p["id"]: p for p in participants}
    return session


def _binding(role="planner", agent_name="RemotePlanner"):
    from aegis.a2a_adapter import A2AParticipantBinding

    return A2AParticipantBinding(
        participant_id="agent-1",
        agent_name=agent_name,
        role=role,
    )


def _prepare(adapter=None, session=None, inv=None, agent_card=None):
    from aegis.a2a_adapter import A2AAdapter

    adapter = adapter or A2AAdapter()
    return adapter.prepare_step(
        session,
        inv or copy.deepcopy(_BASE_INV),
        binding=_binding(),
        agent_card=agent_card or copy.deepcopy(_AGENT_CARD_JSONRPC),
    )


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "constraints",
    [
        {},
        {"protocol_version": "1.0"},
        {"allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"]},
        {"require_task_state": True},
        {
            "protocol_version": "1.0",
            "allowed_protocol_bindings": ["HTTP+JSON"],
            "require_task_state": False,
        },
    ],
)
def test_policy_schema_accepts_a2a_constraints(constraints):
    for schema in _load_schemas():
        jsonschema.validate(_policy_with_a2a_constraints(constraints), schema)


@pytest.mark.parametrize(
    "constraints",
    [
        {"unknown": True},
        {"protocol_version": "0.3"},
        {"allowed_protocol_bindings": ["GRPC"]},
        {"allowed_protocol_bindings": ["grpc"]},
        {"allowed_protocol_bindings": ["JSONRPC", "JSONRPC"]},
        {"require_task_state": "true"},
    ],
)
def test_policy_schema_rejects_invalid_a2a_constraints(constraints):
    for schema in _load_schemas():
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(_policy_with_a2a_constraints(constraints), schema)


# ---------------------------------------------------------------------------
# Import boundary
# ---------------------------------------------------------------------------

def test_adapter_module_importable_without_sdk():
    from aegis import a2a_adapter

    assert a2a_adapter is not None


def test_dataclasses_importable_and_frozen_without_sdk():
    from aegis.a2a_adapter import (
        A2AAdapter,
        A2AParticipantBinding,
        A2APreparedStep,
    )

    assert A2AAdapter() is not None
    binding = A2AParticipantBinding("p1", "Agent", "planner")
    prepared = A2APreparedStep(object(), "step-key", object())
    assert dataclasses.is_dataclass(A2AParticipantBinding)
    assert dataclasses.is_dataclass(A2APreparedStep)
    with pytest.raises((AttributeError, TypeError)):
        binding.participant_id = "other"  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        prepared._adapter_step_key = "other"  # type: ignore[misc]


def test_top_level_aegis_does_not_reexport_a2a_adapter_classes():
    import aegis
    import aegis.a2a_adapter as module

    assert module.__all__ == [
        "A2AAdapter",
        "A2AParticipantBinding",
        "A2APreparedStep",
    ]
    assert not hasattr(aegis, "A2AAdapter")
    assert not hasattr(aegis, "A2AParticipantBinding")
    assert not hasattr(aegis, "A2APreparedStep")


# ---------------------------------------------------------------------------
# Mapping and redaction helpers
# ---------------------------------------------------------------------------

def test_to_mapping_accepts_dict_and_returns_copy():
    from aegis.a2a_adapter import _to_mapping

    original = {"name": "RemotePlanner"}
    converted = _to_mapping(original, label="agent_card")
    assert converted == original
    assert converted is not original


def test_to_mapping_accepts_pydantic_like_objects():
    from aegis.a2a_adapter import _to_mapping

    class V2Model:
        def model_dump(self, *, by_alias=False):
            assert by_alias is True
            return {"supportedInterfaces": []}

    class V1Model:
        def dict(self, *, by_alias=False):
            assert by_alias is True
            return {"supportedInterfaces": []}

    assert _to_mapping(V2Model(), label="card") == {"supportedInterfaces": []}
    assert _to_mapping(V1Model(), label="card") == {"supportedInterfaces": []}


def test_to_mapping_rejects_invalid_objects():
    from aegis._internal.errors import InvocationValidationError
    from aegis.a2a_adapter import _to_mapping

    class BadDump:
        def model_dump(self, *, by_alias=False):
            return ["not", "mapping"]

    with pytest.raises(InvocationValidationError):
        _to_mapping(BadDump(), label="bad")
    with pytest.raises(InvocationValidationError):
        _to_mapping(object(), label="bad")


def test_request_metadata_redaction_drops_secrets_and_bounds_strings():
    from aegis.a2a_adapter import _redacted_request_metadata

    metadata = {
        "Authorization": "Bearer secret",
        "access_token": "secret",
        "api_key": "secret",
        "credential": "secret",
        "password": "secret",
        "secret": "secret",
        "tenant": "acme",
        "debug": True,
        "nested": {"drop": True},
        "long": "x" * 140,
    }
    redacted = _redacted_request_metadata(metadata)

    assert redacted["tenant"] == "acme"
    assert redacted["debug"] is True
    assert "nested" not in redacted
    assert "Authorization" not in redacted
    assert "access_token" not in redacted
    assert redacted["long"].endswith("...[truncated]")
    assert len(redacted["long"]) > 128


# ---------------------------------------------------------------------------
# Agent Card validation
# ---------------------------------------------------------------------------

def test_validate_agent_card_accepts_jsonrpc_http_json_and_later_valid_interface():
    from aegis.a2a_adapter import _validate_agent_card

    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    _, selected_jsonrpc = _validate_agent_card(_AGENT_CARD_JSONRPC, constraints)
    _, selected_http = _validate_agent_card(_AGENT_CARD_HTTP_JSON, constraints)
    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "0.3"},
            {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
        ],
    }
    _, selected_later = _validate_agent_card(card, constraints)

    assert selected_jsonrpc["protocolBinding"] == "JSONRPC"
    assert selected_http["protocolBinding"] == "HTTP+JSON"
    assert selected_later["protocolBinding"] == "HTTP+JSON"


@pytest.mark.parametrize(
    "card",
    [
        {k: v for k, v in _AGENT_CARD_JSONRPC.items() if k != "supportedInterfaces"},
        {**_AGENT_CARD_JSONRPC, "supportedInterfaces": []},
        {**_AGENT_CARD_JSONRPC, "supportedInterfaces": "not-list"},
        {**_AGENT_CARD_JSONRPC, "supportedInterfaces": [object()]},
        {
            **_AGENT_CARD_JSONRPC,
            "supportedInterfaces": [{"protocolBinding": "JSONRPC", "protocolVersion": "0.3"}],
        },
        {
            **_AGENT_CARD_JSONRPC,
            "supportedInterfaces": [{"protocolBinding": "GRPC", "protocolVersion": "1.0"}],
        },
        {
            **_AGENT_CARD_JSONRPC,
            "supportedInterfaces": [{"protocolBinding": "grpc", "protocolVersion": "1.0"}],
        },
        {
            **_AGENT_CARD_JSONRPC,
            "supportedInterfaces": [{"protocolBinding": "jsonrpc", "protocolVersion": "1.0"}],
        },
        {
            "name": "RemotePlanner",
            "version": "1.0.0",
            "supported_interfaces": [
                {"protocol_binding": "JSONRPC", "protocol_version": "1.0"}
            ],
        },
    ],
)
def test_validate_agent_card_rejects_invalid_compatibility(card):
    from aegis._internal.errors import (
        InvocationValidationError,
        WorkflowProtocolViolationError,
    )
    from aegis.a2a_adapter import _validate_agent_card

    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises((InvocationValidationError, WorkflowProtocolViolationError)):
        _validate_agent_card(card, constraints)


@pytest.mark.parametrize(
    "protocol_binding,expected_type",
    [
        (["JSONRPC"], "list"),
        ({"binding": "JSONRPC"}, "dict"),
    ],
)
def test_validate_agent_card_rejects_non_string_protocol_binding(
    protocol_binding, expected_type
):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": protocol_binding, "protocolVersion": "1.0"}
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises(WorkflowProtocolViolationError) as exc_info:
        _validate_agent_card(card, constraints)
    assert exc_info.value.details.get("reason_code") == (
        "WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED"
    )
    assert exc_info.value.details.get("protocol_binding_type") == expected_type


def test_agent_card_version_alone_is_ignored():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        "name": "RemotePlanner",
        "version": "1.0.0",
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
        ],
    }
    with pytest.raises(WorkflowProtocolViolationError):
        _validate_agent_card(
            card,
            {
                "protocol_version": "1.0",
                "allowed_protocol_bindings": ["JSONRPC"],
            },
        )


# ---------------------------------------------------------------------------
# Task state validation
# ---------------------------------------------------------------------------

def test_validate_task_envelope_accepts_every_normative_task_state():
    from aegis.a2a_adapter import _TASK_STATES, _validate_task_envelope

    for state in _TASK_STATES:
        task = {"status": {"state": state}}
        assert _validate_task_envelope(task)["status"]["state"] == state


@pytest.mark.parametrize(
    "state",
    [
        "TASK_STATE_CANCELLED",  # British spelling — not a valid A2A state
        "COMPLETED",             # upper-case shorthand
        "done",                  # not in spec
        "input_required",        # underscore instead of hyphen
        "auth_required",         # underscore instead of hyphen
        "submitted",             # JSON wire shorthand
        "working",
        "completed",
        "failed",
        "canceled",
        "input-required",
        "rejected",
        "auth-required",
    ],
)
def test_validate_task_envelope_rejects_shorthand_or_misspelled_states(state):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_envelope

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_envelope({"status": {"state": state}})


# ---------------------------------------------------------------------------
# P1: JSON wire shorthand values are rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "json_state",
    [
        "submitted",
        "working",
        "completed",
        "failed",
        "canceled",
        "input-required",
        "rejected",
        "auth-required",
    ],
)
def test_validate_task_envelope_rejects_json_wire_shorthand_states(json_state):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_envelope

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_envelope({"id": "t1", "status": {"state": json_state}})


def test_validate_task_updates_rejects_json_wire_shorthand_states():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_updates

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_updates([
            {"status": {"state": "TASK_STATE_WORKING"}},
            {"status": {"state": "completed"}},
        ])


@pytest.mark.parametrize(
    "bad_state",
    [
        "TASK_STATE_CANCELLED",  # British spelling — not a valid value
        "COMPLETED",             # upper-case shorthand
        "done",                  # not in spec
        "input_required",        # underscore variant
        "auth_required",         # underscore variant
    ],
)
def test_validate_task_envelope_still_rejects_non_spec_states(bad_state):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_envelope

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_envelope({"status": {"state": bad_state}})


def test_complete_step_rejects_json_wire_task_state():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    json_task = {
        "id": "task-json-1",
        "contextId": "ctx-json-1",
        "status": {"state": "completed"},
        "artifacts": [{"artifactId": "a1"}],
        "history": [],
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        with pytest.raises(WorkflowProtocolViolationError):
            adapter.complete_step(prepared, dict(_GOOD_OUTPUT), task_envelope=json_task)


@pytest.mark.parametrize(
    "task",
    [
        {},
        {"status": {}},
        {"status": "not-mapping"},
    ],
)
def test_validate_task_envelope_rejects_missing_or_malformed_status(task):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_envelope

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_envelope(task)


def test_validate_task_updates_counts_and_rejects_invalid_state():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_task_updates

    summary = _validate_task_updates([
        {"status": {"state": "TASK_STATE_WORKING"}},
        {"artifact": {"artifactId": "a1", "parts": ["drop"]}},
    ])
    assert summary["status_update_count"] == 1
    assert summary["artifact_update_count"] == 1
    assert summary["latest_task_state"] == "TASK_STATE_WORKING"

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_updates([{"status": {"state": "done"}}])


def test_validate_task_updates_returns_actual_count_beyond_max_summaries():
    from aegis.a2a_adapter import _MAX_TASK_UPDATE_SUMMARIES, _validate_task_updates

    updates = [
        {"status": {"state": "TASK_STATE_WORKING"}}
        for _ in range(_MAX_TASK_UPDATE_SUMMARIES + 10)
    ]
    summary = _validate_task_updates(updates)
    assert summary["status_update_count"] == _MAX_TASK_UPDATE_SUMMARIES + 10


def test_validate_agent_card_accepts_grpc_at_wrong_version_with_valid_fallback():
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": "GRPC", "protocolVersion": "0.3"},
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    _, selected = _validate_agent_card(card, constraints)
    assert selected["protocolBinding"] == "JSONRPC"


# ---------------------------------------------------------------------------
# prepare_step and complete_step
# ---------------------------------------------------------------------------

def test_prepare_step_success_registers_state_and_does_not_mutate_invocation():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    original = copy.deepcopy(_BASE_INV)
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = adapter.prepare_step(
            session,
            original,
            binding=_binding(),
            agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            request_metadata={"tenant": "acme", "Authorization": "secret"},
        )
        state = session.adapter_step_state(prepared._session_result)
        assert state["adapter"] == "a2a"
        assert state["protocol_binding"] == "JSONRPC"
        assert "protocol" not in original
        assert "protocol_evidence" not in original["context"]
        adapter.complete_step(
            prepared,
            dict(_GOOD_OUTPUT),
            task_envelope=copy.deepcopy(_TASK_COMPLETED),
        )


def test_prepare_step_success_with_explicit_http_json_constraints():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(
        protocol_constraints={
            "a2a": {
                "protocol_version": "1.0",
                "allowed_protocol_bindings": ["HTTP+JSON"],
                "require_task_state": True,
            }
        }
    ) as session:
        prepared = adapter.prepare_step(
            session,
            copy.deepcopy(_BASE_INV),
            binding=_binding(),
            agent_card=copy.deepcopy(_AGENT_CARD_HTTP_JSON),
        )
        adapter.complete_step(
            prepared,
            dict(_GOOD_OUTPUT),
            task_envelope=copy.deepcopy(_TASK_COMPLETED),
        )


def test_prepare_step_rejects_participant_protocol_mismatch():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import A2AAdapter

    with _make_session(
        participants=[{"id": "agent-1", "roles": ["planner"], "protocols": ["bedrock"]}],
        protocol_constraints={"a2a": {}},
    ) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            A2AAdapter().prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )


def test_prepare_step_rejects_malformed_agent_card_protocol_binding():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import A2AAdapter

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": {"binding": "JSONRPC"}, "protocolVersion": "1.0"}
        ],
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError) as exc_info:
            A2AAdapter().prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(),
                agent_card=card,
            )
    assert exc_info.value.details.get("reason_code") == (
        "WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED"
    )
    assert exc_info.value.details.get("protocol_binding_type") == "dict"


def test_prepare_step_rejects_binding_name_role_and_participant_role_mismatch():
    from aegis._internal.errors import (
        WorkflowParticipantMismatchError,
        WorkflowProtocolViolationError,
    )
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            adapter.prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(agent_name="OtherAgent"),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowParticipantMismatchError):
            adapter.prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(role="verifier"),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )
    with _make_session(
        participants=[{"id": "agent-1", "roles": ["verifier"], "protocols": ["a2a"]}],
        protocol_constraints={"a2a": {}},
    ) as session:
        with pytest.raises(WorkflowParticipantMismatchError):
            adapter.prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(role="planner"),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )


def test_prepare_step_rolls_back_if_adapter_state_registration_fails():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        def fail_registration(*args, **kwargs):
            raise RuntimeError("registration failed")

        session.register_adapter_step_state = fail_registration  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            adapter.prepare_step(
                session,
                copy.deepcopy(_BASE_INV),
                binding=_binding(),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )
        assert session._authorized_step_count == 0
        assert session._pending_results == {}


def test_complete_step_persists_redacted_a2a_metadata_only():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        adapter.complete_step(
            prepared,
            dict(_GOOD_OUTPUT),
            task_envelope=copy.deepcopy(_TASK_COMPLETED),
            task_updates=[
                {"status": {"state": "TASK_STATE_WORKING"}, "message": {"drop": True}},
                {"artifact": {"parts": ["drop"]}},
            ],
        )
        metadata = session._steps[-1]["metadata"]

    assert metadata == {
        "adapter": "a2a",
        "adapter_version": "0.9.0-beta",
        "adapter_step_key": metadata["adapter_step_key"],
        "participant_id": "agent-1",
        "agent_name": "RemotePlanner",
        "protocol_version": "1.0",
        "protocol_binding": "JSONRPC",
        "task_id": "task-1",
        "context_id": "ctx-1",
        "task_state": "TASK_STATE_COMPLETED",
        "terminal": True,
        "artifact_count": 1,
        "history_count": 0,
        "status_update_count": 1,
        "artifact_update_count": 1,
    }
    assert "artifacts" not in metadata
    assert "history" not in metadata
    assert "message" not in metadata


def test_complete_step_allows_missing_task_when_policy_does_not_require_state():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(
        protocol_constraints={"a2a": {"require_task_state": False}}
    ) as session:
        prepared = _prepare(adapter=adapter, session=session)
        adapter.complete_step(prepared, dict(_GOOD_OUTPUT), task_envelope=None)
        metadata = session._steps[-1]["metadata"]
        assert metadata["task_state"] is None
        assert metadata["artifact_count"] == 0


def test_complete_step_fails_closed_on_missing_or_invalid_task_state():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        with pytest.raises(WorkflowProtocolViolationError):
            adapter.complete_step(
                prepared,
                dict(_GOOD_OUTPUT),
                task_envelope={"status": {}},
            )

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        with pytest.raises(WorkflowProtocolViolationError):
            adapter.complete_step(
                prepared,
                dict(_GOOD_OUTPUT),
                task_envelope={"status": {"state": "done"}},
            )


def test_complete_step_invalid_update_or_post_call_failure_discards_pending_step():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        calls = []
        original_discard = session.discard_adapter_step

        def wrapped_discard(*args, **kwargs):
            calls.append((args, kwargs))
            return original_discard(*args, **kwargs)

        session.discard_adapter_step = wrapped_discard  # type: ignore[method-assign]
        with pytest.raises(WorkflowProtocolViolationError):
            adapter.complete_step(
                prepared,
                dict(_GOOD_OUTPUT),
                task_envelope=copy.deepcopy(_TASK_COMPLETED),
                task_updates=[{"status": {"state": "done"}}],
            )
        assert calls
        assert session._pending_results == {}

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        calls = []
        original_discard = session.discard_adapter_step

        def wrapped_discard_post(*args, **kwargs):
            calls.append((args, kwargs))
            return original_discard(*args, **kwargs)

        session.discard_adapter_step = wrapped_discard_post  # type: ignore[method-assign]
        with pytest.raises(Exception):
            adapter.complete_step(
                prepared,
                {"result": "missing confidence"},
                task_envelope=copy.deepcopy(_TASK_COMPLETED),
            )
        assert calls


def test_complete_step_state_is_popped_once_and_second_completion_fails_closed():
    from aegis._internal.errors import WorkflowSessionTokenInvalidError
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = _prepare(adapter=adapter, session=session)
        adapter.complete_step(
            prepared,
            dict(_GOOD_OUTPUT),
            task_envelope=copy.deepcopy(_TASK_COMPLETED),
        )
        assert session.adapter_step_state(prepared._session_result) is None
        with pytest.raises(WorkflowSessionTokenInvalidError):
            adapter.complete_step(
                prepared,
                dict(_GOOD_OUTPUT),
                task_envelope=copy.deepcopy(_TASK_COMPLETED),
            )


# ---------------------------------------------------------------------------
# Direct session hardening for callers that bypass the adapter
# ---------------------------------------------------------------------------

def _direct_a2a_inv(evidence, role="planner"):
    inv = copy.deepcopy(_BASE_INV)
    inv["role"] = role
    inv["protocol"] = "a2a"
    inv["context"] = {
        **inv["context"],
        "protocol": "a2a",
        "protocol_evidence": {"a2a": evidence},
    }
    return inv


def test_session_accepts_valid_a2a_jsonrpc_and_http_json_evidence():
    for binding in ("JSONRPC", "HTTP+JSON"):
        evidence = {
            "supportedInterfaces": [
                {"protocolBinding": binding, "protocolVersion": "1.0"}
            ]
        }
        with _make_session(protocol_constraints={"a2a": {}}) as session:
            token = session.enforce_step_pre_call(_direct_a2a_inv(evidence))
            session.discard_adapter_step(token, rollback_authorization=True)


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "transport": "grpc",
            "supportedInterfaces": [
                {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
            ],
        },
        {
            "selected_protocol_binding": "GRPC",
            "supportedInterfaces": [
                {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
            ],
        },
        {
            "selected_protocol_binding": "grpc",
            "supportedInterfaces": [
                {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
            ],
        },
        {
            "supportedInterfaces": [
                {"protocolBinding": "GRPC", "protocolVersion": "1.0"}
            ],
        },
        {
            "version": "1.0.0",
            "supportedInterfaces": [
                {"protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
            ],
        },
    ],
)
def test_session_rejects_invalid_a2a_protocol_evidence(evidence):
    from aegis._internal.errors import WorkflowProtocolViolationError

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


@pytest.mark.parametrize(
    "protocol_binding,expected_type",
    [
        (["JSONRPC"], "list"),
        ({"binding": "JSONRPC"}, "dict"),
    ],
)
def test_session_rejects_non_string_a2a_interface_protocol_binding(
    protocol_binding, expected_type
):
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "supportedInterfaces": [
            {"protocolBinding": protocol_binding, "protocolVersion": "1.0"}
        ]
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError) as exc_info:
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))
    assert exc_info.value.details.get("reason_code") == (
        "WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED"
    )
    assert exc_info.value.details.get("protocol_binding_type") == expected_type


def test_session_rejects_non_string_a2a_top_level_protocol_binding():
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "protocolBinding": ["JSONRPC"],
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError) as exc_info:
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))
    assert exc_info.value.details.get("reason_code") == (
        "WORKFLOW_PROTOCOL_A2A_BINDING_REQUIRED"
    )
    assert exc_info.value.details.get("protocol_binding_type") == "list"


def test_session_honors_allowed_a2a_protocol_bindings():
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ]
    }
    with _make_session(
        protocol_constraints={
            "a2a": {"allowed_protocol_bindings": ["HTTP+JSON"]}
        }
    ) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


def test_session_requires_protocol_evidence_when_a2a_constraints_declared():
    from aegis._internal.errors import WorkflowProtocolViolationError

    inv = copy.deepcopy(_BASE_INV)
    inv["protocol"] = "a2a"
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(inv)


@pytest.mark.parametrize("binding_key", ["selected_protocol_binding", "protocol_binding"])
def test_session_rejects_disallowed_selected_a2a_binding(binding_key):
    """P2: evidence with an explicit disallowed binding must be rejected even when
    a supportedInterfaces entry would otherwise satisfy the allowed list."""
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        binding_key: "HTTP+JSON",
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(
        protocol_constraints={"a2a": {"allowed_protocol_bindings": ["JSONRPC"]}}
    ) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


def test_session_accepts_selected_binding_when_in_allowed_list():
    """P2: evidence with selected_protocol_binding matching an allowed binding is accepted."""
    evidence = {
        "selected_protocol_binding": "JSONRPC",
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(
        protocol_constraints={"a2a": {"allowed_protocol_bindings": ["JSONRPC"]}}
    ) as session:
        token = session.enforce_step_pre_call(_direct_a2a_inv(evidence))
        session.discard_adapter_step(token, rollback_authorization=True)


def test_session_rejects_when_second_binding_key_is_disallowed():
    """P2: when both binding keys are present and the second is disallowed, still rejects."""
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "selected_protocol_binding": "JSONRPC",   # allowed
        "protocol_binding": "HTTP+JSON",           # disallowed
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(
        protocol_constraints={"a2a": {"allowed_protocol_bindings": ["JSONRPC"]}}
    ) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


# ---------------------------------------------------------------------------
# P2: protocol conflict rejection in prepare_step
# ---------------------------------------------------------------------------

def test_prepare_step_rejects_non_a2a_protocol_in_invocation():
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.a2a_adapter import A2AAdapter

    inv = copy.deepcopy(_BASE_INV)
    inv["protocol"] = "bedrock"

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowUnsupportedBindingError):
            A2AAdapter().prepare_step(
                session,
                inv,
                binding=_binding(),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )


def test_prepare_step_rejects_non_a2a_protocol_in_context():
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.a2a_adapter import A2AAdapter

    inv = copy.deepcopy(_BASE_INV)
    inv["context"] = {**inv["context"], "protocol": "bedrock"}

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowUnsupportedBindingError):
            A2AAdapter().prepare_step(
                session,
                inv,
                binding=_binding(),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )


def test_prepare_step_rejects_conflicting_top_level_and_context_protocol():
    from aegis._internal.errors import WorkflowUnsupportedBindingError
    from aegis.a2a_adapter import A2AAdapter

    inv = copy.deepcopy(_BASE_INV)
    inv["protocol"] = "a2a"
    inv["context"] = {**inv["context"], "protocol": "bedrock"}

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowUnsupportedBindingError):
            A2AAdapter().prepare_step(
                session,
                inv,
                binding=_binding(),
                agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
            )


def test_prepare_step_accepts_explicit_a2a_protocol():
    from aegis.a2a_adapter import A2AAdapter

    adapter = A2AAdapter()
    inv = copy.deepcopy(_BASE_INV)
    inv["protocol"] = "a2a"

    with _make_session(protocol_constraints={"a2a": {}}) as session:
        prepared = adapter.prepare_step(
            session,
            inv,
            binding=_binding(),
            agent_card=copy.deepcopy(_AGENT_CARD_JSONRPC),
        )
        adapter.complete_step(
            prepared,
            dict(_GOOD_OUTPUT),
            task_envelope=copy.deepcopy(_TASK_COMPLETED),
        )


# ---------------------------------------------------------------------------
# P2: task_updates validation continues past the metadata cap
# ---------------------------------------------------------------------------

def test_validate_task_updates_validates_beyond_cap():
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _MAX_TASK_UPDATE_SUMMARIES, _validate_task_updates

    valid = [
        {"status": {"state": "TASK_STATE_WORKING"}}
        for _ in range(_MAX_TASK_UPDATE_SUMMARIES)
    ]
    bad_after_cap = [{"status": {"state": "done"}}]

    with pytest.raises(WorkflowProtocolViolationError):
        _validate_task_updates(valid + bad_after_cap)


def test_validate_task_updates_rejects_non_mapping_beyond_cap():
    from aegis._internal.errors import InvocationValidationError
    from aegis.a2a_adapter import _MAX_TASK_UPDATE_SUMMARIES, _validate_task_updates

    valid = [
        {"status": {"state": "TASK_STATE_WORKING"}}
        for _ in range(_MAX_TASK_UPDATE_SUMMARIES)
    ]

    with pytest.raises((InvocationValidationError, Exception)):
        _validate_task_updates(valid + [object()])


def test_validate_task_updates_returns_actual_counts_and_latest_state_beyond_cap():
    from aegis.a2a_adapter import _MAX_TASK_UPDATE_SUMMARIES, _validate_task_updates

    updates = [
        {"status": {"state": "TASK_STATE_WORKING"}}
        for _ in range(_MAX_TASK_UPDATE_SUMMARIES)
    ]
    updates.extend([
        {"status": {"state": "TASK_STATE_COMPLETED"}},
        {"artifacts": [{"artifactId": "a1"}, {"artifactId": "a2"}]},
    ])
    summary = _validate_task_updates(updates)
    assert summary["status_update_count"] == _MAX_TASK_UPDATE_SUMMARIES + 1
    assert summary["latest_task_state"] == "TASK_STATE_COMPLETED"
    assert summary["artifact_update_count"] == 2


# ---------------------------------------------------------------------------
# P3: gRPC casefold rejection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("grpc_binding", ["GRPC", "grpc", "gRPC", "Grpc", "GrPC"])
def test_validate_agent_card_rejects_mixed_case_grpc_bindings(grpc_binding):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": grpc_binding, "protocolVersion": "1.0"},
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises(WorkflowProtocolViolationError):
        _validate_agent_card(card, constraints)


@pytest.mark.parametrize("transport_value", ["grpc", "GRPC", "gRPC"])
def test_validate_agent_card_rejects_mixed_case_grpc_transport(transport_value):
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
                "transport": transport_value,
            },
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises(WorkflowProtocolViolationError):
        _validate_agent_card(card, constraints)


@pytest.mark.parametrize("grpc_binding", ["GRPC", "grpc", "gRPC", "Grpc"])
def test_session_rejects_mixed_case_grpc_in_selected_binding(grpc_binding):
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "selected_protocol_binding": grpc_binding,
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


@pytest.mark.parametrize("transport_value", ["grpc", "GRPC", "gRPC"])
def test_session_rejects_mixed_case_grpc_transport_in_evidence(transport_value):
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "transport": transport_value,
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


# ---------------------------------------------------------------------------
# P2 (new): validate ALL interfaces before accepting — interface-order bypass
# ---------------------------------------------------------------------------

def test_validate_agent_card_rejects_grpc_after_valid_jsonrpc():
    """P2: JSONRPC first, then gRPC at required_version — must reject the whole card."""
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"protocolBinding": "grpc", "protocolVersion": "1.0"},
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises(WorkflowProtocolViolationError):
        _validate_agent_card(card, constraints)


@pytest.mark.parametrize("grpc_binding", ["grpc", "GRPC", "gRPC"])
def test_validate_agent_card_rejects_grpc_after_valid_http_json(grpc_binding):
    """P2: HTTP+JSON first, then gRPC at required_version — must reject."""
    from aegis._internal.errors import WorkflowProtocolViolationError
    from aegis.a2a_adapter import _validate_agent_card

    card = {
        **_AGENT_CARD_JSONRPC,
        "supportedInterfaces": [
            {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
            {"protocolBinding": grpc_binding, "protocolVersion": "1.0"},
        ],
    }
    constraints = {
        "protocol_version": "1.0",
        "allowed_protocol_bindings": ["JSONRPC", "HTTP+JSON"],
    }
    with pytest.raises(WorkflowProtocolViolationError):
        _validate_agent_card(card, constraints)


def test_session_rejects_grpc_after_valid_jsonrpc_in_supported_interfaces():
    """P2: direct A2A evidence with JSONRPC first, gRPC at required_version second."""
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"protocolBinding": "grpc", "protocolVersion": "1.0"},
        ]
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


@pytest.mark.parametrize("grpc_binding", ["grpc", "GRPC", "gRPC"])
def test_session_rejects_grpc_transport_after_valid_binding_in_supported_interfaces(grpc_binding):
    """P2: gRPC via transport field in a later interface must still be caught."""
    from aegis._internal.errors import WorkflowProtocolViolationError

    evidence = {
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0", "transport": grpc_binding},
        ]
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        with pytest.raises(WorkflowProtocolViolationError):
            session.enforce_step_pre_call(_direct_a2a_inv(evidence))


def test_session_accepts_older_version_grpc_with_valid_required_version_fallback():
    """Session path: gRPC at old version + JSONRPC at required version = accepted."""
    evidence = {
        "supportedInterfaces": [
            {"protocolBinding": "GRPC", "protocolVersion": "0.3"},
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
        ]
    }
    with _make_session(protocol_constraints={"a2a": {}}) as session:
        token = session.enforce_step_pre_call(_direct_a2a_inv(evidence))
        session.discard_adapter_step(token, rollback_authorization=True)
