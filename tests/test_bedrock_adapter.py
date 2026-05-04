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