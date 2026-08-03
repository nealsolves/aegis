from __future__ import annotations

import pytest

from aegis._internal.enforcement import _reset_module_enforcement_for_test
from aegis._internal.errors import EvidenceConfigurationError
from aegis._internal.sinks import CallbackAuditSink
from aegis.enforcement import configure_module_enforcement, enforce_invocation


INVOCATION = {
    "policy_file": "tests/golden_replays/golden_policy_v1.yaml",
    "model_provider": "openai",
    "model_identifier": "gpt-test",
    "role": "planner",
    "input": {"prompt": "test"},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


@pytest.fixture(autouse=True)
def isolated_runtime():
    _reset_module_enforcement_for_test()
    yield
    _reset_module_enforcement_for_test()


def test_module_api_requires_an_explicit_private_runtime():
    with pytest.raises(EvidenceConfigurationError) as exc_info:
        enforce_invocation(INVOCATION)

    assert exc_info.value.code == "V2_SINK_REQUIRED"


def test_configured_runtime_emits_exact_returned_value_once():
    emitted = []
    configure_module_enforcement(sink=CallbackAuditSink(emitted.append))

    artifact = enforce_invocation(INVOCATION)

    assert emitted == [artifact]


def test_first_attempt_atomically_seals_module_runtime():
    configure_module_enforcement(sink=CallbackAuditSink(lambda artifact: None))
    enforce_invocation(INVOCATION)

    with pytest.raises(RuntimeError, match="sealed"):
        configure_module_enforcement(
            sink=CallbackAuditSink(lambda artifact: None),
        )
