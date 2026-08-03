from concurrent.futures import ThreadPoolExecutor
from types import MappingProxyType

import pytest

from aegis._internal.attempts import AttemptFactory


def test_attempt_envelope_exists_before_invalid_invocation_is_parsed():
    factory = AttemptFactory(clock=lambda: 123)

    envelope = factory.allocate("enforce_invocation", "unified", object())

    assert envelope.attempt_id == 0
    assert envelope.started_at == 123
    assert envelope.entry_point == "enforce_invocation"
    assert envelope.mode == "unified"
    assert envelope.policy_file == "unknown"
    assert envelope.model_provider == "unknown"
    assert envelope.model_identifier == "unknown"
    assert envelope.role == "unknown"
    assert envelope.input == {}
    assert envelope.output == {}
    assert envelope.context == {}
    assert envelope.metadata == {}
    assert envelope.failure_stage == "attempt_allocation"
    assert envelope.reason_code == "ATTEMPT_STARTED"


def test_attempt_envelope_copies_only_bounded_identity_strings():
    factory = AttemptFactory(clock=lambda: 123, max_identity_length=8)
    invocation = {
        "policy_file": "p.yaml",
        "model_provider": "   ",
        "model_identifier": "identifier-too-long",
        "role": 7,
    }

    envelope = factory.allocate("enforce", "split", invocation)

    assert envelope.policy_file == "p.yaml"
    assert envelope.model_provider == "unknown"
    assert envelope.model_identifier == "unknown"
    assert envelope.role == "unknown"


def test_attempt_envelope_detaches_and_freezes_safe_json_mappings():
    invocation = {
        "input": {"prompt": "hello", "parts": [1, True, None]},
        "output": {"answer": "ok"},
        "context": {"tenant": "demo"},
        "metadata": {"trace": {"enabled": True}},
    }

    envelope = AttemptFactory(clock=lambda: 123).allocate(
        "enforce", "unified", invocation
    )
    invocation["input"]["prompt"] = "mutated"
    invocation["metadata"]["trace"]["enabled"] = False

    assert envelope.input["prompt"] == "hello"
    assert envelope.input["parts"] == (1, True, None)
    assert envelope.metadata["trace"]["enabled"] is True
    assert isinstance(envelope.input, MappingProxyType)
    with pytest.raises(TypeError):
        envelope.input["new"] = "value"


@pytest.mark.parametrize(
    "unsafe",
    [
        {1: "non-string-key"},
        {"value": object()},
        {"value": float("nan")},
        {"value": "x" * 4097},
    ],
)
def test_attempt_envelope_drops_unbounded_or_non_json_mapping(unsafe):
    envelope = AttemptFactory(clock=lambda: 123).allocate(
        "enforce", "unified", {"input": unsafe}
    )

    assert envelope.input == {}


def test_attempt_factory_allocates_unique_monotonic_ids_across_threads():
    factory = AttemptFactory(clock=lambda: 123)

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(
            pool.map(
                lambda _: factory.allocate("enforce", "unified", {}).attempt_id,
                range(100),
            )
        )

    assert sorted(ids) == list(range(100))
