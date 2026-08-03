"""Truth-table and immutability tests for closed authorization outcomes."""

from types import MappingProxyType

import pytest

from aegis._internal.errors import OutcomeContractError
from aegis._internal.outcomes import (
    FailureRecord,
    NormalizedOutcome,
    OutcomeNormalizer,
    TerminalClass,
)


@pytest.mark.parametrize(
    ("terminal", "allowed"),
    [
        (TerminalClass.ALLOW, True),
        (TerminalClass.WARN, True),
        (TerminalClass.DENY, False),
        (TerminalClass.INVALID_RESULT, False),
        (TerminalClass.EXECUTION_FAILURE, False),
        (TerminalClass.TIMEOUT, False),
    ],
)
def test_only_closed_allow_classes_continue(terminal, allowed):
    assert NormalizedOutcome(terminal, "TEST").allows_continuation is allowed


def test_unknown_terminal_value_is_rejected():
    with pytest.raises(OutcomeContractError):
        NormalizedOutcome("allow", "TEST")


def test_mutable_metadata_is_rejected():
    with pytest.raises(OutcomeContractError):
        NormalizedOutcome(TerminalClass.ALLOW, "TEST", metadata={"x": 1})


def test_unbounded_public_failure_message_is_rejected():
    with pytest.raises(OutcomeContractError):
        FailureRecord(code="TOO_LONG", message="x" * 1025)


def test_normalizer_builders_freeze_metadata_and_failures():
    outcome = OutcomeNormalizer.deny(
        "DENIED",
        failures=[{"code": "X", "message": "blocked", "field": None}],
        metadata={"nested": {"values": [1, 2]}},
    )
    assert outcome.terminal is TerminalClass.DENY
    assert outcome.failures == (FailureRecord("X", "blocked"),)
    assert isinstance(outcome.metadata, MappingProxyType)
    assert outcome.metadata["nested"]["values"] == (1, 2)


def test_frozen_outcome_cannot_be_reassigned():
    outcome = NormalizedOutcome(TerminalClass.ALLOW, "OK")
    with pytest.raises((AttributeError, TypeError)):
        outcome.reason_code = "CHANGED"


def test_mapping_proxy_metadata_is_detached_from_mutable_backing_data():
    backing = {"nested": {"items": [1]}}
    outcome = NormalizedOutcome(
        TerminalClass.ALLOW,
        "OK",
        metadata=MappingProxyType(backing),
    )

    backing["nested"]["items"].append(2)
    assert outcome.metadata["nested"]["items"] == (1,)
    assert isinstance(outcome.metadata["nested"], MappingProxyType)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_metadata_is_not_a_json_outcome(value):
    with pytest.raises(OutcomeContractError):
        OutcomeNormalizer.allow("OK", metadata={"score": value})
