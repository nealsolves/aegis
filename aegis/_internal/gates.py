"""
Custom EnforcementGate plugin interface.

Allows safe insertion of custom enforcement gates into the pipeline
with deterministic ordering. Custom gates may add failures and metadata
but cannot bypass core governance or remove prior failures.

Safety invariants:
- Custom gates run at defined insertion points (pre/post authorization)
- Failures are append-only: custom gates cannot suppress prior failures
- Core gate ordering is preserved
- Pre-action enforcement proof (gates_evaluated) is maintained
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Mapping

from aegis._internal.errors import OutcomeContractError
from aegis._internal.gate_projection import GateProjectionFactory
from aegis._internal.outcomes import (
    FailureRecord,
    NormalizedOutcome,
    OutcomeNormalizer,
)

logger = logging.getLogger("aegis.gates")


# Supported insertion points for custom gates
INSERTION_PRE_AUTHORIZATION = "pre_authorization"
INSERTION_POST_AUTHORIZATION = "post_authorization"
INSERTION_PRE_OUTPUT = "pre_output"
INSERTION_POST_OUTPUT = "post_output"

VALID_INSERTION_POINTS = (
    INSERTION_PRE_AUTHORIZATION,
    INSERTION_POST_AUTHORIZATION,
    INSERTION_PRE_OUTPUT,
    INSERTION_POST_OUTPUT,
)


class GateResult:
    """Result from a custom gate execution.

    Custom gates return GateResult to report:
    - passed: whether the gate passed
    - failures: list of failure dicts (appended to pipeline failures)
    - metadata: dict of metadata (merged into audit artifact metadata)
    """

    __slots__ = ("passed", "failures", "metadata")

    def __init__(
        self,
        passed: bool = True,
        failures: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.passed = passed
        self.failures = failures or []
        self.metadata = metadata or {}


def _synthetic_failure(
    gate_id: str,
    code: str,
    message: str,
) -> FailureRecord:
    return FailureRecord(code=code, message=f"Gate '{gate_id}' {message}")


def _normalize_gate_failures(
    failures: object,
) -> tuple[FailureRecord, ...]:
    if not isinstance(failures, (list, tuple)):
        return (
            FailureRecord(
                code="CUSTOM_GATE_MALFORMED_FAILURE",
                message="Custom gate returned a malformed failures collection",
            ),
        )
    normalized: list[FailureRecord] = []
    for item in failures:
        if not isinstance(item, Mapping):
            normalized.append(
                FailureRecord(
                    code="CUSTOM_GATE_MALFORMED_FAILURE",
                    message=str(item)[:1024],
                )
            )
            continue
        try:
            normalized.append(OutcomeNormalizer._failure(item))
        except OutcomeContractError:
            normalized.append(
                FailureRecord(
                    code="CUSTOM_GATE_MALFORMED_FAILURE",
                    message="Custom gate returned a malformed failure record",
                )
            )
    return tuple(normalized)


def _plain_json_value(value: Any) -> Any:
    """Thaw a detached outcome value for the public JSON audit artifact."""
    if isinstance(value, Mapping):
        return {key: _plain_json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json_value(item) for item in value]
    return value


def normalize_gate_result(gate_id: str, result: object) -> NormalizedOutcome:
    """Map one untrusted custom-gate return value to a closed outcome."""
    if not isinstance(result, GateResult):
        return OutcomeNormalizer.execution_failure(
            "CUSTOM_GATE_INVALID_RETURN",
            failures=(
                _synthetic_failure(
                    gate_id,
                    "CUSTOM_GATE_INVALID_RETURN",
                    "returned an unsupported result",
                ),
            ),
        )
    failures = _normalize_gate_failures(result.failures)
    if type(result.passed) is not bool:
        return OutcomeNormalizer.invalid(
            "CUSTOM_GATE_INVALID_RESULT",
            failures=failures
            or (
                _synthetic_failure(
                    gate_id,
                    "CUSTOM_GATE_INVALID_RESULT",
                    "returned a non-boolean passed value",
                ),
            ),
        )
    if result.passed is False:
        return OutcomeNormalizer.deny(
            "CUSTOM_GATE_DENIED",
            failures=failures
            or (
                _synthetic_failure(
                    gate_id,
                    "CUSTOM_GATE_DENIED",
                    "denied authorization",
                ),
            ),
        )
    if failures:
        return OutcomeNormalizer.invalid(
            "CUSTOM_GATE_INCONSISTENT_RESULT",
            failures=failures,
        )
    try:
        return OutcomeNormalizer.allow(
            "CUSTOM_GATE_ALLOWED",
            metadata=result.metadata,
        )
    except (OutcomeContractError, TypeError):
        return OutcomeNormalizer.invalid(
            "CUSTOM_GATE_INVALID_METADATA",
            failures=(
                _synthetic_failure(
                    gate_id,
                    "CUSTOM_GATE_INVALID_METADATA",
                    "returned unsupported metadata",
                ),
            ),
        )


class EnforcementGate(abc.ABC):
    """Abstract base class for custom enforcement gates.

    Subclass and implement ``evaluate()`` to add custom governance logic.
    Register instances with the AEGIS class or enforcement pipeline.

    Safety contract:
    - Supplied projections cannot mutate AEGIS enforcement state
    - Gates return GateResult (they cannot raise to bypass governance)
    - Failures are append-only (cannot suppress prior failures)
    - Gate arguments contain detached invocation, policy, and context data

    Usage::

        class ComplianceGate(EnforcementGate):
            name = "compliance_check"
            insertion_point = "post_authorization"

            def evaluate(self, invocation, policy, context):
                if not context.get("compliance_approved"):
                    return GateResult(
                        passed=False,
                        failures=[{"code": "COMPLIANCE",
                                   "message": "Not approved",
                                   "field": None}],
                    )
                return GateResult(passed=True)
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique gate identifier. Used in gates_evaluated list."""

    @property
    @abc.abstractmethod
    def insertion_point(self) -> str:
        """Where this gate runs in the pipeline.

        Must be one of VALID_INSERTION_POINTS.
        """

    @abc.abstractmethod
    def evaluate(
        self,
        invocation: Mapping[str, Any],
        policy: Mapping[str, Any],
        context: dict[str, Any],
    ) -> GateResult:
        """Execute the custom gate logic.

        :param invocation: Detached immutable invocation projection
        :param policy: Detached immutable effective-policy projection
        :param context: Detached per-call context projection
        :return: GateResult indicating pass/fail with optional metadata
        """


def validate_gate(gate: EnforcementGate) -> None:
    """Validate a custom gate configuration.

    :raises ValueError: If gate has invalid name or insertion point
    """
    if not gate.name or not isinstance(gate.name, str):
        raise ValueError(f"Gate must have a non-empty string name, got: {gate.name!r}")

    if gate.insertion_point not in VALID_INSERTION_POINTS:
        raise ValueError(
            f"Gate '{gate.name}' has invalid insertion_point "
            f"'{gate.insertion_point}'; must be one of {VALID_INSERTION_POINTS}"
        )


def sort_gates(gates: list[EnforcementGate]) -> dict[str, list[EnforcementGate]]:
    """Sort gates by insertion point, preserving registration order within groups.

    :param gates: List of custom gates
    :return: Dict mapping insertion_point -> ordered list of gates
    """
    grouped: dict[str, list[EnforcementGate]] = {
        point: [] for point in VALID_INSERTION_POINTS
    }
    for gate in gates:
        validate_gate(gate)
        grouped[gate.insertion_point].append(gate)
    return grouped


def run_gates(
    gates: list[EnforcementGate],
    invocation: Mapping[str, Any],
    policy: Mapping[str, Any],
    pipeline_context: dict[str, Any],
    gates_evaluated: list[str],
    prior_failures: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Compatibility wrapper returning normalized failures and metadata."""
    failures, metadata, _ = run_gates_normalized(
        gates,
        invocation,
        policy,
        pipeline_context,
        gates_evaluated,
        prior_failures,
    )
    return failures, metadata


def run_gates_normalized(
    gates: list[EnforcementGate],
    invocation: Mapping[str, Any],
    policy: Mapping[str, Any],
    pipeline_context: dict[str, Any],
    gates_evaluated: list[str],
    prior_failures: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any], NormalizedOutcome]:
    """Run a list of custom gates and collect results.

    Failures are append-only: prior_failures are preserved.
    Custom gate exceptions are caught and converted to failures
    (gates cannot crash the pipeline).

    :param gates: Gates to run at this insertion point
    :param invocation: Current invocation
    :param policy: Effective policy
    :param pipeline_context: Shared pipeline context
    :param gates_evaluated: Running gates_evaluated list (mutated)
    :param prior_failures: Failures accumulated so far
    :return: (accumulated_failures, merged_metadata)
    """
    accumulated_failures = list(prior_failures)
    merged_metadata: dict[str, Any] = {}

    projected_invocation = GateProjectionFactory.invocation(invocation)
    projected_policy = GateProjectionFactory.policy_from_mapping(policy)
    projected_context = GateProjectionFactory.context(pipeline_context)

    aggregate = OutcomeNormalizer.allow("CUSTOM_GATES_ALLOWED")
    for gate in gates:
        gate_id = f"custom:{gate.name}"
        try:
            result = gate.evaluate(
                projected_invocation, projected_policy, projected_context,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Custom gate '%s' execution failed (%s)",
                gate.name,
                type(exc).__name__,
            )
            outcome = OutcomeNormalizer.execution_failure(
                "CUSTOM_GATE_EXECUTION_FAILURE",
                failures=(
                    _synthetic_failure(
                        gate.name,
                        "CUSTOM_GATE_ERROR",
                        "failed during execution",
                    ),
                ),
            )
        else:
            outcome = normalize_gate_result(gate.name, result)

        gates_evaluated.append(gate_id)

        accumulated_failures.extend(
            {
                "code": failure.code,
                "message": failure.message,
                "field": failure.field,
            }
            for failure in outcome.failures
        )
        if outcome.metadata:
            merged_metadata.update(_plain_json_value(outcome.metadata))
        if aggregate.allows_continuation and not outcome.allows_continuation:
            aggregate = outcome

        logger.debug(
            "Custom gate '%s' completed: terminal=%s, failures=%d",
            gate.name,
            outcome.terminal.value,
            len(outcome.failures),
        )

    return accumulated_failures, merged_metadata, aggregate
