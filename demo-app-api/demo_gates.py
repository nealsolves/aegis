"""Public-hook custom gates used only by the deterministic Northstar fixtures."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis import (
    EnforcementGate,
    GateResult,
    INSERTION_PRE_AUTHORIZATION,
    INSERTION_PRE_OUTPUT,
)


class DemoPrivacyGate(EnforcementGate):
    @property
    def name(self) -> str:
        return "privacy_scope"

    @property
    def insertion_point(self) -> str:
        return INSERTION_PRE_AUTHORIZATION

    def evaluate(
        self,
        invocation: Mapping[str, Any],
        policy: Mapping[str, Any],
        context: dict[str, Any],
    ) -> GateResult:
        invocation_context = invocation.get("context") or {}
        if invocation_context.get("privacy_scope") != "scheduling_only":
            return GateResult(
                passed=False,
                failures=[
                    {
                        "code": "PRIVACY_SCOPE_REQUIRED",
                        "message": "The demo permits scheduling-only access.",
                        "field": "context.privacy_scope",
                    }
                ],
            )
        return GateResult(
            passed=True,
            metadata={"privacy_scope": "scheduling_only"},
        )


class DemoNorthstarRoleGate(EnforcementGate):
    @property
    def name(self) -> str:
        return "northstar_role"

    @property
    def insertion_point(self) -> str:
        return INSERTION_PRE_AUTHORIZATION

    def evaluate(
        self,
        invocation: Mapping[str, Any],
        policy: Mapping[str, Any],
        context: dict[str, Any],
    ) -> GateResult:
        if invocation.get("role") not in policy.get("roles", []):
            return GateResult(
                passed=False,
                failures=[
                    {
                        "code": "ROLE_NOT_ALLOWED",
                        "message": "The demo role is not allowed by policy.",
                        "field": "role",
                    }
                ],
            )
        return GateResult(passed=True)


class DemoClinicalScopeGate(EnforcementGate):
    @property
    def name(self) -> str:
        return "clinical_scope"

    @property
    def insertion_point(self) -> str:
        return INSERTION_PRE_OUTPUT

    def evaluate(
        self,
        invocation: Mapping[str, Any],
        policy: Mapping[str, Any],
        context: dict[str, Any],
    ) -> GateResult:
        output = invocation.get("output") or {}
        if output.get("clinical_recommendation"):
            return GateResult(
                passed=False,
                failures=[
                    {
                        "code": "PHYSICIAN_APPROVAL_REQUIRED",
                        "message": (
                            "Clinical recommendations require physician approval."
                        ),
                        "field": "output.clinical_recommendation",
                    }
                ],
            )
        return GateResult(
            passed=True,
            metadata={"clinical_scope": "scheduling_only"},
        )
