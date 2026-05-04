"""Internal-only PR-10d multi-aspect ValidatorHook examples."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
import yaml

import aegis
from aegis._internal.validator_hook import (
    VALIDATOR_ALLOW,
    VALIDATOR_DENY,
    VALIDATOR_REVIEW_REQUIRED,
    VALIDATOR_TIMEOUT,
    ValidatorHook,
    ValidatorHookEnvelope,
    ValidatorHookResult,
    _invoke_hook,
)


class MultiAspectSafetyHook(ValidatorHook):
    hook_id = "internal-multi-aspect-safety"
    hook_version = "0.1"
    timeout_ms = 100

    def evaluate(self, envelope: ValidatorHookEnvelope) -> ValidatorHookResult:
        invocation = envelope.invocation
        context = invocation.get("context") or {}
        provenance = context.get("provenance") or {}
        required_input_keys = context.get("required_input_keys") or []
        allowed_roles = context.get("allowed_roles") or []
        allowed_protocols = context.get("allowed_protocols") or []
        capability_label = context.get("capability_label")
        protocol = invocation.get("protocol") or context.get("protocol")

        aspects = {
            "source_grounding": (
                not context.get("source_required")
                or bool(provenance.get("source_ids"))
            ),
            "schema_semantics": all(
                key in (invocation.get("input") or {}) for key in required_input_keys
            ),
            "policy_risk": (
                (not allowed_roles or invocation.get("role") in allowed_roles)
                and (not allowed_protocols or protocol in allowed_protocols)
            ),
            "externalization_risk": capability_label != "externalize",
        }

        observed_at = int(time.time() * 1000)
        if not aspects["source_grounding"]:
            return ValidatorHookResult(
                decision=VALIDATOR_DENY,
                reason_code="SOURCE_GROUNDING_MISSING",
                explanation="source_grounding failed",
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=observed_at,
                provenance="internal-fixture",
            )
        if not aspects["schema_semantics"]:
            return ValidatorHookResult(
                decision=VALIDATOR_DENY,
                reason_code="SCHEMA_SEMANTICS_MISSING",
                explanation="schema_semantics failed",
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=observed_at,
                provenance="internal-fixture",
            )
        if not aspects["policy_risk"]:
            return ValidatorHookResult(
                decision=VALIDATOR_DENY,
                reason_code="POLICY_RISK_MISMATCH",
                explanation="policy_risk failed",
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=observed_at,
                provenance="internal-fixture",
            )
        if not aspects["externalization_risk"]:
            return ValidatorHookResult(
                decision=VALIDATOR_REVIEW_REQUIRED,
                reason_code="EXTERNALIZATION_REVIEW_REQUIRED",
                explanation="externalization_risk requires review",
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=observed_at,
                provenance="internal-fixture",
            )
        return ValidatorHookResult(
            decision=VALIDATOR_ALLOW,
            reason_code=None,
            explanation="all aspects passed",
            hook_id=self.hook_id,
            hook_version=self.hook_version,
            attempt=1,
            latency_ms=1,
            observed_at=observed_at,
            provenance="internal-fixture",
        )


def _envelope(invocation: dict, *, deadline_ms: int = 100) -> ValidatorHookEnvelope:
    return ValidatorHookEnvelope(
        hook_schema_version="1.0",
        session_id="session-1",
        step_id="step-1",
        participant_id="participant-1",
        invocation=invocation,
        deadline_ms=deadline_ms,
        observed_at=int(time.time() * 1000),
    )


def _passing_invocation(policy_file: str | None = None) -> dict:
    invocation = {
        "model_provider": "anthropic",
        "model_identifier": "claude-sonnet-4-6",
        "role": "analyst",
        "protocol": "local",
        "input": {"claim": "fixture"},
        "output": {},
        "context": {
            "caller_id": "validator-hook-test",
            "source_required": True,
            "provenance": {"source_ids": ["doc-001"]},
            "required_input_keys": ["claim"],
            "allowed_roles": ["analyst"],
            "allowed_protocols": ["local"],
            "capability_label": "summarize",
        },
    }
    if policy_file is not None:
        invocation["policy_file"] = policy_file
    return invocation


def test_multi_aspect_hook_allows_when_all_aspects_pass():
    result = _invoke_hook(MultiAspectSafetyHook(), _envelope(_passing_invocation()))
    assert result.decision == VALIDATOR_ALLOW
    assert result.provenance == "internal-fixture"


def test_multi_aspect_hook_denies_missing_source_grounding():
    invocation = _passing_invocation()
    invocation["context"] = {
        **invocation["context"],
        "provenance": {},
    }
    result = _invoke_hook(MultiAspectSafetyHook(), _envelope(invocation))
    assert result.decision == VALIDATOR_DENY
    assert result.reason_code == "SOURCE_GROUNDING_MISSING"


def test_multi_aspect_hook_requires_review_for_externalization_label():
    invocation = _passing_invocation()
    invocation["context"] = {
        **invocation["context"],
        "capability_label": "externalize",
    }
    result = _invoke_hook(MultiAspectSafetyHook(), _envelope(invocation))
    assert result.decision == VALIDATOR_REVIEW_REQUIRED
    assert result.reason_code == "EXTERNALIZATION_REVIEW_REQUIRED"


def test_timeout_fails_closed_through_existing_hook_invocation_helper():
    class SlowHook(MultiAspectSafetyHook):
        hook_id = "internal-slow-safety"
        timeout_ms = 10

        def evaluate(self, envelope: ValidatorHookEnvelope) -> ValidatorHookResult:
            time.sleep(0.05)
            return super().evaluate(envelope)

    result = _invoke_hook(SlowHook(), _envelope(_passing_invocation(), deadline_ms=10))
    assert result.decision == VALIDATOR_TIMEOUT
    assert result.reason_code == "HOOK_TIMEOUT"


def test_stale_result_fails_closed_when_result_exceeds_deadline():
    class StaleHook(MultiAspectSafetyHook):
        hook_id = "internal-stale-safety"

        def evaluate(self, envelope: ValidatorHookEnvelope) -> ValidatorHookResult:
            return ValidatorHookResult(
                decision=VALIDATOR_ALLOW,
                reason_code=None,
                explanation="stale allow",
                hook_id=self.hook_id,
                hook_version=self.hook_version,
                attempt=1,
                latency_ms=1,
                observed_at=envelope.observed_at + envelope.deadline_ms + 1,
            )

    result = _invoke_hook(StaleHook(), _envelope(_passing_invocation(), deadline_ms=1))
    assert result.decision == VALIDATOR_TIMEOUT
    assert result.reason_code == "HOOK_STALE_RESULT"
    assert result.stale_result is True


def test_internal_hook_evidence_is_recorded_without_public_hook_export(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        yaml.dump({
            "policy_version": "1.0",
            "roles": ["analyst"],
            "pre_conditions": {"required": {"caller_id": {"type": "string"}}},
        }),
        encoding="utf-8",
    )
    governance = aegis.AEGIS()
    governance._set_validator_hooks([MultiAspectSafetyHook()])

    with governance.open_session(
        session_id=str(uuid.uuid4()),
        policy_file=str(policy_file),
    ) as session:
        token = session.enforce_step_pre_call(
            _passing_invocation(str(policy_file)),
            step_id="source_analysis",
        )
        session.enforce_step_post_call(token, {"result": "ok"})
        session.complete()

    evidence = session.workflow_artifact["validator_hook_evidence"]
    assert evidence[0]["hook_id"] == "internal-multi-aspect-safety"
    assert evidence[0]["decision"] == VALIDATOR_ALLOW
    assert not hasattr(aegis, "ValidatorHook")
