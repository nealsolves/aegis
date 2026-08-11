"""Versioned public models for the deterministic AEGIS demo API."""
from __future__ import annotations

import importlib.metadata
import os
from typing import Any, Literal

import pydantic
from pydantic import BaseModel

if pydantic.VERSION.startswith("2."):
    from pydantic import ConfigDict, model_validator
else:
    from pydantic import root_validator


API_CONTRACT_VERSION = "1"
FIXTURE_SET_VERSION = "2026-07-25"
SDK_DISTRIBUTION = "aegis-ai-governance"

Outcome = Literal["PASS", "FAIL", "PAUSED"]


def installed_sdk_version() -> str:
    """Return the version of the AEGIS distribution installed by the service."""
    return importlib.metadata.version(SDK_DISTRIBUTION)


class DemoSource(BaseModel):
    branch: str | None
    commit: str | None
    sdk_version: str


def demo_source() -> DemoSource:
    return DemoSource(
        branch=os.getenv("RENDER_GIT_BRANCH"),
        commit=os.getenv("RENDER_GIT_COMMIT"),
        sdk_version=installed_sdk_version(),
    )


class DemoManifest(BaseModel):
    api_contract_version: Literal["1"]
    sdk_version: str
    fixture_set_version: Literal["2026-07-25"]
    scenarios: list[Literal["atlas", "northstar", "meridian"]]
    adapters: list[Literal["bedrock", "openai_agents", "a2a"]]
    source: DemoSource


class DemoGateResult(BaseModel):
    name: str
    phase: Literal["pre_call", "post_call", "workflow"]
    evaluated: bool
    outcome: Outcome | None
    reason_code: str | None

    if pydantic.VERSION.startswith("2."):
        @model_validator(mode="after")
        def _outcome_matches_evaluation(self):
            if self.evaluated != (self.outcome is not None):
                raise ValueError(
                    "outcome must be set exactly when the gate was evaluated"
                )
            return self
    else:
        @root_validator
        def _outcome_matches_evaluation(cls, values):
            evaluated = values.get("evaluated")
            outcome = values.get("outcome")
            if evaluated != (outcome is not None):
                raise ValueError(
                    "outcome must be set exactly when the gate was evaluated"
                )
            return values


class DemoError(BaseModel):
    code: str
    message: str
    request_id: str


class _ForbidExtraRequestModel(BaseModel):
    """Reject server-owned path fields under both supported Pydantic major versions."""
    if pydantic.VERSION.startswith("2."):
        model_config = ConfigDict(extra="forbid")
    else:
        class Config:
            extra = "forbid"


class ScenarioRunRequest(_ForbidExtraRequestModel):

    variant: str


class ScenarioRunResponse(BaseModel):
    scenario_id: Literal["atlas", "northstar", "meridian"]
    variant: str
    fixture_version: str
    transcript: list[dict[str, str]]
    gates: list[DemoGateResult]
    decision: Outcome
    artifact: dict[str, Any] | None
    workflow_artifact: dict[str, Any] | None
    error: DemoError | None
    source: DemoSource


class AdapterRunRequest(_ForbidExtraRequestModel):

    fixture_id: str


class AdapterRunResponse(BaseModel):
    adapter_id: Literal["bedrock", "openai_agents", "a2a"]
    fixture_id: str
    provider_input: dict[str, Any]
    normalized_evidence: dict[str, Any]
    decision: Outcome
    artifact: dict[str, Any] | None
    workflow_artifact: dict[str, Any] | None
    error: DemoError | None
    source: DemoSource
