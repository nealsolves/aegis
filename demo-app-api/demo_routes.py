"""Public routes for the versioned deterministic demo API."""
from fastapi import APIRouter

from demo_contract import (
    API_CONTRACT_VERSION,
    FIXTURE_SET_VERSION,
    AdapterRunRequest,
    AdapterRunResponse,
    DemoManifest,
    ScenarioRunRequest,
    ScenarioRunResponse,
    demo_source,
    installed_sdk_version,
)
from demo_registry import (
    SCENARIO_VARIANTS,
    VERIFIED_ADAPTERS,
    is_known_adapter_fixture,
    is_known_scenario,
    is_known_variant,
    is_verified_adapter,
)
from demo_errors import DemoPublicError, safe_demo_message
from demo_adapter_service import run_adapter
from demo_scenario_service import run_scenario


router = APIRouter(prefix="/api/demo", tags=["demo-v1"])


def _unknown_id(kind: str, value: str) -> DemoPublicError:  # noqa: ARG001
    return DemoPublicError(
        "UNKNOWN_DEMO_ID",
        safe_demo_message("UNKNOWN_DEMO_ID"),
        422,
    )


@router.get("/manifest", response_model=DemoManifest)
def demo_manifest() -> DemoManifest:
    return DemoManifest(
        api_contract_version=API_CONTRACT_VERSION,
        sdk_version=installed_sdk_version(),
        fixture_set_version=FIXTURE_SET_VERSION,
        scenarios=sorted(SCENARIO_VARIANTS),
        adapters=sorted(VERIFIED_ADAPTERS),
        source=demo_source(),
    )


@router.post("/scenarios/{scenario_id}/runs", response_model=ScenarioRunResponse)
def run_demo_scenario(
    scenario_id: str,
    request: ScenarioRunRequest,
) -> ScenarioRunResponse:
    if not is_known_scenario(scenario_id):
        raise _unknown_id("scenario_id", scenario_id)
    if not is_known_variant(scenario_id, request.variant):
        raise _unknown_id("variant", request.variant)

    return run_scenario(scenario_id, request.variant)


@router.post("/adapters/{adapter_id}/runs", response_model=AdapterRunResponse)
def run_demo_adapter(
    adapter_id: str,
    request: AdapterRunRequest,
) -> AdapterRunResponse:
    if not is_verified_adapter(adapter_id):
        raise _unknown_id("adapter_id", adapter_id)
    if not is_known_adapter_fixture(adapter_id, request.fixture_id):
        raise _unknown_id("fixture_id", request.fixture_id)

    return run_adapter(adapter_id, request.fixture_id)
