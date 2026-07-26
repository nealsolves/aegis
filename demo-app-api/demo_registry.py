"""Server-side allowlists for deterministic demo fixtures and release-gated adapters."""

from demo_fixtures import ADAPTER_FIXTURES


SCENARIO_VARIANTS = {
    "atlas": frozenset({"first_attempt", "corrected"}),
    "northstar": frozenset({"first_attempt", "authorized_retry", "corrected"}),
    "meridian": frozenset({"first_attempt", "corrected"}),
}

ADAPTER_FIXTURE_IDS = {
    adapter_id: frozenset(
        fixture_id
        for candidate_adapter_id, fixture_id in ADAPTER_FIXTURES
        if candidate_adapter_id == adapter_id
    )
    for adapter_id, _ in ADAPTER_FIXTURES
}

# Adapters are only made public after their deterministic release-gate tests pass.
VERIFIED_ADAPTERS: frozenset[str] = frozenset(
    {"bedrock", "openai_agents", "a2a"},
)


def is_known_scenario(scenario_id: str) -> bool:
    return scenario_id in SCENARIO_VARIANTS


def is_known_variant(scenario_id: str, variant: str) -> bool:
    return variant in SCENARIO_VARIANTS.get(scenario_id, frozenset())


def is_verified_adapter(adapter_id: str) -> bool:
    return adapter_id in VERIFIED_ADAPTERS


def is_known_adapter_fixture(adapter_id: str, fixture_id: str) -> bool:
    return fixture_id in ADAPTER_FIXTURE_IDS.get(adapter_id, frozenset())
