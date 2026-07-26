"""Server-side allowlists for deterministic demo fixtures and release-gated adapters."""

SCENARIO_VARIANTS = {
    "atlas": frozenset({"first_attempt", "corrected"}),
    "northstar": frozenset({"first_attempt", "authorized_retry", "corrected"}),
    "meridian": frozenset({"first_attempt", "corrected"}),
}

# Adapters are only made public after their deterministic release-gate tests pass.
VERIFIED_ADAPTERS: frozenset[str] = frozenset()


def is_known_scenario(scenario_id: str) -> bool:
    return scenario_id in SCENARIO_VARIANTS


def is_known_variant(scenario_id: str, variant: str) -> bool:
    return variant in SCENARIO_VARIANTS.get(scenario_id, frozenset())


def is_verified_adapter(adapter_id: str) -> bool:
    return adapter_id in VERIFIED_ADAPTERS
