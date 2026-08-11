"""Fitness tests for every YAML policy fixture containing preconditions."""

from pathlib import Path
from typing import Any, Iterator, Mapping

import pytest
import yaml

from aegis._internal.errors import PolicyValidationError
from aegis._internal.legacy import (
    LegacyFeature,
    create_legacy_authorization,
)
from aegis._internal.policy_compiler import compile_policy


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_FIXTURE_ROOTS = (
    Path("demo-app-api/demo_policies"),
    Path("demo-app-api/sample_policies"),
    Path("policies"),
    Path("tests"),
)
LEGACY_FIXTURE = Path("tests/fixtures/bare_string_preconditions_policy.yaml")
INVALID_YAML_FIXTURE = Path("tests/golden_replays/invalid_policy.yaml")
EXPECTED_PRECONDITION_FIXTURES = (
    Path("demo-app-api/demo_policies/atlas.yaml"),
    Path("demo-app-api/demo_policies/integration_adapters.yaml"),
    Path("demo-app-api/demo_policies/meridian.yaml"),
    Path("demo-app-api/demo_policies/northstar_base.yaml"),
    Path("demo-app-api/sample_policies/medical_ai.yaml"),
    Path("demo-app-api/sample_policies/medical_ai_low_risk.yaml"),
    Path("policies/base_policy.yaml"),
    Path("policies/base_policy_composable.yaml"),
    Path("policies/support.yaml"),
    LEGACY_FIXTURE,
    Path("tests/fixtures/no_roles_policy.yaml"),
    Path("tests/fixtures/policy_cycle_a.yaml"),
    Path("tests/fixtures/policy_cycle_b.yaml"),
    Path("tests/fixtures/typed_preconditions_policy.yaml"),
    Path("tests/golden_replays/base_policy_composable.yaml"),
    Path("tests/golden_replays/golden_policy_postcondition_only.yaml"),
    Path("tests/golden_replays/golden_policy_v1.yaml"),
    Path("tests/golden_replays/policy_child_extends_base.yaml"),
    Path("tests/golden_replays/policy_guards_multi.yaml"),
    Path("tests/golden_replays/policy_missing_roles.yaml"),
    Path("tests/golden_replays/policy_postcondition_without_schema.yaml"),
    Path("tests/golden_replays/policy_with_conditions.yaml"),
    Path("tests/golden_replays/policy_with_guards.yaml"),
    Path("tests/golden_replays/policy_with_retry.yaml"),
    Path("tests/golden_replays/policy_with_tools.yaml"),
    Path("tests/test_policies/composition_p4_esc_roles_base.yaml"),
    Path("tests/test_policies/workflow_budget_policy.yaml"),
    Path("tests/test_policies/workflow_composition_base.yaml"),
)
STRUCTURALLY_INVALID_FIXTURES = frozenset(
    {
        Path("tests/fixtures/no_roles_policy.yaml"),
        Path("tests/golden_replays/policy_missing_roles.yaml"),
    }
)
STRICT_FIXTURES = tuple(
    path
    for path in EXPECTED_PRECONDITION_FIXTURES
    if path != LEGACY_FIXTURE and path not in STRUCTURALLY_INVALID_FIXTURES
)


def _load(relative_path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(
        (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    )
    assert isinstance(loaded, dict)
    return loaded


def _precondition_blocks(
    policy: Mapping[str, Any],
) -> Iterator[tuple[str, Any]]:
    preconditions = policy.get("pre_conditions")
    if isinstance(preconditions, Mapping) and "required" in preconditions:
        yield "$.pre_conditions.required", preconditions["required"]
    guards = policy.get("guards")
    if isinstance(guards, list):
        for index, guard in enumerate(guards):
            if not isinstance(guard, Mapping):
                continue
            effect = guard.get("then")
            if not isinstance(effect, Mapping):
                continue
            effect_preconditions = effect.get("pre_conditions")
            if (
                isinstance(effect_preconditions, Mapping)
                and "required" in effect_preconditions
            ):
                yield (
                    f"$.guards.{index}.then.pre_conditions.required",
                    effect_preconditions["required"],
                )


def test_precondition_fixture_inventory_is_complete():
    discovered = []
    for root in POLICY_FIXTURE_ROOTS:
        for path in sorted((REPO_ROOT / root).rglob("*.yaml")):
            relative = path.relative_to(REPO_ROOT)
            if relative == INVALID_YAML_FIXTURE:
                continue
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                continue
            policy = loaded
            if any(True for _ in _precondition_blocks(policy)):
                discovered.append(relative)
    assert tuple(discovered) == EXPECTED_PRECONDITION_FIXTURES


@pytest.mark.parametrize("relative_path", STRICT_FIXTURES, ids=str)
def test_strict_precondition_fixtures_compile_under_contract_2(relative_path):
    policy = _load(relative_path)
    for path, block in _precondition_blocks(policy):
        assert isinstance(block, dict), f"{relative_path}:{path} is ambiguous"
        for name, specification in block.items():
            assert isinstance(
                specification, dict
            ), f"{relative_path}:{path}.{name} is ambiguous"
            assert "type" in specification, (
                f"{relative_path}:{path}.{name} omits its declared type"
            )

    compiled = compile_policy(policy, source=str(relative_path))
    assert compiled.policy_contract_version == "2.0"


def test_legacy_fixture_requires_explicit_host_authority():
    policy = _load(LEGACY_FIXTURE)
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(policy, source=str(LEGACY_FIXTURE))
    assert exc.value.code == "LEGACY_PRECONDITION_FORBIDDEN"

    compiled = compile_policy(
        policy,
        source=str(LEGACY_FIXTURE),
        legacy_authorization=create_legacy_authorization(
            LegacyFeature.BARE_STRING_PRECONDITIONS
        ),
    )
    assert all(precondition.legacy for precondition in compiled.preconditions)
