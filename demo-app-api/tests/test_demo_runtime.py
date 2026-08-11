from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis import CallbackAuditSink

from demo_runtime import (
    DemoAegisModuleProxy,
    demo_aegis,
    demo_aegis_with_sink,
    logical_policy_ref,
)
from scenarios import SCENARIOS


DEMO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_POLICIES = DEMO_ROOT / "sample_policies"


def _invocation(policy_ref: str) -> dict:
    scenario = SCENARIOS["low_risk_faq"]
    return {
        "policy_file": policy_ref,
        "model_provider": scenario["model_provider"],
        "model_identifier": scenario["model_id"],
        "role": scenario["role"],
        "input": {"query": scenario["prompt"]},
        "output": scenario["output"],
        "context": scenario["context"],
    }


def test_demo_aegis_enforces_with_logical_policy_reference_and_explicit_sink() -> None:
    engine = demo_aegis(SAMPLE_POLICIES)

    artifact = engine.enforce(_invocation("medical_ai_low_risk.yaml"))

    assert artifact["policy_file"] == "medical_ai_low_risk.yaml"
    assert str(SAMPLE_POLICIES) not in json.dumps(artifact)


def test_demo_aegis_with_sink_preserves_loader_ownership() -> None:
    emitted: list[dict] = []
    sink = CallbackAuditSink(emitted.append)
    engine = demo_aegis_with_sink(SAMPLE_POLICIES, sink)

    artifact = engine.enforce(_invocation("medical_ai_low_risk.yaml"))

    assert emitted == [artifact]
    assert artifact["policy_file"] == "medical_ai_low_risk.yaml"


def test_demo_factory_rejects_authority_overrides() -> None:
    sink = CallbackAuditSink(lambda _artifact: None)
    with pytest.raises(TypeError):
        demo_aegis(SAMPLE_POLICIES, sink=sink)
    with pytest.raises(TypeError):
        demo_aegis(SAMPLE_POLICIES, policy_loader=object())


def test_logical_policy_ref_accepts_only_contained_paths(tmp_path: Path) -> None:
    root = tmp_path / "policies"
    root.mkdir()
    nested = root / "nested" / "policy.yaml"
    nested.parent.mkdir()
    nested.write_text("roles: [reviewer]\n", encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text("roles: [reviewer]\n", encoding="utf-8")

    assert logical_policy_ref(root, nested) == "nested/policy.yaml"
    with pytest.raises(ValueError):
        logical_policy_ref(root, outside)


def test_module_proxy_delegates_attributes_and_injects_demo_factory() -> None:
    original = SimpleNamespace(marker="unchanged")
    proxy = DemoAegisModuleProxy(original, SAMPLE_POLICIES)

    artifact = proxy.AEGIS().enforce(_invocation("medical_ai_low_risk.yaml"))

    assert proxy.marker == "unchanged"
    assert artifact["policy_file"] == "medical_ai_low_risk.yaml"
