from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis import CallbackAuditSink, JsonFileAuditSink

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


def test_module_proxy_accepts_only_its_root_bound_starter_sink_intent(
    tmp_path: Path,
) -> None:
    root = tmp_path / "starter"
    root.mkdir()
    (root / "policy.yaml").write_text(
        (SAMPLE_POLICIES / "medical_ai_low_risk.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    proxy = DemoAegisModuleProxy(SimpleNamespace(marker="unchanged"), root)

    sink_intent = proxy.JsonFileAuditSink(root / "audit.jsonl")
    artifact = proxy.AEGIS(sink=sink_intent).enforce(
        _invocation("policy.yaml")
    )

    assert artifact["enforcement_result"] == "PASS"
    assert (root / "audit.jsonl").is_file()


def test_module_proxy_rejects_foreign_authority_and_unknown_constructor_options(
    tmp_path: Path,
) -> None:
    root = tmp_path / "starter"
    root.mkdir()
    proxy = DemoAegisModuleProxy(SimpleNamespace(), root)
    foreign_sink = JsonFileAuditSink(tmp_path / "outside.jsonl")

    with pytest.raises(TypeError, match="starter sink"):
        proxy.AEGIS(sink=foreign_sink)
    with pytest.raises(TypeError, match="demo runtime owns"):
        proxy.AEGIS(policy_loader=object())
    with pytest.raises(TypeError, match="demo runtime owns"):
        proxy.AEGIS(signer=object())
    with pytest.raises(TypeError, match="demo runtime owns"):
        proxy.AEGIS(chain_linker=object())
    with pytest.raises(TypeError, match="unsupported AEGIS option"):
        proxy.AEGIS(unknown_option=True)
    with pytest.raises(ValueError, match="outside the demo policy root"):
        proxy.JsonFileAuditSink(tmp_path / "outside.jsonl")
