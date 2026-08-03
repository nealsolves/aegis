"""Golden replay tests for artifact signing (M2)."""
from aegis._internal.enforcement import AEGIS, AIGC
from aegis._internal.signing import HMACSigner, verify_artifact


POLICY = "tests/golden_replays/golden_policy_v1.yaml"
INVOCATION = {
    "policy_file": POLICY,
    "model_provider": "openai",
    "model_identifier": "gpt-4",
    "role": "planner",
    "input": {"prompt": "test"},
    "output": {"result": "ok", "confidence": 0.9},
    "context": {"role_declared": True, "schema_exists": True},
}


def test_signed_pass_artifact():
    signer = HMACSigner(key=b"golden-test-key")
    aegis = AIGC(signer=signer)
    audit = aegis.enforce(INVOCATION)
    assert audit["enforcement_result"] == "PASS"
    assert audit["signature"] is not None
    assert verify_artifact(audit, signer)


def test_aegis_legacy_signer_is_adapted_to_v2_metadata():
    audit = AEGIS(signer=HMACSigner(key=b"golden-test-key")).enforce(INVOCATION)

    assert audit["signature"] is not None
    assert audit["signature_status"] == "signed"
    assert audit["signature_metadata"]["canonicalization_profile"] == (
        "aegis-json-v2"
    )


def test_signed_fail_artifact():
    signer = HMACSigner(key=b"golden-test-key")
    aegis = AIGC(signer=signer)
    bad_inv = dict(INVOCATION, role="unauthorized_role")
    import pytest
    from aegis._internal.errors import GovernanceViolationError
    with pytest.raises(GovernanceViolationError) as exc_info:
        aegis.enforce(bad_inv)
    audit = exc_info.value.audit_artifact
    assert audit["enforcement_result"] == "FAIL"
    assert audit["signature"] is not None
    assert verify_artifact(audit, signer)


def test_signature_deterministic():
    signer = HMACSigner(key=b"golden-test-key")
    aegis = AIGC(signer=signer)
    a1 = aegis.enforce(INVOCATION)
    a2 = aegis.enforce(INVOCATION)
    # Timestamps differ, so signatures differ — but both verify
    assert verify_artifact(a1, signer)
    assert verify_artifact(a2, signer)


def test_tampered_signature_fails():
    signer = HMACSigner(key=b"golden-test-key")
    aegis = AIGC(signer=signer)
    audit = aegis.enforce(INVOCATION)
    audit["enforcement_result"] = "FAIL"  # tamper
    assert not verify_artifact(audit, signer)
