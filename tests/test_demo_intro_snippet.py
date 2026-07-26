from aegis import enforce_post_call, enforce_pre_call


def test_introduction_split_enforcement_sample():
    pre = enforce_pre_call(
        {
            "policy_file": "policies/support.yaml",
            "model_provider": "anthropic",
            "model_identifier": "claude-sonnet-4-6",
            "role": "support_agent",
            "input": {"query": "Can I change my booking?"},
            "context": {"customer_verified": True},
        }
    )
    artifact = enforce_post_call(
        pre,
        {"result": "A support agent can review the booking conditions."},
    )
    assert artifact["enforcement_result"] == "PASS"
