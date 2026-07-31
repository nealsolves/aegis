"""Behavioral regression tests for the compiled enforcement boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis._internal.enforcement import (
    AEGIS,
    enforce_invocation,
    enforce_invocation_async,
    enforce_pre_call,
)
from aegis._internal.errors import PolicyValidationError


_LEGACY_POLICY = """\
policy_version: "1.0"
roles: [planner]
pre_conditions:
  required: [approved]
"""


def _invocation(policy_file: str, *, output: bool) -> dict:
    invocation = {
        "policy_file": policy_file,
        "model_provider": "internal",
        "model_identifier": "test-model",
        "role": "planner",
        "input": {"task": "test"},
        "context": {"approved": True},
    }
    if output:
        invocation["output"] = {"result": "ok"}
    return invocation


@pytest.mark.parametrize("entry", ["unified", "split", "instance"])
def test_every_sync_policy_load_is_immediately_strictly_compiled(
    tmp_path: Path,
    entry: str,
) -> None:
    """A loader-valid legacy precondition must never reach authorization."""
    policy_file = tmp_path / "legacy.yaml"
    policy_file.write_text(_LEGACY_POLICY, encoding="utf-8")

    with pytest.raises(PolicyValidationError) as exc:
        if entry == "unified":
            enforce_invocation(_invocation(str(policy_file), output=True))
        elif entry == "split":
            enforce_pre_call(_invocation(str(policy_file), output=False))
        else:
            AEGIS().enforce(_invocation(str(policy_file), output=True))

    assert exc.value.code == "LEGACY_PRECONDITION_FORBIDDEN"
    assert exc.value.details["path"] == "$.pre_conditions.required"


async def test_async_policy_load_is_immediately_strictly_compiled(
    tmp_path: Path,
) -> None:
    """The async loader boundary must enforce the same compiler contract."""
    policy_file = tmp_path / "legacy.yaml"
    policy_file.write_text(_LEGACY_POLICY, encoding="utf-8")

    with pytest.raises(PolicyValidationError) as exc:
        await enforce_invocation_async(
            _invocation(str(policy_file), output=True),
        )

    assert exc.value.code == "LEGACY_PRECONDITION_FORBIDDEN"
    assert exc.value.details["path"] == "$.pre_conditions.required"


def test_session_policy_load_is_immediately_strictly_compiled(
    tmp_path: Path,
) -> None:
    """Opening a policy-backed session cannot retain a raw authority mapping."""
    policy_file = tmp_path / "legacy.yaml"
    policy_file.write_text(_LEGACY_POLICY, encoding="utf-8")

    with pytest.raises(PolicyValidationError) as exc:
        AEGIS().open_session(policy_file=str(policy_file))

    assert exc.value.code == "LEGACY_PRECONDITION_FORBIDDEN"
    assert exc.value.details["path"] == "$.pre_conditions.required"
