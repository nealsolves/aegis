from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegis import AEGIS
from aegis._internal.errors import PolicyLoadError
from aegis._internal.policy_loader import FilePolicyLoader, PolicyCache
from aegis._internal.sinks import CallbackAuditSink


MINIMAL_POLICY = "policy_version: '1.0'\nroles: [reviewer]\n"


def _write_policy(path: Path, body: str = MINIMAL_POLICY) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _valid_invocation(policy_file: str) -> dict[str, object]:
    return {
        "policy_file": policy_file,
        "model_provider": "test",
        "model_identifier": "test-model",
        "role": "reviewer",
        "input": {"task": "review"},
        "output": {},
        "context": {},
    }


def _policy_tree_and_invocation(
    tmp_path: Path,
) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "root"
    _write_policy(root / "base.yaml")
    _write_policy(
        root / "nested" / "entry.yaml",
        "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    return root, _valid_invocation("nested/entry.yaml")


def _exception_text(exc: BaseException) -> str:
    messages: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        messages.append(str(current))
        current = current.__cause__ or current.__context__
    return "\n".join(messages)


def test_cache_key_isolated_by_authority_root(tmp_path: Path) -> None:
    broad = tmp_path / "broad"
    narrow = broad / "narrow"
    _write_policy(broad / "base.yaml")
    _write_policy(
        narrow / "entry.yaml",
        "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    cache = PolicyCache()
    cache.get_or_load(
        "narrow/entry.yaml",
        loader=FilePolicyLoader(broad),
    )
    with pytest.raises(PolicyLoadError) as caught:
        cache.get_or_load(
            "entry.yaml",
            loader=FilePolicyLoader(narrow),
        )
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_cache_does_not_consult_metadata_or_entries_before_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    cache = PolicyCache()
    loader = FilePolicyLoader(root)

    class NoCacheAccess(dict):
        def __contains__(self, key: object) -> bool:
            pytest.fail("cache consulted before containment")

        def get(self, key: object, default: object = None) -> object:
            pytest.fail("cache consulted before containment")

    cache._cache = NoCacheAccess()
    monkeypatch.setattr(
        os.path,
        "getmtime",
        lambda *args, **kwargs: pytest.fail("mtime read"),
    )
    monkeypatch.setattr(
        loader,
        "_preflight",
        lambda ref, **kwargs: (_ for _ in ()).throw(
            PolicyLoadError(
                "Policy path is outside the configured policy root",
                code="POLICY_PATH_OUTSIDE_ROOT",
            )
        ),
    )
    with pytest.raises(PolicyLoadError) as caught:
        cache.get_or_load("../outside.yaml", loader=loader)
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_file_cache_key_preserves_numeric_mtime(tmp_path: Path) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    cache = PolicyCache()
    cache.get_or_load(entry.name, loader=FilePolicyLoader(tmp_path))
    key = next(iter(cache._cache))
    assert len(key) == 3
    assert isinstance(key[2], float)


@pytest.mark.parametrize("method_name", ["enforce", "enforce_pre_call"])
def test_aegis_instance_uses_configured_root(
    tmp_path: Path,
    method_name: str,
) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    emitted: list[dict[str, object]] = []
    engine = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        policy_loader=FilePolicyLoader(root),
    )
    if method_name == "enforce_pre_call":
        invocation.pop("output")
    result = getattr(engine, method_name)(invocation)
    assert result is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    ["enforce_async", "enforce_pre_call_async"],
)
async def test_aegis_async_instance_uses_configured_root(
    tmp_path: Path,
    method_name: str,
) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )
    if method_name == "enforce_pre_call_async":
        invocation.pop("output")
    result = await getattr(engine, method_name)(invocation)
    assert result is not None


@pytest.mark.parametrize("method_name", ["enforce", "enforce_pre_call"])
def test_aegis_escape_failure_is_path_free_and_auditable(
    tmp_path: Path,
    method_name: str,
) -> None:
    root = tmp_path / "root"
    protected = _write_policy(tmp_path / "protected-policy.yaml")
    _write_policy(
        root / "entry.yaml",
        "extends: ../protected-policy.yaml\n"
        "policy_version: '1.0'\nroles: [reviewer]\n",
    )
    invocation = _valid_invocation("entry.yaml")
    if method_name == "enforce_pre_call":
        invocation.pop("output")
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )

    with pytest.raises(PolicyLoadError) as caught:
        getattr(engine, method_name)(invocation)

    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
    assert caught.value.audit_artifact is not None
    assert caught.value.audit_artifact["enforcement_result"] == "FAIL"
    assert str(protected) not in _exception_text(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    ["enforce_async", "enforce_pre_call_async"],
)
async def test_aegis_async_escape_failure_retains_root_authority(
    tmp_path: Path,
    method_name: str,
) -> None:
    root = tmp_path / "root"
    protected = _write_policy(tmp_path / "protected-policy.yaml")
    _write_policy(
        root / "entry.yaml",
        "extends: ../protected-policy.yaml\n"
        "policy_version: '1.0'\nroles: [reviewer]\n",
    )
    invocation = _valid_invocation("entry.yaml")
    if method_name == "enforce_pre_call_async":
        invocation.pop("output")
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )

    with pytest.raises(PolicyLoadError) as caught:
        await getattr(engine, method_name)(invocation)

    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
    assert caught.value.audit_artifact is not None
    assert caught.value.audit_artifact["enforcement_result"] == "FAIL"
    assert str(protected) not in _exception_text(caught.value)


def test_aegis_cached_enforcement_retains_configured_root(tmp_path: Path) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )
    engine.enforce(invocation)
    engine.enforce(invocation)
    assert engine.policy_cache.size == 1


def test_aegis_session_pin_uses_configured_root(tmp_path: Path) -> None:
    root, _ = _policy_tree_and_invocation(tmp_path)
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )
    with engine.open_session(policy_file="nested/entry.yaml") as session:
        assert session._compiled_policy is not None
        session.cancel()
