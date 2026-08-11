from __future__ import annotations

import os
import asyncio
from datetime import date
from pathlib import Path

import pytest

from aegis import AEGIS
from aegis import (
    configure_module_enforcement,
    enforce_invocation,
    enforce_invocation_async,
    enforce_pre_call,
)
from aegis._internal import enforcement as enforcement_module
from aegis._internal import policy_loader as policy_loader_module
from aegis._internal import workflow_doctor
from aegis._internal.cli import build_parser, main
from aegis._internal.errors import PolicyLoadError, PolicyValidationError
from aegis._internal.policy_loader import (
    FilePolicyLoader,
    PolicyCache,
    load_policy,
)
from aegis._internal.sinks import CallbackAuditSink
from aegis._internal.workflow_doctor import diagnose_workflow_policy
from aegis._internal.workflow_lint import lint_policy, lint_starter_dir


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


def _write_starter(directory: Path) -> Path:
    _write_policy(directory / "policy.yaml")
    (directory / "workflow_example.py").write_text(
        "def run():\n    return None\n",
        encoding="utf-8",
    )
    (directory / "README.md").write_text("# Starter\n", encoding="utf-8")
    return directory


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


def test_lint_uses_prepared_policy_without_direct_target_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "authorized"
    entry = _write_policy(root / "entry.yaml")
    original = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == entry:
            pytest.fail("policy target was read outside prepared loading")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    assert lint_policy(entry.name, policy_root=root) == []


def test_doctor_prepares_authorized_policy_once_with_injected_date(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "authorized"
    entry = _write_policy(
        root / "entry.yaml",
        "policy_version: '1.0'\n"
        "effective_date: '2030-01-01'\n"
        "roles: [reviewer]\n"
        "pre_conditions:\n"
        "  required:\n"
        "    session_token:\n"
        "      type: string\n",
    )
    calls = 0
    original_prepare = policy_loader_module._prepare_resolve_compile_policy
    original_read_text = Path.read_text

    def counted(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original_prepare(*args, **kwargs)

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == entry:
            pytest.fail("doctor reopened the prepared policy")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(
        workflow_doctor,
        "_prepare_resolve_compile_policy",
        counted,
        raising=False,
    )
    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    findings = diagnose_workflow_policy(
        entry.name,
        policy_root=root,
        now=date(2029, 1, 1),
    )

    assert calls == 1
    assert any(
        finding["severity"] == "WARNING"
        and finding["message"].startswith("Policy not yet active:")
        for finding in findings
    )
    assert any(
        finding["code"] == "WORKFLOW_SESSION_TOKEN_INVALID"
        for finding in findings
    )
    with pytest.raises(PolicyValidationError):
        load_policy(entry.name, loader=FilePolicyLoader(root))


def test_explicit_root_starter_succeeds(tmp_path: Path) -> None:
    root = tmp_path / "authorized"
    _write_starter(root / "starter")
    assert lint_starter_dir("starter", policy_root=root) == []


def test_explicit_root_rejects_starter_symlink_before_fixture_detection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "authorized"
    root.mkdir()
    outside = _write_starter(tmp_path / "outside")
    (root / "linked-starter").symlink_to(outside, target_is_directory=True)
    findings = lint_starter_dir("linked-starter", policy_root=root)
    assert findings[0]["code"] == "POLICY_PATH_OUTSIDE_ROOT"


def test_implicit_starter_cannot_inherit_from_sibling(tmp_path: Path) -> None:
    first = _write_starter(tmp_path / "starters" / "first")
    _write_starter(tmp_path / "starters" / "second")
    _write_policy(
        first / "policy.yaml",
        "extends: ../second/policy.yaml\n"
        "policy_version: '1.0'\nroles: [reviewer]\n",
    )
    findings = lint_starter_dir(str(first))
    assert findings[0]["code"] == "POLICY_PATH_OUTSIDE_ROOT"


def test_explicit_broader_root_permits_starter_sibling_graph(
    tmp_path: Path,
) -> None:
    starters = tmp_path / "starters"
    first = _write_starter(starters / "first")
    _write_starter(starters / "second")
    _write_policy(
        first / "policy.yaml",
        "extends: ../second/policy.yaml\n"
        "policy_version: '1.0'\nroles: [reviewer]\n",
    )
    assert lint_starter_dir("first", policy_root=starters) == []


@pytest.mark.parametrize(
    "argv",
    [
        ["policy", "lint", "--policy-root", "policies", "entry.yaml"],
        ["policy", "validate", "--policy-root", "policies", "entry.yaml"],
        ["workflow", "lint", "--policy-root", "policies", "entry.yaml"],
        ["workflow", "doctor", "--policy-root", "policies", "entry.yaml"],
    ],
)
def test_policy_commands_accept_policy_root(argv: list[str]) -> None:
    args = build_parser().parse_args(argv)
    assert args.policy_root == "policies"


def test_workflow_artifact_rejects_policy_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    status = main([
        "workflow",
        "lint",
        "--kind",
        "workflow_artifact",
        "--policy-root",
        "policies",
        "artifact.json",
    ])
    assert status == 2
    assert "--policy-root applies only" in capsys.readouterr().err


@pytest.mark.parametrize(
    "prefix",
    [
        ["policy", "lint"],
        ["policy", "validate"],
        ["workflow", "lint", "--kind", "policy"],
        ["workflow", "doctor", "--kind", "policy"],
    ],
)
def test_cli_policy_surfaces_use_only_selected_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    prefix: list[str],
) -> None:
    root = tmp_path / "authorized"
    cwd = tmp_path / "cwd"
    cwd_entry = _write_policy(cwd / "entry.yaml")
    _write_policy(
        root / "entry.yaml",
        "extends: ../outside.yaml\n"
        "policy_version: '1.0'\nroles: [reviewer]\n",
    )
    protected = _write_policy(tmp_path / "outside.yaml")
    monkeypatch.chdir(cwd)
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == cwd_entry:
            pytest.fail("CLI pre-read the same-named CWD policy")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    status = main([
        *prefix,
        "--policy-root",
        str(root),
        "entry.yaml",
    ])
    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert status == 1
    assert "POLICY_PATH_OUTSIDE_ROOT" in rendered
    assert str(root) not in rendered
    assert str(protected) not in rendered


def test_cli_multiple_implicit_targets_get_independent_roots(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = _write_policy(tmp_path / "first" / "entry.yaml")
    second = _write_policy(tmp_path / "second" / "entry.yaml")
    status = main(["policy", "lint", str(first), str(second)])
    assert status == 0
    assert capsys.readouterr().out.count("OK") == 2


def test_module_runtime_seals_configured_policy_loader(tmp_path: Path) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    loader = FilePolicyLoader(root)
    configure_module_enforcement(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=loader,
    )
    enforce_invocation(invocation)
    with pytest.raises(RuntimeError, match="sealed"):
        configure_module_enforcement(
            sink=CallbackAuditSink(lambda artifact: None),
            policy_loader=FilePolicyLoader(root),
        )


@pytest.mark.parametrize("surface", ["module", "aegis"])
def test_sync_operation_reuses_one_implicit_loader_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    invocation = _valid_invocation(str(entry))
    seen: list[int] = []
    original = FilePolicyLoader._prepare

    def recording_prepare(
        self: FilePolicyLoader,
        *args: object,
        **kwargs: object,
    ):
        seen.append(id(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FilePolicyLoader, "_prepare", recording_prepare)
    if surface == "module":
        enforce_invocation(invocation)
    else:
        AEGIS(
            sink=CallbackAuditSink(lambda artifact: None),
        ).enforce(invocation)
    assert seen
    assert len(set(seen)) == 1
    assert enforcement_module._POLICY_AUTHORITY_OVERRIDE.get() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["module", "aegis"])
async def test_async_operation_reuses_one_implicit_loader_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    invocation = _valid_invocation(str(entry))
    seen: list[int] = []
    original = FilePolicyLoader._prepare

    def recording_prepare(
        self: FilePolicyLoader,
        *args: object,
        **kwargs: object,
    ):
        seen.append(id(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FilePolicyLoader, "_prepare", recording_prepare)
    if surface == "module":
        await enforce_invocation_async(invocation)
    else:
        await AEGIS(
            sink=CallbackAuditSink(lambda artifact: None),
        ).enforce_async(invocation)
    assert seen
    assert len(set(seen)) == 1
    assert enforcement_module._POLICY_AUTHORITY_OVERRIDE.get() is None


@pytest.mark.asyncio
async def test_parallel_module_operations_do_not_share_implicit_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _valid_invocation(str(_write_policy(tmp_path / "a" / "entry.yaml")))
    second = _valid_invocation(str(_write_policy(tmp_path / "b" / "entry.yaml")))
    seen: dict[int, set[int]] = {id(first): set(), id(second): set()}
    original = FilePolicyLoader._prepare

    def recording_prepare(
        self: FilePolicyLoader,
        *args: object,
        **kwargs: object,
    ):
        authority = enforcement_module._POLICY_AUTHORITY_OVERRIDE.get()
        assert authority is not None
        seen[id(authority.invocation)].add(id(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FilePolicyLoader, "_prepare", recording_prepare)
    await asyncio.gather(
        enforce_invocation_async(first),
        enforce_invocation_async(second),
    )
    assert all(len(loader_ids) == 1 for loader_ids in seen.values())
    assert seen[id(first)].isdisjoint(seen[id(second)])
    assert enforcement_module._POLICY_AUTHORITY_OVERRIDE.get() is None


def test_nested_module_invocation_shadows_and_restores_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outer = _valid_invocation(str(_write_policy(tmp_path / "a" / "entry.yaml")))
    inner = _valid_invocation(str(_write_policy(tmp_path / "b" / "entry.yaml")))
    original_pipeline = enforcement_module._run_pipeline
    observed: list[tuple[str, int]] = []

    def nested_pipeline(policy: object, invocation: object, **kwargs: object):
        authority = enforcement_module._POLICY_AUTHORITY_OVERRIDE.get()
        assert authority is not None
        if invocation is outer:
            observed.append(("before", id(authority.loader)))
            enforce_invocation(inner)
            restored = enforcement_module._POLICY_AUTHORITY_OVERRIDE.get()
            assert restored is not None
            observed.append(("after", id(restored.loader)))
        elif invocation is inner:
            observed.append(("inner", id(authority.loader)))
        return original_pipeline(policy, invocation, **kwargs)

    monkeypatch.setattr(enforcement_module, "_run_pipeline", nested_pipeline)
    enforce_invocation(outer)
    values = dict(observed)
    assert values["before"] == values["after"]
    assert values["before"] != values["inner"]
    assert enforcement_module._POLICY_AUTHORITY_OVERRIDE.get() is None


def test_explicit_instance_loader_overrides_ambient_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit_root = tmp_path / "explicit"
    entry = _write_policy(explicit_root / "entry.yaml")
    invocation = _valid_invocation(entry.name)
    explicit_loader = FilePolicyLoader(explicit_root)
    ambient_root = tmp_path / "ambient"
    _write_policy(ambient_root / "entry.yaml")
    ambient_loader = FilePolicyLoader(ambient_root)
    ambient = enforcement_module._PolicyAuthority(
        invocation,
        "entry.yaml",
        "entry.yaml",
        ambient_loader,
    )
    seen: list[int] = []
    original = FilePolicyLoader._prepare

    def recording_prepare(
        self: FilePolicyLoader,
        *args: object,
        **kwargs: object,
    ):
        seen.append(id(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FilePolicyLoader, "_prepare", recording_prepare)
    engine = AEGIS(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=explicit_loader,
    )
    with enforcement_module._policy_authority_scope(ambient):
        engine.enforce(invocation)
    assert seen
    assert set(seen) == {id(explicit_loader)}


@pytest.mark.parametrize("surface", ["unified", "pre_call"])
def test_module_split_and_unified_surfaces_use_configured_root(
    tmp_path: Path,
    surface: str,
) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    configure_module_enforcement(
        sink=CallbackAuditSink(lambda artifact: None),
        policy_loader=FilePolicyLoader(root),
    )
    if surface == "pre_call":
        invocation.pop("output")
        assert enforce_pre_call(invocation) is not None
    else:
        assert enforce_invocation(invocation) is not None
