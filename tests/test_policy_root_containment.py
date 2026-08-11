from __future__ import annotations

import builtins
import inspect
import os
import traceback
from pathlib import Path

import pytest
import yaml

from aegis._internal import policy_loader as policy_loader_module
from aegis.errors import PolicyLoadError, PolicyValidationError
from aegis.policy_loader import FilePolicyLoader, PolicyLoaderBase, load_policy


MINIMAL_POLICY = "policy_version: '1.0'\nroles: [reviewer]\n"


def _write_policy(path: Path, body: str = MINIMAL_POLICY) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _symlink_or_skip(
    link: Path,
    target: Path,
    *,
    directory: bool = False,
) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable for test account: {exc}")


def test_file_loader_requires_existing_directory_root(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        FilePolicyLoader()  # type: ignore[call-arg]
    with pytest.raises(PolicyLoadError) as missing:
        FilePolicyLoader(tmp_path / "missing")
    assert missing.value.code == "POLICY_LOAD_ERROR"
    assert str(tmp_path) not in str(missing.value)


def test_legacy_unbound_path_resolver_is_removed() -> None:
    assert not hasattr(policy_loader_module, "_resolve_policy_path")
    assert not hasattr(policy_loader_module, "_resolve_extends")


def test_explicit_loader_is_root_relative_after_chdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    _write_policy(root / "apps" / "reviewer.yaml")
    loader = FilePolicyLoader(root)
    monkeypatch.chdir(tmp_path)
    assert loader.policy_root == root.resolve()
    assert load_policy("apps/reviewer.yaml", loader=loader)["roles"] == [
        "reviewer"
    ]


def test_direct_multicomponent_entry_is_not_double_prefixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = _write_policy(tmp_path / "policies" / "child.yaml")
    monkeypatch.chdir(tmp_path)
    assert load_policy(str(entry.relative_to(tmp_path)))["roles"] == ["reviewer"]


def test_explicit_entry_traversal_is_rejected_before_metadata_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    loader = FilePolicyLoader(root)
    original_exists = Path.exists
    original_is_file = Path.is_file

    def guarded_exists(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> bool:
        if path == outside:
            raise AssertionError("outside metadata was inspected")
        return original_exists(path, *args, **kwargs)

    def guarded_is_file(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> bool:
        if path == outside:
            raise AssertionError("outside metadata was inspected")
        return original_is_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", guarded_exists)
    monkeypatch.setattr(Path, "is_file", guarded_is_file)
    with pytest.raises(PolicyLoadError) as caught:
        load_policy("../outside.yaml", loader=loader)
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
    assert str(caught.value) == (
        "Policy path is outside the configured policy root"
    )


def test_entry_symlink_cannot_redefine_implicit_root(tmp_path: Path) -> None:
    outside = _write_policy(tmp_path / "outside" / "policy.yaml")
    lexical_dir = tmp_path / "inside"
    lexical_dir.mkdir()
    entry = lexical_dir / "entry.yaml"
    _symlink_or_skip(entry, outside)
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(str(entry))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_directory_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    _write_policy(outside / "entry.yaml")
    _symlink_or_skip(root / "linked", outside, directory=True)
    with pytest.raises(PolicyLoadError) as caught:
        load_policy("linked/entry.yaml", loader=FilePolicyLoader(root))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_in_root_symlink_target_is_allowed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    target = _write_policy(root / "real.yaml")
    link = root / "link.yaml"
    _symlink_or_skip(link, target)
    assert load_policy("link.yaml", loader=FilePolicyLoader(root))["roles"] == [
        "reviewer"
    ]


def test_explicit_root_symlink_is_canonicalized(tmp_path: Path) -> None:
    real_root = tmp_path / "real-root"
    _write_policy(real_root / "entry.yaml")
    linked_root = tmp_path / "linked-root"
    _symlink_or_skip(linked_root, real_root, directory=True)
    loader = FilePolicyLoader(linked_root)
    assert loader.policy_root == real_root.resolve()
    assert load_policy("entry.yaml", loader=loader)["roles"] == ["reviewer"]


def test_normalized_in_root_parent_is_allowed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _write_policy(root / "base.yaml")
    (root / "subdirectory").mkdir()
    assert load_policy(
        "subdirectory/../base.yaml",
        loader=FilePolicyLoader(root),
    )["roles"] == ["reviewer"]


def test_absolute_entry_outside_explicit_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = _write_policy(tmp_path / "outside.yaml")
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(str(outside), loader=FilePolicyLoader(root))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_relative_and_absolute_entry_spellings_match(tmp_path: Path) -> None:
    root = tmp_path / "root"
    entry = _write_policy(root / "entry.yaml")
    loader = FilePolicyLoader(root)
    assert load_policy(entry.name, loader=loader) == load_policy(
        str(entry),
        loader=loader,
    )


class ExtendingOpaqueLoader(PolicyLoaderBase):
    def __init__(self, extends: object) -> None:
        self.extends = extends
        self.calls: list[str] = []

    def load(self, policy_ref: str) -> dict[str, object]:
        self.calls.append(policy_ref)
        return {
            "policy_version": "1.0",
            "roles": ["reviewer"],
            "extends": self.extends,
        }


@pytest.mark.parametrize("extends", [None, False, 7, {}, [], ""])
def test_custom_loader_rejects_any_extends_without_filesystem(
    monkeypatch: pytest.MonkeyPatch,
    extends: object,
) -> None:
    loader = ExtendingOpaqueLoader(extends)
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda *args, **kwargs: pytest.fail("path resolution used"),
    )
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *args, **kwargs: pytest.fail("file open used"),
    )
    with pytest.raises(PolicyLoadError, match="not supported with custom loaders"):
        load_policy("opaque-id", loader=loader)
    assert loader.calls == ["opaque-id"]


def test_transitive_child_cannot_widen_original_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _write_policy(tmp_path / "outside.yaml")
    _write_policy(
        root / "base.yaml",
        "extends: ../outside.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    entry = _write_policy(
        root / "nested" / "entry.yaml",
        "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(str(entry), loader=FilePolicyLoader(root))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_in_root_multilevel_composition_uses_one_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _write_policy(root / "base.yaml")
    _write_policy(
        root / "middle" / "middle.yaml",
        "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    _write_policy(
        root / "entry" / "entry.yaml",
        "extends: ../middle/middle.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    assert load_policy(
        "entry/entry.yaml",
        loader=FilePolicyLoader(root),
    )["roles"] == ["reviewer"]


@pytest.mark.parametrize("extends", [None, True, 3, {}, [], ""])
def test_file_loader_rejects_malformed_extends_before_path_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extends: object,
) -> None:
    entry = _write_policy(
        tmp_path / "entry.yaml",
        yaml.safe_dump(
            {
                "policy_version": "1.0",
                "roles": ["reviewer"],
                "extends": extends,
            }
        ),
    )
    loader = FilePolicyLoader(tmp_path)
    context_type = policy_loader_module._FileLoadContext
    context = context_type.create(entry.name)
    prepared = loader._prepare(entry.name, context=context)
    monkeypatch.setattr(
        loader,
        "_canonical_candidate",
        lambda *args, **kwargs: pytest.fail(
            "malformed extends reached path work"
        ),
    )
    with pytest.raises(PolicyValidationError) as caught:
        policy_loader_module._resolve_file_graph(
            prepared,
            loader=loader,
            visited=set(),
            context=context,
        )
    assert caught.value.code == "POLICY_SCHEMA_VALIDATION_ERROR"
    assert caught.value.details == {"path": "$.extends"}


def test_prepared_source_is_bound_to_exact_loader_instance(tmp_path: Path) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    first = FilePolicyLoader(tmp_path)
    second = FilePolicyLoader(tmp_path)
    context_type = policy_loader_module._FileLoadContext
    prepared = first._prepare(
        entry.name,
        context=context_type.create(entry.name),
    )
    with pytest.raises(PolicyLoadError, match="authority does not match loader"):
        policy_loader_module._resolve_file_graph(
            prepared,
            loader=second,
            visited=set(),
            context=context_type.create(),
        )


def test_compiler_boundary_has_no_parsed_policy_fast_path(tmp_path: Path) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    signature = inspect.signature(
        policy_loader_module.load_resolve_compile_policy
    )
    assert "parsed_policy" not in signature.parameters
    with pytest.raises(TypeError):
        policy_loader_module.load_resolve_compile_policy(
            str(entry),
            parsed_policy={"policy_version": "forged"},
        )


@pytest.mark.asyncio
async def test_async_implicit_authority_binds_before_await(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = tmp_path / "original"
    other = tmp_path / "other"
    _write_policy(original / "policies" / "entry.yaml")
    _write_policy(
        other / "policies" / "entry.yaml",
        "policy_version: '2.0'\nroles: [reviewer]\n",
    )
    monkeypatch.chdir(original)
    pending = policy_loader_module.load_policy_async("policies/entry.yaml")
    monkeypatch.chdir(other)
    loaded = await pending
    assert loaded["policy_version"] == "1.0"


def _assert_path_confidential(exc: BaseException, protected: list[str]) -> None:
    chain_text = "".join(traceback.format_exception(exc))
    values = [str(exc), repr(getattr(exc, "details", None)), chain_text]
    cursor: BaseException | None = exc
    while cursor is not None:
        values.extend([str(cursor), repr(getattr(cursor, "details", None))])
        cursor = cursor.__cause__ or cursor.__context__
    rendered = "\n".join(values)
    for secret in protected:
        assert secret not in rendered


@pytest.mark.parametrize(
    "failure_kind",
    [
        "containment",
        "cycle",
        "missing",
        "non_file",
        "malformed_yaml",
        "schema",
        "composition",
        "symlink_loop",
    ],
)
def test_file_graph_failures_are_path_confidential(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    root = tmp_path / "protected-root"
    root.mkdir()
    entry = root / "entry.yaml"
    protected = [str(root), str(entry)]

    if failure_kind == "containment":
        outside = _write_policy(tmp_path / "outside-secret.yaml")
        extends = "../outside-secret.yaml"
        _write_policy(
            entry,
            f"extends: {extends}\n{MINIMAL_POLICY}",
        )
        protected.extend([extends, str(outside)])
    elif failure_kind == "cycle":
        extends = "entry.yaml"
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.append(extends)
    elif failure_kind == "missing":
        extends = "missing-secret.yaml"
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.extend([extends, str(root / extends)])
    elif failure_kind == "non_file":
        extends = "directory-secret.yaml"
        (root / extends).mkdir()
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.extend([extends, str(root / extends)])
    elif failure_kind == "malformed_yaml":
        extends = "malformed-secret.yaml"
        _write_policy(root / extends, "roles: [unterminated\n")
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.extend([extends, str(root / extends)])
    elif failure_kind == "schema":
        extends = "invalid-secret.yaml"
        _write_policy(root / extends, "policy_version: '1.0'\n")
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.extend([extends, str(root / extends)])
    elif failure_kind == "composition":
        extends = "base-secret.yaml"
        _write_policy(root / extends)
        _write_policy(
            entry,
            f"extends: {extends}\npolicy_version: '1.0'\nroles: [admin]\n",
        )
        protected.extend([extends, str(root / extends)])
    else:
        extends = "loop-secret.yaml"
        loop = root / extends
        _symlink_or_skip(loop, loop)
        _write_policy(entry, f"extends: {extends}\n{MINIMAL_POLICY}")
        protected.extend([extends, str(loop)])

    with pytest.raises((PolicyLoadError, PolicyValidationError)) as caught:
        load_policy(entry.name, loader=FilePolicyLoader(root))

    _assert_path_confidential(caught.value, protected)


def test_schema_failure_does_not_disclose_file_or_schema_paths(
    tmp_path: Path,
) -> None:
    root = tmp_path / "protected-root"
    entry = _write_policy(root / "entry.yaml", "policy_version: '1.0'\n")
    with pytest.raises(PolicyValidationError) as caught:
        load_policy(entry.name, loader=FilePolicyLoader(root))
    _assert_path_confidential(
        caught.value,
        [str(root), str(entry), str(policy_loader_module.POLICY_DSL_SCHEMA_PATH)],
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows drive semantics")
def test_windows_different_drive_entry_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loader = FilePolicyLoader(tmp_path)
    foreign_drive = "Z:" if tmp_path.drive.upper() != "Z:" else "Y:"
    foreign = Path(foreign_drive + r"\outside\policy.yaml")
    monkeypatch.setattr(loader, "_canonicalize", lambda lexical: foreign)
    with pytest.raises(PolicyLoadError) as caught:
        loader.load(str(foreign))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
