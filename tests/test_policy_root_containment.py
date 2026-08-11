from __future__ import annotations

from pathlib import Path

import pytest

from aegis.errors import PolicyLoadError
from aegis.policy_loader import FilePolicyLoader, load_policy


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
