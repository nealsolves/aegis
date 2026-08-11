# Issue #57 Policy Root Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one canonical, immutable policy root govern every file-backed policy entry and transitive `extends` load across runtime, cache, diagnostics, CLI, and retry surfaces.

**Architecture:** Replace ambient filesystem loading with a root-bound `FilePolicyLoader` that mints private prepared sources after canonical containment, metadata checks, opening, and YAML parsing. Route composition, compilation, cache, diagnostics, module/instance enforcement, async loading, and retry through the exact bound loader authority; keep custom loaders opaque and unable to enter the file-backed prepared-source path. Normalize every file-backed failure at the loader boundary so callers receive stable typed errors without protected path values or chained exceptions.

**Tech Stack:** Python 3.10+, `pathlib`, `dataclasses`, `contextvars`, `asyncio`, PyYAML 6+, jsonschema Draft 7, pytest 8+.

## Global Constraints

- A file-load graph has exactly one canonical policy root, resolved once and immutable for the loader lifetime.
- Canonical containment runs before suffix, existence, type, modification-time, cache, content, or diagnostic inspection; canonicalization may perform only the lookups needed to resolve symlinks.
- Relative explicit-loader entries are root-relative; transitive `extends` references are source-relative; absolute entries and parents are accepted only when canonically contained.
- Plain direct loads derive authority from the resolved lexical parent before resolving the entry's final component.
- File-backed prepared sources remain private, carry a per-loader identity token, and cannot be supplied or forged through a public parsed-mapping fast path.
- Opaque custom loaders reject any policy containing an `extends` key without attempting filesystem resolution.
- `POLICY_PATH_OUTSIDE_ROOT` uses exactly `Policy path is outside the configured policy root`.
- Public file-backed exceptions and formatted exception chains disclose none of the root, candidate, entry, `extends`, visited-chain, or installed-schema paths.
- Async, cache, diagnostics, module enforcement, AEGIS enforcement/sessions, and retry reuse the same authority selected at their entry boundary.
- No environment variable, global policy-root setting, new runtime dependency, merge-semantic change, or hostile concurrent-filesystem-writer guarantee is introduced.
- Both `schemas/policy_dsl.schema.json` and `aegis/schemas/policy_dsl.schema.json` remain byte-for-byte equivalent where policy DSL constraints overlap.
- Windows different-drive containment is tested on Windows; symlink tests skip only when the test account cannot create symlinks.

---

## File and responsibility map

- `aegis/_internal/policy_loader.py`: sole file authority boundary, prepared-source orchestration, composition, async binding, and root-aware cache identity.
- `aegis/_internal/errors.py`: stable containment reason code support on `PolicyLoadError`.
- `aegis/_internal/enforcement.py`: sealed module loader configuration and private invocation-bound authority context shared by module and AEGIS operations.
- `aegis/_internal/retry.py`: authority inference/attestation and reuse for discovery plus every enforcement attempt.
- `aegis/_internal/workflow_lint.py`: prepared-source linting and contained starter-target discovery.
- `aegis/_internal/workflow_doctor.py`: single-prepare, injected-clock diagnostics and prepared starter reuse.
- `aegis/_internal/cli.py`: `--policy-root` parsing and propagation without policy pre-reads.
- `schemas/policy_dsl.schema.json`, `aegis/schemas/policy_dsl.schema.json`: reject empty `extends` strings consistently in source and wheel data.
- `tests/test_policy_root_containment.py`: new adversarial root, graph, symlink, error-confidentiality, prepared-source, and async tests.
- `tests/test_policy_root_entry_points.py`: new cache, runtime, diagnostics, CLI, and retry authority-integration tests.
- Existing focused test modules: compatibility expectations and regressions for loader, composition, cache, enforcement, retry, workflow tooling, public API, and distribution.
- User and contract documentation: authority semantics, migrations, troubleshooting, security/non-goal boundaries, and release note.

---

### Task 1: Root-bound filesystem loader and containment preflight

**Files:**
- Create: `tests/test_policy_root_containment.py`
- Modify: `aegis/_internal/errors.py:102-106`
- Modify: `aegis/_internal/policy_loader.py:61-164`
- Modify: `tests/test_pluggable_loader.py:56-60,132-142`
- Modify: `tests/test_policy_loader.py:1-110`

**Interfaces:**
- Consumes: `PolicyLoaderBase.load(policy_ref: str) -> dict[str, Any]` and the existing public `FilePolicyLoader` export.
- Produces: `FilePolicyLoader(policy_root: str | Path)`, read-only `policy_root: Path`, `_PreparedFilePolicy`, `_bind_policy_authority(policy_file: str, loader: PolicyLoaderBase | None) -> tuple[str, PolicyLoaderBase]`, and `PolicyLoadError(message: str, *, code: str = "POLICY_LOAD_ERROR", details: dict | None = None)`.

- [ ] **Step 1: Add failing constructor and entry-containment tests**

Create helpers and tests that prove constructor-time root binding, root-relative explicit entries, lexical-parent implicit entries, and rejection before metadata/content access:

```python
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


def test_file_loader_requires_existing_directory_root(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        FilePolicyLoader()  # type: ignore[call-arg]
    with pytest.raises(PolicyLoadError) as missing:
        FilePolicyLoader(tmp_path / "missing")
    assert missing.value.code == "POLICY_LOAD_ERROR"
    assert str(tmp_path) not in str(missing.value)


def test_explicit_loader_is_root_relative_after_chdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    _write_policy(root / "apps" / "reviewer.yaml")
    loader = FilePolicyLoader(root)
    monkeypatch.chdir(tmp_path)
    assert loader.policy_root == root.resolve()
    assert load_policy("apps/reviewer.yaml", loader=loader)["roles"] == ["reviewer"]


def test_direct_multicomponent_entry_is_not_double_prefixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _write_policy(tmp_path / "policies" / "child.yaml")
    monkeypatch.chdir(tmp_path)
    assert load_policy(str(entry.relative_to(tmp_path)))["roles"] == ["reviewer"]


def test_explicit_entry_traversal_is_rejected_before_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    loader = FilePolicyLoader(root)
    original_stat = Path.stat

    def guarded_stat(path: Path, *args: object, **kwargs: object):
        if path == outside:
            raise AssertionError("outside metadata was inspected")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", guarded_stat)
    with pytest.raises(PolicyLoadError) as caught:
        load_policy("../outside.yaml", loader=loader)
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
    assert str(caught.value) == "Policy path is outside the configured policy root"
```

- [ ] **Step 2: Run the constructor and entry tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_containment.py -k 'requires_existing_directory_root or root_relative_after_chdir or multicomponent or traversal'
```

Expected: failures show that `FilePolicyLoader()` is currently accepted, explicit references still use CWD, and containment is not implemented.

- [ ] **Step 3: Add the stable error code and root-bound loader data types**

Change the error constructor and add the private prepared-source record. The mapping stored in the record must be a deep-detached `dict`, not an alias accepted from a caller:

```python
class PolicyLoadError(GovernanceViolationError):
    """Raised when policy loading/parsing fails."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "POLICY_LOAD_ERROR",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)
```

```python
from dataclasses import dataclass
from pathlib import Path, PurePath


@dataclass(frozen=True, slots=True)
class _PreparedFilePolicy:
    authority_token: object
    source_path: Path
    raw_policy: dict[str, Any]


_OUTSIDE_ROOT_MESSAGE = "Policy path is outside the configured policy root"


class FilePolicyLoader(PolicyLoaderBase):
    def __init__(self, policy_root: str | Path) -> None:
        try:
            canonical_root = Path(policy_root).resolve(strict=True)
            is_directory = canonical_root.is_dir()
        except (OSError, RuntimeError):
            canonical_root = Path(".")
            is_directory = False
        if not is_directory:
            raise PolicyLoadError("Configured policy root is unavailable") from None
        self._policy_root = canonical_root
        self._authority_token = object()

    @property
    def policy_root(self) -> Path:
        return self._policy_root
```

Do not land the constructor change while `_default_loader = FilePolicyLoader()` or any
`load_policy()` reference to that singleton remains. Step 4 replaces the singleton and
its callers in the same edit, so this task stays importable and testable at every commit.

- [ ] **Step 4: Implement canonical candidate resolution and prepared loading**

Use one private preflight for both entries and inherited sources. Containment must precede suffix/existence/type/open checks, and every exception created inside a handler must be raised after leaving that handler:

```python
def _is_contained(candidate: PurePath, root: PurePath) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


class FilePolicyLoader(PolicyLoaderBase):
    def _canonicalize(self, lexical: Path) -> Path:
        """Small test seam for platform canonicalization; performs no validation."""
        return lexical.resolve(strict=False)

    def _canonical_candidate(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
    ) -> Path:
        ref = Path(policy_ref)
        base = self._policy_root if relative_to is None else relative_to.parent
        lexical = ref if ref.is_absolute() else base / ref
        resolution_failed = False
        try:
            candidate = self._canonicalize(lexical)
        except (OSError, RuntimeError):
            resolution_failed = True
            candidate = self._policy_root
        if resolution_failed:
            raise PolicyLoadError("Policy path could not be resolved") from None
        if not _is_contained(candidate, self._policy_root):
            raise PolicyLoadError(
                _OUTSIDE_ROOT_MESSAGE,
                code="POLICY_PATH_OUTSIDE_ROOT",
            ) from None
        return candidate

    def _prepare(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
        reject_paths: set[Path] | None = None,
    ) -> _PreparedFilePolicy:
        candidate = self._canonical_candidate(policy_ref, relative_to=relative_to)
        if reject_paths is not None and candidate in reject_paths:
            raise PolicyLoadError("Circular policy inheritance detected")
        self._validate_candidate(candidate)
        parse_failed = False
        parsed: object = None
        try:
            with candidate.open("r", encoding="utf-8") as file_obj:
                parsed = yaml.safe_load(file_obj)
        except (OSError, yaml.YAMLError):
            parse_failed = True
        if parse_failed:
            raise PolicyLoadError("Policy YAML parsing failed") from None
        if not isinstance(parsed, dict):
            raise PolicyLoadError("Policy root must be a mapping object")
        return _PreparedFilePolicy(
            authority_token=self._authority_token,
            source_path=candidate,
            raw_policy=copy.deepcopy(parsed),
        )

    def _validate_candidate(self, candidate: Path) -> None:
        if candidate.suffix.lower() not in {".yaml", ".yml"}:
            raise PolicyLoadError("Policy file must be YAML")
        if not candidate.exists():
            raise PolicyLoadError("Policy file does not exist")
        if not candidate.is_file():
            raise PolicyLoadError("Policy path must reference a file")

    def _preflight(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
    ) -> Path:
        candidate = self._canonical_candidate(policy_ref, relative_to=relative_to)
        self._validate_candidate(candidate)
        return candidate

    def _accept_prepared(self, prepared: _PreparedFilePolicy) -> None:
        if prepared.authority_token is not self._authority_token:
            raise PolicyLoadError("Prepared policy authority does not match loader")

    def load(self, policy_ref: str) -> dict[str, Any]:
        return copy.deepcopy(self._prepare(policy_ref).raw_policy)
```

Implement direct binding exactly once and return the spelling that must be passed to the selected loader:

```python
def _bind_policy_authority(
    policy_file: str,
    loader: PolicyLoaderBase | None,
) -> tuple[str, PolicyLoaderBase]:
    if loader is not None:
        return policy_file, loader
    failure: PolicyLoadError | None = None
    try:
        captured_cwd = Path.cwd()
        lexical_entry = Path(policy_file)
        if not lexical_entry.is_absolute():
            lexical_entry = captured_cwd / lexical_entry
        root = lexical_entry.parent.resolve(strict=False)
    except (OSError, RuntimeError):
        lexical_entry = Path("policy.yaml")
        root = Path(".")
        failure = PolicyLoadError("Policy path could not be resolved")
    if failure is not None:
        raise failure from None
    return str(lexical_entry), FilePolicyLoader(root)
```

In this same edit, delete `_default_loader` and make `load_policy()` call
`_bind_policy_authority()` before any filesystem operation. Thread the returned
`effective_loader` through the existing `_resolve_extends()` recursion as a required
keyword-only argument; resolve every parent with
`effective_loader._prepare(extends, relative_to=policy_path, reject_paths=visited)`.
Recurse on `copy.deepcopy(parent.raw_policy)` and `parent.source_path` with the same
loader and the updated visited set, then retain the existing merge/restriction code.
Do not call public `load_policy()` recursively. This is the minimum coordinated rewrite
that makes the constructor change safe; Task 2 moves the recursion into the final
single-prepare graph orchestrator and adds early schema/confidentiality handling.

- [ ] **Step 5: Add symlink and canonical-inside tests**

Add real-filesystem tests for an entry symlink outside, a directory symlink outside, an in-root symlink, an explicit root that is itself a symlink, and `subdirectory/../base.yaml`. Use this helper so unsupported accounts skip only symlink cases:

```python
def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable for test account: {exc}")


def test_entry_symlink_cannot_redefine_implicit_root(tmp_path: Path) -> None:
    outside = _write_policy(tmp_path / "outside" / "policy.yaml")
    lexical_dir = tmp_path / "inside"
    lexical_dir.mkdir()
    entry = lexical_dir / "entry.yaml"
    _symlink_or_skip(entry, outside)
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(str(entry))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_in_root_symlink_target_is_allowed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    target = _write_policy(root / "real.yaml")
    link = root / "link.yaml"
    _symlink_or_skip(link, target)
    assert load_policy("link.yaml", loader=FilePolicyLoader(root))["roles"] == ["reviewer"]


```

Add explicit tests that relative and absolute spellings of the same entry receive the
same canonical root and that an absolute entry outside an explicit root fails before
open. Do not import or test `_is_contained` directly here; all assertions cross the
public loader boundary. Task 2 owns malformed-`extends` and Windows different-drive
coverage because those behaviors depend on the final graph resolver.

- [ ] **Step 6: Run the complete entry-boundary tests to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_containment.py tests/test_policy_loader.py tests/test_pluggable_loader.py
```

Expected: all selected entry-boundary tests pass; the module imports without a
no-argument singleton, and existing no-argument `FilePolicyLoader()` uses have been
migrated to explicit temp roots. Task 2 graph tests are not added until after this
commit, so Task 1 does not knowingly commit a failing test.

- [ ] **Step 7: Commit the root-bound loader**

```bash
git add aegis/_internal/errors.py aegis/_internal/policy_loader.py tests/test_policy_root_containment.py tests/test_policy_loader.py tests/test_pluggable_loader.py
git commit -m "fix: bind file policy loads to canonical roots"
```

### Task 2: Prepared composition, compiler orchestration, async binding, and path-free errors

**Files:**
- Modify: `aegis/_internal/policy_loader.py:731-951`
- Modify: `schemas/policy_dsl.schema.json:7-10`
- Modify: `aegis/schemas/policy_dsl.schema.json:7-10`
- Modify: `tests/test_policy_root_containment.py`
- Modify: `tests/test_golden_replay_composition.py`
- Modify: `tests/test_policy_composition.py`
- Modify: `tests/test_a1_final_fix_wave_2.py:360-410`
- Modify: `tests/test_architecture_security_boundaries.py:250-330,470-700`

**Interfaces:**
- Consumes: `FilePolicyLoader._prepare()`, `FilePolicyLoader._accept_prepared()`, `_bind_policy_authority()`, `compile_policy()`, and the existing validation `clock`.
- Produces: `_resolve_file_graph(prepared: _PreparedFilePolicy, *, loader: FilePolicyLoader, visited: set[Path], context: _FileLoadContext, clock: Callable[[], date] | None, capture_date_failures: bool = False) -> dict[str, Any]`, `_PreparedCompilationResult`, `_prepare_resolve_compile_policy(...) -> _PreparedCompilationResult`, the same public arguments on `load_resolve_compile_policy() -> CompiledPolicy`, and synchronous `load_policy_async(policy_file: str, visited: set[Path] | None = None, *, loader: PolicyLoaderBase | None = None) -> Awaitable[dict[str, Any]]`.

- [ ] **Step 1: Add failing graph and precedence tests**

Cover in-root multi-level composition, transitive traversal/absolute/symlink escape, valid in-root cycle, containment-before-cycle/missing, absolute in-root parent success, and custom-loader `extends` key presence. The custom loader test must prove that malformed `extends` causes no `Path.resolve`, `exists`, `is_file`, `stat`, or `open` call:

```python
class ExtendingOpaqueLoader(PolicyLoaderBase):
    def __init__(self, extends: object) -> None:
        self.extends = extends
        self.calls: list[str] = []

    def load(self, policy_ref: str) -> dict[str, object]:
        self.calls.append(policy_ref)
        return {"policy_version": "1.0", "roles": ["reviewer"], "extends": self.extends}


@pytest.mark.parametrize("extends", [None, False, 7, {}, [], ""])
def test_custom_loader_rejects_any_extends_without_filesystem(
    monkeypatch: pytest.MonkeyPatch, extends: object
) -> None:
    loader = ExtendingOpaqueLoader(extends)
    monkeypatch.setattr(Path, "resolve", lambda *args, **kwargs: pytest.fail("filesystem used"))
    with pytest.raises(PolicyLoadError, match="not supported with custom loaders"):
        load_policy("opaque-id", loader=loader)
    assert loader.calls == ["opaque-id"]


def test_transitive_child_cannot_widen_original_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _write_policy(tmp_path / "outside.yaml")
    _write_policy(root / "base.yaml", "extends: ../outside.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n")
    entry = _write_policy(root / "nested" / "entry.yaml", "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n")
    with pytest.raises(PolicyLoadError) as caught:
        load_policy(str(entry), loader=FilePolicyLoader(root))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


@pytest.mark.parametrize("extends", [None, True, 3, {}, [], ""])
def test_file_loader_rejects_malformed_extends_before_path_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extends: object
) -> None:
    entry = _write_policy(
        tmp_path / "entry.yaml",
        yaml.safe_dump({
            "policy_version": "1.0",
            "roles": ["reviewer"],
            "extends": extends,
        }),
    )
    loader = FilePolicyLoader(tmp_path)
    prepared = loader._prepare(entry.name, context=_FileLoadContext.create(entry.name))
    monkeypatch.setattr(
        loader,
        "_canonical_candidate",
        lambda *args, **kwargs: pytest.fail("malformed extends reached path work"),
    )
    with pytest.raises(PolicyValidationError) as caught:
        _resolve_file_graph(prepared, loader=loader, visited=set(), context=_FileLoadContext.create())
    assert caught.value.code == "POLICY_SCHEMA_VALIDATION_ERROR"
    assert caught.value.details == {"path": "$.extends"}


@pytest.mark.skipif(os.name != "nt", reason="Windows drive semantics")
def test_windows_different_drive_entry_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loader = FilePolicyLoader(tmp_path)
    foreign_drive = "Z:" if tmp_path.drive.upper() != "Z:" else "Y:"
    foreign = Path(foreign_drive + r"\outside\policy.yaml")
    monkeypatch.setattr(loader, "_canonicalize", lambda lexical: foreign)
    with pytest.raises(PolicyLoadError) as caught:
        loader.load(str(foreign))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
```

Import `os`, `yaml`, `PolicyValidationError`, `_FileLoadContext`, and
`_resolve_file_graph` for these tests. Add `"minLength": 1` beside
`"type": "string"` in both schema copies. The `_canonicalize()` seam performs only
canonicalization; `_canonical_candidate()` owns the subsequent containment check.

- [ ] **Step 2: Run graph tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_containment.py -k 'transitive or cycle or custom_loader or absolute_extends or malformed_extends or different_drive'
```

Expected: recursive loads derive new authority or touch the filesystem, malformed
`extends` reaches path construction, and cycle text leaks canonical paths. The Windows
case participates on Windows and is platform-skipped elsewhere; it is not skipped for
missing secondary drives because it uses the canonicalization seam.

- [ ] **Step 3: Resolve inheritance only through loader-minted prepared sources**

Validate the `extends` key before candidate construction, check the loader token at every consumer, preserve one visited set, and use `prepared.source_path` only internally:

Extend `_canonical_candidate()`, `_preflight()`, and `_prepare()` with a required
keyword-only `context: _FileLoadContext`. `_canonical_candidate()` records the lexical
reference and canonical candidate with `context.protect()`; `_prepare()` records valid
`extends` spellings before resolving them. Update every Task 1 call site to create one
context at the public entry and pass that exact object through recursion. No loader
method constructs a second context mid-graph. `FilePolicyLoader.load()` creates
`_FileLoadContext.create(policy_ref, self.policy_root)` and passes it to `_prepare()`;
`load_policy()` and the compiler orchestrator create their context before calling any
loader method.

```python
def _validated_extends(policy: dict[str, Any]) -> str | None:
    if "extends" not in policy:
        return None
    extends = policy["extends"]
    if not isinstance(extends, str) or not extends:
        raise PolicyValidationError(
            "Policy schema validation failed at $.extends",
            details={"path": "$.extends"},
        )
    return extends


def _resolve_file_graph(
    prepared: _PreparedFilePolicy,
    *,
    loader: FilePolicyLoader,
    visited: set[Path],
    context: _FileLoadContext,
    clock: Callable[[], date] | None = None,
    capture_date_failures: bool = False,
) -> dict[str, Any]:
    loader._accept_prepared(prepared)
    if prepared.source_path in visited:
        raise PolicyLoadError("Circular policy inheritance detected")
    next_visited = {*visited, prepared.source_path}
    policy = copy.deepcopy(prepared.raw_policy)
    extends = _validated_extends(policy)
    if extends is None:
        return _validate_policy_mapping(
            policy,
            context=context,
            clock=clock,
            capture_date_failures=capture_date_failures,
        )
    parent = loader._prepare(
        extends,
        relative_to=prepared.source_path,
        reject_paths=next_visited,
        context=context,
    )
    base = _resolve_file_graph(
        parent,
        loader=loader,
        visited=next_visited,
        context=context,
        clock=clock,
        capture_date_failures=capture_date_failures,
    )
    strategy = _validate_composition_strategy(policy.get("composition_strategy"))
    merged = _merge_policies(base, policy, strategy)
    _compile_and_compare_composition(base, policy, merged)
    merged.pop("extends", None)
    merged.pop("composition_strategy", None)
    return _validate_policy_mapping(
        merged,
        context=context,
        clock=clock,
        capture_date_failures=capture_date_failures,
    )
```

Define every helper introduced by the graph in this task; do not leave pseudocode calls
for later tasks:

```python
def _validate_composition_strategy(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in VALID_COMPOSITION_STRATEGIES:
        raise PolicyValidationError(
            "Invalid policy composition strategy",
            details={"composition_strategy": value},
        )
    return value


def _validate_policy_mapping(
    policy: dict[str, Any],
    *,
    context: _FileLoadContext,
    clock: Callable[[], date] | None,
    capture_date_failures: bool = False,
) -> dict[str, Any]:
    """Run the existing Draft-07 schema and date checks on a detached mapping."""
    failure: PolicyLoadError | PolicyValidationError | None = None
    schema: dict[str, Any] | None = None
    try:
        schema_path = _resolve_policy_schema_path()
        context.protect(schema_path)
        with schema_path.open("r", encoding="utf-8") as schema_file:
            loaded_schema = json.load(schema_file)
        if not isinstance(loaded_schema, dict):
            raise PolicyLoadError("Policy schema root must be an object")
        if loaded_schema.get("$schema") != POLICY_SCHEMA_DRAFT_07:
            raise PolicyLoadError("Policy schema must declare JSON Schema Draft-07")
        Draft7Validator.check_schema(loaded_schema)
        schema = loaded_schema
    except (OSError, json.JSONDecodeError, SchemaError, PolicyLoadError) as exc:
        failure = context.normalize(exc, fallback="Policy schema validation failed")
    if failure is not None:
        raise failure from None
    assert schema is not None

    validator = Draft7Validator(schema)
    errors = sorted(
        validator.iter_errors(policy),
        key=lambda error: _path_to_pointer(list(error.absolute_path)),
    )
    if errors:
        first = errors[0]
        pointer = _path_to_pointer(list(first.absolute_path))
        raise PolicyValidationError(
            f"Policy schema validation failed at {pointer}",
            code="POLICY_SCHEMA_VALIDATION_ERROR",
            details={"path": pointer, "validator": first.validator},
        ) from None

    try:
        validate_policy_dates(policy, clock=clock)
    except PolicyValidationError as exc:
        failure = context.normalize(exc, fallback="Policy date validation failed")
    if failure is not None:
        if capture_date_failures and isinstance(failure, PolicyValidationError):
            context.record_date_failure(failure)
        else:
            raise failure from None
    return copy.deepcopy(policy)


def _load_opaque_policy(
    policy_ref: str,
    loader: PolicyLoaderBase,
    *,
    clock: Callable[[], date] | None,
) -> dict[str, Any]:
    """Call a custom loader once, reject key presence of extends, then validate."""
    failure: PolicyLoadError | None = None
    try:
        loaded = loader.load(policy_ref)
    except Exception:
        loaded = None
        failure = PolicyLoadError("Custom policy loader failed")
    if failure is not None:
        raise failure from None
    if not isinstance(loaded, dict):
        raise PolicyLoadError("Policy root must be a mapping object")
    if "extends" in loaded:
        raise PolicyLoadError("Policy 'extends' is not supported with custom loaders")
    return _validate_policy_mapping(
        copy.deepcopy(loaded),
        context=_FileLoadContext.create(),
        clock=clock,
    )
```

Import `SchemaError` from `jsonschema.exceptions`. Delete the old inline validation
block after moving it. Schema-loading errors must not include schema paths.
Custom-loader normalization must construct the replacement after leaving the handler
and raise it with `from None`.

- [ ] **Step 4: Add failing prepared-source and compiler-boundary tests**

Assert that two loaders with the same canonical root still have distinct tokens; `_resolve_file_graph` rejects a source minted by the other loader. Assert the public compiler has no `parsed_policy` parameter, a fake mapping cannot bypass file loading, and a custom loader is invoked exactly once:

```python
def test_prepared_source_is_bound_to_exact_loader_instance(tmp_path: Path) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    first = FilePolicyLoader(tmp_path)
    second = FilePolicyLoader(tmp_path)
    prepared = first._prepare(entry.name, context=_FileLoadContext.create(entry.name))
    with pytest.raises(PolicyLoadError, match="authority does not match loader"):
        _resolve_file_graph(
            prepared,
            loader=second,
            visited=set(),
            context=_FileLoadContext.create(),
            clock=None,
        )


def test_compiler_boundary_has_no_parsed_policy_fast_path(tmp_path: Path) -> None:
    entry = _write_policy(tmp_path / "entry.yaml")
    with pytest.raises(TypeError):
        load_resolve_compile_policy(
            str(entry),
            parsed_policy={"policy_version": "forged"},  # type: ignore[call-arg]
        )
```

- [ ] **Step 5: Implement the single prepare/resolve/compile orchestrator**

Keep `_PreparedFilePolicy` private and return it only to internal diagnostics. The
private `capture_date_failures` mode exists solely so doctor can report date findings
and continue safe linting; public runtime callers retain fail-fast behavior:

```python
@dataclass(frozen=True, slots=True)
class _PreparedCompilationResult:
    prepared: _PreparedFilePolicy | None
    compiled: CompiledPolicy
    date_failures: tuple[PolicyValidationError, ...]


def _prepare_resolve_compile_policy(
    policy_file: str,
    *,
    loader: PolicyLoaderBase | None = None,
    clock: Callable[[], date] | None = None,
    allow_legacy: bool = False,
    legacy_authorization: object | None = None,
    capture_date_failures: bool = False,
) -> _PreparedCompilationResult:
    bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
    context = _FileLoadContext.create(policy_file, bound_ref)
    if isinstance(effective_loader, FilePolicyLoader):
        context.protect(effective_loader.policy_root)
        prepared = effective_loader._prepare(bound_ref, context=context)
        graph_failure: PolicyLoadError | PolicyValidationError | None = None
        try:
            policy = _resolve_file_graph(
                prepared,
                loader=effective_loader,
                visited=set(),
                context=context,
                clock=clock,
                capture_date_failures=capture_date_failures,
            )
        except (PolicyLoadError, PolicyValidationError) as exc:
            policy = None
            graph_failure = context.normalize(exc, fallback="Policy validation failed")
        if graph_failure is not None:
            raise graph_failure from None
        assert policy is not None
    else:
        prepared = None
        policy = _load_opaque_policy(bound_ref, effective_loader, clock=clock)
    failure: PolicyLoadError | PolicyValidationError | None = None
    try:
        compiled = compile_policy(
            policy,
            source="policy",
            allow_legacy=allow_legacy,
            legacy_authorization=legacy_authorization,
        )
    except (PolicyLoadError, PolicyValidationError) as exc:
        compiled = None
        failure = context.normalize(exc, fallback="Policy compilation failed")
    if failure is not None:
        raise failure from None
    assert compiled is not None
    return _PreparedCompilationResult(
        prepared=prepared,
        compiled=compiled,
        date_failures=tuple(context.date_failures),
    )


def load_resolve_compile_policy(
    policy_file: str,
    *,
    loader: PolicyLoaderBase | None = None,
    clock: Callable[[], date] | None = None,
    allow_legacy: bool = False,
    legacy_authorization: object | None = None,
) -> CompiledPolicy:
    result = _prepare_resolve_compile_policy(
        policy_file,
        loader=loader,
        clock=clock,
        allow_legacy=allow_legacy,
        legacy_authorization=legacy_authorization,
    )
    return result.compiled
```

Make `load_policy()` use the same binding and graph functions and retain its existing return type.

- [ ] **Step 6: Add failing async bind-before-return test**

The test must call the factory, change CWD, then await; it must also monkeypatch `asyncio.to_thread` to observe the exact loader identity passed to the worker:

```python
@pytest.mark.asyncio
async def test_async_implicit_authority_binds_before_await(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = tmp_path / "original"
    other = tmp_path / "other"
    _write_policy(original / "policies" / "entry.yaml")
    _write_policy(other / "policies" / "entry.yaml", "policy_version: '2.0'\nroles: [reviewer]\n")
    monkeypatch.chdir(original)
    pending = load_policy_async("policies/entry.yaml")
    monkeypatch.chdir(other)
    loaded = await pending
    assert loaded["policy_version"] == "1.0"
```

- [ ] **Step 7: Convert `load_policy_async` into a synchronous awaitable factory**

```python
async def _load_policy_async_runner(
    policy_file: str,
    visited: set[Path] | None,
    loader: PolicyLoaderBase,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        load_policy,
        policy_file,
        visited,
        loader=loader,
    )


def load_policy_async(
    policy_file: str,
    visited: set[Path] | None = None,
    *,
    loader: PolicyLoaderBase | None = None,
) -> Awaitable[dict[str, Any]]:
    bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
    return _load_policy_async_runner(bound_ref, visited, effective_loader)
```

- [ ] **Step 8: Add exhaustive public error-confidentiality assertions**

Use one reusable assertion against containment, self-cycle, missing inherited target, non-file target, malformed YAML, schema failure, composition failure, and symlink loop. The assertion must inspect `message`, recursively inspect `details`, walk `__cause__` and `__context__`, and inspect `traceback.format_exception()`:

```python
def _assert_path_confidential(exc: BaseException, protected: list[str]) -> None:
    chain_text = "".join(traceback.format_exception(exc))
    values = [str(exc), repr(getattr(exc, "details", None)), chain_text]
    cursor: BaseException | None = exc
    while cursor is not None:
        values.extend([str(cursor), repr(getattr(cursor, "details", None))])
        cursor = cursor.__cause__ or cursor.__context__
    for secret in protected:
        assert secret not in "\n".join(values)
```

Update old cycle assertions to require `Circular policy inheritance detected` and no path-bearing details. Add the same helper assertions at lint/CLI, doctor, retry, and module/AEGIS enforcement surfaces in their owning tasks.

- [ ] **Step 9: Normalize every file-backed error outside active handlers**

Use an explicit per-load context. It records protected values for testing, accumulates
diagnostic-only date failures, and reconstructs public errors from an allowlist. It
never copies arbitrary exception text, dictionary keys, or values, so a one-character
path cannot trigger fragile substring redaction:

```python
_SAFE_DETAIL_KEYS = frozenset({
    "path", "validator", "composition_strategy",
    "effective_date", "expiration_date", "today", "line", "column",
})

_STABLE_FILE_MESSAGES = frozenset({
    "Configured policy root is unavailable",
    "Policy path could not be resolved",
    "Policy file must be YAML",
    "Policy file does not exist",
    "Policy path must reference a file",
    "Policy YAML parsing failed",
    "Policy root must be a mapping object",
    "Policy schema validation failed",
    "Policy compilation failed",
})


@dataclass(slots=True)
class _FileLoadContext:
    protected: set[str]
    date_failures: list[PolicyValidationError]

    @classmethod
    def create(cls, *values: object) -> "_FileLoadContext":
        context = cls(protected=set(), date_failures=[])
        for value in values:
            context.protect(value)
        return context

    def protect(self, value: object) -> None:
        text = os.fspath(value) if isinstance(value, os.PathLike) else str(value)
        if text:
            self.protected.add(text)

    def record_date_failure(self, failure: PolicyValidationError) -> None:
        fingerprint = (failure.code, repr(failure.details))
        if all(
            (existing.code, repr(existing.details)) != fingerprint
            for existing in self.date_failures
        ):
            self.date_failures.append(failure)

    def normalize(
        self,
        exc: BaseException,
        *,
        fallback: str,
    ) -> PolicyLoadError | PolicyValidationError:
        code = getattr(exc, "code", "POLICY_LOAD_ERROR")
        original = getattr(exc, "details", None)
        safe_details = (
            {
                key: value
                for key, value in original.items()
                if key in _SAFE_DETAIL_KEYS
                and isinstance(value, (str, int, float, bool, type(None)))
                and str(value) not in self.protected
            }
            if isinstance(original, dict)
            else None
        )
        if code == "POLICY_PATH_OUTSIDE_ROOT":
            return PolicyLoadError(_OUTSIDE_ROOT_MESSAGE, code=code)
        if isinstance(exc, PolicyLoadError) and str(exc) == "Circular policy inheritance detected":
            return PolicyLoadError("Circular policy inheritance detected", code=code)
        if isinstance(exc, PolicyLoadError) and str(exc) in _STABLE_FILE_MESSAGES:
            return PolicyLoadError(str(exc), code=code, details=safe_details)
        if "composition_strategy" in (safe_details or {}):
            return PolicyValidationError(
                "Invalid policy composition strategy",
                code=code,
                details=safe_details,
            )
        if code == "POLICY_WIDENING":
            return PolicyValidationError(
                "Policy composition would widen authority",
                code=code,
                details=safe_details,
            )
        if any(
            key in (safe_details or {})
            for key in ("effective_date", "expiration_date", "today")
        ):
            return PolicyValidationError(
                "Policy date validation failed",
                code=code,
                details=safe_details,
            )
        if code == "POLICY_SCHEMA_VALIDATION_ERROR":
            pointer = (safe_details or {}).get("path", "$")
            return PolicyValidationError(
                f"Policy schema validation failed at {pointer}",
                code=code,
                details=safe_details,
            )
        if isinstance(exc, PolicyValidationError):
            return PolicyValidationError(fallback, code=code, details=safe_details)
        return PolicyLoadError(fallback, code=code, details=safe_details)
```

Call `context.protect()` for the caller spelling, bound spelling, root, every canonical
candidate, every valid `extends`, visited paths, and both schema locations. Preserve
the exact containment and cycle messages by constructing them directly. Wrap every
filesystem operation—including `resolve`, `exists`, `is_file`, `stat`, and `open`—and
every YAML/schema/composition/compiler/date boundary. Catch the documented expected
exceptions plus `OSError`/`RuntimeError`, normalize after leaving the handler, and raise
the detached replacement with `from None`:

```python
failure: PolicyLoadError | PolicyValidationError | None = None
try:
    result = operation()
except (OSError, RuntimeError, PolicyLoadError, PolicyValidationError) as exc:
    failure = context.normalize(exc, fallback="Policy validation failed")
if failure is not None:
    raise failure from None
return result
```

The concrete loader methods use narrower expected exception tuples where available
(`yaml.YAMLError`, `json.JSONDecodeError`, `SchemaError`) but must always include raw
filesystem failures. When catching `yaml.MarkedYAMLError`, copy only one-based
`problem_mark.line`/`column` integers into the normalized details so safe parser
location evidence remains available. The confidentiality tests include protected
values as dictionary keys and nested values to prove the allowlist does not miss either
location.

In particular, rewrite `_validate_candidate()` so `exists()` and `is_file()` execute in
one `try`, store either their booleans or a normalized `PolicyLoadError`, leave the
handler, and only then raise `from None`. Apply the same detached pattern to root
`is_dir()`, cache `stat()`, candidate `open()`, and schema `open()`. No `OSError` from a
file-backed public surface may bypass `_FileLoadContext.normalize()`.

- [ ] **Step 10: Run composition, compiler, async, and architecture tests**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_containment.py tests/test_policy_loader.py tests/test_golden_replay_composition.py tests/test_policy_composition.py tests/test_a1_final_fix_wave_2.py tests/test_architecture_security_boundaries.py
```

Expected: all tests pass; no caller-supplied parsed mapping remains; custom loaders never enter `_PreparedFilePolicy` handling.

- [ ] **Step 11: Commit prepared composition and async binding**

```bash
git add aegis/_internal/policy_loader.py schemas/policy_dsl.schema.json aegis/schemas/policy_dsl.schema.json tests/test_policy_root_containment.py tests/test_policy_loader.py tests/test_golden_replay_composition.py tests/test_policy_composition.py tests/test_a1_final_fix_wave_2.py tests/test_architecture_security_boundaries.py
git commit -m "fix: retain policy authority through composition"
```

### Task 3: Root-isolated cache and AEGIS instance/session propagation

**Files:**
- Create: `tests/test_policy_root_entry_points.py`
- Modify: `aegis/_internal/policy_loader.py:953-1050`
- Modify: `aegis/_internal/enforcement.py:2186-2850`
- Modify: `tests/test_policy_loader.py:173-245`
- Modify: `tests/test_pluggable_loader_runtime.py`
- Modify: `tests/test_enforcement_compiled_policy_boundary.py`

**Interfaces:**
- Consumes: `_bind_policy_authority()`, `FilePolicyLoader._canonical_candidate()`, `FilePolicyLoader._prepare()`, and `load_policy(policy_file, visited, loader=effective_loader)`.
- Produces: file cache keys `(canonical_root: str, canonical_entry: str, mtime: float)` and unchanged opaque-loader cache keys `(policy_ref: str, 0.0)`; AEGIS continues to accept `policy_loader: PolicyLoaderBase | None`.

- [ ] **Step 1: Add failing cache isolation and preflight-order tests**

Start `tests/test_policy_root_entry_points.py` with concrete shared helpers so later
tasks do not rely on undefined fixtures:

```python
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


def _policy_tree_and_invocation(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "root"
    _write_policy(root / "base.yaml")
    _write_policy(
        root / "nested" / "entry.yaml",
        "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    return root, _valid_invocation("nested/entry.yaml")
```

Use the same canonical entry under a broad and narrow root. First cache a successful broad-root graph, then request it with the narrow loader and assert containment rather than a cache hit. Instrument `_preflight`, `Path.stat`, and the cache mapping itself to prove neither metadata nor cache lookup happens before containment:

```python
def test_cache_key_isolated_by_authority_root(tmp_path: Path) -> None:
    broad = tmp_path / "broad"
    narrow = broad / "narrow"
    _write_policy(broad / "base.yaml")
    _write_policy(narrow / "entry.yaml", "extends: ../base.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n")
    cache = PolicyCache()
    cache.get_or_load("narrow/entry.yaml", loader=FilePolicyLoader(broad))
    with pytest.raises(PolicyLoadError) as caught:
        cache.get_or_load("entry.yaml", loader=FilePolicyLoader(narrow))
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"


def test_cache_does_not_read_mtime_before_containment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    monkeypatch.setattr(Path, "stat", lambda *args, **kwargs: pytest.fail("mtime read"))
    monkeypatch.setattr(
        loader,
        "_preflight",
        lambda ref, **kwargs: (_ for _ in ()).throw(PolicyLoadError(
            "Policy path is outside the configured policy root",
            code="POLICY_PATH_OUTSIDE_ROOT",
        )),
    )
    with pytest.raises(PolicyLoadError) as caught:
        cache.get_or_load("../outside.yaml", loader=loader)
    assert caught.value.code == "POLICY_PATH_OUTSIDE_ROOT"
```

- [ ] **Step 2: Run cache tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py -k cache
```

Expected: the file cache key lacks the authority root or performs old global path resolution.

- [ ] **Step 3: Implement strict file cache preflight and three-part identity**

Bind the implicit loader once, resolve and contain through that loader, validate suffix/existence/type through `_prepare`'s shared preflight helper, then obtain mtime and consult the cache:

```python
bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
if isinstance(effective_loader, FilePolicyLoader):
    context = _FileLoadContext.create(policy_file, bound_ref, effective_loader.policy_root)
    canonical = effective_loader._preflight(bound_ref, context=context)
    metadata_failure: PolicyLoadError | None = None
    try:
        mtime = canonical.stat().st_mtime
    except (OSError, RuntimeError) as exc:
        mtime = 0.0
        normalized = context.normalize(exc, fallback="Policy metadata is unavailable")
        metadata_failure = (
            normalized
            if isinstance(normalized, PolicyLoadError)
            else PolicyLoadError("Policy metadata is unavailable")
        )
    if metadata_failure is not None:
        raise metadata_failure from None
    key = (
        str(effective_loader.policy_root),
        str(canonical),
        mtime,
    )
else:
    key = (policy_file, 0.0)
```

Use cache-key aliases that preserve numeric mtime:

```python
_FileCacheKey = tuple[str, str, float]
_OpaqueCacheKey = tuple[str, float]
_PolicyCacheKey = _FileCacheKey | _OpaqueCacheKey
```

Pass `bound_ref` and `effective_loader` to `load_policy()` on a miss; never rebind after preflight.

- [ ] **Step 4: Add AEGIS sync/async/cache/session authority tests**

Instantiate `AEGIS(sink=CallbackAuditSink(emitted.append), policy_loader=FilePolicyLoader(root))` and exercise `enforce`, `enforce_async`, `enforce_pre_call`, `enforce_pre_call_async`, cached enforcement, `open_session`, and async session paths with a graph whose parent is valid only under the explicit root. Add escape variants and assert `POLICY_PATH_OUTSIDE_ROOT` reaches audit-facing failures without any protected path in the exception chain.

```python
@pytest.mark.parametrize("method_name", ["enforce", "enforce_pre_call"])
def test_aegis_instance_uses_configured_root(
    tmp_path: Path, method_name: str
) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    emitted: list[dict[str, object]] = []
    engine = AEGIS(
        sink=CallbackAuditSink(emitted.append),
        policy_loader=FilePolicyLoader(root),
    )
    result = getattr(engine, method_name)(invocation)
    assert result is not None
```

- [ ] **Step 5: Run cache and instance regression tests to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_policy_loader.py tests/test_pluggable_loader_runtime.py tests/test_enforcement_compiled_policy_boundary.py -k 'cache or aegis or policy_loader'
```

Expected: all selected tests pass; the custom-loader cache behavior remains unchanged.

- [ ] **Step 6: Commit cache and instance propagation**

```bash
git add aegis/_internal/policy_loader.py aegis/_internal/enforcement.py tests/test_policy_root_entry_points.py tests/test_policy_loader.py tests/test_pluggable_loader_runtime.py tests/test_enforcement_compiled_policy_boundary.py
git commit -m "fix: isolate policy caches by authority root"
```

### Task 4: Prepared-source workflow diagnostics and starter containment

**Files:**
- Modify: `aegis/_internal/workflow_lint.py:465-750,980-1010`
- Modify: `aegis/_internal/workflow_doctor.py:305-520,786-820`
- Modify: `tests/test_policy_root_entry_points.py`
- Modify: `tests/test_workflow_lint.py`
- Modify: `tests/test_workflow_doctor.py`

**Interfaces:**
- Consumes: `_prepare_resolve_compile_policy()`, `_PreparedFilePolicy.raw_policy`, `FilePolicyLoader`, and injected `now: date | None`.
- Produces: `lint_policy(path, *, target_kind="policy", policy_root=None)`, `lint_starter_dir(path, *, policy_root=None)`, `lint_target(path, *, kind="auto", policy_root=None)`, `diagnose_workflow_policy(path, *, now=None, policy_root=None)`, `diagnose_starter_dir(path, *, policy_root=None)`, and `diagnose_target(path, *, kind="auto", now=None, policy_root=None)`.

- [ ] **Step 1: Add failing policy diagnostic source-binding tests**

Create same-named policies in CWD and the explicit root; monkeypatch `Path.read_text` to fail if the policy target is read directly. Assert lint and doctor use only the prepared mapping from the root, doctor prepares once, and its `now` is the clock used by semantic validation:

```python
def test_doctor_prepares_authorized_policy_once_with_injected_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "authorized"
    entry = _write_policy(
        root / "entry.yaml",
        "policy_version: '1.0'\neffective_date: '2030-01-01'\nroles: [reviewer]\n",
    )
    calls = 0
    original = policy_loader._prepare_resolve_compile_policy

    def counted(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(workflow_doctor, "_prepare_resolve_compile_policy", counted)
    findings = diagnose_workflow_policy(
        entry.name,
        policy_root=root,
        now=date(2029, 1, 1),
    )
    assert calls == 1
    assert any("not yet active" in finding["message"].lower() for finding in findings)
```

- [ ] **Step 2: Add failing starter-root tests**

Test these four cases with real directories: explicit-root starter succeeds; explicit-root starter-directory symlink outside is rejected before fixture detection; implicit starter roots nested policy at that starter and rejects `../sibling/policy.yaml`; explicit broader root permits the sibling graph.

```python
def _write_starter(directory: Path) -> Path:
    _write_policy(directory / "policy.yaml")
    (directory / "workflow_example.py").write_text("def run():\n    return None\n", encoding="utf-8")
    (directory / "README.md").write_text("# Starter\n", encoding="utf-8")
    return directory


def test_implicit_starter_cannot_inherit_from_sibling(tmp_path: Path) -> None:
    first = _write_starter(tmp_path / "starters" / "first")
    _write_starter(tmp_path / "starters" / "second")
    (first / "policy.yaml").write_text(
        "extends: ../second/policy.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
        encoding="utf-8",
    )
    findings = lint_starter_dir(str(first))
    assert findings[0]["code"] == "POLICY_PATH_OUTSIDE_ROOT"
```

- [ ] **Step 3: Run diagnostics tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py -k 'lint or doctor or starter'
```

Expected: current diagnostics pre-read policy content, do not accept roots, reopen in doctor, and implicitly authorize starter siblings.

- [ ] **Step 4: Split prepared policy linting from policy acquisition**

Replace file reading in `lint_policy()` with the orchestrator and move mapping-only lint rules into a private helper:

```python
def _lint_prepared_policy(
    prepared: _PreparedFilePolicy,
    compiled: CompiledPolicy,
    *,
    target_kind: str,
    target_label: str,
) -> list[dict]:
    policy = copy.deepcopy(prepared.raw_policy)
    findings: list[dict] = []
    effective = policy.get("effective_date")
    expiration = policy.get("expiration_date")
    if (
        "extends" not in policy
        and isinstance(effective, str)
        and isinstance(expiration, str)
        and effective > expiration
    ):
        findings.append(_finding(
            "POLICY_LOAD_ERROR",
            "effective_date is after expiration_date; policy can never be valid.",
            target_kind,
            target_label,
        ))
    workflow = _plain_compiled_value(compiled.workflow)
    if isinstance(workflow, dict):
        # Move the existing compiled-workflow advisory block from lint_policy()
        # here unchanged (step budget, transition/participant references,
        # unsupported protocols, then _lint_workflow_graph()).
        findings.extend(_lint_workflow_graph(
            workflow,
            target_kind=target_kind,
            path=Path(target_label),
        ))
    return findings


def _policy_exception_finding(
    exc: PolicyLoadError | PolicyValidationError,
    target_kind: str,
    target_label: str,
) -> dict:
    details = dict(exc.details) if isinstance(exc.details, dict) else {}
    return _finding(
        exc.code,
        str(exc),
        target_kind,
        target_label,
        details=details,
    )


def lint_policy(
    path: str,
    *,
    target_kind: str = "policy",
    policy_root: str | Path | None = None,
) -> list[dict]:
    loader = FilePolicyLoader(policy_root) if policy_root is not None else None
    try:
        result = _prepare_resolve_compile_policy(path, loader=loader)
    except (PolicyLoadError, PolicyValidationError) as exc:
        return [_policy_exception_finding(exc, target_kind, path)]
    if result.prepared is None:
        raise AssertionError("file diagnostics require a prepared source")
    return _lint_prepared_policy(
        result.prepared,
        result.compiled,
        target_kind=target_kind,
        target_label=path,
    )
```

The comment in `_lint_prepared_policy()` is a relocation instruction for the concrete
existing block at `workflow_lint.py:580-693`; it does not introduce a helper. Remove
the original block after moving it. The host-provided target spelling may remain in
finding `path`; exception text/details must remain sanitized.

- [ ] **Step 5: Bind starter directories before fixture inspection**

Add a helper that canonicalizes an implicit starter directory, validates it is a directory, and roots its nested policy there; with an explicit root, resolve and contain the starter candidate through the configured loader before calling `is_dir()`, `is_file()`, `stat()`, or reading workflow/README content:

```python
@dataclass(frozen=True, slots=True)
class _PreparedStarterTarget:
    directory: Path
    policy_ref: str
    loader: FilePolicyLoader


def _prepare_starter_target(
    path: str,
    *,
    policy_root: str | Path | None,
) -> _PreparedStarterTarget:
    failure: PolicyLoadError | None = None
    if policy_root is None:
        lexical = Path(path)
        if not lexical.is_absolute():
            lexical = Path.cwd() / lexical
        try:
            directory = lexical.resolve(strict=False)
            available = directory.is_dir()
        except (OSError, RuntimeError):
            directory = lexical
            available = False
        if not available:
            failure = PolicyLoadError("Workflow starter directory is unavailable")
        if failure is not None:
            raise failure from None
        loader = FilePolicyLoader(directory)
        return _PreparedStarterTarget(directory, str(directory / "policy.yaml"), loader)
    loader = FilePolicyLoader(policy_root)
    context = _FileLoadContext.create(path, loader.policy_root)
    directory = loader._canonical_candidate(path, context=context)
    try:
        available = directory.is_dir()
    except OSError:
        available = False
    if not available:
        failure = PolicyLoadError("Workflow starter directory is unavailable")
    if failure is not None:
        raise failure from None
    return _PreparedStarterTarget(directory, str(directory / "policy.yaml"), loader)
```

`lint_starter_dir()` passes `prepared.policy_ref` and `prepared.loader` to the shared orchestrator; `detect_target_kind()` receives a contained starter candidate rather than an unchecked path whenever `policy_root` is present.

- [ ] **Step 6: Make doctor reuse one prepared/compiled pair**

Call `_prepare_resolve_compile_policy(..., capture_date_failures=True)` once, pass its
prepared/compiled values to `_lint_prepared_policy()`, and run advisory rules against
`prepared.raw_policy`. Date failures are classified from their safe structured details,
not by matching exception prose. Do not call public `lint_policy()` from doctor and do
not read policy YAML again:

```python
def _date_failure_finding(exc: PolicyValidationError) -> dict:
    details = dict(exc.details) if isinstance(exc.details, dict) else {}
    effective = details.get("effective_date")
    expiration = details.get("expiration_date")
    today = details.get("today")
    if isinstance(effective, str) and isinstance(today, str) and today < effective:
        return _finding(
            exc.code,
            "WARNING",
            f"Policy not yet active: effective_date is {effective}, today is {today}",
        )
    if isinstance(expiration, str) and isinstance(today, str) and today > expiration:
        return _finding(
            exc.code,
            "ERROR",
            f"Policy expired: expiration_date is {expiration}, today is {today}",
        )
    return _finding(exc.code, "ERROR", "Policy date validation failed")


today = now or date.today()
failure: PolicyLoadError | PolicyValidationError | None = None
try:
    result = _prepare_resolve_compile_policy(
        path,
        loader=loader,
        clock=lambda: today,
        capture_date_failures=True,
    )
except (PolicyLoadError, PolicyValidationError) as exc:
    failure = exc
if failure is not None:
    return [_finding(failure.code, "ERROR", str(failure))]
if result.prepared is None:
    raise AssertionError("file diagnostics require a prepared source")
findings = [_date_failure_finding(exc) for exc in result.date_failures]
lint_findings = _lint_prepared_policy(
    result.prepared,
    result.compiled,
    target_kind="policy",
    target_label=path,
)
findings.extend(_lint_to_doctor(lint_findings))
raw = copy.deepcopy(result.prepared.raw_policy)
# Append the existing doctor advisory checks to findings, then return findings.
```

Add a regression policy containing both a future `effective_date` and an independent
workflow advisory. Assert one `WARNING` whose message begins `Policy not yet active:`
and the independent advisory are both returned. Also assert the normal public loader
still raises for the same date.

Add `POLICY_PATH_OUTSIDE_ROOT` to `_NEXT_ACTIONS` with guidance to select a contained target or supply the intended broader root through `workflow doctor --policy-root ROOT`.

- [ ] **Step 7: Run workflow diagnostic suites to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_workflow_lint.py tests/test_workflow_doctor.py -k 'lint or doctor or starter'
```

Expected: all selected tests pass; policy doctor prepares once and starter inspection cannot precede containment.

- [ ] **Step 8: Commit diagnostic authority propagation**

```bash
git add aegis/_internal/workflow_lint.py aegis/_internal/workflow_doctor.py tests/test_policy_root_entry_points.py tests/test_workflow_lint.py tests/test_workflow_doctor.py
git commit -m "fix: bind workflow diagnostics to policy roots"
```

### Task 5: CLI policy-root authority and no-pre-read routing

**Files:**
- Modify: `aegis/_internal/cli.py:30-135,320-370,620-700`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_pr11_workflow_cli.py`
- Modify: `tests/test_policy_root_entry_points.py`

**Interfaces:**
- Consumes: diagnostic APIs from Task 4 and `FilePolicyLoader(policy_root)`.
- Produces: `--policy-root ROOT` on `policy lint`, `policy validate`, `workflow lint`, and `workflow doctor`; `_lint_policy(path: Path, *, loader: PolicyLoaderBase | None = None, legacy_authorization: LegacyAuthorization | None = None) -> list[str]` and the same signature on `_validate_policy()`.

- [ ] **Step 1: Add failing parser and command routing tests**

Assert all four subcommands expose `args.policy_root`; explicit root makes relative policy/starter targets root-relative; absolute outside targets return the stable containment code; multiple implicit policy targets get separate roots; artifact kinds reject rather than ignore `--policy-root`.

```python
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


def test_workflow_artifact_rejects_policy_root(capsys: pytest.CaptureFixture[str]) -> None:
    status = main([
        "workflow", "lint", "--kind", "workflow_artifact",
        "--policy-root", "policies", "artifact.json",
    ])
    assert status == 2
    assert "--policy-root applies only" in capsys.readouterr().err
```

- [ ] **Step 2: Run CLI root tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_cli.py tests/test_pr11_workflow_cli.py -k 'cli or policy_root'
```

Expected: argparse rejects the new option or commands inspect unchecked paths before routing.

- [ ] **Step 3: Remove policy lint/validate pre-reads and propagate one loader**

Delete `_lint_policy()`'s YAML read/parse and `parsed_policy` call. Bind one explicit loader per command invocation and pass it to every policy target; when there is no explicit root, pass `None` so each target gets its own lexical-parent authority:

```python
def _lint_policy(
    path: Path,
    *,
    loader: PolicyLoaderBase | None = None,
    legacy_authorization: LegacyAuthorization | None = None,
) -> list[str]:
    try:
        load_resolve_compile_policy(
            str(path),
            loader=loader,
            allow_legacy=False,
            legacy_authorization=legacy_authorization,
        )
    except (PolicyLoadError, PolicyValidationError) as exc:
        details = exc.details if isinstance(exc.details, dict) else {}
        return [f"[{exc.code}] {details.get('path', '$')}: {exc}"]
    return []
```

Remove `_cmd_lint()` and `_cmd_validate()` calls to `Path.exists()`. A missing target must be classified by the loader after containment.

- [ ] **Step 4: Add parser options and enforce workflow-kind compatibility**

Add this option to each of the four parsers:

```python
parser.add_argument(
    "--policy-root",
    default=None,
    help="Canonical authority root for policy files and starter policies",
)
```

In command handlers, reject `policy_root` with explicit artifact kinds and route `.yaml`/`.yml` auto targets directly to policy diagnostics before generic `detect_target_kind()`. Possible starter directories must go through `lint_target()`/`diagnose_target()` with `policy_root`, which performs contained fixture detection.

```python
if args.policy_root is not None and args.kind in {
    "workflow_artifact", "audit_artifact"
}:
    print("ERROR: --policy-root applies only to policy and starter_dir targets", file=sys.stderr)
    return 2
```

- [ ] **Step 5: Test every command against containment and source collision**

For policy lint/validate and workflow lint/doctor, add subprocess-style `main(argv)` tests that place a valid same-named file in CWD and an escaping file under the selected root. Assert each command reports `POLICY_PATH_OUTSIDE_ROOT`, does not use the CWD copy, and may print only the exact host-provided target label—not canonical/root/parent values from the exception.

```python
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
    _write_policy(cwd / "entry.yaml")
    _write_policy(
        root / "entry.yaml",
        "extends: ../outside.yaml\npolicy_version: '1.0'\nroles: [reviewer]\n",
    )
    _write_policy(tmp_path / "outside.yaml")
    monkeypatch.chdir(cwd)
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
    assert str(tmp_path / "outside.yaml") not in rendered
```

- [ ] **Step 6: Run CLI suites to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_cli.py tests/test_pr11_workflow_cli.py -k 'cli or policy_root or workflow'
```

Expected: all selected tests pass with consistent status codes and JSON/plain output.

- [ ] **Step 7: Commit CLI root propagation**

```bash
git add aegis/_internal/cli.py tests/test_policy_root_entry_points.py tests/test_cli.py tests/test_pr11_workflow_cli.py
git commit -m "feat: add policy root to diagnostic commands"
```

### Task 6: Sealed module authority and invocation-bound implicit context

**Files:**
- Modify: `aegis/_internal/enforcement.py:124-187,215-300,1521-1900,2186-2850`
- Modify: `aegis/enforcement.py`
- Modify: `aegis/__init__.py`
- Modify: `tests/conftest.py:45-55`
- Modify: `tests/test_module_level_evidence_runtime.py`
- Modify: `tests/test_enforcement_compiled_policy_boundary.py`
- Modify: `tests/test_policy_root_entry_points.py`

**Interfaces:**
- Consumes: `_bind_policy_authority()` and `PolicyLoaderBase`.
- Produces: `configure_module_enforcement(*, sink: AuditSink, signer: ArtifactSigner | None = None, chain_linker: ChainLinker | None = None, policy_loader: PolicyLoaderBase | None = None) -> None`, invocation-bound `_PolicyAuthority`, `_policy_authority_scope(authority)`, and `_effective_policy_authority(policy_file, configured_loader, *, invocation)` used by module and AEGIS boundaries.

- [ ] **Step 1: Add failing sealed-runtime and exact-identity tests**

Test module sync/async invocation and split pre-call paths with an explicit root. For implicit module and `AEGIS(policy_loader=None)` paths, monkeypatch the internal loader prepare method and record `id(loader)`; one operation must observe one identity, and parallel operations must not leak authorities through global state. Also assert a context override cannot replace an explicitly configured loader.

```python
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
```

Add a parameterized identity test that calls these exact public surfaces:
`enforce_invocation(invocation)`, `await enforce_invocation_async(invocation)`,
`AEGIS.enforce(invocation)`, and `await AEGIS.enforce_async(invocation)`. Monkeypatch
`FilePolicyLoader._prepare` with a recording wrapper and assert all prepares associated
with one invocation use one `id(self)`. Add a parallel async test using
`asyncio.gather(enforce_invocation_async(invocation_a),
enforce_invocation_async(invocation_b))`; tag recordings by the exact invocation
mapping identity obtained from `_POLICY_AUTHORITY_OVERRIDE.get().invocation` inside the
recording wrapper, and assert the two loader-id sets are disjoint. Add a nested test whose
enforcement of A calls the real public evidence boundary for B, asserting B shadows A
with a different loader and the outer scope returns to A afterward. These tests exercise
actual decorated enforcement, not a mocked attempt loop.

- [ ] **Step 2: Run module authority tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_module_level_evidence_runtime.py tests/test_enforcement_compiled_policy_boundary.py -k 'module or policy_loader'
```

Expected: `configure_module_enforcement` lacks `policy_loader`, and module paths currently call loaders with `None` independently.

- [ ] **Step 3: Add policy loader to the sealed runtime snapshot**

Validate only `None` or `PolicyLoaderBase`, store it under the runtime lock, and return it from `begin()` with sink/signer/linker:

```python
def configure(
    self,
    *,
    sink: AuditSink,
    signer: ArtifactSigner | None,
    chain_linker: ChainLinker | None,
    policy_loader: PolicyLoaderBase | None,
) -> None:
    if policy_loader is not None and not isinstance(policy_loader, PolicyLoaderBase):
        raise TypeError("policy_loader must be a PolicyLoaderBase")
```

`reset_for_test()` clears the loader. Update `configure_module_enforcement()`'s public signature and forwarding call, preserving the default `None` used by `tests/conftest.py`.

- [ ] **Step 4: Implement private authority context with explicit-loader precedence**

Use a `ContextVar` so async tasks and nested retry calls do not share mutable global authority:

```python
@dataclass(frozen=True, slots=True)
class _PolicyAuthority:
    invocation: Mapping[str, Any]
    requested_policy_ref: str
    bound_policy_ref: str
    loader: PolicyLoaderBase


_POLICY_AUTHORITY_OVERRIDE: ContextVar[_PolicyAuthority | None] = ContextVar(
    "aegis_policy_authority_override",
    default=None,
)


@contextmanager
def _policy_authority_scope(authority: _PolicyAuthority):
    token = _POLICY_AUTHORITY_OVERRIDE.set(authority)
    try:
        yield authority
    finally:
        _POLICY_AUTHORITY_OVERRIDE.reset(token)


def _effective_policy_authority(
    policy_file: str,
    configured_loader: PolicyLoaderBase | None,
    *,
    invocation: Mapping[str, Any],
) -> _PolicyAuthority:
    if configured_loader is not None:
        return _PolicyAuthority(invocation, policy_file, policy_file, configured_loader)
    override = _POLICY_AUTHORITY_OVERRIDE.get()
    if (
        override is not None
        and invocation is override.invocation
        and policy_file == override.requested_policy_ref
    ):
        return override
    bound_ref, loader = _bind_policy_authority(policy_file, None)
    return _PolicyAuthority(invocation, policy_file, bound_ref, loader)
```

Every public module/AEGIS operation computes this once, then passes
`authority.bound_policy_ref` and the exact `authority.loader` through
cache/compiler/session helpers. Nested evidence for a different invocation object—even
with the same policy spelling—must bind and shadow its own authority. Update
`_load_compiled_policy()` and `_compile_cached_policy()` to accept the invocation
mapping (not only its policy string), call `_effective_policy_authority(...,
invocation=invocation)`, and then use the returned bound ref/loader. Thus their ambient
lookup is attested to the exact invocation. An explicit configured loader is checked
before the context override and can never be widened.

- [ ] **Step 5: Propagate the runtime snapshot through sync/async evidence boundaries**

Extend both branches of `_evidence_attempt_boundary` to unpack `runtime_policy_loader`. Store the result of `_attempt_invocation()` in `attempt_invocation`; when it is a mapping containing a string `policy_file`, pass it into the decorated enforcement function through a private context scope rather than changing public invocation signatures:

```python
if (
    isinstance(attempt_invocation, Mapping)
    and isinstance(attempt_invocation.get("policy_file"), str)
):
    authority = _effective_policy_authority(
        attempt_invocation["policy_file"],
        runtime_policy_loader,
        invocation=attempt_invocation,
    )
    with _policy_authority_scope(authority):
        return function(*args, **kwargs)
return function(*args, **kwargs)
```

For instance-scoped methods, use `owner._policy_loader`; for module methods, use the loader returned by `_MODULE_RUNTIME.begin()`. The async branch contains `return await function(*args, **kwargs)` inside the same synchronous context-manager scope; `ContextVar` state follows the task and is reset in `finally`.

- [ ] **Step 6: Run module, instance, async, and isolation tests to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_module_level_evidence_runtime.py tests/test_enforcement_compiled_policy_boundary.py tests/test_pluggable_loader_runtime.py -k 'module or aegis or authority_context or policy_loader'
```

Expected: all selected tests pass; one operation uses one loader identity, and overrides are cleared on success and failure.

- [ ] **Step 7: Commit sealed enforcement authority**

```bash
git add aegis/_internal/enforcement.py aegis/enforcement.py aegis/__init__.py tests/conftest.py tests/test_module_level_evidence_runtime.py tests/test_enforcement_compiled_policy_boundary.py tests/test_pluggable_loader_runtime.py tests/test_policy_root_entry_points.py
git commit -m "fix: seal policy authority with enforcement runtime"
```

### Task 7: Retry authority inference, attestation, and reuse

**Files:**
- Modify: `aegis/_internal/retry.py`
- Modify: `aegis/retry.py`
- Modify: `aegis/_internal/enforcement.py`
- Modify: `tests/test_retry.py`
- Modify: `tests/test_policy_root_entry_points.py`
- Modify: `tests/test_public_api.py`

**Interfaces:**
- Consumes: `_PolicyAuthority`, `_policy_authority_scope()`, module runtime's sealed loader snapshot, bound `AEGIS._policy_loader`, and `_prepare_resolve_compile_policy()`.
- Produces: `with_retry(invocation, *, enforcement_fn=enforce_invocation, policy_loader: PolicyLoaderBase | None = None) -> dict[str, Any]` plus exact mismatch/missing-authority `ValueError` contracts.

- [ ] **Step 1: Add failing authority inference and conflict tests**

Cover the default module function, a bound `AEGIS.enforce` method, a bound `AEGIS.enforce_invocation` method if present, and an arbitrary callable. Assert exact object identity across discovery and every attempt; explicit mismatches fail before loader access; custom omission uses the exact required message:

```python
def test_custom_retry_callable_requires_attested_loader(invocation: dict[str, object]) -> None:
    def custom_enforce(value: Mapping[str, Any]) -> dict[str, Any]:
        return {"enforcement_result": "PASS"}

    with pytest.raises(
        ValueError,
        match="^policy_loader is required when enforcement authority cannot be inferred$",
    ):
        with_retry(invocation, enforcement_fn=custom_enforce)


def test_retry_rejects_loader_conflict_before_policy_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, invocation = _policy_tree_and_invocation(tmp_path)
    engine_loader = FilePolicyLoader(root)
    other_loader = FilePolicyLoader(root)
    engine = AEGIS(sink=CallbackAuditSink(lambda artifact: None), policy_loader=engine_loader)
    monkeypatch.setattr(other_loader, "load", lambda ref: pytest.fail("policy accessed"))
    with pytest.raises(
        ValueError,
        match="^policy_loader does not match enforcement authority$",
    ):
        with_retry(invocation, enforcement_fn=engine.enforce, policy_loader=other_loader)
```

- [ ] **Step 2: Add failing implicit-context cleanup tests**

Run one success and one exhausted attempt-loop path for both the default module callable
and a bound `AEGIS.enforce` callable with no configured loader. Use a real temporary
policy containing `retry_policy: {max_retries: 2, backoff_ms: 0}` and an output schema;
valid output drives success and invalid output drives all three actual enforcement
attempts. Record loader identity in the real loader boundary—do not replace the retry
loop or enforcement callable—then assert the context is cleared:

```python
RETRY_POLICY_WITH_OUTPUT_SCHEMA = """\
policy_version: '1.0'
roles: [reviewer]
output_schema:
  type: object
  required: [result]
  properties:
    result: {type: string}
retry_policy:
  max_retries: 2
  backoff_ms: 0
"""


def _valid_retry_invocation(
    policy_file: str,
    *,
    valid_output: bool,
) -> dict[str, object]:
    return {
        "model_provider": "test",
        "model_identifier": "test-model",
        "role": "reviewer",
        "policy_file": policy_file,
        "input": {"task": "review"},
        "output": {"result": "done"} if valid_output else {},
        "context": {},
    }


@pytest.mark.parametrize("surface", ["module", "aegis"])
@pytest.mark.parametrize("exhaust", [False, True])
def test_retry_implicit_authority_is_cleared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    exhaust: bool,
) -> None:
    entry = _write_policy(tmp_path / "entry.yaml", RETRY_POLICY_WITH_OUTPUT_SCHEMA)
    invocation = _valid_retry_invocation(str(entry), valid_output=not exhaust)
    seen: list[int] = []
    original_prepare = FilePolicyLoader._prepare

    def recording_prepare(self: FilePolicyLoader, *args: object, **kwargs: object):
        seen.append(id(self))
        return original_prepare(self, *args, **kwargs)

    monkeypatch.setattr(FilePolicyLoader, "_prepare", recording_prepare)
    enforcement_fn = enforce_invocation
    if surface == "aegis":
        engine = AEGIS(sink=CallbackAuditSink(lambda artifact: None))
        enforcement_fn = engine.enforce
    if exhaust:
        with pytest.raises(RetryExhaustedError) as caught:
            with_retry(invocation, enforcement_fn=enforcement_fn)
        assert caught.value.details["attempts"] == 3
    else:
        assert with_retry(invocation, enforcement_fn=enforcement_fn)["enforcement_result"] == "PASS"
    assert seen
    assert len(set(seen)) == 1
    assert enforcement._POLICY_AUTHORITY_OVERRIDE.get() is None
```

The assertion observes both discovery and real enforcement prepares, so it cannot pass
while attempts ignore the override.

- [ ] **Step 3: Run retry authority tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_entry_points.py tests/test_retry.py -k retry
```

Expected: current retry performs an independent implicit load and arbitrary callables do not require authority.

- [ ] **Step 4: Implement enforcement-authority inference**

Compare the unwrapped/default module callable by identity and detect bound AEGIS methods through `__self__`. Seal/read the module snapshot through one private helper that returns its configured loader without changing it. Return a sentinel for arbitrary callables:

```python
_UNINFERABLE = object()


def _infer_enforcement_loader(
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> PolicyLoaderBase | None | object:
    if enforcement_fn is enforce_invocation:
        return _module_policy_loader_for_retry()
    owner = getattr(enforcement_fn, "__self__", None)
    if isinstance(owner, AEGIS):
        return owner._policy_loader
    return _UNINFERABLE


def _retry_policy_authority(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
    policy_loader: PolicyLoaderBase | None,
) -> _PolicyAuthority:
    policy_ref = str(invocation["policy_file"])
    inferred = _infer_enforcement_loader(enforcement_fn)
    if inferred is _UNINFERABLE:
        if policy_loader is None:
            raise ValueError(
                "policy_loader is required when enforcement authority cannot be inferred"
            )
        return _PolicyAuthority(invocation, policy_ref, policy_ref, policy_loader)
    if isinstance(inferred, PolicyLoaderBase):
        if policy_loader is not None and policy_loader is not inferred:
            raise ValueError("policy_loader does not match enforcement authority")
        return _PolicyAuthority(invocation, policy_ref, policy_ref, inferred)
    if policy_loader is not None:
        return _PolicyAuthority(invocation, policy_ref, policy_ref, policy_loader)
    bound_ref, implicit_loader = _bind_policy_authority(policy_ref, None)
    return _PolicyAuthority(invocation, policy_ref, bound_ref, implicit_loader)
```

Implement the module helper by calling the idempotent sealed runtime snapshot:

```python
def _module_policy_loader_for_retry() -> PolicyLoaderBase | None:
    _, _, _, policy_loader = _MODULE_RUNTIME.begin()
    return policy_loader
```

If inference returns a loader, a caller-supplied loader must be that exact instance. If inference returns `None`, an explicitly supplied loader becomes the authority; otherwise bind one implicit authority. If inference is unavailable, require `policy_loader` and treat its reuse by the callable as host attestation.

- [ ] **Step 5: Wrap discovery and all attempts in one authority scope**

Remove direct `load_policy()` plus separate `compile_policy()`. Compute authority once and discover retry configuration with the shared compiler boundary:

```python
def with_retry(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable = enforce_invocation,
    policy_loader: PolicyLoaderBase | None = None,
) -> dict[str, Any]:
    authority = _retry_policy_authority(
        invocation,
        enforcement_fn=enforcement_fn,
        policy_loader=policy_loader,
    )
    with _policy_authority_scope(authority):
        compiled_policy = load_resolve_compile_policy(
            authority.bound_policy_ref,
            loader=authority.loader,
        )
        return _execute_retry_loop(
            invocation,
            enforcement_fn=enforcement_fn,
            retry_policy=compiled_policy.retry,
        )
```

Define `_execute_retry_loop()` by extracting the existing loop verbatim, including the
no-retry fast path and exhaustion fallback; only its inputs change:

```python
def _execute_retry_loop(
    invocation: Mapping[str, Any],
    *,
    enforcement_fn: Callable[[Mapping[str, Any]], dict[str, Any]],
    retry_policy: CompiledRetryPolicy | None,
) -> dict[str, Any]:
    if retry_policy is None:
        return enforcement_fn(invocation)
    last_error: Exception | None = None
    for attempt in range(retry_policy.max_retries + 1):
        try:
            return enforcement_fn(invocation)
        except SchemaValidationError as exc:
            last_error = exc
            if attempt < retry_policy.max_retries:
                sleep_ms = retry_policy.backoff_ms * (attempt + 1)
                time.sleep(sleep_ms / 1000.0)
                continue
            raise RetryExhaustedError(
                f"Retry exhausted after {attempt + 1} attempts",
                attempts=attempt + 1,
                last_error=exc,
            ) from exc
        except AIGCError:
            raise
    assert last_error is not None  # unreachable defensive guard
    raise RetryExhaustedError(
        f"Retry exhausted after {retry_policy.max_retries + 1} attempts",
        attempts=retry_policy.max_retries + 1,
        last_error=last_error,
    ) from last_error
```

Import `CompiledRetryPolicy` from `aegis._internal.compiled_policy`. Do not
change retryable exceptions, backoff math, attempt evidence, or exhaustion semantics.

The context scope must cover the no-retry fast path and every raised exception.

- [ ] **Step 6: Migrate existing custom-callable retry tests**

For every `MagicMock` or local callable in `tests/test_retry.py`, create one explicit loader rooted at `tests/golden_replays` and make the invocation reference root-relative `policy_with_retry.yaml` or `golden_policy_v1.yaml`:

```python
RETRY_POLICY_ROOT = Path("tests/golden_replays").resolve()


def _retry_loader() -> FilePolicyLoader:
    return FilePolicyLoader(RETRY_POLICY_ROOT)


audit = with_retry(
    invocation,
    enforcement_fn=mock_enforce,
    policy_loader=_retry_loader(),
)
```

Do not pass a new loader to each attempt; one test call creates one loader instance.

- [ ] **Step 7: Run retry and public signature tests to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_retry.py tests/test_policy_root_entry_points.py tests/test_public_api.py -k 'retry or with_retry'
```

Expected: all selected tests pass; conflict/missing-authority messages match exactly and the context is empty after success/failure.

- [ ] **Step 8: Commit retry authority reuse**

```bash
git add aegis/_internal/retry.py aegis/retry.py aegis/_internal/enforcement.py tests/test_retry.py tests/test_policy_root_entry_points.py tests/test_public_api.py
git commit -m "fix: share enforcement authority with retries"
```

### Task 8: Public, packaged, documentation, and migration contracts

**Files:**
- Modify: `docs/USAGE.md`
- Modify: `docs/INTEGRATION_GUIDE.md`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md`
- Modify: `docs/reference/TROUBLESHOOTING.md`
- Modify: `policies/policy_dsl_spec.md`
- Modify: `docs/decisions/ADR-0005-absolute-policy-path-support.md`
- Modify: `CHANGELOG.md`
- Modify: `tests/test_public_api.py`
- Modify: `tests/test_v090_distribution_contract.py`
- Modify: `tests/test_v090_contract_freeze.py`
- Modify: `scripts/check_doc_parity.py`
- Modify: `scripts/check_public_docs_no_internal_imports.py` only if its maintained public-surface list needs the changed contract prose.

**Interfaces:**
- Consumes: all behavior and signatures from Tasks 1-7.
- Produces: supported migration documentation, packaged schema parity, and public/distribution assertions for the required-root constructor and retry/module signatures.

- [ ] **Step 1: Add failing public and distribution contract assertions**

Assert the installed/public class requires `policy_root`, exposes a canonical read-only property, `PolicyLoadError` accepts the new code, schemas require non-empty `extends`, module configuration accepts `policy_loader`, retry accepts `policy_loader`, and `load_policy_async` retains await usage with optional loader.

```python
def test_file_loader_public_constructor_requires_policy_root() -> None:
    signature = inspect.signature(FilePolicyLoader)
    assert signature.parameters["policy_root"].default is inspect.Parameter.empty


def test_packaged_schema_rejects_empty_extends() -> None:
    schema = json.loads(
        resources.files("aegis.schemas").joinpath("policy_dsl.schema.json").read_text()
    )
    assert schema["properties"]["extends"]["minLength"] == 1
```

- [ ] **Step 2: Run contract tests to verify RED**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_public_api.py tests/test_v090_distribution_contract.py tests/test_v090_contract_freeze.py
```

Expected: failures identify stale signatures, packaged schema assumptions, or missing maintained wording.

- [ ] **Step 3: Document explicit and implicit authority with runnable migrations**

Use the same exact examples and security language across the maintained docs:

```python
loader = FilePolicyLoader("policies")
policy = load_policy("child.yaml", loader=loader)
engine = AEGIS(sink=sink, policy_loader=loader)
audit = with_retry(
    invocation,
    enforcement_fn=custom_enforce,
    policy_loader=loader,
)
```

State all of these explicitly:

- plain `load_policy("policies/entry.yaml")` roots inheritance at the lexical `policies` directory;
- an explicit loader resolves relative entries from its root and permits a deliberate multi-directory tree only inside that root;
- canonical symlink targets must remain inside the root;
- custom loaders cannot use `extends`;
- arbitrary retry callables require the exact loader they attest to using;
- containment failures use `POLICY_PATH_OUTSIDE_ROOT` without filesystem paths;
- `workflow lint/doctor --policy-root ROOT` and policy lint/validate use the same namespace;
- hostile concurrent mutation of filesystem components is outside this guarantee.

- [ ] **Step 4: Update ADR-0005 and the changelog compatibility record**

Preserve absolute entry support while stating that it does not authorize arbitrary inherited targets. Label `FilePolicyLoader()` to `FilePolicyLoader(policy_root)` as an immediate beta security correction, note root-relative explicit references, path-bearing error detail removal, and custom retry loader requirements. Include before/after migration code verbatim from Step 3.

Use this exact compatibility statement in ADR-0005 and the changelog, adjusting only the surrounding heading level:

```markdown
Absolute entry paths remain supported, but they do not authorize inherited targets outside the entry's canonical policy root. `FilePolicyLoader` now requires an explicit root; relative references passed to that loader are root-relative. Containment failures return `POLICY_PATH_OUTSIDE_ROOT` without filesystem paths. Custom retry enforcement callables must receive the same `policy_loader` authority used for enforcement.
```

- [ ] **Step 5: Update doc parity guards with semantic assertions**

Extend `scripts/check_doc_parity.py` so maintained documents must contain `POLICY_PATH_OUTSIDE_ROOT`, `FilePolicyLoader("policies")`, `--policy-root`, the lexical-parent default, and the concurrent-writer non-goal. Assert the source and packaged schema `extends` fragments match exactly.

```python
policy_root_terms = {
    "POLICY_PATH_OUTSIDE_ROOT",
    'FilePolicyLoader("policies")',
    "--policy-root",
    "lexical parent",
    "concurrent",
}
for relative_path in (
    "CHANGELOG.md",
    "docs/USAGE.md",
    "docs/INTEGRATION_GUIDE.md",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
):
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    missing = sorted(term for term in policy_root_terms if term not in text)
    if missing:
        errors.append(f"{relative_path}: missing policy-root terms {missing}")

source_schema = json.loads(
    (REPO_ROOT / "schemas/policy_dsl.schema.json").read_text(encoding="utf-8")
)
package_schema = json.loads(
    (REPO_ROOT / "aegis/schemas/policy_dsl.schema.json").read_text(encoding="utf-8")
)
if source_schema["properties"]["extends"] != package_schema["properties"]["extends"]:
    errors.append("source and packaged extends schemas differ")
```

- [ ] **Step 6: Run contract and documentation verification to verify GREEN**

Run:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_public_api.py tests/test_v090_distribution_contract.py tests/test_v090_contract_freeze.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_doc_parity.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_public_docs_no_internal_imports.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_evidence_claims.py
```

Expected: every command exits 0 and public docs contain no internal imports or overclaims.

- [ ] **Step 7: Commit public contracts and documentation**

```bash
git add docs/USAGE.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/reference/TROUBLESHOOTING.md policies/policy_dsl_spec.md docs/decisions/ADR-0005-absolute-policy-path-support.md CHANGELOG.md tests/test_public_api.py tests/test_v090_distribution_contract.py tests/test_v090_contract_freeze.py scripts/check_doc_parity.py scripts/check_public_docs_no_internal_imports.py
git commit -m "docs: publish policy root security contract"
```

### Task 9: Cross-surface adversarial verification

**Files:**
- Modify only if a verification failure demonstrates an issue #57 defect.
- Review: `aegis/_internal/policy_loader.py`
- Review: `aegis/_internal/enforcement.py`
- Review: `aegis/_internal/retry.py`
- Review: `aegis/_internal/workflow_lint.py`
- Review: `aegis/_internal/workflow_doctor.py`
- Review: `aegis/_internal/cli.py`
- Review: `tests/test_policy_root_containment.py`
- Review: `tests/test_policy_root_entry_points.py`

**Interfaces:**
- Consumes: Tasks 1-8 and the approved issue #57 design specification.
- Produces: a clean security review, full regression result, and implementation-ready branch state without publishing or opening a pull request unless separately requested.

- [ ] **Step 1: Run Windows and platform-sensitive collection checks**

Inspect the new tests and confirm the Windows integration case from Task 2 constructs a
foreign-drive `WindowsPath` through the `_canonicalize()` seam, runs only on Windows,
and requires no physical second drive. Confirm symlink skips are scoped only to symlink
privilege. Run collection on the current platform:

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest --collect-only -q tests/test_policy_root_containment.py tests/test_policy_root_entry_points.py
```

Expected: collection succeeds; traversal and absolute containment tests are never skipped wholesale.

- [ ] **Step 2: Run focused security suites**

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q tests/test_policy_root_containment.py tests/test_policy_root_entry_points.py tests/test_policy_loader.py tests/test_policy_composition.py tests/test_golden_replay_composition.py tests/test_retry.py tests/test_module_level_evidence_runtime.py tests/test_workflow_lint.py tests/test_workflow_doctor.py tests/test_cli.py tests/test_pr11_workflow_cli.py
```

Expected: all tests pass with no unexpected warnings.

- [ ] **Step 3: Audit every file access and recursive edge**

Run searches and inspect every match:

```bash
rg -n "Path\(|\.resolve\(|\.exists\(|\.is_file\(|\.is_dir\(|\.stat\(|getmtime|read_text|open\(" aegis/_internal/policy_loader.py aegis/_internal/workflow_lint.py aegis/_internal/workflow_doctor.py aegis/_internal/cli.py
rg -n "load_policy\(|load_resolve_compile_policy\(|get_or_load\(" aegis/_internal/enforcement.py aegis/_internal/retry.py aegis/_internal/workflow_lint.py aegis/_internal/workflow_doctor.py aegis/_internal/cli.py
rg -n "_default_loader|parsed_policy|Circular extends detected|policy_file.*details|schema_path.*details" aegis tests
```

Expected: policy-source accesses occur only after a bound loader's canonical containment; no recursive edge selects a fresh root; no default singleton or public parsed-policy bypass remains; no protected path-bearing error detail remains.

- [ ] **Step 4: Audit authority identity and cleanup**

Map every entry point to its authority origin and verify tests assert the same loader instance where required:

| Entry point | Authority origin | Reuse requirement |
| --- | --- | --- |
| direct/compiler/cache/async | explicit loader or lexical parent | whole graph/call |
| module sync/async/split | sealed module loader or one invocation-bound loader | whole operation |
| AEGIS sync/async/session | instance loader or one invocation-bound loader | whole operation |
| lint/validate/doctor | `policy_root` or target-specific implicit root | prepare/compile/advisories |
| starter diagnostics | explicit root or canonical starter directory | fixture detection and nested policy |
| retry | inferred/attested loader or one context-bound loader | discovery plus all attempts |

Expected: explicit configured loaders always take precedence over context overrides, and override state is cleared after both success and failure.

- [ ] **Step 5: Run lint, documentation, full tests, and diff checks**

```bash
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/flake8 aegis
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_doc_parity.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_evidence_claims.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_brand_and_version_parity.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python scripts/check_public_docs_no_internal_imports.py
/Users/neal/Documents/_Shenanigans/_myProjects/aegis/.venv/bin/python -m pytest -q
git diff --check
git status --short
```

Expected: every command exits 0; the full suite meets or exceeds the clean baseline of `5058 passed, 20 warnings`; status contains only intentional issue #57 changes.

- [ ] **Step 6: Perform the final design-spec coverage review**

Read `docs/superpowers/specs/2026-08-11-issue-57-policy-root-containment-design.md` line by line and record the implementing test for each containment, graph, entry-point/cache, error-surface, compatibility, documentation, and security-review bullet in the implementation handoff. Explicitly record that descriptor-relative race resistance remains a non-goal.

- [ ] **Step 7: Commit any verification-only correction**

If Steps 1-6 required an issue #57 correction, return to the owning task's file list, add one focused RED regression test, apply the smallest correction, rerun that task's GREEN command and Step 5, then stage only the exact files changed and commit with `git commit -m "fix: close policy root verification gaps"`. If no correction was required, do not create an empty commit.

```bash
git commit -m "fix: close policy root verification gaps"
```
