# Issue #47 Append-Only Evidence Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish provider-neutral append-only evidence operations guidance and add a fail-closed claims guard over every maintained current document and statically extractable React public-copy surface.

**Architecture:** A new canonical operations guide defines the host-owned retention lifecycle while existing maintained surfaces link to it. A standalone Python claims guard derives its document set from `doc_parity_manifest.yaml`, reuses the existing TypeScript-based React extractor, normalizes machine-readable public copy, and rejects contextual immutable-storage or certification overclaims. The guard is enforced in pull-request, release, and demo CI without changing AEGIS runtime APIs or evidence schemas.

**Tech Stack:** Python 3.10–3.14, `pytest`, PyYAML, `jsonschema`, Python `html.parser`, Python `re`, Node.js 24, TypeScript compiler API, GitHub Actions, Markdown.

## Global Constraints

- Do not modify runtime APIs, evidence schemas, checkpoint behavior, or storage implementations.
- `aegis-ai-governance==0.9.0b1` is the released beta; trusted checkpoints are current-source functionality after that release.
- AEGIS owns evidence construction and verification contracts only. Hosts own storage, retention, latest-checkpoint selection, keys, monitoring, backup, and recovery. Organizations own legal and compliance conclusions.
- `JsonFileAuditSink` is not append-only, WORM, durable, or hardened storage; issue #58 remains separate.
- Provider examples are illustrative and non-normative. Add no cloud SDK or storage dependency.
- Scan every repository file matched by `documentation_inventory.current` when its suffix is machine-readable; account explicitly for binary `.png` files.
- Scan statically extractable production React copy; tests, specs, generated files, declarations, dependencies, and dynamically fetched remote text are outside that React extractor boundary.
- Fail closed on inventory, Git enumeration, path, decoding, extraction, configuration, or resource-limit errors.
- Freeze these ceilings: 5 MiB per source file, 50 MiB aggregate source, 10,000 selected files, 250,000 public-copy blocks, 50 MiB serialized extractor output, 1 MiB per normalized block, and 100 MiB aggregate normalized text.
- Preserve the user's pre-existing `.gitignore` modification and never stage it as part of issue #47.
- Write the failing test before each implementation change and commit each task independently.

---

## File Structure

### New files

- `scripts/check_evidence_claims.py` — complete claims-guard models, scope resolution, normalization, contextual rules, diagnostics, and CLI.
- `tests/test_evidence_claims.py` — unit, adversarial, scope, resource-bound, and CLI tests for the claims guard.
- `tests/test_append_only_evidence_guidance.py` — canonical-guide contract, maintained-link, React-copy, and workflow-wiring tests.
- `docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md` — canonical provider-neutral evidence operations guide.
- `docs/superpowers/plans/2026-08-09-issue-47-append-only-evidence-operations.md` — this historical implementation plan.

### Existing files modified

- `scripts/check_doc_parity.py` — add NUL-safe repository enumeration and make documentation collection reuse it.
- `scripts/check_demo_copy.py` — expose the existing React file-selection and extraction helpers for safe reuse.
- `tests/test_doc_parity_v090_truth.py` — freeze repository-enumeration and inventory behavior.
- `tests/test_demo_copy_policy.py` — freeze the shared public helper interface.
- `doc_parity_manifest.yaml` — classify this implementation plan as historical.
- `README.md`, `SECURITY.md`, `CHANGELOG.md` — link the canonical guide and state bounded assurance.
- `docs/USAGE.md`, `docs/INTEGRATION_GUIDE.md`, `docs/PUBLIC_INTEGRATION_CONTRACT.md` — link operations guidance from current checkpoint integration surfaces.
- `docs/architecture/AEGIS_THREAT_MODEL.md` — connect the checkpoint residual-risk section to the host operations guide.
- `docs/reference/OPERATIONS_RUNBOOK.md` — add the guard command and canonical evidence-operations link.
- `docs/reference/external/AWS_KMS_SIGNING.md`, `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md` — link historical-key operations to the canonical guide.
- `demo-app-react/src/help/helpContent.ts` — replace two incorrect “immutable record” descriptions.
- `demo-app-react/src/help/helpContent.test.ts` — freeze corrected tamper-evidence language.
- `.github/workflows/security-boundaries.yml` — add the dedicated pull-request/push claims job.
- `.github/workflows/publish.yml` — enforce claims during release validation.
- `.github/workflows/deploy-demo-react.yml` — enforce comprehensive claims before demo deployment.

---

### Task 1: NUL-Safe Repository Inventory

**Files:**
- Modify: `scripts/check_doc_parity.py:108-173`
- Test: `tests/test_doc_parity_v090_truth.py:20-63`

**Interfaces:**
- Produces: `collect_repository_files(*, require_git: bool = False) -> list[Path]`
- Preserves: `collect_documentation_files() -> list[Path]`
- Consumers: Tasks 3 and 6 import `collect_repository_files(require_git=True)`.

- [ ] **Step 1: Write failing inventory tests**

Add these tests near the existing documentation-inventory test:

```python
def test_collect_repository_files_includes_cached_and_untracked_nonignored(
    tmp_path,
    monkeypatch,
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    _write_file(tmp_path, "docs/cached.md", "# Cached")
    _write_file(tmp_path, "docs/untracked.md", "# Untracked")
    _write_file(tmp_path, ".gitignore", "docs/ignored.md")
    _write_file(tmp_path, "docs/ignored.md", "# Ignored")
    subprocess.run(["git", "add", "docs/cached.md", ".gitignore"], cwd=tmp_path, check=True)

    relative = {
        path.relative_to(tmp_path).as_posix()
        for path in module.collect_repository_files(require_git=True)
    }

    assert "docs/cached.md" in relative
    assert "docs/untracked.md" in relative
    assert "docs/ignored.md" not in relative


def test_collect_repository_files_handles_newline_in_filename(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    unusual = tmp_path / "docs" / "line\nbreak.md"
    unusual.parent.mkdir(parents=True)
    try:
        unusual.write_text("# Visible", encoding="utf-8")
    except OSError:
        pytest.skip("newline filename creation unavailable")

    result = module.collect_repository_files(require_git=True)

    assert unusual in result


def test_collect_repository_files_require_git_fails_closed(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    with pytest.raises(RuntimeError, match="Git repository enumeration failed"):
        module.collect_repository_files(require_git=True)
```

- [ ] **Step 2: Run the new tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_doc_parity_v090_truth.py -k collect_repository_files -v
```

Expected: three failures because `collect_repository_files` does not exist.

- [ ] **Step 3: Implement repository enumeration and reuse it**

Add the public helper and refactor `collect_documentation_files`:

```python
def _fallback_repository_files() -> list[Path]:
    excluded = {
        ".git",
        ".pytest_cache",
        ".venv",
        "aegis-env",
        "dist",
        "node_modules",
        "venv",
    }
    return sorted(
        path
        for path in REPO_ROOT.rglob("*")
        if (path.is_file() or path.is_symlink())
        and not any(part in excluded for part in path.relative_to(REPO_ROOT).parts)
        and not any(
            part.endswith(".egg-info")
            for part in path.relative_to(REPO_ROOT).parts
        )
    )


def collect_repository_files(*, require_git: bool = False) -> list[Path]:
    """Return cached and untracked non-ignored repository paths, NUL-safely."""
    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
        )
    except (subprocess.CalledProcessError, OSError) as error:
        if require_git:
            raise RuntimeError("Git repository enumeration failed") from error
        return _fallback_repository_files()

    result: list[Path] = []
    for encoded in output.split(b"\0"):
        if not encoded:
            continue
        try:
            relative = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise RuntimeError("Git returned a non-UTF-8 repository path") from error
        path = REPO_ROOT / relative
        if path.exists() or path.is_symlink():
            result.append(path)
    return sorted(result)


def collect_documentation_files() -> list[Path]:
    """Collect maintained documentation and visual assets from repository files."""
    return [
        path
        for path in collect_repository_files()
        if path.suffix.lower() in _DOCUMENTATION_SUFFIXES
    ]
```

- [ ] **Step 4: Run focused inventory and documentation tests**

Run:

```bash
.venv/bin/python -m pytest tests/test_doc_parity_v090_truth.py -k "collect_repository_files or documentation_inventory" -v
.venv/bin/python scripts/check_doc_parity.py
```

Expected: all selected tests pass and documentation parity reports all sections PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add scripts/check_doc_parity.py tests/test_doc_parity_v090_truth.py
git commit -m "test: harden documentation inventory discovery"
```

---

### Task 2: Shared React Public-Copy Extraction Interface

**Files:**
- Modify: `scripts/check_demo_copy.py:123-163,185-190`
- Modify: `tests/test_demo_copy_policy.py:1-8`

**Interfaces:**
- Produces: `iter_frontend_public_files(root: Path) -> Iterable[Path]`
- Produces: `extract_frontend_public_copy(paths: list[Path], *, max_output_bytes: int = DEFAULT_MAX_EXTRACTOR_BYTES) -> dict[Path, str]`
- Preserves: `check_demo_copy.main()` behavior and existing extraction semantics.
- Consumers: Task 6 imports both helpers.

- [ ] **Step 1: Write a failing reusable-interface test**

Update the test import and add the interface test:

```python
from scripts.check_demo_copy import (  # noqa: E402
    extract_frontend_public_copy,
    iter_frontend_public_files,
    main,
    scan_text,
)


def test_frontend_extraction_helpers_are_public_and_reusable(tmp_path):
    page = tmp_path / "VisiblePage.tsx"
    page.write_text(
        "export function VisiblePage() { return <p>Visible assurance copy.</p> }",
        encoding="utf-8",
    )

    paths = list(iter_frontend_public_files(tmp_path))
    documents = extract_frontend_public_copy(paths)

    assert paths == [page]
    assert "Visible assurance copy." in documents[page]


def test_frontend_extraction_helper_rejects_oversized_output(tmp_path):
    page = tmp_path / "VisiblePage.tsx"
    page.write_text(
        "export const visibleCopy = 'This output exceeds the test limit.'",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="extractor output limit"):
        extract_frontend_public_copy([page], max_output_bytes=8)
```

- [ ] **Step 2: Run the interface test and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_demo_copy_policy.py::test_frontend_extraction_helpers_are_public_and_reusable -v
```

Expected: import failure for the two new public helper names.

- [ ] **Step 3: Expose the helpers and bound extractor output**

In `scripts/check_demo_copy.py`, add `import tempfile` and expose the bounded helper:

```python
def iter_frontend_public_files(root: Path) -> Iterable[Path]:
    for candidate in root.rglob("*"):
        if not candidate.is_file() or candidate.suffix not in FRONTEND_SUFFIXES:
            continue
        relative = candidate.relative_to(root)
        if any(part in FRONTEND_EXCLUDED_PARTS for part in relative.parts):
            continue
        if (
            ".test." in candidate.name
            or ".spec." in candidate.name
            or candidate.name.endswith(".d.ts")
        ):
            continue
        yield candidate


DEFAULT_MAX_EXTRACTOR_BYTES = 50 * 1024 * 1024
FRONTEND_EXTRACTOR_BATCH_SIZE = 200


def extract_frontend_public_copy(
    paths: list[Path],
    *,
    max_output_bytes: int = DEFAULT_MAX_EXTRACTOR_BYTES,
) -> dict[Path, str]:
    """Return rendered public-copy documents extracted from TypeScript syntax."""
    if not paths:
        return {}
    extracted: list[dict] = []
    consumed_output_bytes = 0
    for offset in range(0, len(paths), FRONTEND_EXTRACTOR_BATCH_SIZE):
        batch = paths[offset : offset + FRONTEND_EXTRACTOR_BATCH_SIZE]
        with (
            tempfile.TemporaryFile(mode="w+b") as output_file,
            tempfile.TemporaryFile(mode="w+b") as error_file,
        ):
            subprocess.run(
                ["node", str(FRONTEND_EXTRACTOR), *(str(path) for path in batch)],
                check=True,
                stdout=output_file,
                stderr=error_file,
            )
            output_bytes = output_file.tell()
            consumed_output_bytes += output_bytes
            if consumed_output_bytes > max_output_bytes:
                raise ValueError("frontend extractor output limit exceeded")
            output_file.seek(0)
            payload = output_file.read(output_bytes + 1)
        parsed = json.loads(payload.decode("utf-8", errors="strict"))
        if not isinstance(parsed, list):
            raise ValueError("frontend extractor output must be a JSON list")
        extracted.extend(parsed)
    documents: dict[Path, str] = {}
    for item in extracted:
        output: list[str] = []
        current_line = 1
        for index, block in enumerate(item["blocks"]):
            target_line = max(current_line, int(block["line"]))
            if index:
                output.append("\0")
            if target_line > current_line:
                output.append("\n" * (target_line - current_line))
                current_line = target_line
            output.append(block["text"])
        documents[Path(item["path"])] = "".join(output)
    return documents
```

Replace the two private helper calls in `main()` with the public names. Do not retain duplicate private wrappers. The fixed-size batches avoid operating-system argument-length failure at the 10,000-file guard ceiling. Temporary files prevent child stdout or stderr from accumulating unboundedly in Python memory; decoding and JSON parsing happen only after the aggregate byte ceiling is checked.

- [ ] **Step 4: Run the full demo-copy test file**

Run:

```bash
.venv/bin/python -m pytest tests/test_demo_copy_policy.py -q
```

Expected: all demo-copy tests pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add scripts/check_demo_copy.py tests/test_demo_copy_policy.py
git commit -m "refactor: share React public copy extraction"
```

---

### Task 3: Claims Guard Scope and Input Preflight

**Files:**
- Create: `scripts/check_evidence_claims.py`
- Create: `tests/test_evidence_claims.py`

**Interfaces:**
- Consumes: `load_manifest`, `check_documentation_inventory`, and `collect_repository_files(require_git=True)` from Task 1.
- Produces: `ScanLimits`, `TextBlock`, `ClaimFinding`, `ClaimsGuardError`.
- Produces: `select_current_paths(repo_root, manifest, repository_files, limits) -> tuple[Path, ...]`.
- Produces: `read_text_source(path, repo_root, limits, counters) -> str`.
- Consumers: Tasks 4–6 build normalization, policy, and orchestration on these exact types.

- [ ] **Step 1: Write failing scope, path, and resource tests**

Start `tests/test_evidence_claims.py` with:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_evidence_claims import (
    ClaimsGuardError,
    ScanLimits,
    select_current_paths,
)


def _manifest(*current: str) -> dict:
    return {
        "documentation_inventory": {
            "current": list(current),
            "target": ["docs/target/**"],
            "historical": ["docs/history/**"],
            "instruction_system": ["CLAUDE.md"],
        },
        "parity_docs": [],
    }


def test_select_current_paths_includes_unknown_suffix_for_fail_closed_check(tmp_path):
    current = tmp_path / "docs" / "reference" / "claims.rst"
    current.parent.mkdir(parents=True)
    current.write_text("AEGIS provides immutable evidence.", encoding="utf-8")

    selected = select_current_paths(
        tmp_path,
        _manifest("docs/reference/**"),
        [current],
        ScanLimits(),
    )

    assert selected == (current,)


def test_select_current_paths_rejects_multiply_classified_path(tmp_path):
    path = tmp_path / "docs" / "shared.md"
    path.parent.mkdir(parents=True)
    path.write_text("shared", encoding="utf-8")
    manifest = _manifest("docs/**")
    manifest["documentation_inventory"]["historical"] = ["docs/shared.md"]

    with pytest.raises(ClaimsGuardError, match="multiple documentation categories"):
        select_current_paths(tmp_path, manifest, [path], ScanLimits())


def test_select_current_paths_enforces_file_count_limit(tmp_path):
    paths = []
    for name in ("one.md", "two.md"):
        path = tmp_path / "docs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")
        paths.append(path)

    with pytest.raises(ClaimsGuardError, match="selected file limit"):
        select_current_paths(
            tmp_path,
            _manifest("docs/**"),
            paths,
            ScanLimits(max_files=1),
        )


def test_select_current_paths_rejects_symlink(tmp_path):
    target = tmp_path / "target.md"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "docs" / "linked.md"
    link.parent.mkdir()
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ClaimsGuardError, match="symlink"):
        select_current_paths(
            tmp_path,
            _manifest("docs/**"),
            [link],
            ScanLimits(),
        )
```

- [ ] **Step 2: Run the new test file and verify collection failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -v
```

Expected: import failure because `scripts/check_evidence_claims.py` does not exist.

- [ ] **Step 3: Add the guard models, constants, and current-path selection**

Create the script with this foundation:

```python
#!/usr/bin/env python3
"""Reject evidence-assurance overclaims in maintained public copy."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "doc_parity_manifest.yaml"
FRONTEND_ROOT = REPO_ROOT / "demo-app-react" / "src"
TEXT_SUFFIXES = frozenset({".html", ".md", ".mermaid", ".svg"})
BINARY_SUFFIXES = frozenset({".png"})
MANDATORY_CURRENT_PATHS = frozenset(
    {
        "README.md",
        "SECURITY.md",
        "docs/INTEGRATION_GUIDE.md",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md",
        "docs/USAGE.md",
        "docs/architecture/AEGIS_THREAT_MODEL.md",
        "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/reference/OPERATIONS_RUNBOOK.md",
    }
)


class ClaimsGuardError(RuntimeError):
    """A bounded infrastructure or configuration failure."""


@dataclass(frozen=True)
class ScanLimits:
    max_file_bytes: int = 5 * 1024 * 1024
    max_source_bytes: int = 50 * 1024 * 1024
    max_files: int = 10_000
    max_public_blocks: int = 250_000
    max_extractor_bytes: int = 50 * 1024 * 1024
    max_normalized_block_bytes: int = 1024 * 1024
    max_normalized_bytes: int = 100 * 1024 * 1024


@dataclass(frozen=True)
class TextBlock:
    path: Path
    line: int
    text: str


@dataclass(frozen=True)
class ClaimFinding:
    rule_id: str
    path: Path
    line: int
    excerpt: str


def _category_matches(relative: str, inventory: dict) -> tuple[str, ...]:
    return tuple(
        category
        for category in ("current", "target", "historical", "instruction_system")
        if any(fnmatch.fnmatch(relative, pattern) for pattern in inventory[category])
    )


def select_current_paths(
    repo_root: Path,
    manifest: dict,
    repository_files: list[Path],
    limits: ScanLimits,
) -> tuple[Path, ...]:
    inventory = manifest.get("documentation_inventory")
    if not isinstance(inventory, dict):
        raise ClaimsGuardError("manifest missing documentation_inventory")
    selected: list[Path] = []
    for path in repository_files:
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError as error:
            raise ClaimsGuardError(f"{path}: path is outside repository") from error
        matches = _category_matches(relative, inventory)
        if len(matches) > 1:
            raise ClaimsGuardError(f"{relative}: multiple documentation categories")
        if matches != ("current",):
            continue
        if path.is_symlink():
            raise ClaimsGuardError(f"{relative}: symlink is not scannable")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ClaimsGuardError(f"{relative}: path resolution failed") from error
        if not resolved.is_relative_to(repo_root.resolve(strict=True)):
            raise ClaimsGuardError(f"{relative}: path resolves outside repository")
        if not resolved.is_file():
            raise ClaimsGuardError(f"{relative}: special file is not scannable")
        selected.append(path)
    if len(selected) > limits.max_files:
        raise ClaimsGuardError("selected file limit exceeded")
    return tuple(sorted(selected))


def read_text_source(
    path: Path,
    repo_root: Path,
    limits: ScanLimits,
    counters: dict[str, int],
) -> str:
    relative = path.relative_to(repo_root).as_posix()
    suffix = path.suffix.lower()
    if suffix in BINARY_SUFFIXES:
        counters["binary_files"] += 1
        return ""
    if suffix not in TEXT_SUFFIXES:
        raise ClaimsGuardError(f"{relative}: unsupported current-document suffix")
    try:
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise ClaimsGuardError(f"{relative}: source file limit exceeded")
        with path.open("rb") as source_file:
            payload = source_file.read(limits.max_file_bytes + 1)
    except OSError as error:
        raise ClaimsGuardError(f"{relative}: source read failed") from error
    if len(payload) > limits.max_file_bytes:
        raise ClaimsGuardError(f"{relative}: source file limit exceeded")
    counters["source_bytes"] += len(payload)
    if counters["source_bytes"] > limits.max_source_bytes:
        raise ClaimsGuardError("aggregate source limit exceeded")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClaimsGuardError(f"{relative}: source is not valid UTF-8") from error
```

- [ ] **Step 4: Add and run remaining preflight tests**

Add these concrete resource/input tests, plus the analogous aggregate counter assertion:

```python
@pytest.mark.parametrize(
    ("name", "payload", "message"),
    [
        ("claims.rst", b"unsafe", "unsupported current-document suffix"),
        ("claims.md", b"\xff", "source is not valid UTF-8"),
        ("claims.md", b"12345", "source file limit exceeded"),
    ],
)
def test_read_text_source_rejects_unsupported_invalid_and_oversized(
    tmp_path,
    name,
    payload,
    message,
):
    path = tmp_path / name
    path.write_bytes(payload)
    limits = ScanLimits(max_file_bytes=4)
    counters = {"source_bytes": 0, "binary_files": 0}

    with pytest.raises(ClaimsGuardError, match=message):
        read_text_source(path, tmp_path, limits, counters)


def test_read_text_source_accounts_for_binary_without_decoding(tmp_path):
    path = tmp_path / "diagram.png"
    path.write_bytes(b"\x89PNG\r\n")
    counters = {"source_bytes": 0, "binary_files": 0}

    assert read_text_source(path, tmp_path, ScanLimits(), counters) == ""
    assert counters == {"source_bytes": 0, "binary_files": 1}


def test_read_text_source_enforces_aggregate_limit(tmp_path):
    first = tmp_path / "first.md"
    second = tmp_path / "second.md"
    first.write_text("123", encoding="utf-8")
    second.write_text("456", encoding="utf-8")
    counters = {"source_bytes": 0, "binary_files": 0}
    limits = ScanLimits(max_source_bytes=5)

    assert read_text_source(first, tmp_path, limits, counters) == "123"
    with pytest.raises(ClaimsGuardError, match="aggregate source limit"):
        read_text_source(second, tmp_path, limits, counters)
```

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k "select_current_paths or read_text_source" -v
```

Expected: all preflight tests pass.

- [ ] **Step 5: Commit Task 3**

```bash
git add scripts/check_evidence_claims.py tests/test_evidence_claims.py
git commit -m "test: define evidence claims guard preflight"
```

---

### Task 4: Public-Text Normalization and Block Extraction

**Files:**
- Modify: `scripts/check_evidence_claims.py`
- Modify: `tests/test_evidence_claims.py`

**Interfaces:**
- Consumes: `ScanLimits`, `TextBlock` from Task 3.
- Produces: `normalize_public_text(text: str) -> str`.
- Produces: `extract_document_blocks(path: Path, text: str, limits: ScanLimits, counters: dict[str, int]) -> tuple[TextBlock, ...]`.
- Consumers: Tasks 5 and 6 pass these blocks into `scan_claims`.

- [ ] **Step 1: Write failing normalization tests**

Add parameterized tests:

```python
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("immutable\u00a0storage", "immutable storage"),
        ("ｉｍｍｕｔａｂｌｅ storage", "immutable storage"),
        ("immut\u200bable storage", "immutable storage"),
        ("immut&#97;ble storage", "immutable storage"),
        ("[immutable storage](https://example.test)", "immutable storage"),
        ("![immutable evidence](diagram.png)", "immutable evidence"),
    ],
)
def test_normalize_public_text_closes_encoding_bypasses(source, expected):
    assert normalize_public_text(source) == expected


def test_extract_html_blocks_includes_visible_attributes(tmp_path):
    path = tmp_path / "public.html"
    blocks = extract_document_blocks(
        path,
        '<img alt="Immutable evidence"><div aria-label="Certified by AEGIS">Body</div>',
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    text = "\n".join(block.text for block in blocks)
    assert "Immutable evidence" in text
    assert "Certified by AEGIS" in text
    assert "Body" in text


def test_extract_svg_blocks_includes_title_desc_and_text(tmp_path):
    path = tmp_path / "diagram.svg"
    blocks = extract_document_blocks(
        path,
        "<svg><title>Hash chain</title><desc>Immutable storage</desc><text>AEGIS</text></svg>",
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [block.text for block in blocks] == [
        "Hash chain",
        "Immutable storage",
        "AEGIS",
    ]
```

- [ ] **Step 2: Run normalization tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k "normalize_public_text or extract_html_blocks or extract_svg_blocks" -v
```

Expected: import or name failures for the two new functions.

- [ ] **Step 3: Implement normalization and visible HTML/SVG extraction**

Use `unicodedata.normalize("NFKC", text)`, `html.unescape`, an explicit translation table for `\u200b`, `\u200c`, `\u200d`, and `\ufeff`, and bounded regexes that preserve Markdown labels/alt text while removing link targets. Implement an `HTMLParser` subclass that records data nodes and the public attributes `alt`, `aria-description`, `aria-label`, `placeholder`, and `title`. For SVG, the same parser retains `text`, `title`, and `desc` data nodes.

The final function must enforce both ceilings before appending a block:

```python
def _bounded_block(
    path: Path,
    line: int,
    text: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> TextBlock | None:
    normalized = normalize_public_text(text)
    if not normalized:
        return None
    encoded_size = len(normalized.encode("utf-8"))
    if encoded_size > limits.max_normalized_block_bytes:
        raise ClaimsGuardError(f"{path}: normalized block limit exceeded")
    counters["normalized_bytes"] += encoded_size
    counters["public_blocks"] += 1
    if counters["normalized_bytes"] > limits.max_normalized_bytes:
        raise ClaimsGuardError("aggregate normalized text limit exceeded")
    if counters["public_blocks"] > limits.max_public_blocks:
        raise ClaimsGuardError("public copy block limit exceeded")
    return TextBlock(path=path, line=line, text=normalized)
```

- [ ] **Step 4: Add resource and adjacent-block extraction tests**

Add these exact ceiling and boundary tests:

```python
@pytest.mark.parametrize(
    ("limits", "message"),
    [
        (ScanLimits(max_normalized_block_bytes=3), "normalized block limit"),
        (ScanLimits(max_normalized_bytes=3), "aggregate normalized text limit"),
        (ScanLimits(max_public_blocks=0), "public copy block limit"),
    ],
)
def test_extract_document_blocks_enforces_normalized_limits(
    tmp_path,
    limits,
    message,
):
    path = tmp_path / "public.md"
    with pytest.raises(ClaimsGuardError, match=message):
        extract_document_blocks(
            path,
            "four",
            limits,
            {"normalized_bytes": 0, "public_blocks": 0},
        )


def test_extract_document_blocks_preserves_adjacent_markdown_lines(tmp_path):
    path = tmp_path / "public.md"
    blocks = extract_document_blocks(
        path,
        "# Hash chaining\n\nMakes storage immutable.\n",
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [(block.line, block.text) for block in blocks] == [
        (1, "Hash chaining"),
        (3, "Makes storage immutable."),
    ]


def test_extract_html_blocks_scans_source_and_visible_copy(tmp_path):
    path = tmp_path / "public.html"
    blocks = extract_document_blocks(
        path,
        '<meta name="description" content="AEGIS evidence"><p>Public claim</p>',
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert any("AEGIS evidence" in block.text for block in blocks)
    assert any(block.text == "Public claim" for block in blocks)
```

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k "normalize or extract or block" -v
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit Task 4**

```bash
git add scripts/check_evidence_claims.py tests/test_evidence_claims.py
git commit -m "feat: normalize maintained evidence claims copy"
```

---

### Task 5: Contextual Evidence-Claims Policy

**Files:**
- Modify: `scripts/check_evidence_claims.py`
- Modify: `tests/test_evidence_claims.py`

**Interfaces:**
- Consumes: `TextBlock`, `ClaimFinding` from Task 3.
- Produces: `scan_claims(blocks: tuple[TextBlock, ...]) -> tuple[ClaimFinding, ...]`.
- Rule IDs: `INTEGRITY_IS_STORAGE`, `CHECKPOINT_OVERCLAIM`, `AEGIS_CERTIFICATION_CLAIM`, `IMMUTABLE_EVIDENCE_RECORD`.
- Consumers: Task 6 prints findings and maps them to exit code 1.

- [ ] **Step 1: Write the unsafe/safe policy matrix**

Add parameterized unsafe tests:

```python
@pytest.mark.parametrize(
    ("rule_id", "text"),
    [
        ("INTEGRITY_IS_STORAGE", "Checksums make the audit log immutable."),
        ("INTEGRITY_IS_STORAGE", "Hash chaining guarantees WORM evidence."),
        ("INTEGRITY_IS_STORAGE", "Signatures make records deletion-proof."),
        ("CHECKPOINT_OVERCLAIM", "A trusted checkpoint proves this is the latest record."),
        ("CHECKPOINT_OVERCLAIM", "Checkpoint-proven means no later activity occurred."),
        ("AEGIS_CERTIFICATION_CLAIM", "AEGIS provides certified compliance evidence."),
        ("AEGIS_CERTIFICATION_CLAIM", "The AEGIS export is regulatory-ready."),
        ("AEGIS_CERTIFICATION_CLAIM", "AEGIS records are legally admissible."),
        ("IMMUTABLE_EVIDENCE_RECORD", "Each invocation produces an immutable audit record."),
        ("INTEGRITY_IS_STORAGE", "Not only does hash chaining provide immutable storage."),
        ("INTEGRITY_IS_STORAGE", "Hash chaining does not merely help; it guarantees immutable storage."),
        ("INTEGRITY_IS_STORAGE", "Hash chaining does not fail to guarantee immutable storage."),
    ],
)
def test_scan_claims_rejects_overclaims(tmp_path, rule_id, text):
    findings = scan_claims((TextBlock(tmp_path / "public.md", 7, text),))
    assert [finding.rule_id for finding in findings] == [rule_id]
    assert findings[0].line == 7
```

Add safe tests:

```python
@pytest.mark.parametrize(
    "text",
    [
        "Hash chaining provides tamper-evidence, not immutable storage.",
        "Checksums alone do not make storage WORM.",
        "A checkpoint does not prove latest retrieval or compliance.",
        "The immutable Python tuple contains approved algorithms.",
        "Retain the exact immutable CryptoKeyVersion identifier.",
        "Run aegis compliance export to create a technical report.",
        "Azure immutable storage is an illustrative and non-normative provider example.",
    ],
)
def test_scan_claims_accepts_bounded_language(tmp_path, text):
    assert scan_claims((TextBlock(tmp_path / "public.md", 1, text),)) == ()
```

- [ ] **Step 2: Run policy tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k scan_claims -v
```

Expected: import or name failure for `scan_claims`.

- [ ] **Step 3: Implement immutable module-level policy data and matching**

Define only bounded compiled patterns. Use subject/predicate pairing rather than banning words globally:

```python
import re


INTEGRITY_SUBJECT = re.compile(
    r"\b(?:checksums?|signatures?|hash(?:[- ]?chains?| chaining))\b",
    re.IGNORECASE,
)
CHECKPOINT_SUBJECT = re.compile(
    r"\b(?:(?:trusted|chain|workflow) )?checkpoints?\b|\bcheckpoint[- ]proven\b",
    re.IGNORECASE,
)
AEGIS_SUBJECT = re.compile(
    r"\bAEGIS\b|\bAEGIS (?:APIs?|exports?|reports?|records?|evidence)\b",
    re.IGNORECASE,
)
EVIDENCE_RECORD_SUBJECT = re.compile(
    r"\b(?:audit|invocation|workflow|evidence) (?:artifacts?|records?|logs?)\b",
    re.IGNORECASE,
)
PROVIDER_SUBJECT = re.compile(
    r"\b(?:Amazon S3|AWS|Azure|Google Cloud|Cloud Storage|storage provider)\b",
    re.IGNORECASE,
)
STORAGE_PREDICATE = re.compile(
    r"\b(?:immutable|immutability|append[- ]only|WORM|unalterable|indelible|"
    r"tamper[- ]proof|deletion[- ]proof|cannot be (?:changed|deleted|modified|rewritten))\b",
    re.IGNORECASE,
)
CERTIFICATION_PREDICATE = re.compile(
    r"\b(?:certified|certification|compliant|guaranteed compliance|audit[- ]ready|"
    r"regulatory[- ]ready|regulatory approval|legally (?:admissible|sufficient))\b",
    re.IGNORECASE,
)
CHECKPOINT_EXCESS_PREDICATE = re.compile(
    r"\b(?:latest retrieval|latest record|no later activity|future inactivity|"
    r"immutable storage|WORM storage|certification|compliance)\b",
    re.IGNORECASE,
)
PSEUDO_NEGATION = re.compile(
    r"\b(?:not only|does not merely|do not merely|cannot merely|"
    r"does not fail to|do not fail to|cannot fail to)\b",
    re.IGNORECASE,
)
BOUNDED_NEGATIVE = re.compile(
    r"\b(?:(?:do|does) not|cannot|can not|never) (?:provide|create|make|guarantee|"
    r"establish|prove|constitute|mean)\b|\bprovides? tamper[- ]evidence, not\b|"
    r"\balone (?:do|does) not\b",
    re.IGNORECASE,
)
MAX_RELATION_DISTANCE = 400
```

Evaluate each block and each adjacent pair joined by one space, but emit a finding only when the end of a subject match and the start of its predicate match are no more than `MAX_RELATION_DISTANCE` characters apart (in either order). For an adjacent pair, retain the predicate block's path and line. Suppress a relation only when `BOUNDED_NEGATIVE` connects that same subject/predicate span; an unrelated negative elsewhere in the block must not suppress it, and `PSEUDO_NEGATION` always defeats suppression. For provider terminology, require a known provider subject, the phrase `illustrative and non-normative`, no `AEGIS_SUBJECT`, and no certification predicate. Attribute provider-label laundering by AEGIS to `IMMUTABLE_EVIDENCE_RECORD`. Deduplicate findings by `(rule_id, path, predicate_line)` and sort by path, line, then rule ID.

- [ ] **Step 4: Add split-block, markup, and bypass tests**

Add these exact contextual-evasion tests (the Task 4 normalization matrix already covers entities, full-width characters, zero-width separators, and Markdown image alt text):

```python
@pytest.mark.parametrize(
    ("blocks", "expected_rule"),
    [
        (
            (TextBlock(Path("public.md"), 1, "Hash chaining"),
             TextBlock(Path("public.md"), 3, "Makes storage immutable.")),
            "INTEGRITY_IS_STORAGE",
        ),
        (
            (TextBlock(Path("public.tsx"), 8, "AEGIS evidence"),
             TextBlock(Path("public.tsx"), 9, "is regulatory-ready.")),
            "AEGIS_CERTIFICATION_CLAIM",
        ),
        (
            (TextBlock(Path("public.md"), 1, "Hash chaining does not merely help;"),
             TextBlock(Path("public.md"), 2, "it guarantees immutable storage.")),
            "INTEGRITY_IS_STORAGE",
        ),
        (
            (TextBlock(Path("public.md"), 1, "AEGIS uses Azure immutable storage"),
             TextBlock(Path("public.md"), 2, "as an illustrative and non-normative example.")),
            "IMMUTABLE_EVIDENCE_RECORD",
        ),
    ],
)
def test_scan_claims_rejects_split_and_laundered_claims(blocks, expected_rule):
    assert expected_rule in {finding.rule_id for finding in scan_claims(blocks)}


@pytest.mark.parametrize(
    "blocks",
    [
        (
            TextBlock(Path("public.md"), 1, "Hash chaining does not make"),
            TextBlock(Path("public.md"), 2, "storage immutable."),
        ),
        (
            TextBlock(Path("public.md"), 1, "AEGIS does not provide"),
            TextBlock(Path("public.md"), 2, "certified compliance evidence."),
        ),
        (
            TextBlock(Path("public.md"), 1, "Do not delete this section."),
            TextBlock(Path("public.md"), 2, "Hash chaining guarantees immutable storage."),
        ),
        (
            TextBlock(Path("public.md"), 1, "Hash chaining " + "context " * 60),
            TextBlock(Path("public.md"), 2, "Immutable storage is a separate host control."),
        ),
    ],
)
def test_scan_claims_handles_adjacent_negation_without_unrelated_suppression(blocks):
    findings = scan_claims(blocks)
    if blocks[0].text == "Do not delete this section.":
        assert [finding.rule_id for finding in findings] == ["INTEGRITY_IS_STORAGE"]
    else:
        assert findings == ()
```

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k "claims or overclaim or bounded_language or split" -v
```

Expected: all selected tests pass with exact rule IDs and predicate-bearing line numbers.

- [ ] **Step 5: Commit Task 5**

```bash
git add scripts/check_evidence_claims.py tests/test_evidence_claims.py
git commit -m "feat: reject evidence assurance overclaims"
```

---

### Task 6: End-to-End Claims Guard and Diagnostics

**Files:**
- Modify: `scripts/check_evidence_claims.py`
- Modify: `tests/test_evidence_claims.py`

**Interfaces:**
- Consumes: inventory helpers from Task 1, React helpers from Task 2, and guard functions from Tasks 3–5.
- Produces: `ScanResult`.
- Produces: `run_guard(repo_root: Path = REPO_ROOT, frontend_root: Path = FRONTEND_ROOT, limits: ScanLimits = ScanLimits()) -> ScanResult`.
- Produces: `main(argv: list[str] | None = None) -> int` with exit codes 0 clean, 1 claim findings, and 2 infrastructure/configuration failure.

- [ ] **Step 1: Write failing orchestration and CLI tests**

Add tests that monkeypatch the imported inventory and React helpers:

```python
def test_main_returns_one_and_prints_bounded_finding(monkeypatch, capsys, tmp_path):
    finding = ClaimFinding(
        rule_id="INTEGRITY_IS_STORAGE",
        path=Path("README.md"),
        line=4,
        excerpt="Hash chaining makes storage immutable.",
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.run_guard",
        lambda **_kwargs: ScanResult(findings=(finding,), scanned_files=1, binary_files=0),
    )

    assert main([]) == 1
    assert "INTEGRITY_IS_STORAGE: README.md:4" in capsys.readouterr().out


def test_main_returns_two_on_infrastructure_failure(monkeypatch, capsys):
    def fail(**_kwargs):
        raise ClaimsGuardError("React extraction failed")

    monkeypatch.setattr("scripts.check_evidence_claims.run_guard", fail)

    assert main([]) == 2
    assert "claims guard failed: React extraction failed" in capsys.readouterr().err


def test_run_guard_requires_mandatory_current_paths(tmp_path, monkeypatch):
    manifest = _manifest("docs/**")
    monkeypatch.setattr("scripts.check_evidence_claims.load_manifest", lambda: manifest)
    monkeypatch.setattr("scripts.check_evidence_claims.check_documentation_inventory", lambda _manifest: [])
    monkeypatch.setattr("scripts.check_evidence_claims.collect_repository_files", lambda **_kwargs: [])

    with pytest.raises(ClaimsGuardError, match="mandatory current path"):
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")
```

- [ ] **Step 2: Run orchestration tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -k "main_returns or run_guard" -v
```

Expected: failures because `ScanResult`, `run_guard`, and `main` are not defined.

- [ ] **Step 3: Implement orchestration and exact exit behavior**

Add:

```python
from scripts.check_demo_copy import (
    extract_frontend_public_copy,
    iter_frontend_public_files,
)
from scripts.check_doc_parity import (
    check_documentation_inventory,
    collect_repository_files,
    load_manifest,
)


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[ClaimFinding, ...]
    scanned_files: int
    binary_files: int


def _display_path(path: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        result = run_guard()
    except ClaimsGuardError as error:
        print(f"claims guard failed: {error}", file=sys.stderr)
        return 2
    for finding in result.findings:
        display = _display_path(finding.path)
        print(f"{finding.rule_id}: {display}:{finding.line}: {finding.excerpt}")
    if result.findings:
        return 1
    print(
        "PASS: evidence claims guard scanned "
        f"{result.scanned_files} text files and accounted for "
        f"{result.binary_files} binary files"
    )
    return 0
```

`run_guard` must perform this order: load manifest; validate documentation inventory; enumerate with `require_git=True`; select current paths; verify every mandatory path resolves to current; read and extract current document blocks; preflight React file count and source bytes; call `extract_frontend_public_copy(frontend_paths, max_output_bytes=limits.max_extractor_bytes)`; convert NUL-separated React documents into line-preserving `TextBlock` values; enforce normalized block limits; call `scan_claims`; return a sorted `ScanResult`. The mandatory set is the union of `MANDATORY_CURRENT_PATHS` and every string in `manifest["parity_docs"]`, so parity authorities cannot silently leave scan scope.

Wrap `OSError`, `UnicodeError`, `subprocess.SubprocessError`, `json.JSONDecodeError`, `ValueError`, and inventory errors as bounded `ClaimsGuardError` messages. Do not include raw extractor output or unbounded exception payloads.

- [ ] **Step 4: Complete failure-isolation and real-repository tests**

Add failure-isolation tests by monkeypatching one boundary at a time: `load_manifest` raises malformed YAML/configuration errors; `check_documentation_inventory` returns an error; `collect_repository_files` raises Git failure; `iter_frontend_public_files` raises `OSError`; and `extract_frontend_public_copy` raises `FileNotFoundError`, `subprocess.CalledProcessError`, `json.JSONDecodeError`, or returns an oversized serialized/normalized document. Every case must assert a bounded `ClaimsGuardError` message that does not echo child-process output.

Add this end-to-end fixture test now; it proves orchestration without requiring the not-yet-created canonical guide in the real checkout:

```python
def test_run_guard_scans_fixture_documents_and_react_copy(tmp_path, monkeypatch):
    current = sorted(MANDATORY_CURRENT_PATHS | {"CHANGELOG.md"})
    for relative in current:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Bounded tamper-evidence language.\n", encoding="utf-8")
    frontend = tmp_path / "demo-app-react" / "src"
    react_path = frontend / "Visible.tsx"
    react_path.parent.mkdir(parents=True)
    react_path.write_text("export const copy = 'Checksums make storage immutable.'", encoding="utf-8")
    manifest = _manifest(*current)
    manifest["parity_docs"] = ["README.md", "SECURITY.md"]
    repository_files = [tmp_path / relative for relative in current]

    monkeypatch.setattr("scripts.check_evidence_claims.load_manifest", lambda: manifest)
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        lambda _manifest: [],
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        lambda **_kwargs: repository_files,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.iter_frontend_public_files",
        lambda _root: iter((react_path,)),
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {
            react_path: "Checksums make storage immutable."
        },
    )

    result = run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert [finding.rule_id for finding in result.findings] == ["INTEGRITY_IS_STORAGE"]
    assert result.findings[0].path == react_path
    assert result.scanned_files == len(current) + 1


def test_run_guard_sorts_and_bounds_findings(tmp_path, monkeypatch):
    # Reuse the fixture above, but return two unsafe documents in reverse path order.
    first = TextBlock(Path("a.md"), 2, "Hash chaining guarantees immutable storage.")
    second = TextBlock(Path("z.md"), 8, "AEGIS provides certified compliance evidence.")
    findings = scan_claims((second, first))

    assert [(finding.path.as_posix(), finding.line) for finding in findings] == [
        ("a.md", 2),
        ("z.md", 8),
    ]
    assert all(len(finding.excerpt.encode("utf-8")) <= 240 for finding in findings)
```

Run:

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py -v
```

Expected: all unit, boundary-failure, and fixture-repository tests pass. Do not scan the real checkout yet: its mandatory guide does not exist until Task 7, and its known React overclaims are corrected in Task 8.

- [ ] **Step 5: Commit Task 6**

```bash
git add scripts/check_evidence_claims.py tests/test_evidence_claims.py
git commit -m "feat: add maintained evidence claims guard"
```

---

### Task 7: Canonical Append-Only Evidence Operations Guide

**Files:**
- Create: `docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md`
- Create: `tests/test_append_only_evidence_guidance.py`

**Interfaces:**
- Consumes: exact #44/ADR-0012 and #46/ADR-0015 contracts documented in the approved specification.
- Produces: the one canonical maintained operator guide linked by Task 8.
- Produces: guide-contract tests used by final verification.

- [ ] **Step 1: Write failing guide-contract tests**

Create:

```python
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _normalized() -> str:
    return " ".join(_guide().lower().split())


def test_guide_has_complete_operational_lifecycle():
    text = _guide()
    for heading in (
        "## Assurance model",
        "## Provider-neutral reference architecture",
        "## Ownership matrix",
        "## Retention and object locking",
        "## Ingest verification",
        "## Least privilege",
        "## Trusted checkpoint operations",
        "## Monitoring",
        "## Export verification",
        "## Backup and disaster recovery",
        "## Key rotation",
        "## Revocation",
        "## Suspected or confirmed compromise",
        "## Provider outage",
        "## Non-normative provider examples",
    ):
        assert heading in text


def test_guide_freezes_aegis_and_host_ownership_boundaries():
    normalized = _normalized()
    for phrase in (
        "aegis does not create or operate durable storage",
        "latest-checkpoint selection",
        "checkpointed_at is signed but host-supplied",
        "jsonfileauditsink",
        "issue #58",
        "adr-0012",
        "adr-0015",
        "checkpoint_proven",
        "illustrative and non-normative",
    ):
        assert phrase in normalized


def test_guide_separates_all_five_assurance_properties():
    normalized = _normalized()
    for phrase in (
        "tamper-evidence",
        "external anchoring",
        "checkpoint-backed completeness",
        "append-only/worm retention",
        "legal/compliance status",
    ):
        assert phrase in normalized
```

- [ ] **Step 2: Run guide tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py -v
```

Expected: three failures because the guide file does not exist.

- [ ] **Step 3: Write the canonical guide from the approved specification**

Use the exact headings frozen above. Include:

- the provider-neutral ASCII flow from finalized evidence through quarantine, protected storage, independent checkpoints, export, and recovery;
- the four-column ownership matrix for AEGIS, host/provider, and organization;
- evidence-set inventory including historical verifier material and control-plane audit evidence;
- pre-finalization data minimization and confidentiality/erasure warnings;
- unique validated object-key requirements;
- ingest and export ordered checklists;
- role separation for writer, verifier, checkpoint authority, retention admin, recovery operator, and break glass;
- monitoring of write/delete/policy/key/checkpoint/read/export/backup events;
- restore-to-quarantine and promotion checklist;
- exact planned-rotation, revocation, compromise, and outage runbooks;
- five-axis assurance table;
- provider appendix naming S3 Object Lock, Cloud Storage retention/Bucket Lock, and Azure immutable-storage policies only as illustrative and non-normative examples.

Copy the exact `0.9.0b1` versus current-source distinction and the exact #58 disclaimer from the design specification. Do not add provider configuration commands.

- [ ] **Step 4: Run guide and parity tests**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py -v
.venv/bin/python scripts/check_doc_parity.py
```

Expected: all guide tests pass and the new `docs/reference/**` file is classified current automatically.

- [ ] **Step 5: Commit Task 7**

```bash
git add docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md tests/test_append_only_evidence_guidance.py
git commit -m "docs: add append-only evidence operations guide"
```

---

### Task 8: Maintained Cross-Links and Public-Copy Corrections

**Files:**
- Modify: `tests/test_append_only_evidence_guidance.py`
- Modify: `README.md:45-55,113-127,160-172`
- Modify: `SECURITY.md:40-49`
- Modify: `CHANGELOG.md:15-36`
- Modify: `docs/USAGE.md:414-463`
- Modify: `docs/INTEGRATION_GUIDE.md:755-793`
- Modify: `docs/PUBLIC_INTEGRATION_CONTRACT.md:1060-1080,1130-1150`
- Modify: `docs/architecture/AEGIS_THREAT_MODEL.md:453-471,490-504`
- Modify: `docs/reference/OPERATIONS_RUNBOOK.md:1-20,130-149`
- Modify: `docs/reference/external/AWS_KMS_SIGNING.md:149-179`
- Modify: `docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md:164-199`
- Modify: `demo-app-react/src/help/helpContent.ts:80-90,447-456`
- Modify: `demo-app-react/src/help/helpContent.test.ts`

**Interfaces:**
- Consumes: canonical guide from Task 7 and claims guard from Task 6.
- Produces: discoverable maintained guidance and a clean real-repository claims scan.

- [ ] **Step 1: Write failing link and React-copy tests**

Add exact link mappings:

```python
def test_maintained_entry_points_link_to_canonical_guide():
    expected = {
        "README.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "SECURITY.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "CHANGELOG.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/USAGE.md": "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/INTEGRATION_GUIDE.md": "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md": "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/architecture/AEGIS_THREAT_MODEL.md": "../reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/reference/OPERATIONS_RUNBOOK.md": "APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/reference/external/AWS_KMS_SIGNING.md": "../APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md": "../APPEND_ONLY_EVIDENCE_OPERATIONS.md",
    }
    for relative, target in expected.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert target in text, f"{relative} must link {target}"


def test_react_help_uses_finalized_not_immutable_record_language():
    text = (ROOT / "demo-app-react/src/help/helpContent.ts").read_text(encoding="utf-8")
    normalized = " ".join(text.lower().split())
    assert "immutable per-attempt record" not in normalized
    assert "immutable record produced" not in normalized
    assert "finalized per-attempt record" in normalized
    assert "finalized record produced" in normalized


def test_real_repository_claims_guard_is_clean():
    from scripts.check_evidence_claims import run_guard

    assert run_guard().findings == ()
```

Add a Vitest assertion in `helpContent.test.ts` that both glossary definitions contain `finalized` and neither contains `immutable record`.

- [ ] **Step 2: Run cross-link and React tests and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py -k "entry_points or react_help" -v
npm --prefix demo-app-react test -- --run src/help/helpContent.test.ts
```

Expected: Python link/copy tests and the real-repository clean assertion fail; the new Vitest assertion fails on both old definitions. The claims guard should report the two known React help-copy findings, not an infrastructure error.

- [ ] **Step 3: Add concise links and bounded summaries**

At each checkpoint or signing boundary, add one short paragraph linking the canonical guide. Use this exact common claim shape, adjusted only for the relative link:

```markdown
For host-owned retention, object locking, checkpoint selection, historical
verification, backup, and recovery, see the
[Append-Only Evidence Operations Guide](relative/path.md). Checksums, signatures,
hash chains, and checkpoints provide bounded verification results; they do not
make AEGIS storage immutable or establish certification or compliance.
```

In README and CHANGELOG, preserve the released-beta/current-source distinction. In SECURITY, state that storage-control or evidence-handling vulnerabilities may be reported but host storage configuration remains outside the AEGIS runtime boundary. In both KMS guides, link from rotation/revocation and assurance limits without duplicating the full runbook.

Replace the two React definitions with:

```typescript
{ term: 'Invocation artifact', definition: 'The finalized per-attempt record produced after enforcement. It contains checksums, policy metadata, result, and supporting evidence.' }
{ term: 'Audit artifact', definition: 'The finalized record produced by each enforcement call. It carries the result plus evidence such as checksums, metadata, and optional signature.' }
```

- [ ] **Step 4: Run cross-link, React, claims, and parity checks**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py tests/test_demo_copy_policy.py -q
npm --prefix demo-app-react test -- --run src/help/helpContent.test.ts
.venv/bin/python scripts/check_evidence_claims.py
.venv/bin/python scripts/check_doc_parity.py
```

Expected: all commands pass; the claims guard reports zero findings.

- [ ] **Step 5: Commit Task 8**

```bash
git add README.md SECURITY.md CHANGELOG.md docs/USAGE.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/architecture/AEGIS_THREAT_MODEL.md docs/reference/OPERATIONS_RUNBOOK.md docs/reference/external/AWS_KMS_SIGNING.md docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md demo-app-react/src/help/helpContent.ts demo-app-react/src/help/helpContent.test.ts tests/test_append_only_evidence_guidance.py
git commit -m "docs: bound public evidence assurance claims"
```

---

### Task 9: Pull-Request, Release, and Demo CI Enforcement

**Files:**
- Modify: `tests/test_append_only_evidence_guidance.py`
- Modify: `.github/workflows/security-boundaries.yml:7-30`
- Modify: `.github/workflows/publish.yml:14-38`
- Modify: `.github/workflows/deploy-demo-react.yml:25-74`

**Interfaces:**
- Consumes: `python scripts/check_evidence_claims.py` from Task 6.
- Produces: one dedicated non-matrix PR/push job and release/demo guard steps using the same command.

- [ ] **Step 1: Write failing workflow-contract tests**

Add:

```python
def test_claims_guard_is_wired_into_all_required_workflows():
    security = (ROOT / ".github/workflows/security-boundaries.yml").read_text(encoding="utf-8")
    publish = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    demo = (ROOT / ".github/workflows/deploy-demo-react.yml").read_text(encoding="utf-8")

    assert "evidence-claims:" in security
    assert "runs-on: ubuntu-latest" in security.split("evidence-claims:", 1)[1]
    for workflow in (security, publish, demo):
        assert "python scripts/check_evidence_claims.py" in workflow
        assert "node-version: \"24\"" in workflow
        assert 'python -m pip install -e ".[dev]"' in workflow or ".[dev,aws-kms,gcp-kms]" in workflow
        assert "npm ci" in workflow
```

- [ ] **Step 2: Run the workflow test and verify failure**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py::test_claims_guard_is_wired_into_all_required_workflows -v
```

Expected: failure because none of the three workflows runs the comprehensive guard yet.

- [ ] **Step 3: Add the dedicated security-boundaries job**

Append this sibling job, not another matrix step:

```yaml
  evidence-claims:
    name: evidence claims
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: "24"
          cache: npm
          cache-dependency-path: demo-app-react/package-lock.json
      - name: Install Python validation dependencies
        run: python -m pip install -e ".[dev]"
      - name: Install frontend extraction dependencies
        working-directory: demo-app-react
        run: npm ci
      - name: Reject evidence assurance overclaims
        run: python scripts/check_evidence_claims.py
```

- [ ] **Step 4: Add release and demo workflow steps**

In `publish.yml`, add the same pinned Node setup after Python setup, run `npm ci` after Python dependencies, and add `python scripts/check_evidence_claims.py` to release validation.

In `deploy-demo-react.yml`, add `python -m pip install -e ".[dev]"` after Python setup and add the comprehensive guard immediately after the existing demo-copy check.

- [ ] **Step 5: Run workflow, guard, and YAML-adjacent tests**

Run:

```bash
.venv/bin/python -m pytest tests/test_append_only_evidence_guidance.py -q
.venv/bin/python scripts/check_evidence_claims.py
.venv/bin/python scripts/check_doc_parity.py
```

Expected: all commands pass and the workflow contract confirms all dependencies and commands.

- [ ] **Step 6: Commit Task 9**

```bash
git add .github/workflows/security-boundaries.yml .github/workflows/publish.yml .github/workflows/deploy-demo-react.yml tests/test_append_only_evidence_guidance.py
git commit -m "ci: enforce maintained evidence claims"
```

---

### Task 10: Full Verification and Adversarial Completion Review

**Files:**
- Review: every file listed in Tasks 1–9
- Modify only when a review finding requires a correction.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: fresh verification evidence and a reviewed branch ready for publication workflow.

- [ ] **Step 1: Run focused Python tests**

```bash
.venv/bin/python -m pytest tests/test_evidence_claims.py tests/test_append_only_evidence_guidance.py tests/test_demo_copy_policy.py tests/test_doc_parity_v090_truth.py -q
```

Expected: all focused tests pass.

- [ ] **Step 2: Run both public-copy guards and documentation parity**

```bash
.venv/bin/python scripts/check_evidence_claims.py
.venv/bin/python scripts/check_demo_copy.py --frontend-root demo-app-react/src
.venv/bin/python scripts/check_doc_parity.py
```

Expected: both guards return 0 and documentation parity reports every section PASS.

- [ ] **Step 3: Run script syntax and style checks**

```bash
.venv/bin/python -m compileall scripts/check_evidence_claims.py scripts/check_demo_copy.py scripts/check_doc_parity.py
.venv/bin/python -m flake8 scripts/check_evidence_claims.py scripts/check_demo_copy.py
.venv/bin/python -m flake8 aegis
git diff --check
```

Expected: all commands return 0 with no whitespace errors.

- [ ] **Step 4: Run frontend verification**

```bash
npm --prefix demo-app-react test
npm --prefix demo-app-react run lint
npm --prefix demo-app-react run build
```

Expected: tests, lint, and production build all pass.

- [ ] **Step 5: Run the full Python suite**

```bash
.venv/bin/python -m pytest -q
```

Expected: the full suite passes with no new warning category or failure.

- [ ] **Step 6: Perform the completion self-review**

Review the staged range from `5de1cc9` through `HEAD` and map each #47 acceptance criterion to a file and passing test. Confirm:

- no runtime or schema file changed;
- the canonical guide covers every operational lifecycle section;
- all maintained entry points link rather than duplicate procedures;
- every current machine-readable doc and extracted React public string is in guard scope;
- `.gitignore` remains unstaged and unchanged by issue #47 commits;
- design and plan files remain historical, not current claim authority.

- [ ] **Step 7: Perform the completion adversarial review**

Re-run or inspect the exact attack matrix: same-admin checkpoint rollback, stale-checkpoint selection, host-supplied time misuse, destroyed historical key, WORM-secret retention, recovery into weaker controls, symlink/out-of-root input, newline filename, invalid UTF-8, unsupported suffix, missing Git/Node, oversized source/output/normalized text, HTML/SVG attributes, Markdown alt text, Unicode and zero-width evasion, split heading/body relation, “not only,” double-negative reframes, provider-label laundering, and AEGIS certification synonyms.

For every discovered issue, add a failing regression test first, implement the correction, and rerun Steps 1–5.

- [ ] **Step 8: Commit review corrections only if required**

When review produces changes:

```bash
git add scripts/check_evidence_claims.py scripts/check_demo_copy.py scripts/check_doc_parity.py tests/test_evidence_claims.py tests/test_append_only_evidence_guidance.py docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md README.md SECURITY.md CHANGELOG.md docs/USAGE.md docs/INTEGRATION_GUIDE.md docs/PUBLIC_INTEGRATION_CONTRACT.md docs/architecture/AEGIS_THREAT_MODEL.md docs/reference/OPERATIONS_RUNBOOK.md docs/reference/external/AWS_KMS_SIGNING.md docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md demo-app-react/src/help/helpContent.ts demo-app-react/src/help/helpContent.test.ts .github/workflows/security-boundaries.yml .github/workflows/publish.yml .github/workflows/deploy-demo-react.yml
git commit -m "fix: close issue 47 review findings"
```

When review produces no changes, do not create an empty commit.

- [ ] **Step 9: Record final branch state**

```bash
git status --short --branch
git log --oneline --decorate 5de1cc9..HEAD
```

Expected: only the user's pre-existing unstaged `.gitignore` modification remains; all issue #47 work is committed on `codex/issue-47-evidence-operations`.
