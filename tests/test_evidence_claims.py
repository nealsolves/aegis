from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter

import pytest
import yaml

from scripts import check_doc_parity
from scripts.check_evidence_claims import (
    MANDATORY_CURRENT_PATHS,
    ClaimFinding,
    ClaimsGuardError,
    ScanResult,
    ScanLimits,
    TextBlock,
    extract_document_blocks,
    main,
    normalize_public_text,
    read_text_source,
    run_guard,
    scan_claims,
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


def _guard_fixture(tmp_path, monkeypatch, *, document_text="Bounded language.\n"):
    current = sorted(MANDATORY_CURRENT_PATHS | {"CHANGELOG.md"})
    for relative in current:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document_text, encoding="utf-8")
    frontend = tmp_path / "demo-app-react" / "src"
    react_path = frontend / "Visible.tsx"
    react_path.parent.mkdir(parents=True)
    react_path.write_text(
        "export const copy = 'Bounded language.';",
        encoding="utf-8",
    )
    manifest = _manifest(*current)
    manifest["parity_docs"] = ["README.md", "CHANGELOG.md"]
    repository_files = [tmp_path / relative for relative in current]

    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: manifest,
    )
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
    return frontend, react_path, manifest, repository_files


def test_direct_script_runs_from_repository_root_without_pythonpath():
    repo_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [sys.executable, "scripts/check_evidence_claims.py"],
        cwd=repo_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    output_lines = completed.stdout.splitlines()
    assert len(output_lines) == 1
    assert output_lines[0].startswith("PASS: evidence claims guard scanned ")
    assert output_lines[0].endswith(" binary files")


def test_main_returns_one_and_prints_bounded_finding(monkeypatch, capsys):
    finding = ClaimFinding(
        rule_id="INTEGRITY_IS_STORAGE",
        path=Path("README.md"),
        line=4,
        excerpt="Hash chaining makes storage immutable.",
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.run_guard",
        lambda **_kwargs: ScanResult(
            findings=(finding,),
            scanned_files=1,
            binary_files=0,
        ),
    )

    assert main([]) == 1
    assert "INTEGRITY_IS_STORAGE: README.md:4" in capsys.readouterr().out


def test_main_reports_when_additional_findings_are_truncated(monkeypatch, capsys):
    """Fails if the CLI can silently print an unbounded findings stream."""
    findings = tuple(
        ClaimFinding(
            rule_id="INTEGRITY_IS_STORAGE",
            path=Path(f"docs/{index}.md"),
            line=1,
            excerpt="Hash chaining makes storage immutable.",
        )
        for index in range(2)
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.run_guard",
        lambda **_kwargs: ScanResult(
            findings=findings,
            scanned_files=3,
            binary_files=0,
            findings_truncated=True,
        ),
    )

    assert main([]) == 1
    output = capsys.readouterr().out.splitlines()
    assert len(output) == 3
    assert output[-1] == (
        "FINDINGS_TRUNCATED: displayed 2 findings; additional findings omitted"
    )


def test_main_prints_bounded_name_for_absolute_external_path(
    tmp_path,
    monkeypatch,
    capsys,
):
    finding = ClaimFinding(
        rule_id="INTEGRITY_IS_STORAGE",
        path=tmp_path / "Visible.tsx",
        line=9,
        excerpt="Checksums make storage immutable.",
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.run_guard",
        lambda **_kwargs: ScanResult(
            findings=(finding,),
            scanned_files=1,
            binary_files=0,
        ),
    )

    assert main([]) == 1
    output = capsys.readouterr().out
    assert "INTEGRITY_IS_STORAGE: Visible.tsx:9" in output
    assert tmp_path.as_posix() not in output


def test_main_returns_two_on_infrastructure_failure(monkeypatch, capsys):
    def fail(**_kwargs):
        raise ClaimsGuardError("React extraction failed")

    monkeypatch.setattr("scripts.check_evidence_claims.run_guard", fail)

    assert main([]) == 2
    assert (
        "claims guard failed: React extraction failed"
        in capsys.readouterr().err
    )


def test_main_returns_zero_and_prints_accounting(monkeypatch, capsys):
    monkeypatch.setattr(
        "scripts.check_evidence_claims.run_guard",
        lambda **_kwargs: ScanResult(
            findings=(),
            scanned_files=7,
            binary_files=2,
        ),
    )

    assert main([]) == 0
    assert (
        "scanned 7 text files and accounted for 2 binary files"
        in capsys.readouterr().out
    )


def test_run_guard_requires_mandatory_current_paths(tmp_path, monkeypatch):
    manifest = _manifest("docs/**")
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        lambda _manifest: [],
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        lambda **_kwargs: [],
    )

    with pytest.raises(ClaimsGuardError, match="mandatory current path"):
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")


def test_run_guard_requires_parity_docs_to_be_current(tmp_path, monkeypatch):
    manifest = _manifest(*MANDATORY_CURRENT_PATHS)
    manifest["parity_docs"] = ["CHANGELOG.md"]
    repository_files = []
    for relative in MANDATORY_CURRENT_PATHS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Bounded language.\n", encoding="utf-8")
        repository_files.append(path)
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        lambda _manifest: [],
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        lambda **_kwargs: repository_files,
    )

    with pytest.raises(ClaimsGuardError, match="CHANGELOG.md"):
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")


def test_run_guard_validates_parity_docs_after_git_and_selection(
    tmp_path,
    monkeypatch,
):
    manifest = _manifest()
    manifest["parity_docs"] = [42]
    calls = []
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        lambda _manifest: [],
    )

    def collect(*, require_git):
        calls.append(("collect", require_git))
        return []

    def select(repo_root, loaded_manifest, repository_files, limits):
        calls.append("select")
        assert repo_root == tmp_path
        assert loaded_manifest is manifest
        assert repository_files == []
        assert limits == ScanLimits()
        return ()

    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        collect,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.select_current_paths",
        select,
    )

    with pytest.raises(ClaimsGuardError, match="malformed parity_docs"):
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")

    assert calls == [("collect", True), "select"]


def test_main_bounds_malformed_inventory_pattern_failure(
    monkeypatch,
    capsys,
):
    manifest = _manifest()
    manifest["documentation_inventory"]["current"] = [42]
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: manifest,
    )
    monkeypatch.setattr(
        check_doc_parity,
        "collect_documentation_files",
        lambda: [check_doc_parity.REPO_ROOT / "README.md"],
    )

    assert main([]) == 2
    error = capsys.readouterr().err
    assert error == "claims guard failed: documentation inventory validation failed\n"
    assert "Traceback" not in error
    assert "42" not in error


def test_main_bounds_inventory_key_error(monkeypatch, capsys):
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: _manifest(),
    )

    def fail(_manifest):
        raise KeyError("SECRET inventory payload")

    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        fail,
    )

    assert main([]) == 2
    error = capsys.readouterr().err
    assert error == "claims guard failed: documentation inventory validation failed\n"
    assert "SECRET" not in error


def test_run_guard_scans_fixture_documents_and_react_copy(tmp_path, monkeypatch):
    frontend, react_path, _manifest_data, repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {
            react_path: "Checksums make storage immutable."
        },
    )

    result = run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert [finding.rule_id for finding in result.findings] == [
        "INTEGRITY_IS_STORAGE"
    ]
    assert result.findings[0].path == react_path
    assert result.scanned_files == len(repository_files) + 1
    assert result.binary_files == 0


def test_run_guard_scans_json_string_values_with_source_lines(
    tmp_path,
    monkeypatch,
):
    frontend, react_path, manifest, repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    json_path = (
        tmp_path
        / "docs/spec-driven-dev/changes/example/context.json"
    )
    json_path.parent.mkdir(parents=True)
    json_path.write_text(
        "{\n"
        '  "mechanism": "Hash chaining",\n'
        '  "claim": "Makes storage immutable."\n'
        "}\n",
        encoding="utf-8",
    )
    manifest["documentation_inventory"]["current"].append(
        "docs/spec-driven-dev/changes/example/**"
    )
    repository_files.append(json_path)
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {react_path: "Bounded language."},
    )

    result = run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert [
        (finding.rule_id, finding.path, finding.line)
        for finding in result.findings
    ] == [("INTEGRITY_IS_STORAGE", json_path, 3)]


def test_run_guard_preserves_react_block_source_lines(tmp_path, monkeypatch):
    frontend, react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {
            react_path: "\n\nHash chaining\0\n\nMakes storage immutable."
        },
    )

    result = run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert [(finding.rule_id, finding.line) for finding in result.findings] == [
        ("INTEGRITY_IS_STORAGE", 5)
    ]


def test_run_guard_counts_empty_react_segments_before_processing_next_block(
    tmp_path,
    monkeypatch,
):
    frontend, react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
        document_text="",
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {
            react_path: "\0\0\0SHOULD_NOT_BE_NORMALIZED"
        },
    )
    limits = ScanLimits(
        max_public_blocks=3,
        max_normalized_block_bytes=1,
    )

    with pytest.raises(ClaimsGuardError, match="public copy block limit"):
        run_guard(repo_root=tmp_path, frontend_root=frontend, limits=limits)


def test_run_guard_caps_retained_findings_and_marks_truncation(
    tmp_path,
    monkeypatch,
):
    """Fails if run_guard again retains every public-copy diagnostic."""
    frontend, react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
        document_text="Hash chaining makes storage immutable.\n",
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {react_path: "Bounded language."},
    )

    result = run_guard(
        repo_root=tmp_path,
        frontend_root=frontend,
        limits=ScanLimits(max_findings=2),
    )

    assert len(result.findings) == 2
    assert result.findings_truncated is True


def test_run_guard_passes_required_boundary_arguments(tmp_path, monkeypatch):
    frontend, react_path, manifest, repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    calls = []

    def load():
        calls.append("load")
        return manifest

    def inventory(loaded_manifest):
        calls.append("inventory")
        assert loaded_manifest is manifest
        return []

    def collect(*, require_git):
        calls.append(("collect", require_git))
        return repository_files

    def iterate(root):
        calls.append(("iterate", root))
        return iter((react_path,))

    def extract(paths, *, max_output_bytes):
        calls.append(("extract", paths, max_output_bytes))
        return {react_path: "Bounded language."}

    monkeypatch.setattr("scripts.check_evidence_claims.load_manifest", load)
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        inventory,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        collect,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.iter_frontend_public_files",
        iterate,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        extract,
    )
    limits = ScanLimits(max_extractor_bytes=1234)

    run_guard(repo_root=tmp_path, frontend_root=frontend, limits=limits)

    assert calls == [
        "load",
        "inventory",
        ("collect", True),
        ("iterate", frontend),
        ("extract", [react_path], 1234),
    ]


@pytest.mark.parametrize(
    ("boundary", "failure", "message"),
    [
        ("load_manifest", ValueError("SECRET manifest payload"), "manifest load"),
        (
            "load_manifest",
            yaml.YAMLError("SECRET malformed YAML payload"),
            "manifest load",
        ),
        (
            "collect_repository_files",
            RuntimeError("SECRET git payload"),
            "Git repository enumeration",
        ),
    ],
)
def test_run_guard_bounds_manifest_and_git_failures(
    tmp_path,
    monkeypatch,
    boundary,
    failure,
    message,
):
    if boundary != "load_manifest":
        monkeypatch.setattr(
            "scripts.check_evidence_claims.load_manifest",
            lambda: _manifest(),
        )
        monkeypatch.setattr(
            "scripts.check_evidence_claims.check_documentation_inventory",
            lambda _manifest: [],
        )

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(f"scripts.check_evidence_claims.{boundary}", fail)

    with pytest.raises(ClaimsGuardError, match=message) as captured:
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")

    assert "SECRET" not in str(captured.value)
    assert len(str(captured.value).encode("utf-8")) <= 120


def test_run_guard_rejects_inventory_errors_before_git(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "scripts.check_evidence_claims.load_manifest",
        lambda: _manifest(),
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.check_documentation_inventory",
        lambda _manifest: ["SECRET inventory payload" * 100],
    )

    def unexpected_collect(**_kwargs):
        raise AssertionError("Git must not run after invalid inventory")

    monkeypatch.setattr(
        "scripts.check_evidence_claims.collect_repository_files",
        unexpected_collect,
    )

    with pytest.raises(ClaimsGuardError, match="inventory validation") as captured:
        run_guard(repo_root=tmp_path, frontend_root=tmp_path / "frontend")

    assert "SECRET" not in str(captured.value)


def test_run_guard_bounds_frontend_enumeration_failure(tmp_path, monkeypatch):
    frontend, _react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )

    def fail(_root):
        raise OSError("SECRET frontend path payload")

    monkeypatch.setattr(
        "scripts.check_evidence_claims.iter_frontend_public_files",
        fail,
    )

    with pytest.raises(ClaimsGuardError, match="frontend enumeration") as captured:
        run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert "SECRET" not in str(captured.value)


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("SECRET missing node"),
        subprocess.CalledProcessError(
            1,
            ["node", "extractor.mjs"],
            output=b"SECRET stdout",
            stderr=b"SECRET stderr",
        ),
        json.JSONDecodeError("SECRET JSON", "SECRET child output", 0),
    ],
)
def test_run_guard_bounds_frontend_extraction_failures(
    tmp_path,
    monkeypatch,
    failure,
):
    frontend, _react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )

    def fail(_paths, **_kwargs):
        raise failure

    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        fail,
    )

    with pytest.raises(ClaimsGuardError, match="frontend extraction") as captured:
        run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert "SECRET" not in str(captured.value)
    assert len(str(captured.value).encode("utf-8")) <= 120


@pytest.mark.parametrize(
    ("limits", "document", "message"),
    [
        (ScanLimits(max_extractor_bytes=4), "12345", "extractor output limit"),
        (
            ScanLimits(max_normalized_block_bytes=4),
            "12345",
            "normalized block limit",
        ),
    ],
)
def test_run_guard_rejects_oversized_extracted_documents(
    tmp_path,
    monkeypatch,
    limits,
    document,
    message,
):
    frontend, react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {react_path: document},
    )

    with pytest.raises(ClaimsGuardError, match=message):
        run_guard(repo_root=tmp_path, frontend_root=frontend, limits=limits)


def test_run_guard_bounds_oversized_parity_path_diagnostic(tmp_path, monkeypatch):
    frontend, _react_path, manifest, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    long_path = "SECRET_PARITY_PATH_" * 1_000 + ".md"
    manifest["parity_docs"] = [long_path]

    with pytest.raises(ClaimsGuardError) as captured:
        run_guard(repo_root=tmp_path, frontend_root=frontend)

    message = str(captured.value)
    assert len(message.encode("utf-8")) <= 120
    assert long_path not in message


@pytest.mark.parametrize(
    ("limits", "message"),
    [
        (ScanLimits(max_files=len(MANDATORY_CURRENT_PATHS) + 1), "file limit"),
        (ScanLimits(max_file_bytes=4), "source file limit"),
        (ScanLimits(max_source_bytes=4), "aggregate source limit"),
    ],
)
def test_run_guard_preflights_frontend_limits_before_extraction(
    tmp_path,
    monkeypatch,
    limits,
    message,
):
    frontend, _react_path, _manifest_data, _repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
        document_text="",
    )

    def unexpected_extract(_paths, **_kwargs):
        raise AssertionError("extractor must not run after failed preflight")

    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        unexpected_extract,
    )

    with pytest.raises(ClaimsGuardError, match=message):
        run_guard(repo_root=tmp_path, frontend_root=frontend, limits=limits)


def test_run_guard_accounts_for_binary_current_files(tmp_path, monkeypatch):
    frontend, react_path, manifest, repository_files = _guard_fixture(
        tmp_path,
        monkeypatch,
    )
    binary = tmp_path / "docs" / "diagram.png"
    binary.write_bytes(b"\x89PNG\r\n")
    manifest["documentation_inventory"]["current"].append("docs/diagram.png")
    repository_files.append(binary)
    monkeypatch.setattr(
        "scripts.check_evidence_claims.extract_frontend_public_copy",
        lambda _paths, **_kwargs: {react_path: "Bounded language."},
    )

    result = run_guard(repo_root=tmp_path, frontend_root=frontend)

    assert result.binary_files == 1
    assert result.scanned_files == len(repository_files)


def test_scan_claims_sorts_and_bounds_findings():
    first = TextBlock(Path("a.md"), 2, "Hash chaining guarantees immutable storage.")
    second = TextBlock(
        Path("z.md"),
        8,
        "AEGIS provides certified compliance evidence.",
    )
    findings = scan_claims((second, first))

    assert [(finding.path.as_posix(), finding.line) for finding in findings] == [
        ("a.md", 2),
        ("z.md", 8),
    ]
    assert all(len(finding.excerpt.encode("utf-8")) <= 240 for finding in findings)


def test_scan_claims_applies_an_explicit_aggregate_finding_cap():
    """Fails if direct policy evaluation can retain an unbounded result."""
    blocks = tuple(
        TextBlock(
            Path("public.md"),
            line,
            "Hash chaining makes storage immutable.",
        )
        for line in range(1, 5)
    )

    findings = scan_claims(blocks, max_findings=2)

    assert len(findings) == 2


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


def test_select_current_paths_rejects_malformed_inventory(tmp_path):
    path = tmp_path / "docs" / "claims.md"
    path.parent.mkdir()
    path.write_text("claims", encoding="utf-8")
    manifest = _manifest("docs/**")
    manifest["documentation_inventory"].pop("target")

    with pytest.raises(ClaimsGuardError, match="malformed documentation_inventory"):
        select_current_paths(tmp_path, manifest, [path], ScanLimits())


def test_select_current_paths_rejects_path_outside_repository(tmp_path):
    outside = tmp_path.parent / "outside.md"
    outside.write_text("outside", encoding="utf-8")

    with pytest.raises(ClaimsGuardError, match="path is outside repository"):
        select_current_paths(tmp_path, _manifest("**/*.md"), [outside], ScanLimits())


def test_select_current_paths_rejects_special_file(tmp_path):
    directory = tmp_path / "docs" / "directory.md"
    directory.mkdir(parents=True)

    with pytest.raises(ClaimsGuardError, match="special file"):
        select_current_paths(
            tmp_path,
            _manifest("docs/**"),
            [directory],
            ScanLimits(),
        )


@pytest.mark.parametrize(
    ("name", "payload", "message"),
    [
        ("claims.rst", b"unsafe", "unsupported current-document suffix"),
        ("claims.md", b"\xff", "source is not valid UTF-8"),
        ("claims.md", b"12345", "source file limit exceeded"),
        ("context.json", b"12345", "source file limit exceeded"),
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


def test_read_text_source_rejects_unreadable_binary_before_accounting(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "diagram.png"
    path.write_bytes(b"\x89PNG\r\n")
    original_mode = path.stat().st_mode
    try:
        path.chmod(0)
    except OSError:
        read_is_denied = False
        permissions_changed = False
    else:
        permissions_changed = True
        try:
            with path.open("rb"):
                pass
        except OSError:
            read_is_denied = True
        else:
            read_is_denied = False
    try:
        if not read_is_denied:
            original_open = Path.open

            def deny_binary_read(self, *args, **kwargs):
                if self == path:
                    raise PermissionError("read denied")
                return original_open(self, *args, **kwargs)

            monkeypatch.setattr(Path, "open", deny_binary_read)

        counters = {"source_bytes": 0, "binary_files": 0}
        with pytest.raises(ClaimsGuardError, match="source read failed"):
            read_text_source(path, tmp_path, ScanLimits(), counters)
        assert counters == {"source_bytes": 0, "binary_files": 0}
    finally:
        if permissions_changed:
            path.chmod(original_mode)


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


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "[immutable storage](https://example.test/Function_(math))",
            "immutable storage",
        ),
        ("![immutable evidence](diagram_(final).png)", "immutable evidence"),
        (
            "[immutable storage](https://example.test/Function_(math)",
            "[immutable storage](https://example.test/Function_(math)",
        ),
    ],
)
def test_normalize_public_text_removes_balanced_markdown_targets(source, expected):
    assert normalize_public_text(source) == expected


def test_normalize_public_text_preserves_unclosed_outer_markdown_target():
    source = "[outer](one [inner](two)"

    assert normalize_public_text(source) == source


def test_normalize_public_text_handles_adversarial_markdown_targets_linearly():
    """Fails if each Markdown marker restores a bounded forward rescan."""
    source = "](" * 11_000 + ")" * 11_000

    started = perf_counter()
    normalized = normalize_public_text(source)
    elapsed = perf_counter() - started

    assert normalized == source
    assert elapsed < 0.5


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

    assert [block.text for block in blocks if not block.text.startswith("<")] == [
        "Hash chain",
        "Immutable storage",
        "AEGIS",
    ]


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


def test_extract_document_blocks_adds_normalized_html_source_by_line(tmp_path):
    path = tmp_path / "public.html"
    blocks = extract_document_blocks(
        path,
        '<meta name="description" content="AEGIS evidence">\n<p>immut\u200bable evidence</p>',
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [(block.line, block.text) for block in blocks if block.text.startswith("<")] == [
        (1, '<meta name="description" content="AEGIS evidence">'),
        (2, "<p>immutable evidence</p>"),
    ]


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (".md", "Hash **chaining** makes storage immutable."),
        (".md", "Hash _chaining_ makes storage immutable."),
        (".md", "Hash <em>chaining</em> makes storage immutable."),
        (".html", "<p>Hash <em>chaining</em> makes storage immutable.</p>"),
        (".svg", "<text>Hash <tspan>chaining</tspan> makes storage immutable.</text>"),
    ],
)
def test_extract_document_blocks_joins_inline_visible_text_for_claims(
    tmp_path,
    suffix,
    source,
):
    """Fails if inline formatting can split a policy subject or predicate."""
    path = tmp_path / f"public{suffix}"
    blocks = extract_document_blocks(
        path,
        source,
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [finding.rule_id for finding in scan_claims(blocks)] == [
        "INTEGRITY_IS_STORAGE"
    ]


def test_extract_html_blocks_retains_true_block_boundaries(tmp_path):
    """Fails if joining inline children also merges sibling paragraphs."""
    path = tmp_path / "public.html"
    blocks = extract_document_blocks(
        path,
        "<div><p>First sentence.</p><p>Second sentence.</p></div>",
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    visible = [block.text for block in blocks if "<" not in block.text]
    assert visible == ["First sentence.", "Second sentence."]


def test_extract_json_blocks_decodes_unicode_escapes_with_source_lines(tmp_path):
    """Fails if JSON is scanned as raw source instead of decoded values."""
    path = tmp_path / "public.json"
    blocks = extract_document_blocks(
        path,
        "{\n"
        '  "mechanism": "H\\u0061sh chaining",\n'
        '  "claim": "Makes storage immutable."\n'
        "}\n",
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [(block.line, block.text) for block in blocks] == [
        (2, "Hash chaining"),
        (3, "Makes storage immutable."),
    ]
    assert [(finding.rule_id, finding.line) for finding in scan_claims(blocks)] == [
        ("INTEGRITY_IS_STORAGE", 3)
    ]


def test_extract_json_blocks_rejects_malformed_input(tmp_path):
    """Fails if malformed maintained JSON can be treated as a clean scan."""
    path = tmp_path / "public.json"

    with pytest.raises(ClaimsGuardError, match="malformed JSON"):
        extract_document_blocks(
            path,
            '{"claim": "Hash chaining"',
            ScanLimits(),
            {"normalized_bytes": 0, "public_blocks": 0},
        )


def test_extract_json_blocks_scans_nested_string_values_not_keys(tmp_path):
    """Fails if nested JSON values disappear or object keys become copy."""
    path = tmp_path / "public.json"
    blocks = extract_document_blocks(
        path,
        '{"outer": {"values": ["Hash chaining", "Makes storage immutable."]}}',
        ScanLimits(),
        {"normalized_bytes": 0, "public_blocks": 0},
    )

    assert [block.text for block in blocks] == [
        "Hash chaining",
        "Makes storage immutable.",
    ]


def test_extract_json_blocks_enforces_public_block_limit(tmp_path):
    """Fails if decoded JSON strings bypass the shared block ceiling."""
    path = tmp_path / "public.json"

    with pytest.raises(ClaimsGuardError, match="public copy block limit"):
        extract_document_blocks(
            path,
            '["one", "two"]',
            ScanLimits(max_public_blocks=1),
            {"normalized_bytes": 0, "public_blocks": 0},
        )


@pytest.mark.parametrize(
    ("rule_id", "text"),
    [
        ("INTEGRITY_IS_STORAGE", "Checksums make the audit log immutable."),
        ("INTEGRITY_IS_STORAGE", "Hash chaining guarantees WORM evidence."),
        ("INTEGRITY_IS_STORAGE", "Signatures make records deletion-proof."),
        (
            "CHECKPOINT_OVERCLAIM",
            "A trusted checkpoint proves this is the latest record.",
        ),
        (
            "CHECKPOINT_OVERCLAIM",
            "Checkpoint-proven means no later activity occurred.",
        ),
        (
            "AEGIS_CERTIFICATION_CLAIM",
            "AEGIS provides certified compliance evidence.",
        ),
        ("AEGIS_CERTIFICATION_CLAIM", "The AEGIS export is regulatory-ready."),
        ("AEGIS_CERTIFICATION_CLAIM", "AEGIS records are legally admissible."),
        (
            "IMMUTABLE_EVIDENCE_RECORD",
            "Each invocation produces an immutable audit record.",
        ),
        (
            "INTEGRITY_IS_STORAGE",
            "Not only does hash chaining provide immutable storage.",
        ),
        (
            "INTEGRITY_IS_STORAGE",
            "Hash chaining does not merely help; it guarantees immutable storage.",
        ),
        (
            "INTEGRITY_IS_STORAGE",
            "Hash chaining does not fail to guarantee immutable storage.",
        ),
    ],
)
def test_scan_claims_rejects_overclaims(tmp_path, rule_id, text):
    findings = scan_claims((TextBlock(tmp_path / "public.md", 7, text),))

    assert [finding.rule_id for finding in findings] == [rule_id]
    assert findings[0].line == 7


@pytest.mark.parametrize(
    ("rule_id", "unsafe", "safe"),
    [
        (
            "IMMUTABLE_EVIDENCE_RECORD",
            "AEGIS evidence is immutable.",
            "AEGIS evidence is not immutable.",
        ),
        (
            "AEGIS_CERTIFICATION_CLAIM",
            "AEGIS guarantees compliance.",
            "AEGIS does not guarantee compliance.",
        ),
        (
            "INTEGRITY_IS_STORAGE",
            "Hash chaining makes evidence impossible to rewrite.",
            "Hash chaining does not make evidence impossible to rewrite.",
        ),
        (
            "CHECKPOINT_OVERCLAIM",
            "A checkpoint makes storage append-only.",
            "A checkpoint does not make storage append-only.",
        ),
        (
            "CHECKPOINT_OVERCLAIM",
            "A trusted checkpoint proves this is the newest record.",
            "A trusted checkpoint does not prove this is the newest record.",
        ),
        (
            "CHECKPOINT_OVERCLAIM",
            "A checkpoint proves no subsequent activity occurred.",
            "A checkpoint does not prove no subsequent activity occurred.",
        ),
        (
            "CHECKPOINT_OVERCLAIM",
            "A checkpoint proves this is the most-recent record.",
            "A checkpoint does not prove this is the most-recent record.",
        ),
        (
            "INTEGRITY_IS_STORAGE",
            "Hash-chaining makes evidence impossible-to-rewrite.",
            "Hash-chaining does not make evidence impossible-to-rewrite.",
        ),
    ],
)
def test_scan_claims_covers_direct_contract_claims_and_negated_forms(
    rule_id,
    unsafe,
    safe,
):
    """Fails if approved subject/predicate relationships are narrowed again."""
    unsafe_findings = scan_claims((TextBlock(Path("public.md"), 7, unsafe),))

    assert [finding.rule_id for finding in unsafe_findings] == [rule_id]
    assert scan_claims((TextBlock(Path("public.md"), 8, safe),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS is not compliant.",
        "AEGIS isn't compliant.",
        "An audit record is not immutable.",
        "An audit record isn't immutable.",
    ],
)
def test_scan_claims_accepts_copular_and_contracted_negatives(text):
    """Fails if copular negatives stop suppressing their own relationship."""
    assert scan_claims((TextBlock(Path("public.md"), 9, text),)) == ()


@pytest.mark.parametrize(
    ("rule_id", "text"),
    [
        (
            "AEGIS_CERTIFICATION_CLAIM",
            "AEGIS is not a storage provider but is compliant.",
        ),
        (
            "IMMUTABLE_EVIDENCE_RECORD",
            "An audit record is not provisional but is immutable.",
        ),
    ],
)
def test_scan_claims_does_not_apply_copular_negation_to_a_later_clause(
    rule_id,
    text,
):
    """Fails if an unrelated copular negative suppresses a later claim."""
    findings = scan_claims((TextBlock(Path("public.md"), 9, text),))

    assert [finding.rule_id for finding in findings] == [rule_id]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS is a library. The external auditor is certified.",
        "A checkpoint records scope. Compliance remains an organizational conclusion.",
        "An audit record is finalized. The immutable Python tuple is internal.",
    ],
)
def test_scan_claims_does_not_join_relationships_across_sentences(text):
    """Fails if the relationship window again ignores sentence boundaries."""
    assert scan_claims((TextBlock(Path("public.md"), 10, text),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "Hash chaining provides tamper-evidence, not immutable storage.",
        "Checksums alone do not make storage WORM.",
        "A checkpoint does not prove latest retrieval or compliance.",
        "The immutable Python tuple contains approved algorithms.",
        "Retain the exact immutable CryptoKeyVersion identifier.",
        "Run aegis compliance export to create a technical report.",
        (
            "Azure immutable storage is an illustrative and non-normative "
            "provider example."
        ),
    ],
)
def test_scan_claims_accepts_bounded_language(tmp_path, text):
    assert scan_claims((TextBlock(tmp_path / "public.md", 1, text),)) == ()


@pytest.mark.parametrize(
    ("blocks", "expected_rule"),
    [
        (
            (
                TextBlock(Path("public.md"), 1, "Hash chaining"),
                TextBlock(Path("public.md"), 3, "Makes storage immutable."),
            ),
            "INTEGRITY_IS_STORAGE",
        ),
        (
            (
                TextBlock(Path("public.tsx"), 8, "AEGIS evidence"),
                TextBlock(Path("public.tsx"), 9, "is regulatory-ready."),
            ),
            "AEGIS_CERTIFICATION_CLAIM",
        ),
        (
            (
                TextBlock(
                    Path("public.md"),
                    1,
                    "Hash chaining does not merely help;",
                ),
                TextBlock(
                    Path("public.md"),
                    2,
                    "it guarantees immutable storage.",
                ),
            ),
            "INTEGRITY_IS_STORAGE",
        ),
        (
            (
                TextBlock(
                    Path("public.md"),
                    1,
                    "AEGIS uses Azure immutable storage",
                ),
                TextBlock(
                    Path("public.md"),
                    2,
                    "as an illustrative and non-normative example.",
                ),
            ),
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
            TextBlock(
                Path("public.md"),
                2,
                "Hash chaining guarantees immutable storage.",
            ),
        ),
        (
            TextBlock(
                Path("public.md"),
                1,
                "Hash chaining " + "context " * 60,
            ),
            TextBlock(
                Path("public.md"),
                2,
                "Immutable storage is a separate host control.",
            ),
        ),
    ],
)
def test_scan_claims_handles_adjacent_negation_without_unrelated_suppression(blocks):
    findings = scan_claims(blocks)
    if blocks[0].text == "Do not delete this section.":
        assert [finding.rule_id for finding in findings] == [
            "INTEGRITY_IS_STORAGE"
        ]
    else:
        assert findings == ()


def test_scan_claims_relates_predicate_before_subject_and_uses_predicate_line():
    findings = scan_claims(
        (
            TextBlock(Path("public.md"), 5, "Immutable storage"),
            TextBlock(Path("public.md"), 8, "is guaranteed by hash chaining."),
        )
    )

    assert [
        (finding.rule_id, finding.path, finding.line) for finding in findings
    ] == [("INTEGRITY_IS_STORAGE", Path("public.md"), 5)]


def test_scan_claims_does_not_flow_negation_across_an_unrelated_clause():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                4,
                (
                    "Hash chaining does not make compliance claims, but "
                    "guarantees immutable storage."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "INTEGRITY_IS_STORAGE"
    ]


def test_scan_claims_relates_only_within_maximum_distance():
    near_findings = scan_claims(
        (
            TextBlock(
                Path("near.md"),
                1,
                "Hash chaining " + "x" * 398 + " immutable storage.",
            ),
        )
    )
    far_findings = scan_claims(
        (
            TextBlock(
                Path("far.md"),
                1,
                "Hash chaining " + "x" * 399 + " immutable storage.",
            ),
        )
    )

    assert [finding.rule_id for finding in near_findings] == [
        "INTEGRITY_IS_STORAGE"
    ]
    assert far_findings == ()


def test_scan_claims_bounds_excerpt_around_the_predicate():
    finding = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                12,
                "Hash chaining " + "context " * 48 + "immutable storage.",
            ),
        )
    )[0]

    assert "immutable storage" in finding.excerpt
    assert len(finding.excerpt.encode("utf-8")) <= 240


def test_scan_claims_deduplicates_overlapping_adjacent_windows_and_sorts_findings():
    findings = scan_claims(
        (
            TextBlock(Path("z.md"), 3, "AEGIS evidence is regulatory-ready."),
            TextBlock(Path("z.md"), 4, "Supporting context."),
            TextBlock(Path("a.md"), 8, "Hash chaining makes storage immutable."),
        )
    )

    assert [
        (finding.rule_id, finding.path, finding.line) for finding in findings
    ] == [
        ("INTEGRITY_IS_STORAGE", Path("a.md"), 8),
        ("AEGIS_CERTIFICATION_CLAIM", Path("z.md"), 3),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "Azure immutable storage.",
        "The archive uses immutable storage.",
    ],
)
def test_scan_claims_rejects_unqualified_storage_capabilities(text):
    findings = scan_claims((TextBlock(Path("public.md"), 14, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]
    assert findings[0].line == 14


def test_scan_claims_does_not_launder_a_positive_coordinated_predicate():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                15,
                (
                    "Hash chaining does not prove compliance and guarantees "
                    "immutable storage."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "INTEGRITY_IS_STORAGE"
    ]


def test_scan_claims_scopes_provider_exemption_to_the_capability_relation():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                16,
                (
                    "Azure immutable evidence records are illustrative and "
                    "non-normative. Each invocation creates an immutable "
                    "audit record."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]
    assert "invocation creates an immutable audit record" in findings[0].excerpt


def test_scan_claims_does_not_flow_provider_exemption_across_a_clause():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                16,
                (
                    "Azure immutable evidence records are illustrative and "
                    "non-normative, but each invocation creates an immutable "
                    "audit record."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


def test_scan_claims_accepts_provider_qualification_from_an_adjacent_block():
    blocks = (
        TextBlock(Path("public.md"), 21, "Azure immutable storage"),
        TextBlock(
            Path("public.md"),
            22,
            "is an illustrative and non-normative provider example.",
        ),
    )

    assert scan_claims(blocks) == ()


def test_scan_claims_rejects_negated_provider_qualification():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                17,
                (
                    "Azure immutable storage is not an illustrative and "
                    "non-normative example."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS certifies compliance.",
        "AEGIS proves compliance.",
    ],
)
def test_scan_claims_rejects_active_aegis_certification_claims(text):
    findings = scan_claims((TextBlock(Path("public.md"), 18, text),))

    assert [finding.rule_id for finding in findings] == [
        "AEGIS_CERTIFICATION_CLAIM"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS does not certify compliance.",
        "AEGIS cannot certify compliance.",
    ],
)
def test_scan_claims_accepts_negated_aegis_certification_actions(text):
    assert scan_claims((TextBlock(Path("public.md"), 18, text),)) == ()


def test_scan_claims_accepts_aegis_immutable_python_value():
    blocks = (
        TextBlock(
            Path("public.md"),
            19,
            "AEGIS stores approved algorithms in an immutable Python tuple.",
        ),
    )

    assert scan_claims(blocks) == ()


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS does not provide immutable storage.",
        "The archive does not use immutable storage.",
    ],
)
def test_scan_claims_accepts_negated_storage_capability_claims(text):
    assert scan_claims((TextBlock(Path("public.md"), 20, text),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "Storage is immutable.",
        "The database uses immutable storage.",
        "The archive guarantees immutable storage.",
    ],
)
def test_scan_claims_rejects_additional_unqualified_storage_claims(text):
    findings = scan_claims((TextBlock(Path("public.md"), 23, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "Storage is not immutable.",
        "The database does not use immutable storage.",
        "The archive does not guarantee immutable storage.",
    ],
)
def test_scan_claims_accepts_negated_general_storage_claims(text):
    assert scan_claims((TextBlock(Path("public.md"), 24, text),)) == ()


def test_scan_claims_rejects_storage_impossibility_claim():
    findings = scan_claims(
        (TextBlock(Path("public.md"), 24, "Storage cannot be changed."),)
    )

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "Azure immutable storage isn't illustrative and non-normative.",
        (
            "Azure immutable storage is not merely illustrative and "
            "non-normative."
        ),
        (
            "Azure immutable storage is not strictly illustrative and "
            "non-normative."
        ),
        (
            "Azure immutable storage is not really clearly illustrative and "
            "non-normative."
        ),
    ],
)
def test_scan_claims_rejects_additional_negated_provider_qualifiers(text):
    findings = scan_claims((TextBlock(Path("public.md"), 25, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS retains the exact immutable CryptoKeyVersion identifier in storage.",
        "AEGIS retains the immutable release reference in storage.",
    ],
)
def test_scan_claims_accepts_immutable_identifiers_and_references_in_storage(text):
    assert scan_claims((TextBlock(Path("public.md"), 26, text),)) == ()


def test_scan_claims_accepts_proof_without_a_certification_object():
    blocks = (
        TextBlock(
            Path("public.md"),
            27,
            "AEGIS proves cryptographic integrity, supporting compliance reviews.",
        ),
    )

    assert scan_claims(blocks) == ()


def test_scan_claims_rejects_coordinated_active_certification_claim():
    findings = scan_claims(
        (
            TextBlock(
                Path("public.md"),
                28,
                (
                    "AEGIS does not prove data integrity and certifies "
                    "compliance."
                ),
            ),
        )
    )

    assert [finding.rule_id for finding in findings] == [
        "AEGIS_CERTIFICATION_CLAIM"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS retains the immutable storage-release reference.",
        "AEGIS retains the immutable storage reference for the release.",
        "AEGIS retains the immutable Cloud Storage release reference.",
    ],
)
def test_scan_claims_accepts_storage_qualified_release_references(text):
    assert scan_claims((TextBlock(Path("public.md"), 29, text),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS provides storage that is immutable.",
        "AEGIS uses immutable managed storage.",
        "Azure uses immutable archival storage.",
    ],
)
def test_scan_claims_rejects_extended_storage_assurance_connectors(text):
    findings = scan_claims((TextBlock(Path("public.md"), 30, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS does not use immutable managed storage.",
        "Azure does not use immutable archival storage.",
        "Azure does not offer immutable archival storage.",
    ],
)
def test_scan_claims_accepts_negated_extended_storage_connectors(text):
    assert scan_claims((TextBlock(Path("public.md"), 30, text),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS retains the immutable managed storage identifier.",
        "AEGIS retains the immutable archival storage identifier.",
    ],
)
def test_scan_claims_accepts_managed_and_archival_storage_identifiers(text):
    assert scan_claims((TextBlock(Path("public.md"), 31, text),)) == ()


@pytest.mark.parametrize(
    "text",
    [
        (
            "AEGIS does not use archival storage and uses immutable managed "
            "storage."
        ),
        (
            "Azure does not offer archival storage but offers immutable "
            "managed storage."
        ),
    ],
)
def test_scan_claims_rejects_coordinated_storage_uses_and_offers(text):
    findings = scan_claims((TextBlock(Path("public.md"), 32, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


def test_scan_claims_accepts_qualified_carried_provider_claim():
    text = (
        "Azure does not offer archival storage but offers immutable managed "
        "storage as an illustrative and non-normative example."
    )

    assert scan_claims((TextBlock(Path("public.md"), 33, text),)) == ()


def test_scan_claims_does_not_carry_provider_qualification_to_a_later_claim():
    text = (
        "Azure does not offer archival storage as an illustrative and "
        "non-normative example but offers immutable managed storage."
    )

    findings = scan_claims((TextBlock(Path("public.md"), 33, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        (
            "Azure does not offer archival storage but offers immutable "
            "managed storage and this note is illustrative and non-normative."
        ),
        (
            "Azure does not offer archival storage but offers immutable "
            "managed storage while this note is illustrative and non-normative."
        ),
    ],
)
def test_scan_claims_does_not_carry_provider_qualification_from_copular_clause(
    text,
):
    findings = scan_claims((TextBlock(Path("public.md"), 34, text),))

    assert [finding.rule_id for finding in findings] == [
        "IMMUTABLE_EVIDENCE_RECORD"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "AEGIS certifies full compliance.",
        "AEGIS certifies ongoing regulatory compliance.",
        "AEGIS certifies SOC 2 compliance.",
    ],
)
def test_scan_claims_rejects_modified_compliance_objects(text):
    findings = scan_claims((TextBlock(Path("public.md"), 31, text),))

    assert [finding.rule_id for finding in findings] == [
        "AEGIS_CERTIFICATION_CLAIM"
    ]
