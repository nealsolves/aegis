from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_evidence_claims import (
    ClaimsGuardError,
    ScanLimits,
    extract_document_blocks,
    normalize_public_text,
    read_text_source,
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
