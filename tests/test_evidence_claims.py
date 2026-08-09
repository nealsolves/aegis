from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_evidence_claims import (
    ClaimsGuardError,
    ScanLimits,
    TextBlock,
    extract_document_blocks,
    normalize_public_text,
    read_text_source,
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


def test_normalize_public_text_preserves_unclosed_outer_markdown_target():
    source = "[outer](one [inner](two)"

    assert normalize_public_text(source) == source


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
