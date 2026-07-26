import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_demo_copy import main, scan_text  # noqa: E402


def test_scanner_flags_banned_marketing_language():
    findings = scan_text(
        "At its core, this robust framework will unlock the full potential."
    )
    assert {finding.pattern for finding in findings} >= {
        "at its core",
        "robust framework",
        "unlock the full potential",
    }


def test_scanner_accepts_specific_governance_copy():
    assert scan_text(
        "AEGIS checks the request before the model call and records reason code "
        "ROLE_NOT_ALLOWED."
    ) == []


def test_question_cluster_reports_its_later_paragraph_location():
    text = "Opening copy.\n\n  \n\nWhat happened? Who approved it? Where is the record?"

    finding = next(
        finding
        for finding in scan_text(text)
        if finding.pattern == "rhetorical_question_cluster"
    )

    assert finding.line == 5
    assert finding.excerpt == "What happened? Who approved it? Where is the record?"


def test_cli_ignores_directories_with_scannable_suffixes(tmp_path):
    (tmp_path / "notes.md").mkdir()

    assert main([str(tmp_path)]) == 0


def test_frontend_root_recursively_covers_production_public_copy(capsys, tmp_path):
    public_files = [
        "pages/ArchitecturePage.tsx",
        "labs/Lab12IntegrationAdapters.tsx",
        "pages/LabsIndexPage.tsx",
        "components/service/DemoServiceNotice.tsx",
    ]
    for index, relative_path in enumerate(public_files):
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"<h1>At its core, public copy {index}.</h1>",
            encoding="utf-8",
        )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    for relative_path in public_files:
        assert relative_path in output


def test_frontend_root_ignores_tests_identifiers_urls_and_generated_assets(
    capsys,
    tmp_path,
):
    (tmp_path / "pages").mkdir()
    (tmp_path / "pages/ArchitecturePage.test.tsx").write_text(
        "<h1>At its core, this robust framework.</h1>",
        encoding="utf-8",
    )
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib/runtime.ts").write_text(
        "const journey = 'https://example.test/journey';",
        encoding="utf-8",
    )
    (tmp_path / "lib/styles.tsx").write_text(
        """
        {/* At its core, this comment is not public copy. */}
        <div
          className="what? why? how?"
          style={{ color: 'var(--what?)', border: 'rgba(0,0,0,0.2)' }}
        >
          AEGIS checks the request before the host call.
        </div>
        """,
        encoding="utf-8",
    )
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated/diagram.tsx").write_text(
        "<svg><text>At its core, generated copy.</text></svg>",
        encoding="utf-8",
    )
    (tmp_path / "pages/SafePage.tsx").write_text(
        "<h1>AEGIS checks the request before the host call.</h1>",
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 0
    assert capsys.readouterr().out == ""
