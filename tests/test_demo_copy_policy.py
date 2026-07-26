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


def test_frontend_root_reconstructs_public_copy_across_inline_jsx(
    capsys,
    tmp_path,
):
    page = tmp_path / "InlinePage.tsx"
    page.write_text(
        """
        export function InlinePage() {
          return <p>At its <strong>core</strong>, AEGIS checks policy.</p>
        }
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    assert "at its core" in capsys.readouterr().out


def test_frontend_root_joins_visible_static_literal_concatenation(
    capsys,
    tmp_path,
):
    page = tmp_path / "ConcatenatedPage.tsx"
    page.write_text(
        """
        export function ConcatenatedPage() {
          return <p>{'At its ' + 'core, AEGIS checks policy.'}</p>
        }
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    assert "at its core" in capsys.readouterr().out


def test_frontend_root_checks_not_but_across_inline_markup_not_blocks(
    capsys,
    tmp_path,
):
    page = tmp_path / "StructuralPage.tsx"
    page.write_text(
        """
        export function StructuralPage() {
          return (
            <main>
              <p>This is not a prompt <strong>but</strong> an enforced policy.</p>
              <p>This is not a report <em>but</em> runtime evidence.</p>
              <p>This boundary is not a model.</p>
              <p>But it records a governed result.</p>
            </main>
          )
        }
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert output.count("repeated_not_but") == 1


def test_frontend_root_ignores_internal_identifier_but_scans_visible_copy(
    capsys,
    tmp_path,
):
    implementation_root = tmp_path / "implementation"
    implementation_root.mkdir()
    implementation = implementation_root / "Implementation.ts"
    implementation.write_text(
        "export const routeState = 'journey_state'",
        encoding="utf-8",
    )
    visible_root = tmp_path / "visible"
    visible_root.mkdir()
    visible = visible_root / "VisiblePage.tsx"
    visible.write_text(
        "export function VisiblePage() { return <p>Review the journey state.</p> }",
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(implementation_root)]) == 0
    assert capsys.readouterr().out == ""

    assert main(["--frontend-root", str(visible_root)]) == 1
    assert "journey" in capsys.readouterr().out


def test_frontend_root_recurses_into_jsx_returned_by_map_callbacks(
    capsys,
    tmp_path,
):
    page = tmp_path / "MappedPage.tsx"
    page.write_text(
        """
        export function MappedPage({ items }) {
          return <section>{items.map(() => (
            <p>At its <strong>core</strong>, AEGIS checks policy.</p>
          ))}</section>
        }
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    assert "at its core" in capsys.readouterr().out


def test_frontend_root_scans_public_capitalized_component_props_only(
    capsys,
    tmp_path,
):
    internal_root = tmp_path / "internal"
    internal_root.mkdir()
    (internal_root / "InternalCard.tsx").write_text(
        """
        export const card = (
          <FeatureCard
            state="journey_state"
            href="https://example.test/journey"
            style={{ background: 'var(--journey-state)' }}
          />
        )
        """,
        encoding="utf-8",
    )
    public_root = tmp_path / "public"
    public_root.mkdir()
    public_page = public_root / "PublicCard.tsx"
    public_page.write_text(
        """
        export const card = (
          <FeatureCard
            description="At its core, AEGIS checks policy."
            state="journey_state"
            href="https://example.test/journey"
          />
        )
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(internal_root)]) == 0
    assert capsys.readouterr().out == ""

    assert main(["--frontend-root", str(public_root)]) == 1
    output = capsys.readouterr().out
    assert "at its core" in output
    assert "journey" not in output


def test_frontend_root_keeps_router_links_inline_with_source_line_mapping(
    capsys,
    tmp_path,
):
    page = tmp_path / "LinkedPage.tsx"
    page.write_text(
        """import { Link } from 'react-router-dom'
        export function LinkedPage() {
          return <p>At its <Link to="/core">core</Link>, AEGIS checks policy.</p>
        }
        """,
        encoding="utf-8",
    )

    assert main(["--frontend-root", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "at its core" in output
    assert f"{page}:3:" in output
