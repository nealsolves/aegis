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
