import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_demo_copy import scan_text  # noqa: E402


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
