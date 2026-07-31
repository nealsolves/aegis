"""Portable smoke test for the required RE2 dependency."""

from __future__ import annotations

import re2


def test_google_re2_compiles_and_matches_a_representative_policy_pattern():
    """Each supported platform must ship a usable RE2 extension module."""
    pattern = re2.compile(r"^(APPROVED|REJECTED)-[0-9]{6}$")

    assert pattern.fullmatch("APPROVED-123456") is not None
