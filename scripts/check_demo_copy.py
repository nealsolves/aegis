#!/usr/bin/env python3
"""Fail public-copy review when approved language-policy rules are found."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


RULE_FILE = (
    Path(__file__).resolve().parents[1]
    / "docs/language-policy/aegis-demo-copy-rules.json"
)
SCAN_SUFFIXES = {".ts", ".tsx", ".md", ".html"}
NOT_BUT_PATTERN = re.compile(r"\bnot\b[^.!?\n]{0,120}\bbut\b", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    pattern: str
    line: int
    excerpt: str


def _load_rules() -> dict:
    with RULE_FILE.open(encoding="utf-8") as rule_file:
        return json.load(rule_file)


def _line_and_excerpt(text: str, offset: int) -> tuple[int, str]:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return line, text[line_start:line_end].strip()


def _find_rule_matches(text: str, rule: dict) -> list[Finding]:
    pattern = rule["pattern"]
    if rule["type"] == "regex":
        matches = re.finditer(pattern, text, re.IGNORECASE)
    else:
        matches = re.finditer(re.escape(pattern), text, re.IGNORECASE)
    return [
        Finding(pattern, *_line_and_excerpt(text, match.start()))
        for match in matches
    ]


def _find_structural_matches(text: str, checks: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    if "repeated_not_but" in checks:
        matches = list(NOT_BUT_PATTERN.finditer(text))
        if len(matches) >= 2:
            findings.append(
                Finding(
                    "repeated_not_but",
                    *_line_and_excerpt(text, matches[1].start()),
                )
            )
    if "rhetorical_question_cluster" in checks:
        paragraph_offset = 0
        for paragraph in re.split(r"\n\s*\n", text):
            if paragraph.count("?") >= 3:
                findings.append(
                    Finding(
                        "rhetorical_question_cluster",
                        *_line_and_excerpt(text, paragraph_offset),
                    )
                )
            paragraph_offset += len(paragraph) + 2
    return findings


def scan_text(text: str) -> list[Finding]:
    """Return public-copy findings for *text* using the local approved rules."""
    policy = _load_rules()
    rules = [*policy["rules"], *policy["project_overrides"]]
    findings = [
        finding
        for rule in rules
        for finding in _find_rule_matches(text, rule)
    ]
    findings.extend(_find_structural_matches(text, policy["structural_checks"]))
    return findings


def _iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_file() and path.suffix in SCAN_SUFFIXES:
            yield path
        elif path.is_dir():
            yield from (
                candidate
                for candidate in path.rglob("*")
                if candidate.suffix in SCAN_SUFFIXES
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="+", type=Path, help="Files or directories to review"
    )
    arguments = parser.parse_args(argv)

    found = False
    for path in _iter_files(arguments.paths):
        for finding in scan_text(path.read_text(encoding="utf-8")):
            found = True
            print(f"{finding.pattern}: {path}:{finding.line}: {finding.excerpt}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
