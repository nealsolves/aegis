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
FRONTEND_SUFFIXES = {".ts", ".tsx"}
FRONTEND_EXCLUDED_PARTS = {
    "__tests__",
    "generated",
    "node_modules",
}
NOT_BUT_PATTERN = re.compile(
    r"\bnot\b[^.!?\n\0]{0,120}\bbut\b",
    re.IGNORECASE,
)
TYPESCRIPT_STRING_PATTERN = re.compile(
    r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"|`((?:\\.|[^`\\])*)`",
    re.DOTALL,
)
JSX_TEXT_PATTERN = re.compile(r">([^<>{}]+)<", re.DOTALL)


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
    return line, text[line_start:line_end].replace("\0", " ").strip()


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
        paragraph_start = 0
        paragraphs: list[tuple[int, str]] = []
        for separator in re.finditer(r"\0|\n\s*\n", text):
            paragraphs.append((paragraph_start, text[paragraph_start:separator.start()]))
            paragraph_start = separator.end()
        paragraphs.append((paragraph_start, text[paragraph_start:]))
        for paragraph_offset, paragraph in paragraphs:
            if paragraph.count("?") >= 3:
                findings.append(
                    Finding(
                        "rhetorical_question_cluster",
                        *_line_and_excerpt(text, paragraph_offset),
                    )
                )
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
                if candidate.is_file() and candidate.suffix in SCAN_SUFFIXES
            )


def _iter_frontend_public_files(root: Path) -> Iterable[Path]:
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


def _is_implementation_string(source: str, start: int, value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if re.match(
        r"^(?:https?://|[./#]|data:|var\(--|rgba?\(|hsla?\()",
        stripped,
    ):
        return True
    line_start = source.rfind("\n", 0, start) + 1
    prefix = source[line_start:start]
    return bool(re.search(
        r"(?:className|id|href|src|to|key|value|data-[\w-]+)"
        r"\s*=\s*['\"`]?$",
        prefix,
    ))


def _mask_typescript_comments(source: str) -> str:
    """Mask JavaScript comments without treating comment markers in strings as comments."""
    masked = list(source)
    index = 0
    quote: str | None = None

    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""

        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue

        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue

        if character == "/" and next_character == "/":
            while index < len(source) and source[index] != "\n":
                masked[index] = " "
                index += 1
            continue

        if character == "/" and next_character == "*":
            masked[index] = " "
            masked[index + 1] = " "
            index += 2
            while index < len(source):
                if (
                    source[index] == "*"
                    and index + 1 < len(source)
                    and source[index + 1] == "/"
                ):
                    masked[index] = " "
                    masked[index + 1] = " "
                    index += 2
                    break
                if source[index] != "\n":
                    masked[index] = " "
                index += 1
            continue

        index += 1

    return "".join(masked)


def _frontend_public_copy(source: str) -> str:
    """Mask TypeScript implementation while preserving public-copy line numbers."""
    mask = ["\n" if character == "\n" else " " for character in source]
    uncommented = _mask_typescript_comments(source)

    ranges: list[tuple[int, int]] = []
    for match in JSX_TEXT_PATTERN.finditer(uncommented):
        ranges.append(match.span(1))
    for match in TYPESCRIPT_STRING_PATTERN.finditer(uncommented):
        group_index = next(
            index for index in (1, 2, 3) if match.group(index) is not None
        )
        start, end = match.span(group_index)
        if not _is_implementation_string(uncommented, start, match.group(group_index)):
            ranges.append((start, end))

    merged_ranges: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged_ranges and start <= merged_ranges[-1][1]:
            previous_start, previous_end = merged_ranges[-1]
            merged_ranges[-1] = (previous_start, max(previous_end, end))
        else:
            merged_ranges.append((start, end))

    for range_index, (start, end) in enumerate(merged_ranges):
        mask[start:end] = uncommented[start:end]
        if range_index > 0:
            separator = start - 1
            while separator >= 0 and mask[separator] == "\n":
                separator -= 1
            if separator >= 0 and separator < merged_ranges[range_index - 1][1]:
                separator = end
            if separator < len(mask) and mask[separator] != "\n":
                mask[separator] = "\0"
    return "".join(mask)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="*", type=Path, help="Files or directories to review"
    )
    parser.add_argument(
        "--frontend-root",
        type=Path,
        help="Recursively scan public copy in production TypeScript sources",
    )
    arguments = parser.parse_args(argv)
    if not arguments.paths and arguments.frontend_root is None:
        parser.error("supply paths or --frontend-root")

    found = False
    inputs = [
        (path, path.read_text(encoding="utf-8"))
        for path in _iter_files(arguments.paths)
    ]
    if arguments.frontend_root is not None:
        inputs.extend(
            (
                path,
                _frontend_public_copy(path.read_text(encoding="utf-8")),
            )
            for path in _iter_frontend_public_files(arguments.frontend_root)
        )

    for path, text in inputs:
        for finding in scan_text(text):
            found = True
            print(f"{finding.pattern}: {path}:{finding.line}: {finding.excerpt}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
