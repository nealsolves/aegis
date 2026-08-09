#!/usr/bin/env python3
"""Fail public-copy review when approved language-policy rules are found."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
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
FRONTEND_EXTRACTOR = (
    Path(__file__).resolve().parents[1]
    / "demo-app-react/scripts/extract-public-copy.mjs"
)
NOT_BUT_PATTERN = re.compile(
    r"\bnot\b[^.!?\n\0]{0,120}\bbut\b",
    re.IGNORECASE,
)


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


def iter_frontend_public_files(root: Path) -> Iterable[Path]:
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


DEFAULT_MAX_EXTRACTOR_BYTES = 50 * 1024 * 1024
FRONTEND_EXTRACTOR_BATCH_SIZE = 200


def extract_frontend_public_copy(
    paths: list[Path],
    *,
    max_output_bytes: int = DEFAULT_MAX_EXTRACTOR_BYTES,
) -> dict[Path, str]:
    """Return rendered public-copy documents extracted from TypeScript syntax."""
    if not paths:
        return {}
    extracted: list[dict] = []
    consumed_output_bytes = 0
    for offset in range(0, len(paths), FRONTEND_EXTRACTOR_BATCH_SIZE):
        batch = paths[offset: offset + FRONTEND_EXTRACTOR_BATCH_SIZE]
        with (
            tempfile.TemporaryFile(mode="w+b") as output_file,
            tempfile.TemporaryFile(mode="w+b") as error_file,
        ):
            subprocess.run(
                ["node", str(FRONTEND_EXTRACTOR), *(str(path) for path in batch)],
                check=True,
                stdout=output_file,
                stderr=error_file,
            )
            output_bytes = output_file.tell()
            consumed_output_bytes += output_bytes
            if consumed_output_bytes > max_output_bytes:
                raise ValueError("frontend extractor output limit exceeded")
            output_file.seek(0)
            payload = output_file.read(output_bytes + 1)
        parsed = json.loads(payload.decode("utf-8", errors="strict"))
        if not isinstance(parsed, list):
            raise ValueError("frontend extractor output must be a JSON list")
        extracted.extend(parsed)
    documents: dict[Path, str] = {}
    for item in extracted:
        output: list[str] = []
        current_line = 1
        for index, block in enumerate(item["blocks"]):
            target_line = max(current_line, int(block["line"]))
            if index:
                output.append("\0")
            if target_line > current_line:
                output.append("\n" * (target_line - current_line))
                current_line = target_line
            output.append(block["text"])
        documents[Path(item["path"])] = "".join(output)
    return documents


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
        frontend_paths = list(iter_frontend_public_files(arguments.frontend_root))
        frontend_documents = extract_frontend_public_copy(frontend_paths)
        inputs.extend(
            (path, frontend_documents[path])
            for path in frontend_paths
        )

    for path, text in inputs:
        for finding in scan_text(text):
            found = True
            print(f"{finding.pattern}: {path}:{finding.line}: {finding.excerpt}")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
