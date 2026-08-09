#!/usr/bin/env python3
"""Reject evidence-assurance overclaims in maintained public copy."""

from __future__ import annotations

import fnmatch
import html
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
import re
import unicodedata

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "doc_parity_manifest.yaml"
FRONTEND_ROOT = REPO_ROOT / "demo-app-react" / "src"
TEXT_SUFFIXES = frozenset({".html", ".md", ".mermaid", ".svg"})
BINARY_SUFFIXES = frozenset({".png"})
_ZERO_WIDTH_TRANSLATION = str.maketrans(
    {"\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": ""}
)
_WHITESPACE_RE = re.compile(r"\s+")
_MAX_MARKDOWN_LABEL_CHARS = 8_192
_MAX_MARKDOWN_TARGET_CHARS = 16_384
_MARKDOWN_PREFIX_RE = re.compile(
    r"^[ \t]{0,3}(?:#{1,6}[ \t]+|[-*+][ \t]+|>[ \t]?|\d{1,9}[.)][ \t]+)"
)
_PUBLIC_ATTRIBUTES = frozenset(
    {"alt", "aria-description", "aria-label", "placeholder", "title"}
)
MANDATORY_CURRENT_PATHS = frozenset(
    {
        "README.md",
        "SECURITY.md",
        "docs/INTEGRATION_GUIDE.md",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md",
        "docs/USAGE.md",
        "docs/architecture/AEGIS_THREAT_MODEL.md",
        "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/reference/OPERATIONS_RUNBOOK.md",
    }
)


class ClaimsGuardError(RuntimeError):
    """A bounded infrastructure or configuration failure."""


@dataclass(frozen=True)
class ScanLimits:
    max_file_bytes: int = 5 * 1024 * 1024
    max_source_bytes: int = 50 * 1024 * 1024
    max_files: int = 10_000
    max_public_blocks: int = 250_000
    max_extractor_bytes: int = 50 * 1024 * 1024
    max_normalized_block_bytes: int = 1024 * 1024
    max_normalized_bytes: int = 100 * 1024 * 1024


@dataclass(frozen=True)
class TextBlock:
    path: Path
    line: int
    text: str


@dataclass(frozen=True)
class ClaimFinding:
    rule_id: str
    path: Path
    line: int
    excerpt: str


def _balanced_markdown_target_end(text: str, opening: int) -> int | None:
    """Return the closing parenthesis for a bounded Markdown target."""
    depth = 0
    limit = min(len(text), opening + _MAX_MARKDOWN_TARGET_CHARS + 2)
    for position in range(opening, limit):
        character = text[position]
        if character in "\r\n":
            return None
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return position
    return None


def _strip_markdown_targets(text: str) -> str:
    """Retain Markdown labels while safely dropping bounded link targets."""
    parts: list[str] = []
    copied_until = 0
    marker_start = 0
    while True:
        marker = text.find("](", marker_start)
        if marker < 0:
            break
        label_opening = text.rfind(
            "[",
            max(copied_until, marker - _MAX_MARKDOWN_LABEL_CHARS - 1),
            marker,
        )
        target_end = _balanced_markdown_target_end(text, marker + 1)
        if label_opening < 0 or target_end is None:
            marker_start = marker + 2
            continue
        source_start = label_opening
        if label_opening > copied_until and text[label_opening - 1] == "!":
            source_start -= 1
        parts.append(text[copied_until:source_start])
        parts.append(text[label_opening + 1:marker])
        copied_until = target_end + 1
        marker_start = copied_until
    parts.append(text[copied_until:])
    return "".join(parts)


def normalize_public_text(text: str) -> str:
    """Canonicalize user-visible text before evaluating assurance claims."""
    normalized = html.unescape(text)
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = normalized.translate(_ZERO_WIDTH_TRANSLATION)
    normalized = _strip_markdown_targets(normalized)
    return _WHITESPACE_RE.sub(" ", normalized).strip()


def _bounded_block(
    path: Path,
    line: int,
    text: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> TextBlock | None:
    normalized = normalize_public_text(text)
    if not normalized:
        return None
    encoded_size = len(normalized.encode("utf-8"))
    if encoded_size > limits.max_normalized_block_bytes:
        raise ClaimsGuardError(f"{path}: normalized block limit exceeded")
    counters["normalized_bytes"] += encoded_size
    counters["public_blocks"] += 1
    if counters["normalized_bytes"] > limits.max_normalized_bytes:
        raise ClaimsGuardError("aggregate normalized text limit exceeded")
    if counters["public_blocks"] > limits.max_public_blocks:
        raise ClaimsGuardError("public copy block limit exceeded")
    return TextBlock(path=path, line=line, text=normalized)


class _PublicCopyParser(HTMLParser):
    """Extract public HTML/SVG strings without combining rendered blocks."""

    def __init__(
        self,
        path: Path,
        limits: ScanLimits,
        counters: dict[str, int],
        blocks: list[TextBlock],
    ) -> None:
        super().__init__(convert_charrefs=True)
        self._path = path
        self._limits = limits
        self._counters = counters
        self.blocks = blocks

    def _append(self, text: str) -> None:
        block = _bounded_block(
            self._path,
            self.getpos()[0],
            text,
            self._limits,
            self._counters,
        )
        if block is not None:
            self.blocks.append(block)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs}
        for name, value in attrs:
            if name.lower() in _PUBLIC_ATTRIBUTES and value is not None:
                self._append(value)
        if tag.lower() == "meta" and attributes.get("content") is not None:
            self._append(attributes["content"])

    def handle_data(self, data: str) -> None:
        self._append(data)


def extract_document_blocks(
    path: Path,
    text: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> tuple[TextBlock, ...]:
    """Return bounded public text blocks from a maintained document."""
    if path.suffix.lower() in {".html", ".svg"}:
        blocks: list[TextBlock] = []
        for line_number, source_line in enumerate(text.splitlines(), start=1):
            block = _bounded_block(path, line_number, source_line, limits, counters)
            if block is not None:
                blocks.append(block)
        parser = _PublicCopyParser(path, limits, counters, blocks)
        parser.feed(text)
        parser.close()
        return tuple(parser.blocks)

    blocks: list[TextBlock] = []
    for line_number, source_line in enumerate(text.splitlines(), start=1):
        public_line = _MARKDOWN_PREFIX_RE.sub("", source_line)
        block = _bounded_block(path, line_number, public_line, limits, counters)
        if block is not None:
            blocks.append(block)
    return tuple(blocks)


def _category_matches(relative: str, inventory: dict) -> tuple[str, ...]:
    return tuple(
        category
        for category in ("current", "target", "historical", "instruction_system")
        if any(fnmatch.fnmatch(relative, pattern) for pattern in inventory[category])
    )


def select_current_paths(
    repo_root: Path,
    manifest: dict,
    repository_files: list[Path],
    limits: ScanLimits,
) -> tuple[Path, ...]:
    inventory = manifest.get("documentation_inventory")
    if not isinstance(inventory, dict):
        raise ClaimsGuardError("manifest missing documentation_inventory")
    for category in ("current", "target", "historical", "instruction_system"):
        patterns = inventory.get(category)
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise ClaimsGuardError("manifest has malformed documentation_inventory")
    try:
        resolved_repo_root = repo_root.resolve(strict=True)
    except OSError as error:
        raise ClaimsGuardError("repository path resolution failed") from error
    selected: list[Path] = []
    for path in repository_files:
        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError as error:
            raise ClaimsGuardError(f"{path}: path is outside repository") from error
        matches = _category_matches(relative, inventory)
        if len(matches) > 1:
            raise ClaimsGuardError(f"{relative}: multiple documentation categories")
        if matches != ("current",):
            continue
        if path.is_symlink():
            raise ClaimsGuardError(f"{relative}: symlink is not scannable")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ClaimsGuardError(f"{relative}: path resolution failed") from error
        if not resolved.is_relative_to(resolved_repo_root):
            raise ClaimsGuardError(f"{relative}: path resolves outside repository")
        if not resolved.is_file():
            raise ClaimsGuardError(f"{relative}: special file is not scannable")
        selected.append(path)
    if len(selected) > limits.max_files:
        raise ClaimsGuardError("selected file limit exceeded")
    return tuple(sorted(selected))


def read_text_source(
    path: Path,
    repo_root: Path,
    limits: ScanLimits,
    counters: dict[str, int],
) -> str:
    relative = path.relative_to(repo_root).as_posix()
    suffix = path.suffix.lower()
    if suffix in BINARY_SUFFIXES:
        try:
            with path.open("rb") as source_file:
                source_file.read(1)
        except OSError as error:
            raise ClaimsGuardError(f"{relative}: source read failed") from error
        counters["binary_files"] += 1
        return ""
    if suffix not in TEXT_SUFFIXES:
        raise ClaimsGuardError(f"{relative}: unsupported current-document suffix")
    try:
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise ClaimsGuardError(f"{relative}: source file limit exceeded")
        with path.open("rb") as source_file:
            payload = source_file.read(limits.max_file_bytes + 1)
    except OSError as error:
        raise ClaimsGuardError(f"{relative}: source read failed") from error
    if len(payload) > limits.max_file_bytes:
        raise ClaimsGuardError(f"{relative}: source file limit exceeded")
    counters["source_bytes"] += len(payload)
    if counters["source_bytes"] > limits.max_source_bytes:
        raise ClaimsGuardError("aggregate source limit exceeded")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ClaimsGuardError(f"{relative}: source is not valid UTF-8") from error
