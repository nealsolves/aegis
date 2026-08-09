#!/usr/bin/env python3
"""Reject evidence-assurance overclaims in maintained public copy."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "doc_parity_manifest.yaml"
FRONTEND_ROOT = REPO_ROOT / "demo-app-react" / "src"
TEXT_SUFFIXES = frozenset({".html", ".md", ".mermaid", ".svg"})
BINARY_SUFFIXES = frozenset({".png"})
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
