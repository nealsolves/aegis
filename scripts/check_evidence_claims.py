#!/usr/bin/env python3
"""Reject evidence-assurance overclaims in maintained public copy."""

from __future__ import annotations

from bisect import bisect_left
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
INTEGRITY_SUBJECT = re.compile(
    r"\b(?:checksums?|signatures?|hash(?:[- ]?chains?| chaining))\b",
    re.IGNORECASE,
)
CHECKPOINT_SUBJECT = re.compile(
    r"\b(?:(?:trusted|chain|workflow) )?checkpoints?\b|\bcheckpoint[- ]proven\b",
    re.IGNORECASE,
)
AEGIS_SUBJECT = re.compile(
    r"\bAEGIS\b|\bAEGIS (?:APIs?|exports?|reports?|records?|evidence)\b",
    re.IGNORECASE,
)
EVIDENCE_RECORD_SUBJECT = re.compile(
    r"\b(?:audit|invocation|workflow|evidence) (?:artifacts?|records?|logs?)\b",
    re.IGNORECASE,
)
PROVIDER_SUBJECT = re.compile(
    r"\b(?:Amazon S3|AWS|Azure|Google Cloud|Cloud Storage|storage provider)\b",
    re.IGNORECASE,
)
STORAGE_SUBJECT = re.compile(
    r"\bstorage\b(?= (?:(?:is|are|remains?) (?:immutable|immutability|"
    r"append[- ]only|WORM|unalterable|indelible|tamper[- ]proof|"
    r"deletion[- ]proof)|cannot be (?:changed|deleted|modified|rewritten))\b)|"
    r"\b(?:archives?|repositories?|databases?|systems?|services?|backends?)\b"
    r"(?= (?:is|are|has|have|uses?|provides?|offers?|creates?|guarantees?) "
    r"(?:(?:an?|the) )?(?:\w+ ){0,3}storage\b)",
    re.IGNORECASE,
)
STORAGE_TERM = re.compile(r"\bstorage\b", re.IGNORECASE)
_PREDICATE_BEFORE_STORAGE = re.compile(
    r"^\s*(?:(?:cloud|object|blob|audit|evidence|record|records|archive|"
    r"provider|managed|archival)\s+)*$",
    re.IGNORECASE,
)
_STORAGE_BEFORE_PREDICATE = re.compile(
    r"^\s*(?:(?:(?:that|which) )?(?:is|are|remains?)|provides?|offers?|"
    r"guarantees?)?\s*$",
    re.IGNORECASE,
)
_STORAGE_NON_ASSURANCE_SUFFIX = re.compile(
    r"^(?:(?:[- ]release)? reference(?: (?:for|of) (?:the )?release)?|"
    r" identifier)\b",
    re.IGNORECASE,
)
STORAGE_PREDICATE = re.compile(
    r"\b(?:immutable|immutability|append[- ]only|WORM|unalterable|indelible|"
    r"tamper[- ]proof|deletion[- ]proof|cannot be (?:changed|deleted|modified|rewritten))\b",
    re.IGNORECASE,
)
CERTIFICATION_PREDICATE = re.compile(
    r"\b(?:certified|certification|compliant|guaranteed compliance|audit[- ]ready|"
    r"regulatory[- ]ready|regulatory approval|legally (?:admissible|sufficient))\b",
    re.IGNORECASE,
)
CHECKPOINT_EXCESS_PREDICATE = re.compile(
    r"\b(?:latest retrieval|latest record|no later activity|future inactivity|"
    r"immutable storage|WORM storage|certification|compliance)\b",
    re.IGNORECASE,
)
PSEUDO_NEGATION = re.compile(
    r"\b(?:not only|does not merely|do not merely|cannot merely|"
    r"does not fail to|do not fail to|cannot fail to)\b",
    re.IGNORECASE,
)
BOUNDED_NEGATIVE = re.compile(
    r"\b(?:(?:do|does) not|cannot|can not|never) (?:provide|create|make|use|"
    r"offer|guarantee|establish|prove|certify|constitute|mean)\b|"
    r"\bprovides? tamper[- ]evidence, not\b|\balone (?:do|does) not\b",
    re.IGNORECASE,
)
CERTIFICATION_ACTION = re.compile(
    r"\b(?:certif(?:y|ies)|proves?)\b",
    re.IGNORECASE,
)
CERTIFICATION_OBJECT = re.compile(
    r"\b(?:(?:(?:full|ongoing|complete|continuous|regulatory|legal|policy|"
    r"technical) ){0,3}|(?:SOC 2(?: Type (?:I|II))? ))"
    r"(?:compliance|certification)\b",
    re.IGNORECASE,
)
_ACTION_OBJECT_CONNECTOR = re.compile(r"^\s*$")
_ILLUSTRATIVE_PROVIDER_CONTEXT = re.compile(
    r"\billustrative and non[- ]normative\b",
    re.IGNORECASE,
)
_NEGATED_PROVIDER_CONTEXT = re.compile(
    r"\b(?:(?:is|are|was|were)n['’]t|(?:is|are|was|were) not|not|never)"
    r"(?: [A-Za-z]+){0,3} illustrative and non[- ]normative\b",
    re.IGNORECASE,
)
_SENTENCE_BOUNDARY = re.compile(r"[.;!?]")
_CLAUSE_BOUNDARY = re.compile(
    r"[.;!?]|,\s*(?:and|but|while|yet)\b|"
    r"\b(?:and|but|while|yet)\b(?:\s+\w+){0,3}\s+"
    r"(?:provides?|creates?|makes?|uses?|offers?|guarantees?|establishes?|"
    r"proves?|certif(?:y|ies)|constitutes?|means?)\b",
    re.IGNORECASE,
)
_SHARED_PROVIDER_SUBJECT_BOUNDARY = re.compile(
    r"\b(?:and|but|while|yet)\s+(?:uses?|offers?)\b",
    re.IGNORECASE,
)
MAX_RELATION_DISTANCE = 400
_CONTEXTUAL_RULES = (
    ("INTEGRITY_IS_STORAGE", INTEGRITY_SUBJECT, STORAGE_PREDICATE),
    ("CHECKPOINT_OVERCLAIM", CHECKPOINT_SUBJECT, CHECKPOINT_EXCESS_PREDICATE),
    ("AEGIS_CERTIFICATION_CLAIM", AEGIS_SUBJECT, CERTIFICATION_PREDICATE),
    ("IMMUTABLE_EVIDENCE_RECORD", EVIDENCE_RECORD_SUBJECT, STORAGE_PREDICATE),
    ("IMMUTABLE_EVIDENCE_RECORD", STORAGE_SUBJECT, STORAGE_PREDICATE),
    ("IMMUTABLE_EVIDENCE_RECORD", PROVIDER_SUBJECT, STORAGE_PREDICATE),
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


def scan_claims(blocks: tuple[TextBlock, ...]) -> tuple[ClaimFinding, ...]:
    """Return contextual assurance overclaims from normalized public blocks."""

    def relation_distance(subject: re.Match[str], predicate: re.Match[str]) -> int:
        if subject.end() <= predicate.start():
            return predicate.start() - subject.end()
        if predicate.end() <= subject.start():
            return subject.start() - predicate.end()
        return 0

    def related(subject: re.Match[str], predicate: re.Match[str]) -> bool:
        return relation_distance(subject, predicate) <= MAX_RELATION_DISTANCE

    def negates_relation(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> bool:
        if subject.end() <= predicate.start():
            between = text[subject.end():predicate.start()]
            subject_precedes = True
        elif predicate.end() <= subject.start():
            between = text[predicate.end():subject.start()]
            subject_precedes = False
        else:
            between = ""
            subject_precedes = True
        if PSEUDO_NEGATION.search(between) is not None:
            return False
        for negative in BOUNDED_NEGATIVE.finditer(between):
            connection = (
                between[negative.end():]
                if subject_precedes
                else between[:negative.start()]
            )
            if _CLAUSE_BOUNDARY.search(connection) is None:
                return True
        return False

    def related_matches(
        subject_pattern: re.Pattern[str],
        predicate: re.Match[str],
    ) -> tuple[re.Match[str], ...]:
        subjects = pattern_matches[subject_pattern]
        first_possible = bisect_left(
            match_ends[subject_pattern],
            predicate.start() - MAX_RELATION_DISTANCE,
        )
        candidates: list[re.Match[str]] = []
        for subject in subjects[first_possible:]:
            if subject.start() > predicate.end() + MAX_RELATION_DISTANCE:
                break
            if related(subject, predicate):
                candidates.append(subject)
        return tuple(candidates)

    def has_unnegated_relation(
        text: str,
        subject_pattern: re.Pattern[str],
        predicate: re.Match[str],
    ) -> bool:
        return any(
            not negates_relation(text, subject, predicate)
            for subject in related_matches(subject_pattern, predicate)
        )

    def bounded_relation_context(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
        boundary_pattern: re.Pattern[str],
    ) -> str | None:
        relation_start = min(subject.start(), predicate.start())
        relation_end = max(subject.end(), predicate.end())
        if boundary_pattern.search(text, relation_start, relation_end):
            return None
        context_floor = max(0, relation_start - MAX_RELATION_DISTANCE)
        context_start = context_floor
        for boundary in boundary_pattern.finditer(
            text,
            context_floor,
            relation_start,
        ):
            context_start = boundary.end()
        context_ceiling = min(len(text), relation_end + MAX_RELATION_DISTANCE)
        boundary = boundary_pattern.search(text, relation_end, context_ceiling)
        context_end = (
            boundary.start() if boundary is not None else context_ceiling
        )
        return text[context_start:context_end]

    def relation_context(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> str | None:
        return bounded_relation_context(
            text,
            subject,
            predicate,
            _CLAUSE_BOUNDARY,
        )

    def provider_subject_carries_to_predicate(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> bool:
        if subject.end() > predicate.start():
            return False
        boundaries = tuple(
            _CLAUSE_BOUNDARY.finditer(
                text,
                subject.end(),
                predicate.start(),
            )
        )
        return (
            len(boundaries) == 1
            and _SHARED_PROVIDER_SUBJECT_BOUNDARY.fullmatch(
                boundaries[0].group()
            )
            is not None
        )

    def carried_provider_clause_context(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> str | None:
        if not provider_subject_carries_to_predicate(text, subject, predicate):
            return None
        boundary = _SHARED_PROVIDER_SUBJECT_BOUNDARY.search(
            text,
            subject.end(),
            predicate.start(),
        )
        if boundary is None:
            return None
        context_ceiling = min(len(text), predicate.end() + MAX_RELATION_DISTANCE)
        next_boundary = _CLAUSE_BOUNDARY.search(
            text,
            predicate.end(),
            context_ceiling,
        )
        context_end = (
            next_boundary.start()
            if next_boundary is not None
            else context_ceiling
        )
        return text[boundary.start():context_end]

    def sentence_context(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> str | None:
        return bounded_relation_context(
            text,
            subject,
            predicate,
            _SENTENCE_BOUNDARY,
        )

    def predicate_describes_storage(
        text: str,
        predicate: re.Match[str],
    ) -> bool:
        for storage in related_matches(STORAGE_TERM, predicate):
            if relation_context(text, storage, predicate) is None:
                continue
            if _STORAGE_NON_ASSURANCE_SUFFIX.match(text[storage.end():]) is not None:
                continue
            if predicate.end() <= storage.start():
                connector = text[predicate.end():storage.start()]
                pattern = _PREDICATE_BEFORE_STORAGE
            elif storage.end() <= predicate.start():
                connector = text[storage.end():predicate.start()]
                pattern = _STORAGE_BEFORE_PREDICATE
            else:
                continue
            if pattern.fullmatch(connector) is not None:
                return True
        return False

    def action_connects(
        text: str,
        subject: re.Match[str],
        action: re.Match[str],
        predicate: re.Match[str],
    ) -> bool:
        if subject.end() <= predicate.start():
            return (
                subject.end() <= action.start()
                and action.end() <= predicate.start()
                and _ACTION_OBJECT_CONNECTOR.fullmatch(
                    text[action.end():predicate.start()]
                )
                is not None
            )
        if predicate.end() <= subject.start():
            return (
                predicate.end() <= action.start()
                and action.end() <= subject.start()
                and _ACTION_OBJECT_CONNECTOR.fullmatch(
                    text[predicate.end():action.start()]
                )
                is not None
            )
        return False

    def bounded_excerpt(text: str, predicate_offset: int) -> str:
        encoded = text.encode("utf-8")
        predicate_byte = len(text[:predicate_offset].encode("utf-8"))
        start = max(0, predicate_byte - 120)
        end = min(len(encoded), start + 240)
        start = max(0, end - 240)
        return encoded[start:end].decode("utf-8", errors="ignore").strip()

    def iter_windows():
        for block in blocks:
            yield block.text, block, None
        for first, second in zip(blocks, blocks[1:]):
            if first.path == second.path:
                yield f"{first.text} {second.text}", first, second

    candidate_findings: dict[
        tuple[str, tuple[Path, int, int, str]],
        ClaimFinding,
    ] = {}
    provider_exemptions: set[tuple[Path, int, int, str]] = set()
    patterns = frozenset(
        pattern
        for _, subject_pattern, predicate_pattern in _CONTEXTUAL_RULES
        for pattern in (subject_pattern, predicate_pattern)
    ) | frozenset({CERTIFICATION_ACTION, CERTIFICATION_OBJECT, STORAGE_TERM})

    for text, first, second in iter_windows():
        pattern_matches = {
            pattern: tuple(pattern.finditer(text)) for pattern in patterns
        }
        match_ends = {
            pattern: tuple(match.end() for match in matches)
            for pattern, matches in pattern_matches.items()
        }
        split_at = len(first.text) + 1

        def predicate_identity(
            predicate: re.Match[str],
        ) -> tuple[Path, int, int, str]:
            predicate_block = (
                second
                if second is not None and predicate.start() >= split_at
                else first
            )
            local_offset = (
                predicate.start() - split_at
                if predicate_block is second
                else predicate.start()
            )
            return (
                predicate_block.path,
                predicate_block.line,
                local_offset,
                predicate.group().casefold(),
            )

        def record_finding(rule_id: str, predicate: re.Match[str]) -> None:
            identity = predicate_identity(predicate)
            candidate_findings.setdefault(
                (rule_id, identity),
                ClaimFinding(
                    rule_id=rule_id,
                    path=identity[0],
                    line=identity[1],
                    excerpt=bounded_excerpt(text, predicate.start()),
                ),
            )

        def provider_example_qualifies(predicate: re.Match[str]) -> bool:
            for provider in related_matches(PROVIDER_SUBJECT, predicate):
                context = relation_context(text, provider, predicate)
                if context is None:
                    context = carried_provider_clause_context(
                        text,
                        provider,
                        predicate,
                    )
                if context is None:
                    continue
                active_certification = (
                    CERTIFICATION_ACTION.search(context) is not None
                    and CERTIFICATION_OBJECT.search(context) is not None
                )
                if (
                    _ILLUSTRATIVE_PROVIDER_CONTEXT.search(context) is not None
                    and _NEGATED_PROVIDER_CONTEXT.search(context) is None
                    and AEGIS_SUBJECT.search(context) is None
                    and CERTIFICATION_PREDICATE.search(context) is None
                    and not active_certification
                ):
                    return True
            return False

        for rule_id, subject_pattern, predicate_pattern in _CONTEXTUAL_RULES:
            subjects = pattern_matches[subject_pattern]
            if not subjects:
                continue
            for predicate in pattern_matches[predicate_pattern]:
                if not has_unnegated_relation(text, subject_pattern, predicate):
                    continue
                if subject_pattern in {STORAGE_SUBJECT, PROVIDER_SUBJECT} and not any(
                    (
                        relation_context(text, subject, predicate) is not None
                        or (
                            subject_pattern is PROVIDER_SUBJECT
                            and provider_subject_carries_to_predicate(
                                text,
                                subject,
                                predicate,
                            )
                        )
                    )
                    and not negates_relation(text, subject, predicate)
                    for subject in related_matches(subject_pattern, predicate)
                ):
                    continue
                if (
                    subject_pattern in {STORAGE_SUBJECT, PROVIDER_SUBJECT}
                    and not predicate_describes_storage(text, predicate)
                ):
                    continue
                if (
                    rule_id == "IMMUTABLE_EVIDENCE_RECORD"
                    and subject_pattern
                    in {EVIDENCE_RECORD_SUBJECT, STORAGE_SUBJECT, PROVIDER_SUBJECT}
                    and related_matches(INTEGRITY_SUBJECT, predicate)
                ):
                    continue
                if (
                    rule_id == "IMMUTABLE_EVIDENCE_RECORD"
                    and provider_example_qualifies(predicate)
                ):
                    provider_exemptions.add(predicate_identity(predicate))
                    continue

                record_finding(rule_id, predicate)

        for predicate in pattern_matches[STORAGE_PREDICATE]:
            if not predicate_describes_storage(text, predicate):
                continue
            for subject in related_matches(AEGIS_SUBJECT, predicate):
                if sentence_context(text, subject, predicate) is None:
                    continue
                if negates_relation(text, subject, predicate):
                    continue
                record_finding("IMMUTABLE_EVIDENCE_RECORD", predicate)
                break

        for predicate in pattern_matches[CERTIFICATION_OBJECT]:
            actions = related_matches(CERTIFICATION_ACTION, predicate)
            if not actions:
                continue
            for subject in related_matches(AEGIS_SUBJECT, predicate):
                if sentence_context(text, subject, predicate) is None:
                    continue
                if negates_relation(text, subject, predicate):
                    continue
                if any(
                    action_connects(text, subject, action, predicate)
                    for action in actions
                ):
                    record_finding("AEGIS_CERTIFICATION_CLAIM", predicate)
                    break

    findings: dict[tuple[str, Path, int], ClaimFinding] = {}
    for (_, identity), finding in candidate_findings.items():
        if (
            finding.rule_id == "IMMUTABLE_EVIDENCE_RECORD"
            and identity in provider_exemptions
        ):
            continue
        findings.setdefault(
            (finding.rule_id, finding.path, finding.line),
            finding,
        )

    return tuple(
        sorted(
            findings.values(),
            key=lambda finding: (
                finding.path.as_posix(),
                finding.line,
                finding.rule_id,
            ),
        )
    )


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
        if label_opening < 0:
            marker_start = marker + 2
            continue
        if target_end is None:
            break
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
