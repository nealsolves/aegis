#!/usr/bin/env python3
"""Reject evidence-assurance overclaims in maintained public copy."""

from __future__ import annotations

from bisect import bisect_left
from collections import deque
import fnmatch
import html
import json
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys
import unicodedata

import yaml

if __package__:
    from scripts.check_demo_copy import (
        extract_frontend_public_copy,
        iter_frontend_public_files,
    )
    from scripts.check_doc_parity import (
        check_documentation_inventory,
        collect_repository_files,
        load_manifest,
    )
else:
    from check_demo_copy import (
        extract_frontend_public_copy,
        iter_frontend_public_files,
    )
    from check_doc_parity import (
        check_documentation_inventory,
        collect_repository_files,
        load_manifest,
    )

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "doc_parity_manifest.yaml"
FRONTEND_ROOT = REPO_ROOT / "demo-app-react" / "src"
TEXT_SUFFIXES = frozenset({".html", ".json", ".md", ".mermaid", ".svg"})
BINARY_SUFFIXES = frozenset({".png"})
_ZERO_WIDTH_TRANSLATION = str.maketrans(
    {"\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": ""}
)
_WHITESPACE_RE = re.compile(r"\s+")
_MAX_MARKDOWN_LABEL_CHARS = 8_192
_MAX_MARKDOWN_TARGET_CHARS = 16_384
_MAX_PARITY_DOC_PATH_BYTES = 1_024
DEFAULT_MAX_FINDINGS = 1_000
_MARKDOWN_PREFIX_RE = re.compile(
    r"^[ \t]{0,3}(?:#{1,6}[ \t]+|[-*+][ \t]+|>[ \t]?|\d{1,9}[.)][ \t]+)"
)
_MARKDOWN_INLINE_MARKER_RE = re.compile(r"(?<!\\)(?:\*{1,3}|`{1,3}|~{2})")
_MARKDOWN_UNDERSCORE_OPEN_RE = re.compile(r"(?<![\w\\])_{1,3}(?=\S)")
_MARKDOWN_UNDERSCORE_CLOSE_RE = re.compile(
    r"(?<=\S)_{1,3}(?=$|[\s.,;:!?)}\]])"
)
_MARKDOWN_INLINE_TAG_RE = re.compile(
    r"</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^>\r\n]{0,1024})?/?>"
)
_PUBLIC_ATTRIBUTES = frozenset(
    {"alt", "aria-description", "aria-label", "placeholder", "title"}
)
_HTML_BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "body",
        "dd",
        "desc",
        "div",
        "dl",
        "dt",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "html",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tbody",
        "td",
        "text",
        "tfoot",
        "th",
        "thead",
        "title",
        "tr",
        "ul",
    }
)
_HTML_HIDDEN_TAGS = frozenset({"script", "style", "template"})
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
    r"\b(?:checksums?|signatures?|hash[- ]?(?:chains?|chaining))\b",
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
    r"\b(?:AEGIS evidence|evidence(?: (?:artifacts?|objects?|records?|logs?))?|"
    r"(?:audit|invocation|workflow) "
    r"(?:artifacts?|records?|logs?|evidence))\b(?! operations?\b)",
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
    r"tamper[- ]proof|deletion[- ]proof|cannot be (?:changed|deleted|modified|rewritten)|"
    r"impossible[- ]to[- ](?:change|delete|modify|rewrite))\b",
    re.IGNORECASE,
)
CERTIFICATION_PREDICATE = re.compile(
    r"\b(?:certified|certification|compliant|guaranteed compliance|audit[- ]ready|"
    r"regulatory[- ]ready|regulatory approval|legally (?:admissible|sufficient))\b",
    re.IGNORECASE,
)
CHECKPOINT_EXCESS_PREDICATE = re.compile(
    r"\b(?:(?:latest|newest|most[- ]recent) (?:retrieval|record|evidence)|"
    r"no (?:later|newer|subsequent) (?:activity|events?|records?|evidence)|"
    r"future inactivity|immutable(?: storage)?|immutability|append[- ]only|WORM|"
    r"unalterable|indelible|tamper[- ]proof|deletion[- ]proof|"
    r"cannot be (?:changed|deleted|modified|rewritten)|"
    r"impossible[- ]to[- ](?:change|delete|modify|rewrite)|"
    r"certification|compliance)\b",
    re.IGNORECASE,
)
PSEUDO_NEGATION = re.compile(
    r"\b(?:not only|does not merely|do not merely|cannot merely|"
    r"does not fail to|do not fail to|cannot fail to)\b",
    re.IGNORECASE,
)
BOUNDED_NEGATIVE = re.compile(
    r"\b(?:(?:do|does|did) not|(?:do|does|did)n['’]t|cannot|can not|"
    r"can['’]t|never) (?:provide|create|make|use|offer|guarantee|establish|"
    r"prove|certify|constitute|mean)\b|"
    r"\bprovides? tamper[- ]evidence, not\b|\balone (?:do|does) not\b",
    re.IGNORECASE,
)
_COPULAR_NEGATIVE = re.compile(
    r"\b(?:(?:is|are|was|were) not|(?:is|are|was|were)n['’]t|never)\b",
    re.IGNORECASE,
)
_COPULAR_NEGATIVE_TAIL = re.compile(
    r"\s*(?:(?:an?|the|automatically|currently|fully|legally|necessarily|"
    r"really|strictly|technically)\s+){0,3}",
    re.IGNORECASE,
)
CERTIFICATION_ACTION = re.compile(
    r"\b(?:certif(?:y|ies)|proves?|guarantees?|establishes?|provides?)\b",
    re.IGNORECASE,
)
CERTIFICATION_OBJECT = re.compile(
    r"\b(?:(?:(?:(?:full|ongoing|complete|continuous|regulatory|legal|policy|"
    r"technical) ){0,3}|(?:SOC 2(?: Type (?:I|II))? ))"
    r"(?:compliance|certification)|legal (?:sufficiency|admissibility))\b",
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
_SENTENCE_BOUNDARY = re.compile(r"[.!?]")
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
_INDEPENDENT_COPULAR_CLAUSE_BOUNDARY = re.compile(
    r"\b(?:and|but|while|yet)\b(?:\s+\w+){1,3}\s+"
    r"(?:is|are|was|were)\b",
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
    max_findings: int = DEFAULT_MAX_FINDINGS


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


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[ClaimFinding, ...]
    scanned_files: int
    binary_files: int
    findings_truncated: bool = False


def _scan_claims(
    blocks: tuple[TextBlock, ...],
    *,
    max_findings: int | None,
) -> tuple[tuple[ClaimFinding, ...], bool]:
    """Return bounded contextual findings and whether more were omitted."""

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
        if subject_precedes and any(
            _COPULAR_NEGATIVE_TAIL.fullmatch(between[negative.end():]) is not None
            for negative in _COPULAR_NEGATIVE.finditer(between)
        ):
            return True
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
        for subject in related_matches(subject_pattern, predicate):
            if sentence_context(text, subject, predicate) is None:
                continue
            if not negates_relation(text, subject, predicate):
                return True
        return False

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
        next_boundary = min(
            (
                candidate
                for pattern in (
                    _CLAUSE_BOUNDARY,
                    _INDEPENDENT_COPULAR_CLAUSE_BOUNDARY,
                )
                if (
                    candidate := pattern.search(
                        text,
                        predicate.end(),
                        context_ceiling,
                    )
                )
                is not None
            ),
            key=lambda boundary: boundary.start(),
            default=None,
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
                return True
            if pattern.fullmatch(connector) is not None:
                return True
        return False

    def predicate_describes_evidence_record(
        text: str,
        subject: re.Match[str],
        predicate: re.Match[str],
    ) -> bool:
        if predicate.end() <= subject.start():
            connector = text[predicate.end():subject.start()]
            return re.fullmatch(r"\s*(?:(?:an?|the)\s+)?", connector) is not None
        if subject.end() <= predicate.start():
            connector = text[subject.end():predicate.start()]
            direct = re.fullmatch(
                r"\s*(?:(?:that|which)\s+)?(?:is|are|was|were|remains?|"
                r"becomes?|provides?|creates?|makes?|guarantees?|"
                r"constitutes?|means?)?\s*",
                connector,
                re.IGNORECASE,
            )
            carried = re.fullmatch(
                r"\s*(?:is|are|was|were|remains?)\b[^.;!?]{0,120}"
                r"\b(?:and|but|yet)\s+(?:is|are|was|were|remains?)\s*",
                connector,
                re.IGNORECASE,
            )
            return direct is not None or carried is not None
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
    findings_truncated = False
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
            nonlocal findings_truncated
            identity = predicate_identity(predicate)
            key = (rule_id, identity)
            if key in candidate_findings:
                return
            if max_findings is not None and len(candidate_findings) >= max_findings:
                findings_truncated = True
                return
            candidate_findings[key] = ClaimFinding(
                rule_id=rule_id,
                path=identity[0],
                line=identity[1],
                excerpt=bounded_excerpt(text, predicate.start()),
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
                    subject_pattern is EVIDENCE_RECORD_SUBJECT
                    and not any(
                        predicate_describes_evidence_record(text, subject, predicate)
                        and not negates_relation(text, subject, predicate)
                        for subject in related_matches(subject_pattern, predicate)
                    )
                ):
                    continue
                if (
                    rule_id == "CHECKPOINT_OVERCLAIM"
                    and STORAGE_PREDICATE.search(predicate.group()) is not None
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

    ordered = tuple(
        sorted(
            findings.values(),
            key=lambda finding: (
                finding.path.as_posix(),
                finding.line,
                finding.rule_id,
            ),
        )
    )
    if max_findings is not None and len(ordered) > max_findings:
        findings_truncated = True
        ordered = ordered[:max_findings]
    return ordered, findings_truncated


def scan_claims(
    blocks: tuple[TextBlock, ...],
    *,
    max_findings: int | None = DEFAULT_MAX_FINDINGS,
) -> tuple[ClaimFinding, ...]:
    """Return contextual assurance overclaims from normalized public blocks."""
    return _scan_claims(blocks, max_findings=max_findings)[0]


def _strip_markdown_targets(text: str) -> str:
    """Retain Markdown labels while dropping targets in one bounded pass."""
    output: list[str] = []
    label_stack: deque[tuple[int, int, int | None]] = deque()
    position = 0
    while position < len(text):
        character = text[position]
        if character == "\\" and position + 1 < len(text):
            output.extend((character, text[position + 1]))
            position += 2
            continue
        if character == "[":
            while (
                label_stack
                and position - label_stack[0][0] > _MAX_MARKDOWN_LABEL_CHARS + 1
            ):
                label_stack.popleft()
            image_marker = (
                len(output) - 1
                if (
                    position > 0
                    and text[position - 1] == "!"
                    and output[-1:] == ["!"]
                )
                else None
            )
            label_stack.append((position, len(output), image_marker))
            output.append(character)
            position += 1
            continue
        if character != "]":
            output.append(character)
            position += 1
            continue

        while (
            label_stack
            and position - label_stack[0][0] > _MAX_MARKDOWN_LABEL_CHARS + 1
        ):
            label_stack.popleft()
        label = label_stack.pop() if label_stack else None
        if label is None or position + 1 >= len(text) or text[position + 1] != "(":
            output.append(character)
            position += 1
            continue
        label_source, label_output, image_marker = label
        if position - label_source - 1 > _MAX_MARKDOWN_LABEL_CHARS:
            output.append(character)
            position += 1
            continue

        marker_start = position
        target_opening = position + 1
        target_depth = 1
        cursor = target_opening + 1
        while cursor < len(text):
            target_character = text[cursor]
            if (
                target_character in "\r\n"
                or cursor - target_opening > _MAX_MARKDOWN_TARGET_CHARS
            ):
                output.append(text[marker_start:])
                return "".join(output)
            if target_character == "\\" and cursor + 1 < len(text):
                cursor += 2
                continue
            if target_character == "(":
                target_depth += 1
            elif target_character == ")":
                target_depth -= 1
                if target_depth == 0:
                    break
            cursor += 1
        if target_depth != 0:
            output.append(text[marker_start:])
            return "".join(output)

        output[label_output] = ""
        if image_marker is not None:
            output[image_marker] = ""
        position = cursor + 1
    return "".join(output)


def normalize_public_text(text: str) -> str:
    """Canonicalize user-visible text before evaluating assurance claims."""
    normalized = html.unescape(text)
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = normalized.translate(_ZERO_WIDTH_TRANSLATION)
    normalized = _strip_markdown_targets(normalized)
    normalized = _MARKDOWN_INLINE_MARKER_RE.sub("", normalized)
    normalized = _MARKDOWN_UNDERSCORE_OPEN_RE.sub("", normalized)
    normalized = _MARKDOWN_UNDERSCORE_CLOSE_RE.sub("", normalized)
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
        self._parts: list[str] = []
        self._line: int | None = None
        self._hidden_depth = 0

    def _append_block(self, text: str, line: int) -> None:
        block = _bounded_block(
            self._path,
            line,
            text,
            self._limits,
            self._counters,
        )
        if block is not None:
            self.blocks.append(block)

    def _flush(self) -> None:
        if self._parts:
            self._append_block("".join(self._parts), self._line or 1)
        self._parts = []
        self._line = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in _HTML_BLOCK_TAGS:
            self._flush()
        if tag in _HTML_HIDDEN_TAGS:
            self._hidden_depth += 1
            return
        if self._hidden_depth:
            return
        attributes = {name.lower(): value for name, value in attrs}
        for name, value in attrs:
            if name.lower() in _PUBLIC_ATTRIBUTES and value is not None:
                self._append_block(value, self.getpos()[0])
        if tag == "meta" and attributes.get("content") is not None:
            self._append_block(attributes["content"], self.getpos()[0])
        if tag == "br":
            self._parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _HTML_HIDDEN_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)
            return
        if not self._hidden_depth and tag in _HTML_BLOCK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        if self._line is None and data.strip():
            self._line = self.getpos()[0]
        self._parts.append(data)

    def close(self) -> None:
        super().close()
        self._flush()


def _extract_json_blocks(
    path: Path,
    text: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> tuple[TextBlock, ...]:
    """Validate JSON and return decoded string values with source lines."""
    try:
        json.loads(text)
    except json.JSONDecodeError as error:
        raise ClaimsGuardError(f"{path}: malformed JSON") from error
    except RecursionError as error:
        raise ClaimsGuardError(f"{path}: JSON nesting limit exceeded") from error

    blocks: list[TextBlock] = []
    position = 0
    line = 1
    while position < len(text):
        if text[position] != '"':
            if text[position] == "\n":
                line += 1
            position += 1
            continue

        string_start = position
        string_line = line
        position += 1
        while position < len(text):
            if text[position] == "\\":
                position += 2
                continue
            if text[position] == '"':
                break
            position += 1
        string_end = position + 1
        decoded = json.loads(text[string_start:string_end])
        following = string_end
        while following < len(text) and text[following].isspace():
            following += 1
        if following >= len(text) or text[following] != ":":
            block = _bounded_block(
                path,
                string_line,
                decoded,
                limits,
                counters,
            )
            if block is not None:
                blocks.append(block)
        position = string_end
    return tuple(blocks)


def extract_document_blocks(
    path: Path,
    text: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> tuple[TextBlock, ...]:
    """Return bounded public text blocks from a maintained document."""
    if path.suffix.lower() == ".json":
        return _extract_json_blocks(path, text, limits, counters)
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
        public_line = _MARKDOWN_INLINE_TAG_RE.sub("", public_line)
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


def _validated_parity_docs(manifest: dict) -> frozenset[str]:
    parity_docs = manifest.get("parity_docs")
    if not isinstance(parity_docs, list):
        raise ClaimsGuardError("manifest has malformed parity_docs")
    validated: set[str] = set()
    for relative in parity_docs:
        if not isinstance(relative, str) or not relative:
            raise ClaimsGuardError("manifest has malformed parity_docs")
        try:
            encoded_size = len(relative.encode("utf-8"))
        except UnicodeError as error:
            raise ClaimsGuardError("manifest has malformed parity_docs") from error
        if (
            encoded_size > _MAX_PARITY_DOC_PATH_BYTES
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise ClaimsGuardError("manifest has malformed parity_docs")
        validated.add(relative)
    return frozenset(validated)


def _preflight_frontend_sources(
    frontend_paths: list[Path],
    frontend_root: Path,
    current_file_count: int,
    limits: ScanLimits,
    counters: dict[str, int],
) -> None:
    if current_file_count + len(frontend_paths) > limits.max_files:
        raise ClaimsGuardError("frontend file limit exceeded")
    try:
        resolved_frontend_root = frontend_root.resolve(strict=True)
    except OSError as error:
        raise ClaimsGuardError("frontend path resolution failed") from error

    for path in frontend_paths:
        try:
            relative = path.relative_to(frontend_root).as_posix()
        except ValueError as error:
            raise ClaimsGuardError("frontend path is outside frontend root") from error
        if path.is_symlink():
            raise ClaimsGuardError(f"{relative}: frontend symlink is not scannable")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ClaimsGuardError(
                f"{relative}: frontend path resolution failed"
            ) from error
        if not resolved.is_relative_to(resolved_frontend_root):
            raise ClaimsGuardError(
                f"{relative}: frontend path resolves outside frontend root"
            )
        if not resolved.is_file():
            raise ClaimsGuardError(
                f"{relative}: frontend special file is not scannable"
            )
        try:
            size = path.stat().st_size
            if size > limits.max_file_bytes:
                raise ClaimsGuardError(
                    f"{relative}: frontend source file limit exceeded"
                )
            with path.open("rb") as source_file:
                payload = source_file.read(limits.max_file_bytes + 1)
        except OSError as error:
            raise ClaimsGuardError(
                f"{relative}: frontend source read failed"
            ) from error
        if len(payload) > limits.max_file_bytes:
            raise ClaimsGuardError(
                f"{relative}: frontend source file limit exceeded"
            )
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ClaimsGuardError(
                f"{relative}: frontend source is not valid UTF-8"
            ) from error
        counters["source_bytes"] += len(payload)
        if counters["source_bytes"] > limits.max_source_bytes:
            raise ClaimsGuardError("aggregate source limit exceeded")


def _extract_frontend_blocks(
    path: Path,
    document: str,
    limits: ScanLimits,
    counters: dict[str, int],
) -> tuple[TextBlock, ...]:
    blocks: list[TextBlock] = []
    segment_start = 0
    source_line = 1
    while True:
        separator = document.find("\0", segment_start)
        segment_end = len(document) if separator < 0 else separator
        if counters["public_blocks"] >= limits.max_public_blocks:
            raise ClaimsGuardError("public copy block limit exceeded")
        segment = document[segment_start:segment_end]
        content_offset = 0
        while content_offset < len(segment) and segment[content_offset].isspace():
            content_offset += 1
        line = source_line + segment.count("\n", 0, content_offset)
        block = _bounded_block(path, line, segment, limits, counters)
        if block is not None:
            blocks.append(block)
        else:
            counters["public_blocks"] += 1
        source_line += segment.count("\n")
        if separator < 0:
            break
        segment_start = separator + 1
    return tuple(blocks)


def run_guard(
    repo_root: Path = REPO_ROOT,
    frontend_root: Path = FRONTEND_ROOT,
    limits: ScanLimits = ScanLimits(),
) -> ScanResult:
    """Scan maintained documentation and frontend copy for overclaims."""
    try:
        manifest = load_manifest()
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        raise ClaimsGuardError("manifest load failed") from error
    if not isinstance(manifest, dict):
        raise ClaimsGuardError("manifest load failed")

    try:
        inventory_errors = check_documentation_inventory(manifest)
    except (
        OSError,
        UnicodeError,
        ValueError,
        RuntimeError,
        TypeError,
        KeyError,
    ) as error:
        raise ClaimsGuardError("documentation inventory validation failed") from error
    if inventory_errors:
        raise ClaimsGuardError("documentation inventory validation failed")

    try:
        repository_files = collect_repository_files(require_git=True)
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        raise ClaimsGuardError("Git repository enumeration failed") from error
    current_paths = select_current_paths(
        repo_root,
        manifest,
        repository_files,
        limits,
    )
    current_relatives = {
        path.relative_to(repo_root).as_posix() for path in current_paths
    }
    parity_docs = _validated_parity_docs(manifest)
    mandatory_paths = MANDATORY_CURRENT_PATHS | parity_docs
    missing = sorted(mandatory_paths - current_relatives)
    if missing:
        raise ClaimsGuardError(
            f"mandatory current path is missing: {missing[0]}"
        )

    source_counters = {"source_bytes": 0, "binary_files": 0}
    block_counters = {"normalized_bytes": 0, "public_blocks": 0}
    blocks: list[TextBlock] = []
    text_document_count = 0
    for path in current_paths:
        text = read_text_source(path, repo_root, limits, source_counters)
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        text_document_count += 1
        try:
            blocks.extend(
                extract_document_blocks(path, text, limits, block_counters)
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise ClaimsGuardError("document block extraction failed") from error

    try:
        frontend_paths = sorted(set(iter_frontend_public_files(frontend_root)))
    except (OSError, UnicodeError, ValueError) as error:
        raise ClaimsGuardError("frontend enumeration failed") from error
    _preflight_frontend_sources(
        frontend_paths,
        frontend_root,
        len(current_paths),
        limits,
        source_counters,
    )
    try:
        frontend_documents = extract_frontend_public_copy(
            frontend_paths,
            max_output_bytes=limits.max_extractor_bytes,
        )
    except (
        OSError,
        UnicodeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        raise ClaimsGuardError("frontend extraction failed") from error
    if not isinstance(frontend_documents, dict):
        raise ClaimsGuardError("frontend extraction returned invalid documents")
    if set(frontend_documents) != set(frontend_paths):
        raise ClaimsGuardError("frontend extraction returned invalid documents")

    extracted_bytes = 0
    for path in frontend_paths:
        document = frontend_documents[path]
        if not isinstance(document, str):
            raise ClaimsGuardError("frontend extraction returned invalid documents")
        try:
            extracted_bytes += len(document.encode("utf-8"))
        except UnicodeError as error:
            raise ClaimsGuardError(
                "frontend extraction returned invalid documents"
            ) from error
        if extracted_bytes > limits.max_extractor_bytes:
            raise ClaimsGuardError("frontend extractor output limit exceeded")
        blocks.extend(
            _extract_frontend_blocks(path, document, limits, block_counters)
        )

    findings, findings_truncated = _scan_claims(
        tuple(blocks),
        max_findings=limits.max_findings,
    )
    return ScanResult(
        findings=findings,
        scanned_files=text_document_count + len(frontend_paths),
        binary_files=source_counters["binary_files"],
        findings_truncated=findings_truncated,
    )


def _display_path(path: Path) -> str:
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def main(argv: list[str] | None = None) -> int:
    del argv
    try:
        result = run_guard()
    except ClaimsGuardError as error:
        print(f"claims guard failed: {error}", file=sys.stderr)
        return 2
    for finding in result.findings:
        display = _display_path(finding.path)
        print(f"{finding.rule_id}: {display}:{finding.line}: {finding.excerpt}")
    if result.findings_truncated:
        print(
            "FINDINGS_TRUNCATED: displayed "
            f"{len(result.findings)} findings; additional findings omitted"
        )
    if result.findings or result.findings_truncated:
        return 1
    print(
        "PASS: evidence claims guard scanned "
        f"{result.scanned_files} text files and accounted for "
        f"{result.binary_files} binary files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
