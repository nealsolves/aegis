"""Strict, non-executable loading and validation for the compliance catalog."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import unicodedata
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker
import yaml


MAX_FILE_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_NODES = 50_000
MAX_SCALAR_CHARS = 16_384
MAX_FINDINGS = 1_000
PR_URL = re.compile(r"https://github\.com/nealsolves/aegis/pull/[1-9][0-9]*\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/() -]{0,255}\Z")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class CatalogInputError(ValueError):
    """Raised when catalog bytes cannot safely become catalog data."""


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    location: str
    message: str


@dataclass(frozen=True)
class CatalogData:
    root: Path
    manifest: dict[str, Any]
    modules: tuple[dict[str, Any], ...]


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise CatalogInputError("YAML merge keys are not allowed")
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise CatalogInputError("mapping keys must be strings")
        if key in mapping:
            raise CatalogInputError(f"duplicate key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _reject_obscuring_yaml(text: str) -> None:
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None):
                raise CatalogInputError("YAML aliases and anchors are not allowed")
            if isinstance(event, yaml.events.ScalarEvent) and event.tag:
                if not event.tag.startswith("tag:yaml.org,2002:"):
                    raise CatalogInputError("custom YAML tags are not allowed")
    except CatalogInputError:
        raise
    except yaml.YAMLError as exc:
        message = str(exc)
        if "could not determine a constructor" in message or "tag" in message.lower():
            raise CatalogInputError("custom YAML tags are not allowed") from exc
        raise CatalogInputError(f"invalid YAML: {message}") from exc


def _validate_tree(value: Any, *, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise CatalogInputError("YAML node limit exceeded")
    if depth > MAX_DEPTH:
        raise CatalogInputError("YAML nesting limit exceeded")
    if isinstance(value, str):
        if len(value) > MAX_SCALAR_CHARS:
            raise CatalogInputError("YAML scalar length limit exceeded")
        if CONTROL_CHARS.search(value):
            raise CatalogInputError("control characters are not allowed")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_tree(item, depth=depth + 1, count=count)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CatalogInputError("mapping keys must be strings")
            _validate_tree(key, depth=depth + 1, count=count)
            _validate_tree(item, depth=depth + 1, count=count)
        return
    raise CatalogInputError(f"unsafe YAML scalar type: {type(value).__name__}")


def load_yaml_text(text: str) -> dict[str, Any]:
    """Load one bounded YAML mapping from already-decoded UTF-8 text."""
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CatalogInputError("catalog YAML is not valid UTF-8") from exc
    if len(encoded) > MAX_FILE_BYTES:
        raise CatalogInputError("YAML file size limit exceeded")
    if CONTROL_CHARS.search(text):
        raise CatalogInputError("control characters are not allowed")
    _reject_obscuring_yaml(text)
    try:
        value = yaml.load(text, Loader=_UniqueKeyLoader)
    except CatalogInputError:
        raise
    except yaml.constructor.ConstructorError as exc:
        raise CatalogInputError("custom YAML tags are not allowed") from exc
    except yaml.YAMLError as exc:
        raise CatalogInputError(f"invalid YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise CatalogInputError("catalog YAML root must be a mapping")
    _validate_tree(value)
    return value


def load_yaml(path: Path) -> dict[str, Any]:
    """Load one bounded UTF-8 YAML mapping without aliases or duplicate keys."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CatalogInputError(f"cannot read {path}: {exc}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise CatalogInputError("YAML file size limit exceeded")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogInputError("catalog YAML is not valid UTF-8") from exc
    return load_yaml_text(text)


def _finding(code: str, location: str, message: str) -> Finding:
    return Finding(code=code, location=location, message=message)


def _parse_date(value: object, location: str, findings: list[Finding]) -> date | None:
    if not isinstance(value, str):
        findings.append(_finding("INVALID_DATE", location, "date must be YYYY-MM-DD text"))
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        findings.append(_finding("INVALID_DATE", location, "date must be YYYY-MM-DD"))
        return None


def _duplicates(values: Iterable[object]) -> set[object]:
    seen: set[object] = set()
    duplicate: set[object] = set()
    for value in values:
        if value in seen:
            duplicate.add(value)
        seen.add(value)
    return duplicate


def validate_framework_module(
    module: Mapping[str, Any],
    *,
    phase: str,
    as_of: date,
    publication: bool = False,
    review_interval_days: int | None = None,
) -> tuple[Finding, ...]:
    """Validate cross-field framework semantics independent of file location."""
    findings: list[Finding] = []
    if phase not in {"scope", "mapping", "publication"}:
        return (
            _finding(
                "INVALID_PHASE",
                "phase",
                "phase must be scope, mapping, or publication",
            ),
        )
    framework = (
        module.get("framework")
        if isinstance(module.get("framework"), dict)
        else {}
    )
    sources = (
        framework.get("authoritative_sources")
        if isinstance(framework.get("authoritative_sources"), list)
        else []
    )
    source_ids = [
        source.get("source_id") for source in sources if isinstance(source, dict)
    ]
    source_access_dates: list[date] = []
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            continue
        accessed_on = _parse_date(
            source.get("accessed_on"),
            f"framework.authoritative_sources[{index}].accessed_on",
            findings,
        )
        if accessed_on is None:
            continue
        source_access_dates.append(accessed_on)
        if accessed_on > as_of:
            findings.append(
                _finding(
                    "SOURCE_ACCESS_DATE_IN_FUTURE",
                    f"framework.authoritative_sources[{index}].accessed_on",
                    "source access date cannot be later than --as-of",
                )
            )
    for duplicate in sorted(_duplicates(source_ids), key=str):
        findings.append(
            _finding(
                "DUPLICATE_SOURCE_ID",
                "framework.authoritative_sources",
                f"duplicate source_id: {duplicate}",
            )
        )
    defining_sources = {
        source.get("source_id")
        for source in sources
        if isinstance(source, dict)
        and source.get("role") in {"control_source", "amending_act"}
    }

    scope = (
        module.get("declared_scope")
        if isinstance(module.get("declared_scope"), dict)
        else {}
    )
    controls = (
        module.get("controls")
        if isinstance(module.get("controls"), list)
        else []
    )
    framework_id = framework.get("id")
    is_eu_citation_index = framework_id == "eu-ai-act-2024-1689-amended-2026"
    if is_eu_citation_index and phase != "scope":
        for field, code in (
            ("applicability_statement", "EU_APPLICABILITY_STATEMENT_REQUIRED"),
            ("effective_date_basis", "EU_EFFECTIVE_DATE_BASIS_REQUIRED"),
        ):
            value = scope.get(field)
            if not isinstance(value, str) or not value.strip():
                findings.append(
                    _finding(code, f"declared_scope.{field}", f"EU module requires {field}")
                )
    expected = scope.get("expected_mapping_count")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        findings.append(
            _finding(
                "INVALID_EXPECTED_COUNT",
                "declared_scope.expected_mapping_count",
                "expected count must be a non-negative integer",
            )
        )
    elif expected != len(controls):
        findings.append(
            _finding(
                "SCOPE_COUNT_MISMATCH",
                "declared_scope.expected_mapping_count",
                f"expected {expected} controls but found {len(controls)}",
            )
        )

    control_ids = [
        control.get("control_id")
        for control in controls
        if isinstance(control, dict)
    ]
    for duplicate in sorted(_duplicates(control_ids), key=str):
        findings.append(
            _finding(
                "DUPLICATE_CONTROL_ID",
                "controls",
                f"duplicate control_id: {duplicate}",
            )
        )

    for index, control in enumerate(controls):
        location = f"controls[{index}]"
        if not isinstance(control, dict):
            findings.append(_finding("INVALID_CONTROL", location, "control must be an object"))
            continue
        control_id = control.get("control_id")
        if not isinstance(control_id, str) or not IDENTIFIER.fullmatch(control_id):
            findings.append(
                _finding(
                    "INVALID_CONTROL_ID",
                    f"{location}.control_id",
                    "control_id is not a bounded identifier",
                )
            )
        reference = (
            control.get("source_reference")
            if isinstance(control.get("source_reference"), dict)
            else {}
        )
        if reference.get("source_id") not in defining_sources:
            findings.append(
                _finding(
                    "UNKNOWN_DEFINING_SOURCE",
                    f"{location}.source_reference.source_id",
                    "control must reference one control_source or amending_act",
                )
            )
        locator = reference.get("locator")
        if not isinstance(locator, str) or not locator.strip():
            findings.append(
                _finding(
                    "SOURCE_LOCATOR_REQUIRED",
                    f"{location}.source_reference.locator",
                    "source locator is required",
                )
            )
        if is_eu_citation_index and phase != "scope":
            rationale = control.get("inclusion_rationale")
            if not isinstance(rationale, str) or not rationale.strip():
                findings.append(
                    _finding(
                        "EU_INCLUSION_RATIONALE_REQUIRED",
                        f"{location}.inclusion_rationale",
                        "EU citation rows require a neutral inclusion rationale",
                    )
                )
            source_date = _parse_date(
                control.get("applicable_source_date"),
                f"{location}.applicable_source_date",
                findings,
            )
            if source_date is None:
                findings.append(
                    _finding(
                        "EU_SOURCE_DATE_REQUIRED",
                        f"{location}.applicable_source_date",
                        "EU citation rows require an applicable source date",
                    )
                )
            elif source_date > as_of:
                findings.append(
                    _finding(
                        "EU_SOURCE_DATE_IN_FUTURE",
                        f"{location}.applicable_source_date",
                        "applicable source date cannot be later than --as-of",
                    )
                )
        if phase == "scope":
            continue
        mapping = (
            control.get("mapping")
            if isinstance(control.get("mapping"), dict)
            else None
        )
        if mapping is None:
            findings.append(
                _finding(
                    "MAPPING_REQUIRED",
                    f"{location}.mapping",
                    "mapping is required",
                )
            )
            continue
        _validate_mapping(mapping, location=f"{location}.mapping", findings=findings)

    review = module.get("review") if isinstance(module.get("review"), dict) else {}
    reviewed_on = None
    next_due = None
    if phase != "scope" and "reviewed_on" in review:
        reviewed_on = _parse_date(
            review.get("reviewed_on"),
            "review.reviewed_on",
            findings,
        )
    if phase != "scope" and "next_review_due" in review:
        next_due = _parse_date(
            review.get("next_review_due"),
            "review.next_review_due",
            findings,
        )
    if reviewed_on and next_due and next_due <= reviewed_on:
        findings.append(
            _finding(
                "INVALID_REVIEW_WINDOW",
                "review.next_review_due",
                "next review must follow reviewed_on",
            )
        )
    if publication or phase == "publication":
        if reviewed_on is None:
            findings.append(
                _finding(
                    "REVIEW_DATE_REQUIRED",
                    "review.reviewed_on",
                    "publication requires reviewed_on",
                )
            )
        if next_due is None:
            findings.append(
                _finding(
                    "REVIEW_DATE_REQUIRED",
                    "review.next_review_due",
                    "publication requires next_review_due",
                )
            )
        if next_due and as_of > next_due:
            findings.append(
                _finding(
                    "REVIEW_OVERDUE",
                    "review.next_review_due",
                    f"review was due {next_due.isoformat()}",
                )
            )
        if reviewed_on and reviewed_on > as_of:
            findings.append(
                _finding(
                    "REVIEW_DATE_IN_FUTURE",
                    "review.reviewed_on",
                    "completed review date cannot be later than --as-of",
                )
            )
        if reviewed_on and source_access_dates and reviewed_on < max(source_access_dates):
            findings.append(
                _finding(
                    "REVIEW_PRECEDES_SOURCE_ACCESS",
                    "review.reviewed_on",
                    "completed review cannot predate its latest source access",
                )
            )
        tier = review.get("tier")
        decision = review.get("decision")
        if tier == "unreviewed" or tier not in {
            "maintainer_verified",
            "community_reviewed",
            "qualified_reviewed",
        }:
            findings.append(
                _finding(
                    "COMPLETED_REVIEW_REQUIRED",
                    "review.tier",
                    "publication requires a completed review tier",
                )
            )
        if decision != "approved":
            findings.append(
                _finding(
                    "REVIEW_DECISION_REQUIRED",
                    "review.decision",
                    "publication requires an approved review decision",
                )
            )
        contributors = review.get("contributor_github_ids")
        reviewers = review.get("reviewer_github_ids")
        contributor_set = set(contributors) if isinstance(contributors, list) else set()
        reviewer_set = set(reviewers) if isinstance(reviewers, list) else set()
        if not contributor_set:
            findings.append(
                _finding(
                    "CONTRIBUTOR_IDENTITY_REQUIRED",
                    "review.contributor_github_ids",
                    "publication requires at least one contributor GitHub identity",
                )
            )
        if not reviewer_set:
            findings.append(
                _finding(
                    "REVIEWER_IDENTITY_REQUIRED",
                    "review.reviewer_github_ids",
                    "publication requires at least one reviewer GitHub identity",
                )
            )
        if tier == "community_reviewed" and not (reviewer_set - contributor_set):
            findings.append(
                _finding(
                    "COMMUNITY_REVIEWER_NOT_DISTINCT",
                    "review.reviewer_github_ids",
                    "community review requires a reviewer distinct from contributors",
                )
            )
        if (
            reviewed_on is not None
            and next_due is not None
            and isinstance(review_interval_days, int)
            and next_due > reviewed_on + timedelta(days=review_interval_days)
        ):
            findings.append(
                _finding(
                    "REVIEW_CADENCE_EXCEEDED",
                    "review.next_review_due",
                    f"next review exceeds {review_interval_days}-day policy",
                )
            )
        pr_url = review.get("pr_url")
        if not isinstance(pr_url, str) or not PR_URL.fullmatch(pr_url):
            findings.append(
                _finding(
                    "REVIEW_PR_REQUIRED",
                    "review.pr_url",
                    "publication requires a nealsolves/aegis pull request URL",
                )
            )
        reviewed_commit = review.get("reviewed_commit_sha")
        if not isinstance(reviewed_commit, str) or not re.fullmatch(
            r"[a-f0-9]{40}", reviewed_commit
        ):
            findings.append(
                _finding(
                    "REVIEW_COMMIT_REQUIRED",
                    "review.reviewed_commit_sha",
                    "publication requires the exact reviewed commit SHA",
                )
            )
        if tier == "qualified_reviewed":
            review_scope = review.get("review_scope")
            if not isinstance(review_scope, str) or not review_scope.strip():
                findings.append(
                    _finding(
                        "QUALIFIED_REVIEW_SCOPE_REQUIRED",
                        "review.review_scope",
                        "qualified review requires a recorded review scope",
                    )
                )
            basis = review.get("qualification_basis")
            if not isinstance(basis, str) or not basis.strip():
                findings.append(
                    _finding(
                        "QUALIFICATION_BASIS_REQUIRED",
                        "review.qualification_basis",
                        "qualified review requires a recorded qualification basis",
                    )
                )
            evidence_url = review.get("qualification_evidence_url")
            if not isinstance(evidence_url, str) or not re.fullmatch(
                r"https://[^\s<>]+", evidence_url
            ):
                findings.append(
                    _finding(
                        "QUALIFICATION_EVIDENCE_REQUIRED",
                        "review.qualification_evidence_url",
                        "qualified review requires an HTTPS qualification evidence URL",
                    )
                )
            verification = review.get("qualification_verification")
            if verification not in {
                "self_declared",
                "independently_verified",
            }:
                findings.append(
                    _finding(
                        "QUALIFICATION_VERIFICATION_REQUIRED",
                        "review.qualification_verification",
                        "qualified review requires a verification status",
                    )
                )
            if verification == "independently_verified":
                verifier = review.get("qualification_verified_by_github_id")
                if not isinstance(verifier, str) or not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
                    verifier,
                ):
                    findings.append(
                        _finding(
                            "QUALIFICATION_VERIFIER_REQUIRED",
                            "review.qualification_verified_by_github_id",
                            "independent verification requires an identified verifier",
                        )
                    )
    return tuple(sorted(set(findings)))[:MAX_FINDINGS]


def _validate_mapping(
    mapping: Mapping[str, Any],
    *,
    location: str,
    findings: list[Finding],
) -> None:
    status = mapping.get("aegis_evidence_status")
    allowed = {
        "supported_evidence",
        "partial_evidence",
        "external_control",
        "not_addressed",
    }
    if status not in allowed:
        findings.append(
            _finding(
                "INVALID_EVIDENCE_STATUS",
                f"{location}.aegis_evidence_status",
                "unknown evidence contribution state",
            )
        )
        return
    evidence = mapping.get("evidence")
    if not isinstance(evidence, list):
        findings.append(
            _finding(
                "EVIDENCE_ARRAY_REQUIRED",
                f"{location}.evidence",
                "evidence must be an array",
            )
        )
        evidence = []
    for required in (
        "interpretation",
        "limitations",
        "host_controls",
        "retention_assumptions",
    ):
        value = mapping.get(required)
        if required == "interpretation":
            valid = isinstance(value, str) and bool(value.strip())
        else:
            valid = isinstance(value, list) and bool(value)
        if not valid:
            findings.append(
                _finding(
                    "MAPPING_FIELD_REQUIRED",
                    f"{location}.{required}",
                    f"{required} must be non-empty",
                )
            )
    if status in {"supported_evidence", "partial_evidence"}:
        positive_source = any(
            isinstance(item, dict)
            and item.get("baseline") == "aegis_source"
            and item.get("kind") != "documentation"
            for item in evidence
        )
        executable_test = any(
            isinstance(item, dict)
            and item.get("baseline") == "aegis_source"
            and item.get("kind") == "test"
            for item in evidence
        )
        if not positive_source:
            findings.append(
                _finding(
                    "POSITIVE_SOURCE_EVIDENCE_REQUIRED",
                    f"{location}.evidence",
                    "positive status requires pinned non-documentation evidence",
                )
            )
        if not executable_test:
            findings.append(
                _finding(
                    "EXECUTABLE_TEST_EVIDENCE_REQUIRED",
                    f"{location}.evidence",
                    "positive status requires a pinned executable test reference",
                )
            )
        if status == "partial_evidence" and not isinstance(
            mapping.get("unsupported_portion"), str
        ):
            findings.append(
                _finding(
                    "UNSUPPORTED_PORTION_REQUIRED",
                    f"{location}.unsupported_portion",
                    "partial evidence must name the unsupported portion",
                )
            )
    else:
        if evidence:
            findings.append(
                _finding(
                    "GAP_STATUS_EVIDENCE_FORBIDDEN",
                    f"{location}.evidence",
                    "gap statuses require an empty evidence array",
                )
            )
        if status == "external_control":
            for field in ("external_owner", "external_control"):
                if not isinstance(mapping.get(field), str) or not mapping.get(
                    field, ""
                ).strip():
                    findings.append(
                        _finding(
                            "EXTERNAL_CONTROL_FIELD_REQUIRED",
                            f"{location}.{field}",
                            f"{field} is required",
                        )
                    )
        else:
            for field in ("gap", "review_note"):
                if not isinstance(mapping.get(field), str) or not mapping.get(
                    field, ""
                ).strip():
                    findings.append(
                        _finding(
                            "GAP_FIELD_REQUIRED",
                            f"{location}.{field}",
                            f"{field} is required",
                        )
                    )


def _safe_repo_path(root: Path, relative: object, *, must_exist: bool = True) -> Path:
    if not isinstance(relative, str) or not relative:
        raise CatalogInputError("repository path must be non-empty text")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "\\" in relative:
        raise CatalogInputError(f"unsafe repository path: {relative}")
    path = root.joinpath(*pure.parts)
    resolved_root = root.resolve()
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as exc:
        raise CatalogInputError(f"missing repository path: {relative}") from exc
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise CatalogInputError(f"path escapes repository: {relative}")
    if path.is_symlink():
        raise CatalogInputError(f"symlink repository path is not allowed: {relative}")
    if must_exist and not path.is_file():
        raise CatalogInputError(f"repository path is not a normal file: {relative}")
    return path


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, check=False, capture_output=True, text=True, timeout=30
    )


def git_blob(root: Path, commit: str, relative: str) -> str:
    _safe_repo_path(root, relative, must_exist=False)
    completed = _git(root, "show", f"{commit}:{relative}")
    if completed.returncode:
        raise CatalogInputError(f"pinned source path does not exist: {relative}")
    return completed.stdout


def catalog_asset_text(root: Path, relative: str) -> str:
    path = _safe_repo_path(root, relative)
    tracked = _git(root, "ls-files", "--stage", "--error-unmatch", "--", relative)
    if tracked.returncode or not tracked.stdout.strip():
        raise CatalogInputError(f"catalog asset is not tracked: {relative}")
    stage_fields = tracked.stdout.split(maxsplit=3)
    if (
        len(stage_fields) < 4
        or stage_fields[0] not in {"100644", "100755"}
        or stage_fields[2] != "0"
    ):
        raise CatalogInputError(f"catalog asset is not a normal stage-0 file: {relative}")
    status = _git(root, "status", "--porcelain=v2", "--", relative)
    if status.returncode:
        raise CatalogInputError(f"cannot inspect catalog asset index state: {relative}")
    status_fields = status.stdout.split(maxsplit=8)
    if len(status_fields) >= 4 and status_fields[0] == "1" and status_fields[3] == "000000":
        raise CatalogInputError(f"catalog asset is intent-to-add: {relative}")
    ignored = _git(root, "check-ignore", "--quiet", "--", relative)
    if ignored.returncode == 0:
        raise CatalogInputError(f"catalog asset is ignored: {relative}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogInputError(f"catalog asset is not UTF-8: {relative}") from exc


def _json_pointer_exists(document: object, pointer: str) -> bool:
    if pointer == "":
        return True
    if not pointer.startswith("/"):
        return False
    current = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False
    return True


def locator_exists(kind: str, text: str, locator: str, *, suffix: str) -> bool:
    if kind in {"policy_field", "artifact_field"}:
        try:
            document = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
        except (json.JSONDecodeError, yaml.YAMLError):
            return False
        if locator.startswith("/"):
            return _json_pointer_exists(document, locator)
        current: object = document
        for part in locator.split("."):
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        return True
    if kind == "test":
        name = locator.split("::")[-1]
        return bool(
            re.search(
                rf"^(?:async )?def {re.escape(name)}\s*\(",
                text,
                re.MULTILINE,
            )
        )
    if kind in {"documentation", "command"}:
        anchor = locator.lstrip("#")
        headings = re.findall(r"^#{1,6}\s+(.+?)\s*$", text, re.MULTILINE)
        anchors = {
            re.sub(
                r"[^a-z0-9 -]",
                "",
                unicodedata.normalize("NFKC", heading).lower(),
            ).replace(" ", "-")
            for heading in headings
        }
        return anchor in anchors
    if kind == "fixture":
        return locator in text
    return False


def validate_evidence_references(
    data: CatalogData,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    baseline = data.manifest.get("aegis_baseline", {})
    commit = baseline.get("git_commit", "") if isinstance(baseline, dict) else ""
    for module in data.modules:
        for c_index, control in enumerate(module.get("controls", [])):
            mapping = control.get("mapping", {}) if isinstance(control, dict) else {}
            for e_index, evidence in enumerate(mapping.get("evidence", [])):
                module_id = module.get("framework", {}).get("id", "module")
                location = (
                    f"{module_id}.controls[{c_index}].mapping.evidence[{e_index}]"
                )
                if not isinstance(evidence, dict):
                    findings.append(
                        _finding(
                            "INVALID_EVIDENCE_REFERENCE",
                            location,
                            "evidence must be an object",
                        )
                    )
                    continue
                kind = evidence.get("kind")
                relative = evidence.get("path")
                locator = evidence.get("locator")
                if not all(isinstance(item, str) for item in (kind, relative, locator)):
                    findings.append(
                        _finding(
                            "INVALID_EVIDENCE_REFERENCE",
                            location,
                            "kind, path, and locator are required",
                        )
                    )
                    continue
                try:
                    if evidence.get("baseline") == "aegis_source":
                        text = git_blob(data.root, str(commit), relative)
                    elif evidence.get("baseline") == "catalog_asset":
                        text = catalog_asset_text(data.root, relative)
                    else:
                        raise CatalogInputError("unknown evidence baseline")
                    if not locator_exists(
                        kind,
                        text,
                        locator,
                        suffix=Path(relative).suffix,
                    ):
                        raise CatalogInputError(f"locator does not exist: {locator}")
                    invocation = evidence.get("invocation")
                    if kind == "command":
                        if not isinstance(invocation, str) or invocation not in text:
                            raise CatalogInputError("documented command invocation does not exist")
                    elif invocation is not None:
                        raise CatalogInputError("invocation is only valid for command evidence")
                except CatalogInputError as exc:
                    findings.append(_finding("EVIDENCE_LOCATOR_FAILURE", location, str(exc)))
    return tuple(findings[:MAX_FINDINGS])


def validate_schema(
    instance: Mapping[str, Any],
    schema_path: Path,
) -> tuple[Finding, ...]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    findings = []

    def leaf_errors(error):
        if error.context:
            for child in error.context:
                yield from leaf_errors(child)
        else:
            yield error

    errors = sorted(
        (
            leaf
            for error in validator.iter_errors(instance)
            for leaf in leaf_errors(error)
        ),
        key=lambda item: (list(item.absolute_path), item.message),
    )
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "$"
        findings.append(
            _finding(
                "SCHEMA_VALIDATION_FAILURE",
                location,
                error.message[:500],
            )
        )
    return tuple(findings[:MAX_FINDINGS])


def validate_claims(data: CatalogData) -> tuple[Finding, ...]:
    if __package__:
        from scripts.check_evidence_claims import TextBlock, scan_claims
    else:
        from check_evidence_claims import TextBlock, scan_claims  # type: ignore

    prose_keys = {
        "disclaimer",
        "display_name",
        "name",
        "title",
        "label",
        "version",
        "publication_id",
        "control_id",
        "locator",
        "invocation",
        "summary",
        "mapping_unit",
        "exclusions",
        "interpretation",
        "demonstrates",
        "host_controls",
        "limitations",
        "retention_assumptions",
        "unsupported_portion",
        "external_control",
        "external_owner",
        "gap",
        "review_note",
    }
    blocks: list[TextBlock] = []

    def collect(value: object, location: str) -> None:
        if isinstance(value, str):
            blocks.append(TextBlock(Path(location), 1, value))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                collect(item, f"{location}[{index}]")
        elif isinstance(value, dict):
            if set(value) >= {"owner", "control"}:
                collect(value.get("owner"), f"{location}.owner")
                collect(value.get("control"), f"{location}.control")

    documents = [
        ("compliance/catalog.yaml", data.manifest),
        *[(f"module:{i}", item) for i, item in enumerate(data.modules)],
    ]
    for prefix, document in documents:
        def walk(value: object, location: str) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    child = f"{location}.{key}"
                    if key in prose_keys:
                        collect(item, child)
                    else:
                        walk(item, child)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, f"{location}[{index}]")

        walk(document, prefix)
    return tuple(
        _finding(
            "CLAIMS_POLICY_FAILURE",
            finding.path.as_posix(),
            f"{finding.rule_id}: {finding.excerpt}",
        )
        for finding in scan_claims(tuple(blocks))
    )


def load_catalog(root: Path) -> CatalogData:
    manifest = load_yaml(root / "compliance" / "catalog.yaml")
    schema_path = root / "schemas" / "compliance_mapping.schema.json"
    manifest_findings = validate_schema(manifest, schema_path)
    if manifest_findings:
        first = manifest_findings[0]
        raise CatalogInputError(
            f"manifest schema validation failed at {first.location}: {first.message}"
        )
    paths = manifest.get("framework_modules")
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise CatalogInputError(
            "framework_modules must be a list of repository paths"
        )
    modules = tuple(load_yaml(_safe_repo_path(root, path)) for path in paths)
    return CatalogData(root=root.resolve(), manifest=manifest, modules=modules)


def baseline_drift(data: CatalogData) -> tuple[Finding, ...]:
    baseline = data.manifest.get("aegis_baseline", {})
    if not isinstance(baseline, dict):
        return (
            _finding(
                "BASELINE_INVALID",
                "aegis_baseline",
                "baseline must be an object",
            ),
        )
    commit = baseline.get("git_commit")
    paths = baseline.get("runtime_paths", [])
    if not isinstance(commit, str) or not isinstance(paths, list):
        return (
            _finding(
                "BASELINE_INVALID",
                "aegis_baseline",
                "commit and runtime_paths are required",
            ),
        )
    pathspecs = [str(item) for item in paths]
    completed = _git(
        data.root,
        "status",
        "--porcelain=v1",
        "--ignored",
        "--untracked-files=all",
        "--",
        *pathspecs,
    )
    diff = _git(data.root, "diff", "--name-only", commit, "--", *pathspecs)
    if completed.returncode or diff.returncode:
        diagnostic = (completed.stderr or diff.stderr or "Git command failed").strip()
        return (
            _finding(
                "BASELINE_GIT_FAILURE",
                "aegis_baseline",
                diagnostic[:500],
            ),
        )

    changed = [
        line
        for line in completed.stdout.splitlines()
        if line.strip()
    ]
    changed.extend(line for line in diff.stdout.splitlines() if line.strip())
    if changed:
        return (
            _finding(
                "BASELINE_DRIFT",
                "aegis_baseline.runtime_paths",
                "runtime paths differ from the pinned commit: "
                + ", ".join(sorted(set(changed))[:20]),
            ),
        )
    return ()
