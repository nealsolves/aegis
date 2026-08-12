"""
Policy loading and normalization.

- Loads YAML policy definitions
- Normalizes them into Python-native objects
- Validates structure against JSON schema
- Supports pluggable PolicyLoader interface
- Supports composition restriction semantics (intersect/union/replace)
- Supports policy version dates (effective_date/expiration_date)
"""

from __future__ import annotations

import abc
import asyncio
import copy
import json
import logging
import os
import threading
import yaml
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path, PurePath
from typing import Any, Awaitable, Callable

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError

from aegis._internal.errors import PolicyLoadError, PolicyValidationError
from aegis._internal.compiled_policy import CompiledPolicy
from aegis._internal.policy_compiler import compile_policy
from aegis._internal.restrictions import (
    RestrictionComparator,
    compare_protocol_capabilities,
)

logger = logging.getLogger("aegis.policy_loader")

# Schema resolution: prefer package-internal schemas (works in wheel installs),
# fall back to repo-root schemas (works in editable/dev installs).
_PKG_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
_REPO_SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "schemas"
SCHEMAS_DIR = _PKG_SCHEMAS_DIR if _PKG_SCHEMAS_DIR.is_dir() else _REPO_SCHEMAS_DIR
LEGACY_POLICY_SCHEMA_PATH = SCHEMAS_DIR / "invocation_policy.schema.json"
POLICY_DSL_SCHEMA_PATH = SCHEMAS_DIR / "policy_dsl.schema.json"
POLICY_SCHEMA_DRAFT_07 = "http://json-schema.org/draft-07/schema#"

# Valid composition strategies
COMPOSITION_INTERSECT = "intersect"
COMPOSITION_UNION = "union"
COMPOSITION_REPLACE = "replace"
VALID_COMPOSITION_STRATEGIES = (
    COMPOSITION_INTERSECT,
    COMPOSITION_UNION,
    COMPOSITION_REPLACE,
)


# ── Pluggable PolicyLoader interface ─────────────────────────────


class PolicyLoaderBase(abc.ABC):
    """Abstract base class for policy loaders.

    Implement this interface to load policies from custom sources
    (databases, APIs, remote stores) instead of the default filesystem.

    Safety constraints:
    - Loaders must return valid policy dicts
    - Loaders must not bypass schema validation
    - Loaders must handle errors by raising PolicyLoadError

    Usage::

        class DatabasePolicyLoader(PolicyLoaderBase):
            def load(self, policy_ref):
                row = db.query("SELECT yaml FROM policies WHERE id = ?", policy_ref)
                return yaml.safe_load(row["yaml"])

        aegis = AEGIS(policy_loader=DatabasePolicyLoader())
    """

    @abc.abstractmethod
    def load(self, policy_ref: str) -> dict[str, Any]:
        """Load a raw policy dict from the source.

        :param policy_ref: Policy reference (file path, ID, URL, etc.)
        :return: Parsed policy dict (before schema validation)
        :raises PolicyLoadError: On load failure
        """


@dataclass(frozen=True, slots=True)
class _PreparedFilePolicy:
    authority_token: object
    source_path: Path
    raw_policy: dict[str, Any]


_OUTSIDE_ROOT_MESSAGE = "Policy path is outside the configured policy root"

_SAFE_DETAIL_KEYS = frozenset({
    "path",
    "validator",
    "composition_strategy",
    "effective_date",
    "expiration_date",
    "today",
    "line",
    "column",
    "tool_names",
})

_STABLE_FILE_MESSAGES = frozenset({
    "Configured policy root is unavailable",
    "Policy path could not be resolved",
    "Policy file must be YAML",
    "Policy file does not exist",
    "Policy path must reference a file",
    "Policy YAML parsing failed",
    "Policy root must be a mapping object",
    "Policy schema root must be an object",
    "Policy schema must declare JSON Schema Draft-07",
    "Policy schema validation failed",
    "Policy compilation failed",
})


@dataclass(slots=True)
class _FileLoadContext:
    protected: set[str]
    date_failures: list[PolicyValidationError]

    @classmethod
    def create(cls, *values: object) -> _FileLoadContext:
        context = cls(protected=set(), date_failures=[])
        for value in values:
            context.protect(value)
        return context

    def protect(self, value: object) -> None:
        text = os.fspath(value) if isinstance(value, os.PathLike) else str(value)
        if text:
            self.protected.add(text)

    def record_date_failure(self, failure: PolicyValidationError) -> None:
        fingerprint = (failure.code, repr(failure.details))
        if all(
            (existing.code, repr(existing.details)) != fingerprint
            for existing in self.date_failures
        ):
            self.date_failures.append(failure)

    def normalize(
        self,
        exc: BaseException,
        *,
        fallback: str,
    ) -> PolicyLoadError | PolicyValidationError:
        code = getattr(exc, "code", "POLICY_LOAD_ERROR")
        original = getattr(exc, "details", None)

        def safe_value(value: object) -> object | None:
            if isinstance(value, (str, int, float, bool, type(None))):
                if isinstance(value, str) and any(
                    secret in value for secret in self.protected
                ):
                    return None
                return value
            if isinstance(value, (list, tuple)):
                cleaned = [safe_value(item) for item in value]
                if any(item is None for item in cleaned):
                    return None
                return cleaned
            return None

        safe_details = (
            {
                key: cleaned
                for key, value in original.items()
                if key in _SAFE_DETAIL_KEYS
                if (cleaned := safe_value(value)) is not None
            }
            if isinstance(original, dict)
            else None
        )
        if code == "POLICY_PATH_OUTSIDE_ROOT":
            return PolicyLoadError(_OUTSIDE_ROOT_MESSAGE, code=code)
        if (
            isinstance(exc, PolicyLoadError)
            and str(exc) == "Circular policy inheritance detected"
        ):
            return PolicyLoadError(
                "Circular policy inheritance detected",
                code=code,
            )
        if isinstance(exc, PolicyLoadError) and str(exc) in _STABLE_FILE_MESSAGES:
            return PolicyLoadError(str(exc), code=code, details=safe_details)
        if "composition_strategy" in (safe_details or {}):
            return PolicyValidationError(
                self.safe_semantic_message(
                    exc,
                    fallback="Invalid policy composition strategy",
                ),
                code=code,
                details=safe_details,
            )
        if code == "POLICY_WIDENING":
            return PolicyValidationError(
                self.safe_semantic_message(
                    exc,
                    fallback="Policy composition would widen authority",
                ),
                code=code,
                details=safe_details,
            )
        if any(
            key in (safe_details or {})
            for key in ("effective_date", "expiration_date", "today")
        ):
            return PolicyValidationError(
                self.safe_semantic_message(
                    exc,
                    fallback="Policy date validation failed",
                ),
                code=code,
                details=safe_details,
            )
        if code == "POLICY_SCHEMA_VALIDATION_ERROR":
            pointer = (safe_details or {}).get("path", "$")
            return PolicyValidationError(
                f"Policy schema validation failed at {pointer}",
                code=code,
                details=safe_details,
            )
        if isinstance(exc, PolicyValidationError):
            return PolicyValidationError(
                self.safe_semantic_message(exc, fallback=fallback),
                code=code,
                details=safe_details,
            )
        return PolicyLoadError(fallback, code=code, details=safe_details)

    def safe_semantic_message(
        self,
        exc: BaseException,
        *,
        fallback: str,
    ) -> str:
        message = str(exc)
        if any(secret in message for secret in self.protected):
            return fallback
        return message


def _is_contained(candidate: PurePath, root: PurePath) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


class FilePolicyLoader(PolicyLoaderBase):
    """Filesystem policy loader bound to one immutable canonical root."""

    def __init__(self, policy_root: str | Path) -> None:
        try:
            canonical_root = Path(policy_root).resolve(strict=True)
            is_directory = canonical_root.is_dir()
        except (OSError, RuntimeError):
            canonical_root = Path(".")
            is_directory = False
        if not is_directory:
            raise PolicyLoadError("Configured policy root is unavailable") from None
        self._policy_root = canonical_root
        self._authority_token = object()

    @property
    def policy_root(self) -> Path:
        return self._policy_root

    def _canonicalize(self, lexical: Path) -> Path:
        return lexical.resolve(strict=False)

    def _canonical_candidate(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
        context: _FileLoadContext,
    ) -> Path:
        ref = Path(policy_ref)
        base = self._policy_root if relative_to is None else relative_to.parent
        lexical = ref if ref.is_absolute() else base / ref
        context.protect(lexical)
        try:
            candidate = self._canonicalize(lexical)
        except (OSError, RuntimeError):
            raise PolicyLoadError("Policy path could not be resolved") from None
        context.protect(candidate)
        if not _is_contained(candidate, self._policy_root):
            raise PolicyLoadError(
                _OUTSIDE_ROOT_MESSAGE,
                code="POLICY_PATH_OUTSIDE_ROOT",
            ) from None
        return candidate

    def _validate_candidate(self, candidate: Path) -> None:
        if candidate.suffix.lower() not in {".yaml", ".yml"}:
            raise PolicyLoadError("Policy file must be YAML")
        failure: PolicyLoadError | None = None
        try:
            exists = candidate.exists()
            is_file = candidate.is_file() if exists else False
        except (OSError, RuntimeError):
            exists = False
            is_file = False
            failure = PolicyLoadError("Policy metadata is unavailable")
        if failure is not None:
            raise failure from None
        if not exists:
            raise PolicyLoadError("Policy file does not exist")
        if not is_file:
            raise PolicyLoadError("Policy path must reference a file")

    def _prepare(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
        reject_paths: set[Path] | None = None,
        context: _FileLoadContext,
    ) -> _PreparedFilePolicy:
        candidate = self._canonical_candidate(
            policy_ref,
            relative_to=relative_to,
            context=context,
        )
        if reject_paths is not None and candidate in reject_paths:
            raise PolicyLoadError("Circular policy inheritance detected")
        self._validate_candidate(candidate)
        parsed: object = None
        failure: PolicyLoadError | None = None
        try:
            with candidate.open("r", encoding="utf-8") as file_obj:
                parsed = yaml.safe_load(file_obj)
        except yaml.MarkedYAMLError as exc:
            mark = exc.problem_mark
            details = (
                {"line": mark.line + 1, "column": mark.column + 1}
                if mark is not None
                else None
            )
            failure = PolicyLoadError(
                "Policy YAML parsing failed",
                details=details,
            )
        except (OSError, yaml.YAMLError):
            failure = PolicyLoadError("Policy YAML parsing failed")
        if failure is not None:
            raise failure from None
        if not isinstance(parsed, dict):
            raise PolicyLoadError("Policy root must be a mapping object")
        return _PreparedFilePolicy(
            authority_token=self._authority_token,
            source_path=candidate,
            raw_policy=copy.deepcopy(parsed),
        )

    def _preflight(
        self,
        policy_ref: str | Path,
        *,
        relative_to: Path | None = None,
        context: _FileLoadContext,
    ) -> Path:
        candidate = self._canonical_candidate(
            policy_ref,
            relative_to=relative_to,
            context=context,
        )
        self._validate_candidate(candidate)
        return candidate

    def _accept_prepared(self, prepared: _PreparedFilePolicy) -> None:
        if prepared.authority_token is not self._authority_token:
            raise PolicyLoadError("Prepared policy authority does not match loader")

    def load(self, policy_ref: str) -> dict[str, Any]:
        """Load one raw policy mapping relative to this loader's root."""
        context = _FileLoadContext.create(policy_ref, self.policy_root)
        return copy.deepcopy(
            self._prepare(policy_ref, context=context).raw_policy
        )


# ── Path resolution ──────────────────────────────────────────────


def _resolve_policy_schema_path() -> Path:
    """
    Prefer the extended DSL schema when present.
    Fall back to the legacy schema.
    """
    if POLICY_DSL_SCHEMA_PATH.exists():
        return POLICY_DSL_SCHEMA_PATH
    if not LEGACY_POLICY_SCHEMA_PATH.exists():
        raise PolicyLoadError(
            "No policy schema file found",
            details={
                "searched": [
                    str(POLICY_DSL_SCHEMA_PATH),
                    str(LEGACY_POLICY_SCHEMA_PATH),
                ]
            },
        )
    logger.warning("Using legacy policy schema: %s", LEGACY_POLICY_SCHEMA_PATH)
    return LEGACY_POLICY_SCHEMA_PATH


def _bind_policy_authority(
    policy_file: str,
    loader: PolicyLoaderBase | None,
) -> tuple[str, PolicyLoaderBase]:
    if loader is not None:
        return policy_file, loader
    try:
        captured_cwd = Path.cwd()
        lexical_entry = Path(policy_file)
        if not lexical_entry.is_absolute():
            lexical_entry = captured_cwd / lexical_entry
        root = lexical_entry.parent.resolve(strict=False)
    except (OSError, RuntimeError):
        raise PolicyLoadError("Policy path could not be resolved") from None
    return str(lexical_entry), FilePolicyLoader(root)


def _path_to_pointer(path: list[Any]) -> str:
    if not path:
        return "$"
    return "$." + ".".join(str(part) for part in path)


# ── Composition restriction semantics ────────────────────────────


def _merge_arrays_intersect(base: list, overlay: list) -> list:
    """Intersect: keep only items present in both arrays."""
    return [item for item in base if item in overlay]


def _merge_arrays_union(base: list, overlay: list) -> list:
    """Union: combine both arrays, deduplicating."""
    seen = set()
    result = []
    for item in base + overlay:
        key = str(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_policies(
    base: dict[str, Any],
    overlay: dict[str, Any],
    composition_strategy: str | None = None,
) -> dict[str, Any]:
    """
    Merge overlay policy into base policy.

    Merge rules depend on composition_strategy:
    - None/default: arrays append, dicts recursive merge, scalars replace
    - "intersect": arrays intersect, dicts recursive merge, scalars overlay
    - "union": arrays union (deduplicated), dicts recursive merge, scalars overlay
    - "replace": overlay completely replaces base for all keys present

    :param base: Base policy dict
    :param overlay: Overlay policy dict
    :param composition_strategy: Optional strategy override
    :return: New merged dict (base and overlay unchanged)
    """
    if composition_strategy == COMPOSITION_REPLACE:
        merged = copy.deepcopy(base)
        for key, value in overlay.items():
            if key in ("extends", "composition_strategy"):
                continue
            merged[key] = copy.deepcopy(value)
        return merged

    merged = copy.deepcopy(base)

    for key, value in overlay.items():
        if key in ("extends", "composition_strategy"):
            continue

        if key not in merged:
            merged[key] = copy.deepcopy(value)
        elif key == "stateful" and isinstance(value, dict):
            # Stateful declarations are complete migration identities. They
            # cannot be recursively merged or have constraint arrays appended.
            merged[key] = copy.deepcopy(value)
        elif (
            key in {
                "allowed_tools",
                "participants",
                "required_sequence",
                "roles",
            }
            and isinstance(merged[key], list)
            and isinstance(value, list)
        ):
            # Authorization-bearing allowlists and the inherited workflow
            # sequence are complete declarations, not additive generic lists.
            # The registry separately proves subset/exact monotonicity.
            merged[key] = copy.deepcopy(value)
        elif isinstance(merged[key], list) and isinstance(value, list):
            if composition_strategy == COMPOSITION_INTERSECT:
                merged[key] = _merge_arrays_intersect(merged[key], value)
            elif composition_strategy == COMPOSITION_UNION:
                merged[key] = _merge_arrays_union(merged[key], value)
            else:
                # Default: append
                merged[key] = merged[key] + copy.deepcopy(value)
        elif isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_policies(
                merged[key], value, composition_strategy
            )
        else:
            # Scalar replacement
            merged[key] = copy.deepcopy(value)

    return merged


def _validate_composition_restriction(
    base: dict[str, Any],
    merged: dict[str, Any],
    overlay: dict[str, Any] | None = None,
) -> None:
    """Enforce monotonic restriction: child policies may not expand roles or
    remove required postconditions relative to the base policy.

    :param base: The resolved base policy dict (before overlay was applied).
    :param merged: The merged policy dict (after overlay was applied).
    :param overlay: The raw child (overlay) policy dict before merging.
        Used for workflow field checks where array intersection can hide what
        the child is attempting to add.
    :raises PolicyValidationError: If the merged policy escalates privileges or
        weakens postconditions.
    """
    # Use overlay when available for workflow field comparisons so that
    # intersect/union merge strategies cannot hide widening attempts.
    child_wf_source = (overlay or {}).get("workflow") or {} if overlay is not None else None
    # Role escalation check: merged roles must be a subset of base roles
    base_roles = set(base.get("roles") or [])
    merged_roles = set(merged.get("roles") or [])
    if base_roles and (escalated := sorted(merged_roles - base_roles)):
        raise PolicyValidationError(
            f"Composition escalation: child policy adds roles not present "
            f"in base policy: {escalated}",
            details={
                "base_roles": sorted(base_roles),
                "merged_roles": sorted(merged_roles),
                "escalated_roles": escalated,
            },
        )

    # Postcondition weakening check: merged must retain all base required postconditions
    base_post = set(
        base.get("post_conditions", {}).get("required") or []
    )
    merged_post = set(
        merged.get("post_conditions", {}).get("required") or []
    )
    if base_post and (removed := sorted(base_post - merged_post)):
        raise PolicyValidationError(
            f"Composition weakening: child policy removes required "
            f"postconditions from base policy: {removed}",
            details={
                "base_required": sorted(base_post),
                "merged_required": sorted(merged_post),
                "removed_postconditions": removed,
            },
        )

    # Workflow budget escalation checks: child must not widen base budgets
    base_wf = base.get("workflow") or {}
    merged_wf = merged.get("workflow") or {}

    base_max_steps = base_wf.get("max_steps")
    merged_max_steps = merged_wf.get("max_steps")
    if base_max_steps is not None:
        if merged_max_steps is None or merged_max_steps > base_max_steps:
            raise PolicyValidationError(
                f"Composition escalation: child policy widens max_steps "
                f"(base={base_max_steps}, merged={merged_max_steps})",
                details={
                    "base_max_steps": base_max_steps,
                    "merged_max_steps": merged_max_steps,
                },
            )

    base_max_calls = base_wf.get("max_total_tool_calls")
    merged_max_calls = merged_wf.get("max_total_tool_calls")
    if base_max_calls is not None:
        if merged_max_calls is None or merged_max_calls > base_max_calls:
            raise PolicyValidationError(
                f"Composition escalation: child policy widens max_total_tool_calls "
                f"(base={base_max_calls}, merged={merged_max_calls})",
                details={
                    "base_max_total_tool_calls": base_max_calls,
                    "merged_max_total_tool_calls": merged_max_calls,
                },
            )

    # For workflow DSL field checks, prefer the raw child overlay (before merge)
    # so that array intersection/union strategies cannot hide widening attempts.
    # When overlay is None (legacy call sites), fall back to merged_wf.
    child_wf = child_wf_source if child_wf_source is not None else merged_wf

    # Participant lists are complete runtime declarations keyed by stable ID.
    base_participants_map = {
        p["id"]: p for p in (base_wf.get("participants") or [])
    }
    merged_participants_map = {
        p["id"]: p for p in (merged_wf.get("participants") or [])
    }
    base_participants = set(base_participants_map)
    merged_participants = set(merged_participants_map)
    if base_participants and not merged_participants:
        # Removal-to-empty: cleared participants disable enforcement entirely
        raise PolicyValidationError(
            "Composition escalation: child policy clears all participants declared in base, "
            "disabling participant enforcement",
            details={"base_participant_ids": sorted(base_participants)},
        )
    if base_participants and (
        added := sorted(merged_participants - base_participants)
    ):
        raise PolicyValidationError(
            f"Composition escalation: child policy adds participants not in base: {added}",
            details={
                "base_participant_ids": sorted(base_participants),
                "merged_participant_ids": sorted(merged_participants),
                "added_participant_ids": added,
            },
        )

    # Retained participant restrictions must stay nonempty and subset the base.
    for pid in sorted(base_participants & merged_participants):
        base_p = base_participants_map[pid]
        merged_p = merged_participants_map[pid]
        base_p_roles = set(base_p.get("roles") or [])
        merged_p_roles = set(merged_p.get("roles") or [])
        if base_p_roles and (
            not merged_p_roles or not merged_p_roles <= base_p_roles
        ):
            raise PolicyValidationError(
                f"Composition escalation: child widens or removes roles for "
                f"participant {pid!r}",
                details={
                    "participant_id": pid,
                    "base_roles": sorted(base_p_roles),
                    "merged_roles": sorted(merged_p_roles),
                },
            )
        base_p_protocols = set(base_p.get("protocols") or [])
        merged_p_protocols = set(merged_p.get("protocols") or [])
        if base_p_protocols and (
            not merged_p_protocols
            or not merged_p_protocols <= base_p_protocols
        ):
            raise PolicyValidationError(
                f"Composition escalation: child widens or removes protocols for "
                f"participant {pid!r}",
                details={
                    "participant_id": pid,
                    "base_protocols": sorted(base_p_protocols),
                    "merged_protocols": sorted(merged_p_protocols),
                },
            )
        base_manifest = base_p.get("manifest_ref")
        merged_manifest = merged_p.get("manifest_ref")
        if base_manifest is not None and merged_manifest != base_manifest:
            raise PolicyValidationError(
                f"Composition escalation: child changes manifest_ref for participant {pid!r}",
                details={
                    "participant_id": pid,
                    "base_manifest_ref": base_manifest,
                    "merged_manifest_ref": merged_manifest,
                },
            )

    # Until a formal narrowing prover exists, an inherited required sequence
    # is exact authority. Omission inherits it; every explicit change,
    # including shortening, reordering, replacement, or clearing, widens.
    if "required_sequence" in base_wf:
        base_seq = base_wf.get("required_sequence")
        child_declares_sequence = "required_sequence" in child_wf
        child_seq = child_wf.get("required_sequence")
        merged_seq = merged_wf.get("required_sequence")
        if child_declares_sequence and child_seq != base_seq:
            raise PolicyValidationError(
                "Composition escalation: child changes inherited "
                "required_sequence",
                details={
                    "base_required_sequence": base_seq,
                    "child_required_sequence": child_seq,
                },
            )
        if merged_seq != base_seq:
            raise PolicyValidationError(
                "Composition escalation: effective policy changes inherited "
                "required_sequence",
                details={
                    "base_required_sequence": base_seq,
                    "merged_required_sequence": merged_seq,
                },
            )

    # allowed_transitions must only narrow (check child overlay vs base)
    base_trans = base_wf.get("allowed_transitions") or {}
    child_trans = child_wf.get("allowed_transitions") or {}
    # {} means "no transitions permitted" (gate active, deny-all) — a valid narrowing.
    # Only reject a true drop: key absent or null in the merged result.
    if base_trans and merged_wf.get("allowed_transitions") is None:
        raise PolicyValidationError(
            "Composition escalation: child policy clears allowed_transitions declared in base, "
            "disabling transition enforcement",
            details={"base_allowed_transitions": dict(base_trans)},
        )
    if base_trans:
        new_from_keys = sorted(set(child_trans) - set(base_trans))
        if new_from_keys:
            raise PolicyValidationError(
                f"Composition escalation: child adds new 'from' step keys in "
                f"allowed_transitions: {new_from_keys}",
                details={"new_from_step_keys": new_from_keys},
            )
        for from_step, child_to_steps in child_trans.items():
            base_to_steps = set(base_trans.get(from_step, []))
            child_to_steps_set = set(child_to_steps)
            if widened := sorted(child_to_steps_set - base_to_steps):
                raise PolicyValidationError(
                    f"Composition escalation: child widens allowed_transitions "
                    f"for {from_step!r}: {widened}",
                    details={"from_step": from_step, "widened_transitions": widened},
                )

    # allowed_agent_roles must only narrow (check child overlay vs base)
    base_agent_roles = set(base_wf.get("allowed_agent_roles") or [])
    child_agent_roles = set(child_wf.get("allowed_agent_roles") or [])
    # [] means "no agent role permitted" (gate active, deny-all) — a valid fail-closed narrowing.
    # Only reject a true drop: key absent or null in the merged result.
    if base_agent_roles and merged_wf.get("allowed_agent_roles") is None:
        raise PolicyValidationError(
            "Composition escalation: child policy clears allowed_agent_roles declared in base, "
            "disabling agent role enforcement",
            details={"base_allowed_agent_roles": sorted(base_agent_roles)},
        )
    if base_agent_roles and (widened := sorted(child_agent_roles - base_agent_roles)):
        raise PolicyValidationError(
            f"Composition escalation: child widens allowed_agent_roles: {widened}",
            details={
                "base_allowed_agent_roles": sorted(base_agent_roles),
                "widened_roles": widened,
            },
        )

    # handoffs must only narrow (check child overlay vs base)
    base_handoffs = {(h["from"], h["to"]) for h in (base_wf.get("handoffs") or [])}
    child_handoffs = {(h["from"], h["to"]) for h in (child_wf.get("handoffs") or [])}
    # [] means "no handoffs permitted" (gate active, deny-all) — a valid fail-closed narrowing.
    # Only reject a true drop: key absent or null in the merged result.
    if base_handoffs and merged_wf.get("handoffs") is None:
        raise PolicyValidationError(
            "Composition escalation: child policy clears all handoffs declared in base, "
            "disabling handoff enforcement",
            details={"base_handoffs": [{"from": f, "to": t} for f, t in sorted(base_handoffs)]},
        )
    if base_handoffs and (added := sorted(child_handoffs - base_handoffs)):
        raise PolicyValidationError(
            f"Composition escalation: child adds handoff pairs not in base: {added}",
            details={"added_handoffs": [{"from": f, "to": t} for f, t in added]},
        )

    # escalation.require_approval_after_steps can only tighten (lower or match)
    # Use merged_wf here: the merged value correctly reflects the final resolved threshold.
    base_esc = base_wf.get("escalation") or {}
    merged_esc = merged_wf.get("escalation") or {}
    base_esc_n = base_esc.get("require_approval_after_steps")
    merged_esc_n = merged_esc.get("require_approval_after_steps")
    if base_esc_n is not None:
        if merged_esc_n is None or merged_esc_n > base_esc_n:
            raise PolicyValidationError(
                f"Composition escalation: child raises escalation threshold "
                f"(base={base_esc_n}, merged={merged_esc_n})",
                details={
                    "base_require_approval_after_steps": base_esc_n,
                    "merged_require_approval_after_steps": merged_esc_n,
                },
            )

    # escalation.require_approval_for_roles can only narrow (child cannot remove roles)
    base_esc_roles = set(base_esc.get("require_approval_for_roles") or [])
    merged_esc_roles = set(merged_esc.get("require_approval_for_roles") or [])
    if base_esc_roles and (removed_roles := sorted(base_esc_roles - merged_esc_roles)):
        raise PolicyValidationError(
            f"Composition weakening: child removes roles from "
            f"require_approval_for_roles: {removed_roles}",
            details={
                "base_require_approval_for_roles": sorted(base_esc_roles),
                "merged_require_approval_for_roles": sorted(merged_esc_roles),
                "removed_roles": removed_roles,
            },
        )

    # Protocol capabilities use their adapter runtime defaults even when a
    # family or field is omitted. Unknown capabilities fail closed.
    base_proto_raw = base_wf.get("protocol_constraints")
    child_proto_raw = child_wf.get("protocol_constraints")
    merged_proto_raw = merged_wf.get("protocol_constraints")
    if base_proto_raw and child_proto_raw is not None:
        removed_families = sorted(
            set(base_proto_raw) - set(child_proto_raw),
        )
        if removed_families:
            raise PolicyValidationError(
                "Composition weakening: child removes base protocol families",
                details={"removed_protocol_families": removed_families},
            )
    if base_proto_raw is not None and merged_proto_raw is None:
        raise PolicyValidationError(
            "Composition weakening: child disables protocol constraints",
        )
    compare_protocol_capabilities(
        base_proto_raw or {},
        merged_proto_raw or {},
    )


def _compile_and_compare_composition(
    parent: dict[str, Any],
    overlay: dict[str, Any],
    effective: dict[str, Any],
):
    """Compile both sides of one inheritance edge and prove restriction."""
    compiled_parent = compile_policy(parent, source="composition-parent")
    comparator = RestrictionComparator()
    try:
        comparator.assert_overlay(compiled_parent, overlay)
    except PolicyValidationError as exc:
        if exc.code != "POLICY_WIDENING":
            raise
        category = (
            "weakening"
            if exc.details.get("path") in {"pre_conditions", "post_conditions"}
            else "escalation"
        )
        raise PolicyValidationError(
            f"Composition {category}: {exc}",
            code=exc.code,
            details=exc.details,
        ) from exc
    compiled_effective = compile_policy(
        effective,
        source="composition-effective",
    )
    try:
        comparator.assert_effective(
            compiled_parent.authority,
            compiled_effective,
        )
    except PolicyValidationError as exc:
        if exc.code != "POLICY_WIDENING":
            raise
        category = (
            "weakening"
            if exc.details.get("path") in {"pre_conditions", "post_conditions"}
            else "escalation"
        )
        raise PolicyValidationError(
            f"Composition {category}: {exc}",
            code=exc.code,
            details=exc.details,
        ) from exc
    return compiled_effective


def compile_composed_policy(
    parent: dict[str, Any],
    child: dict[str, Any],
):
    """Compile a child policy only after raw and effective restriction checks."""
    strategy = child.get("composition_strategy")
    if strategy is not None and strategy not in VALID_COMPOSITION_STRATEGIES:
        raise PolicyValidationError(
            f"Invalid composition_strategy: {strategy!r}; "
            f"expected one of {VALID_COMPOSITION_STRATEGIES}",
            details={"composition_strategy": strategy},
        )
    effective = _merge_policies(parent, child, strategy)
    return _compile_and_compare_composition(parent, child, effective)


# ── Policy version dates ─────────────────────────────────────────


def _parse_date(value: Any) -> date | None:
    """Parse a date value from policy. Accepts YYYY-MM-DD strings or date objects."""
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            raise PolicyValidationError(
                f"Invalid date format: {value!r}; expected YYYY-MM-DD",
                details={"value": value},
            )
    raise PolicyValidationError(
        f"Invalid date type: {type(value).__name__}; expected string or date",
        details={"value": str(value)},
    )


def validate_policy_dates(
    policy: dict[str, Any],
    *,
    clock: Callable[[], date] | None = None,
) -> dict[str, Any]:
    """Validate policy effective_date and expiration_date.

    :param policy: Policy dict with optional date fields
    :param clock: Injectable clock function for testing (default: date.today)
    :return: Dict with date validation evidence
    :raises PolicyValidationError: If policy is not currently active
    """
    effective_date = _parse_date(policy.get("effective_date"))
    expiration_date = _parse_date(policy.get("expiration_date"))

    if effective_date is None and expiration_date is None:
        return {"policy_dates": "none_specified", "active": True}

    # Check logical consistency first (before time-dependent checks)
    if effective_date and expiration_date and effective_date > expiration_date:
        raise PolicyValidationError(
            "Policy effective_date is after expiration_date",
            details={
                "effective_date": effective_date.isoformat(),
                "expiration_date": expiration_date.isoformat(),
            },
        )

    today = (clock or date.today)()

    evidence: dict[str, Any] = {
        "evaluation_date": today.isoformat(),
        "active": True,
    }

    if effective_date is not None:
        evidence["effective_date"] = effective_date.isoformat()
        if today < effective_date:
            evidence["active"] = False
            raise PolicyValidationError(
                f"Policy not yet active: effective_date is "
                f"{effective_date.isoformat()}, today is {today.isoformat()}",
                details={
                    "effective_date": effective_date.isoformat(),
                    "today": today.isoformat(),
                },
            )

    if expiration_date is not None:
        evidence["expiration_date"] = expiration_date.isoformat()
        if today > expiration_date:
            evidence["active"] = False
            raise PolicyValidationError(
                f"Policy expired: expiration_date is "
                f"{expiration_date.isoformat()}, today is {today.isoformat()}",
                details={
                    "expiration_date": expiration_date.isoformat(),
                    "today": today.isoformat(),
                },
            )

    return evidence


# ── Extends resolution ───────────────────────────────────────────


def _validated_extends(policy: dict[str, Any]) -> str | None:
    if "extends" not in policy:
        return None
    extends = policy["extends"]
    if not isinstance(extends, str) or not extends:
        raise PolicyValidationError(
            "Policy schema validation failed at $.extends",
            details={"path": "$.extends"},
        )
    return extends


def _validate_composition_strategy(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in VALID_COMPOSITION_STRATEGIES:
        raise PolicyValidationError(
            f"Invalid composition_strategy: {value!r}; "
            f"expected one of {VALID_COMPOSITION_STRATEGIES}",
            details={"composition_strategy": value},
        )
    return value


def _validate_policy_mapping(
    policy: dict[str, Any],
    *,
    context: _FileLoadContext,
    clock: Callable[[], date] | None,
    capture_date_failures: bool = False,
) -> dict[str, Any]:
    failure: PolicyLoadError | PolicyValidationError | None = None
    schema: dict[str, Any] | None = None
    try:
        schema_path = _resolve_policy_schema_path()
        context.protect(schema_path)
        with schema_path.open("r", encoding="utf-8") as schema_file:
            loaded_schema = json.load(schema_file)
        if not isinstance(loaded_schema, dict):
            raise PolicyLoadError("Policy schema root must be an object")
        if loaded_schema.get("$schema") != POLICY_SCHEMA_DRAFT_07:
            raise PolicyLoadError(
                "Policy schema must declare JSON Schema Draft-07"
            )
        Draft7Validator.check_schema(loaded_schema)
        schema = loaded_schema
    except (
        OSError,
        json.JSONDecodeError,
        SchemaError,
        PolicyLoadError,
    ) as exc:
        failure = context.normalize(
            exc,
            fallback="Policy schema validation failed",
        )
    if failure is not None:
        raise failure from None
    assert schema is not None

    validator = Draft7Validator(schema)
    errors = sorted(
        validator.iter_errors(policy),
        key=lambda error: _path_to_pointer(list(error.absolute_path)),
    )
    if errors:
        first = errors[0]
        pointer = _path_to_pointer(list(first.absolute_path))
        raise PolicyValidationError(
            f"Policy schema validation failed at {pointer}",
            details={"path": pointer, "validator": first.validator},
        ) from None

    failure = None
    try:
        validate_policy_dates(policy, clock=clock)
    except PolicyValidationError as exc:
        failure = context.normalize(
            exc,
            fallback="Policy date validation failed",
        )
    if failure is not None:
        if capture_date_failures and isinstance(
            failure,
            PolicyValidationError,
        ):
            context.record_date_failure(failure)
        else:
            raise failure from None
    return copy.deepcopy(policy)


def _resolve_file_graph(
    prepared: _PreparedFilePolicy,
    *,
    loader: FilePolicyLoader,
    visited: set[Path],
    context: _FileLoadContext,
    clock: Callable[[], date] | None = None,
    capture_date_failures: bool = False,
) -> dict[str, Any]:
    loader._accept_prepared(prepared)
    if prepared.source_path in visited:
        raise PolicyLoadError("Circular policy inheritance detected")
    next_visited = {*visited, prepared.source_path}
    policy = copy.deepcopy(prepared.raw_policy)
    extends = _validated_extends(policy)
    if extends is None:
        return _validate_policy_mapping(
            policy,
            context=context,
            clock=clock,
            capture_date_failures=capture_date_failures,
        )

    context.protect(extends)
    parent = loader._prepare(
        extends,
        relative_to=prepared.source_path,
        reject_paths=next_visited,
        context=context,
    )
    base = _resolve_file_graph(
        parent,
        loader=loader,
        visited=next_visited,
        context=context,
        clock=clock,
        capture_date_failures=capture_date_failures,
    )
    strategy = _validate_composition_strategy(
        policy.get("composition_strategy")
    )
    merged = _merge_policies(base, policy, strategy)
    _compile_and_compare_composition(base, policy, merged)
    merged.pop("extends", None)
    merged.pop("composition_strategy", None)
    return _validate_policy_mapping(
        merged,
        context=context,
        clock=clock,
        capture_date_failures=capture_date_failures,
    )


def _load_opaque_policy(
    policy_ref: str,
    loader: PolicyLoaderBase,
    *,
    clock: Callable[[], date] | None,
) -> dict[str, Any]:
    failure: PolicyLoadError | None = None
    try:
        loaded = loader.load(policy_ref)
    except PolicyLoadError as exc:
        loaded = None
        failure = exc
    except Exception:
        loaded = None
        failure = PolicyLoadError("Custom policy loader failed")
    if failure is not None:
        raise failure from None
    if not isinstance(loaded, dict):
        raise PolicyLoadError("Policy root must be a mapping object")
    if "extends" in loaded:
        raise PolicyLoadError(
            "Policy 'extends' is not supported with custom loaders"
        )
    return _validate_policy_mapping(
        copy.deepcopy(loaded),
        context=_FileLoadContext.create(),
        clock=clock,
    )


# ── Core load_policy ─────────────────────────────────────────────


def load_policy(
    policy_file: str,
    visited: set[Path] | None = None,
    *,
    loader: PolicyLoaderBase | None = None,
    clock: Callable[[], date] | None = None,
) -> dict[str, Any]:
    """
    Load and validate a policy YAML file.

    :param policy_file: Path to YAML policy file
    :param visited: Set of visited policy paths (for cycle detection)
    :param loader: Optional custom policy loader
    :param clock: Optional clock function for date validation
    :return: Python dict representing the policy
    """
    bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
    context = _FileLoadContext.create(policy_file, bound_ref)

    if isinstance(effective_loader, FilePolicyLoader):
        context.protect(effective_loader.policy_root)
        prepared = effective_loader._prepare(bound_ref, context=context)
        failure: PolicyLoadError | PolicyValidationError | None = None
        try:
            policy = _resolve_file_graph(
                prepared,
                loader=effective_loader,
                visited=set(visited or ()),
                context=context,
                clock=clock,
            )
        except (PolicyLoadError, PolicyValidationError) as exc:
            policy = None
            failure = context.normalize(
                exc,
                fallback="Policy validation failed",
            )
        if failure is not None:
            raise failure from None
        assert policy is not None
    else:
        policy = _load_opaque_policy(
            bound_ref,
            effective_loader,
            clock=clock,
        )

    logger.debug(
        "Policy loaded and validated: %s (version=%s)",
        policy_file,
        policy.get("policy_version"),
    )
    return policy


@dataclass(frozen=True, slots=True)
class _PreparedCompilationResult:
    prepared: _PreparedFilePolicy | None
    policy: dict[str, Any]
    compiled: CompiledPolicy
    date_failures: tuple[PolicyValidationError, ...]


def _prepare_resolve_compile_policy(
    policy_file: str,
    *,
    loader: PolicyLoaderBase | None = None,
    clock: Callable[[], date] | None = None,
    allow_legacy: bool = False,
    legacy_authorization: object | None = None,
    capture_date_failures: bool = False,
) -> _PreparedCompilationResult:
    bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
    context = _FileLoadContext.create(policy_file, bound_ref)
    if isinstance(effective_loader, FilePolicyLoader):
        context.protect(effective_loader.policy_root)
        prepared = effective_loader._prepare(bound_ref, context=context)
        graph_failure: PolicyLoadError | PolicyValidationError | None = None
        try:
            policy = _resolve_file_graph(
                prepared,
                loader=effective_loader,
                visited=set(),
                context=context,
                clock=clock,
                capture_date_failures=capture_date_failures,
            )
        except (PolicyLoadError, PolicyValidationError) as exc:
            policy = None
            graph_failure = context.normalize(
                exc,
                fallback="Policy validation failed",
            )
        if graph_failure is not None:
            raise graph_failure from None
        assert policy is not None
    else:
        prepared = None
        policy = _load_opaque_policy(
            bound_ref,
            effective_loader,
            clock=clock,
        )

    compile_failure: PolicyLoadError | PolicyValidationError | None = None
    try:
        compiled = compile_policy(
            policy,
            source="policy",
            allow_legacy=allow_legacy,
            legacy_authorization=legacy_authorization,
        )
    except (PolicyLoadError, PolicyValidationError) as exc:
        compiled = None
        compile_failure = context.normalize(
            exc,
            fallback="Policy compilation failed",
        )
    if compile_failure is not None:
        raise compile_failure from None
    assert compiled is not None
    return _PreparedCompilationResult(
        prepared=prepared,
        policy=copy.deepcopy(policy),
        compiled=compiled,
        date_failures=tuple(context.date_failures),
    )


def load_resolve_compile_policy(
    policy_file: str,
    *,
    loader: PolicyLoaderBase | None = None,
    clock: Callable[[], date] | None = None,
    allow_legacy: bool = False,
    legacy_authorization: object | None = None,
) -> CompiledPolicy:
    """Load and compile a policy without exposing an untrusted mapping fast path."""
    result = _prepare_resolve_compile_policy(
        policy_file,
        loader=loader,
        clock=clock,
        allow_legacy=allow_legacy,
        legacy_authorization=legacy_authorization,
    )
    return result.compiled


async def _load_policy_async_runner(
    policy_file: str,
    visited: set[Path] | None,
    loader: PolicyLoaderBase,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        load_policy,
        policy_file,
        visited,
        loader=loader,
    )


def load_policy_async(
    policy_file: str,
    visited: set[Path] | None = None,
    *,
    loader: PolicyLoaderBase | None = None,
) -> Awaitable[dict[str, Any]]:
    """Bind policy authority immediately and return an awaitable load.

    Runs load_policy in a thread pool to avoid blocking the event loop
    during file I/O and schema validation.

    :param policy_file: Path to YAML policy file
    :param visited: Set of visited policy paths (for cycle detection)
    :param loader: Optional explicit policy loader
    :return: Python dict representing the policy
    """
    bound_ref, effective_loader = _bind_policy_authority(policy_file, loader)
    return _load_policy_async_runner(bound_ref, visited, effective_loader)


_FileCacheKey = tuple[str, str, float]
_OpaqueCacheKey = tuple[str, float]
_PolicyCacheKey = _FileCacheKey | _OpaqueCacheKey


class PolicyCache:
    """LRU cache for loaded policies, isolated by loader authority.

    Thread-safe via threading.Lock. Cache lives on an AEGIS instance to
    eliminate global mutable state.

    Usage::

        cache = PolicyCache(max_size=128)
        policy = cache.get_or_load("policies/my_policy.yaml")
    """

    def __init__(self, max_size: int = 128) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self._max_size = max_size
        self._cache: dict[_PolicyCacheKey, dict[str, Any]] = {}
        self._compiled_cache: dict[_PolicyCacheKey, CompiledPolicy] = {}
        self._access_order: list[_PolicyCacheKey] = []
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def get_or_load(
        self,
        policy_file: str,
        visited: set[Path] | None = None,
        *,
        loader: PolicyLoaderBase | None = None,
    ) -> dict[str, Any]:
        """Load policy from cache or the supplied loader.

        :param policy_file: Path or reference to policy
        :param visited: For cycle detection during extends resolution
        :param loader: Optional custom policy loader (bypasses filesystem)
        :return: Loaded policy dict
        """
        bound_ref, effective_loader = _bind_policy_authority(
            policy_file,
            loader,
        )
        if isinstance(effective_loader, FilePolicyLoader):
            context = _FileLoadContext.create(
                policy_file,
                bound_ref,
                effective_loader.policy_root,
            )
            canonical = effective_loader._preflight(
                bound_ref,
                context=context,
            )
            metadata_failure: PolicyLoadError | None = None
            try:
                mtime = canonical.stat().st_mtime
            except (OSError, RuntimeError) as exc:
                normalized = context.normalize(
                    exc,
                    fallback="Policy metadata is unavailable",
                )
                metadata_failure = (
                    normalized
                    if isinstance(normalized, PolicyLoadError)
                    else PolicyLoadError("Policy metadata is unavailable")
                )
                mtime = 0.0
            if metadata_failure is not None:
                raise metadata_failure from None
            key: _PolicyCacheKey = (
                str(effective_loader.policy_root),
                str(canonical),
                mtime,
            )
        else:
            # Opaque sources have no filesystem metadata. Callers needing
            # cache-busting can clear the per-AEGIS cache explicitly.
            key = (bound_ref, 0.0)

        with self._lock:
            if key in self._cache:
                logger.debug("Policy cache hit: %s", policy_file)
                # Move to end for LRU
                if key in self._access_order:
                    self._access_order.remove(key)
                self._access_order.append(key)
                return self._cache[key]

        # Load outside lock to avoid blocking other threads
        policy = load_policy(
            bound_ref,
            visited,
            loader=effective_loader,
        )

        with self._lock:
            if len(self._cache) >= self._max_size:
                self._evict_oldest()
            self._cache[key] = policy
            self._access_order.append(key)
            logger.debug(
                "Policy cached: %s (cache size: %d)",
                policy_file,
                len(self._cache),
            )

        return policy

    def get_or_load_compiled(
        self,
        policy_file: str,
        *,
        loader: PolicyLoaderBase | None = None,
    ) -> CompiledPolicy:
        """Load and compile through one normalized, root-bound cache boundary."""
        bound_ref, effective_loader = _bind_policy_authority(
            policy_file,
            loader,
        )
        if isinstance(effective_loader, FilePolicyLoader):
            context = _FileLoadContext.create(
                policy_file,
                bound_ref,
                effective_loader.policy_root,
            )
            canonical = effective_loader._preflight(
                bound_ref,
                context=context,
            )
            metadata_failure: PolicyLoadError | None = None
            try:
                mtime = canonical.stat().st_mtime
            except (OSError, RuntimeError) as exc:
                normalized = context.normalize(
                    exc,
                    fallback="Policy metadata is unavailable",
                )
                metadata_failure = (
                    normalized
                    if isinstance(normalized, PolicyLoadError)
                    else PolicyLoadError("Policy metadata is unavailable")
                )
                mtime = 0.0
            if metadata_failure is not None:
                raise metadata_failure from None
            key: _PolicyCacheKey = (
                str(effective_loader.policy_root),
                str(canonical),
                mtime,
            )
        else:
            key = (bound_ref, 0.0)

        with self._lock:
            if key in self._compiled_cache:
                if key in self._access_order:
                    self._access_order.remove(key)
                self._access_order.append(key)
                return self._compiled_cache[key]

        result = _prepare_resolve_compile_policy(
            bound_ref,
            loader=effective_loader,
        )
        with self._lock:
            if key not in self._cache and len(self._cache) >= self._max_size:
                self._evict_oldest()
            self._cache[key] = copy.deepcopy(result.policy)
            self._compiled_cache[key] = result.compiled
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
        return result.compiled

    def _evict_oldest(self) -> None:
        """Evict the least recently used cache entry. Must hold lock."""
        if self._access_order:
            oldest = self._access_order.pop(0)
            self._cache.pop(oldest, None)
            self._compiled_cache.pop(oldest, None)

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self._compiled_cache.clear()
            self._access_order.clear()
