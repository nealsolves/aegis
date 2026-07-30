"""Default-deny comparison for policy authority restrictions."""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from aegis._internal.compiled_policy import (
    AuthorityEnvelope,
    CompiledPolicy,
    CompiledToolLimit,
)
from aegis._internal.errors import PolicyValidationError


_MISSING = object()
_NON_SECURITY_ROOT_FIELDS = frozenset(
    {
        "extends",
        "composition_strategy",
        "policy_version",
        "description",
        "effective_date",
        "expiration_date",
    },
)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(item) for item in value), key=repr)
    return copy.deepcopy(value)


def _same(left: Any, right: Any) -> bool:
    def encoded(value: Any) -> str:
        return json.dumps(
            _plain(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    return encoded(left) == encoded(right)


def _path_value(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _raise_widening(
    *,
    path: str,
    phase: str,
    parent: Any,
    candidate: Any,
    reason: str,
) -> None:
    raise PolicyValidationError(
        f"Policy restriction widens authority at {path}: {reason}",
        code="POLICY_WIDENING",
        details={
            "path": path,
            "phase": phase,
            "parent": None if parent is _MISSING else _plain(parent),
            "candidate": None if candidate is _MISSING else _plain(candidate),
            "reason": reason,
        },
    )


class RestrictionRule(Protocol):
    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        """Raise when *candidate* is weaker than *parent*."""


@dataclass(frozen=True, slots=True)
class SetSubsetRule:
    """A declared candidate allowlist may contain only parent members."""

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        if parent in (_MISSING, None):
            return
        if candidate in (_MISSING, None):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate removes an inherited allowlist",
            )
        parent_values = set(parent)
        candidate_values = set(candidate)
        if not candidate_values <= parent_values:
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate adds values outside the parent allowlist",
            )


@dataclass(frozen=True, slots=True)
class ToolSubsetRule:
    """Tool names must be a subset and every call limit must not increase."""

    def _limits(self, value: Any) -> dict[str, int]:
        if value in (_MISSING, None):
            return {}
        limits: dict[str, int] = {}
        for item in value:
            if isinstance(item, CompiledToolLimit):
                name, maximum = item.name, item.max_calls
            else:
                name, maximum = item["name"], item["max_calls"]
            previous = limits.get(name)
            limits[name] = maximum if previous is None else min(previous, maximum)
        return limits

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        if parent in (_MISSING, None):
            return
        if candidate in (_MISSING, None):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate removes inherited tool constraints",
            )
        parent_limits = self._limits(parent)
        candidate_limits = self._limits(candidate)
        if not set(candidate_limits) <= set(parent_limits):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate adds a tool name",
            )
        raised = {
            name: maximum
            for name, maximum in candidate_limits.items()
            if maximum > parent_limits[name]
        }
        if raised:
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate increases a tool call limit",
            )


@dataclass(frozen=True, slots=True)
class RiskModeCompositionRule:
    """Risk mode may stay unchanged or become strict."""

    only_same_or_strict: bool = True

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        if parent is _MISSING:
            return
        if candidate is _MISSING or (
            candidate != parent
            and (not self.only_same_or_strict or candidate != "strict")
        ):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="risk modes are unordered except for strict",
            )


@dataclass(frozen=True, slots=True)
class NumericMaximumRule:
    """A numeric candidate must be no greater than the parent value."""

    absent_value: int | float | None = None

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        normalized_parent = (
            self.absent_value if parent in (_MISSING, None) else parent
        )
        normalized_candidate = (
            self.absent_value if candidate in (_MISSING, None) else candidate
        )
        if normalized_parent is None:
            return
        if (
            normalized_candidate is None
            or normalized_candidate > normalized_parent
        ):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate increases a security limit",
            )


@dataclass(frozen=True, slots=True)
class RequirementsSupersetRule:
    """Existing requirements must remain unchanged and new ones may be added."""

    def _required(self, value: Any) -> Any:
        if value in (_MISSING, None):
            return {}
        if not isinstance(value, Mapping):
            return value
        return value.get("required", {})

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        parent_required = self._required(parent)
        candidate_required = self._required(candidate)
        if not parent_required:
            return
        if isinstance(parent_required, Mapping):
            if not isinstance(candidate_required, Mapping):
                if phase.endswith("overlay") and candidate is not _MISSING:
                    return
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason="candidate changes the requirement representation",
                )
            if phase.endswith("overlay"):
                names = set(parent_required) & set(candidate_required)
            else:
                if not set(parent_required) <= set(candidate_required):
                    _raise_widening(
                        path=path,
                        phase=phase,
                        parent=parent,
                        candidate=candidate,
                        reason="candidate removes inherited requirements",
                    )
                names = set(parent_required)
            for name in names:
                if not _same(parent_required[name], candidate_required[name]):
                    _raise_widening(
                        path=path,
                        phase=phase,
                        parent=parent,
                        candidate=candidate,
                        reason=(
                            "changed requirement is not compiler-proven stronger"
                        ),
                    )
            return

        parent_names = set(parent_required)
        candidate_names = set(candidate_required)
        if not phase.endswith("overlay") and not parent_names <= candidate_names:
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="candidate removes inherited requirements",
            )


@dataclass(frozen=True, slots=True)
class SchemaRestrictionRule:
    """Output schemas remain unchanged unless a future prover narrows them."""

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        if parent in (_MISSING, None):
            return
        if candidate in (_MISSING, None) or not _same(parent, candidate):
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason="output schema change lacks a narrowing proof",
            )


@dataclass(frozen=True, slots=True)
class ExistingMappingRule:
    """Existing declarations are immutable; additions are allowed."""

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        parent_mapping = {} if parent in (_MISSING, None) else parent
        candidate_mapping = {} if candidate in (_MISSING, None) else candidate
        for key, value in parent_mapping.items():
            if key not in candidate_mapping:
                if phase.endswith("overlay"):
                    continue
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason=f"candidate removes inherited declaration {key!r}",
                )
            if not _same(value, candidate_mapping[key]):
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason=f"candidate replaces declaration {key!r}",
                )


@dataclass(frozen=True, slots=True)
class RiskFactorsRule:
    """Risk factors may be added, but existing weights may not decrease."""

    def _group(self, value: Any) -> dict[tuple[str, str], list[float]]:
        grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
        if value in (_MISSING, None):
            return grouped
        for factor in value:
            if isinstance(factor, Mapping):
                name = factor["name"]
                condition = factor["condition"]
                weight = factor["weight"]
            else:
                name = factor.name
                condition = factor.condition
                weight = factor.weight
            grouped[(name, condition)].append(weight)
        for weights in grouped.values():
            weights.sort()
        return grouped

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        parent_groups = self._group(parent)
        candidate_groups = self._group(candidate)
        for identity, parent_weights in parent_groups.items():
            candidate_weights = candidate_groups.get(identity, [])
            if phase.endswith("overlay") and not candidate_weights:
                continue
            if len(candidate_weights) < len(parent_weights) or any(
                candidate_weight < parent_weight
                for parent_weight, candidate_weight in zip(
                    parent_weights,
                    candidate_weights,
                )
            ):
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason="candidate removes or weakens a risk factor",
                )


@dataclass(frozen=True, slots=True)
class GuardSupersetRule:
    """Resolved policies must retain every inherited guard declaration."""

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if phase.endswith("overlay") or parent in (_MISSING, None):
            return
        candidate_items = [] if candidate in (_MISSING, None) else list(candidate)
        remaining = [
            json.dumps(_plain(item), sort_keys=True, separators=(",", ":"))
            for item in candidate_items
        ]
        for item in parent:
            encoded = json.dumps(
                _plain(item),
                sort_keys=True,
                separators=(",", ":"),
            )
            if encoded not in remaining:
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason="candidate removes an inherited guard",
                )
            remaining.remove(encoded)


@dataclass(frozen=True, slots=True)
class WorkflowRestrictionRule:
    """Delegate the established workflow narrowing proof through the registry."""

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        if candidate is _MISSING and phase.endswith("overlay"):
            return
        if parent in (_MISSING, None):
            return
        from aegis._internal.policy_loader import (
            _merge_policies,
            _validate_composition_restriction,
        )

        parent_policy = {"workflow": _plain(parent)}
        if phase.endswith("overlay"):
            overlay_policy = {"workflow": _plain(candidate)}
            merged_policy = _merge_policies(parent_policy, overlay_policy)
        else:
            overlay_policy = None
            merged_policy = {
                "workflow": (
                    None
                    if candidate in (_MISSING, None)
                    else _plain(candidate)
                ),
            }
        try:
            _validate_composition_restriction(
                parent_policy,
                merged_policy,
                overlay=overlay_policy,
            )
        except PolicyValidationError as exc:
            _raise_widening(
                path=path,
                phase=phase,
                parent=parent,
                candidate=candidate,
                reason=str(exc),
            )


class RestrictionRegistry:
    """Closed mapping from marked schema paths to restriction semantics."""

    def __init__(self, rules: Mapping[str, RestrictionRule]) -> None:
        self._rules = dict(rules)

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(self._rules)

    def compare(
        self,
        parent: Any,
        candidate: Any,
        *,
        path: str,
        phase: str,
    ) -> None:
        rule = self._rules.get(path)
        if rule is None:
            raise PolicyValidationError(
                f"No restriction semantics are registered for {path}",
                code="RESTRICTION_SEMANTICS_MISSING",
                details={"path": path, "phase": phase},
            )
        rule.compare(
            parent,
            candidate,
            path=path,
            phase=phase,
        )


REGISTRY = RestrictionRegistry(
    {
        "roles": SetSubsetRule(),
        "conditions": ExistingMappingRule(),
        "tools.allowed_tools": ToolSubsetRule(),
        "retry_policy.max_retries": NumericMaximumRule(absent_value=0),
        "retry_policy.backoff_ms": NumericMaximumRule(absent_value=0),
        "risk.mode": RiskModeCompositionRule(only_same_or_strict=True),
        "risk.threshold": NumericMaximumRule(),
        "risk.factors": RiskFactorsRule(),
        "pre_conditions": RequirementsSupersetRule(),
        "post_conditions": RequirementsSupersetRule(),
        "output_schema": SchemaRestrictionRule(),
        "guards": GuardSupersetRule(),
        "workflow": WorkflowRestrictionRule(),
    },
)


def security_sensitive_schema_fields(
    schema: Mapping[str, Any],
) -> frozenset[str]:
    """Return policy-property paths carrying the stable security annotation."""
    result: set[str] = set()

    def walk(node: Any, prefix: str = "") -> None:
        if not isinstance(node, Mapping):
            return
        properties = node.get("properties")
        if not isinstance(properties, Mapping):
            return
        for name, child in properties.items():
            path = f"{prefix}.{name}" if prefix else name
            if (
                isinstance(child, Mapping)
                and child.get("x-aegis-security-sensitive") is True
            ):
                result.add(path)
            walk(child, path)

    walk(schema)
    return frozenset(result)


def validate_registry_coverage(
    schema: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    """Fail closed for marker drift and unknown root authority fields."""
    marked = security_sensitive_schema_fields(schema)
    missing = sorted(marked - REGISTRY.fields)
    stale = sorted(REGISTRY.fields - marked)
    if missing or stale:
        field = (missing or stale)[0]
        raise PolicyValidationError(
            "Policy restriction registry and schema markers differ",
            code="RESTRICTION_SEMANTICS_MISSING",
            details={
                "path": field,
                "missing_registry_rules": missing,
                "unmarked_registry_rules": stale,
            },
        )

    schema_fields = set((schema.get("properties") or {}).keys())
    unknown = sorted(
        set(policy) - schema_fields - _NON_SECURITY_ROOT_FIELDS,
        key=repr,
    )
    if unknown:
        raise PolicyValidationError(
            f"Unknown policy field has no restriction semantics: {unknown[0]}",
            code="RESTRICTION_SEMANTICS_MISSING",
            details={"path": unknown[0]},
        )


class RestrictionComparator:
    """Compare raw overlays and compiled effective policies to one envelope."""

    def __init__(self, registry: RestrictionRegistry = REGISTRY) -> None:
        self._registry = registry

    def _compare_values(
        self,
        parent: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        phase: str,
    ) -> None:
        for path in sorted(self._registry.fields):
            self._registry.compare(
                _path_value(parent, path),
                _path_value(candidate, path),
                path=path,
                phase=phase,
            )

    def assert_overlay_and_effective(
        self,
        parent: CompiledPolicy,
        overlay: Mapping[str, Any],
        effective: CompiledPolicy,
        *,
        phase_prefix: str = "",
    ) -> None:
        self.assert_overlay(
            parent,
            overlay,
            phase=f"{phase_prefix}overlay",
        )
        self.assert_effective(
            parent.authority,
            effective,
            phase=f"{phase_prefix}effective",
        )

    def assert_overlay(
        self,
        parent: CompiledPolicy,
        overlay: Mapping[str, Any],
        *,
        phase: str = "overlay",
    ) -> None:
        self._compare_values(
            parent.authority.restriction_values,
            overlay,
            phase=phase,
        )

    def assert_effective(
        self,
        loaded_authority: AuthorityEnvelope,
        candidate: CompiledPolicy,
        *,
        phase: str = "effective",
    ) -> None:
        self._compare_values(
            loaded_authority.restriction_values,
            candidate.authority.restriction_values,
            phase=phase,
        )


def merge_policy_effect(
    base: dict[str, Any],
    overlay: Mapping[str, Any],
) -> None:
    """Apply deterministic legacy guard merge semantics to a detached value."""
    for key, value in overlay.items():
        if key not in base:
            base[key] = _plain(value)
        elif (
            key == "allowed_tools"
            and isinstance(base[key], list)
            and isinstance(value, (list, tuple))
        ):
            base[key] = _plain(value)
        elif isinstance(base[key], list) and isinstance(value, (list, tuple)):
            base[key].extend(_plain(value))
        elif isinstance(base[key], dict) and isinstance(value, Mapping):
            merge_policy_effect(base[key], value)
        else:
            base[key] = _plain(value)


def policy_from_restriction_values(
    values: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a detached compiler input from normalized restriction values."""
    policy = _plain(values)
    policy["policy_version"] = "2.0"
    for key in (
        "conditions",
        "tools",
        "retry_policy",
        "pre_conditions",
        "post_conditions",
        "output_schema",
        "workflow",
    ):
        if policy.get(key) is None:
            policy.pop(key, None)
    return policy
