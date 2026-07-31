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
    CompiledPrecondition,
    CompiledToolLimit,
    CompiledToolPolicy,
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


@dataclass(frozen=True, slots=True)
class ProtocolCapabilityRule:
    """Runtime default and direction for one protocol capability."""

    default: Any
    direction: str


PROTOCOL_CAPABILITY_RULES: Mapping[str, ProtocolCapabilityRule] = {
    "bedrock.require_trace": ProtocolCapabilityRule(False, "require"),
    "bedrock.require_alias_backed_identity": ProtocolCapabilityRule(
        True,
        "require",
    ),
    "bedrock.require_alias": ProtocolCapabilityRule(True, "require"),
    "a2a.protocol_version": ProtocolCapabilityRule("1.0", "exact"),
    "a2a.allowed_protocol_bindings": ProtocolCapabilityRule(
        ("JSONRPC", "HTTP+JSON"),
        "subset",
    ),
    "a2a.require_task_state": ProtocolCapabilityRule(True, "require"),
    "openai_agents.require_trace": ProtocolCapabilityRule(False, "require"),
    "openai_agents.allow_hosted_tools": ProtocolCapabilityRule(False, "allow"),
    "openai_agents.allow_agent_as_tool": ProtocolCapabilityRule(True, "allow"),
    "openai_agents.require_unique_agent_names": ProtocolCapabilityRule(
        True,
        "require",
    ),
}
_PROTOCOL_FAMILIES = frozenset(
    path.split(".", 1)[0] for path in PROTOCOL_CAPABILITY_RULES
)


def _plain(value: Any) -> Any:
    if isinstance(value, CompiledPrecondition):
        specification: dict[str, Any] = {}
        if value.declared_type is not None:
            specification["type"] = value.declared_type
        if value.pattern is not None:
            specification["pattern"] = value.pattern.source
        if value.enum is not None:
            specification["enum"] = _plain(value.enum)
        if value.min_length is not None:
            specification["minLength"] = value.min_length
        if value.max_length is not None:
            specification["maxLength"] = value.max_length
        if value.minimum is not None:
            specification["minimum"] = value.minimum
        if value.maximum is not None:
            specification["maximum"] = value.maximum
        return specification
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


def _authority_value(authority: AuthorityEnvelope, path: str) -> Any:
    """Select one registered field from explicit typed authority."""
    if path == "roles":
        return authority.roles
    if path == "conditions":
        return authority.conditions
    if path == "tools.allowed_tools":
        return authority.tools
    if path == "retry_policy.max_retries":
        return (
            authority.retry.max_retries
            if authority.retry is not None
            else None
        )
    if path == "retry_policy.backoff_ms":
        return (
            authority.retry.backoff_ms
            if authority.retry is not None
            else None
        )
    if path == "risk.mode":
        return authority.risk.mode
    if path == "risk.threshold":
        return authority.risk.threshold
    if path == "risk.factors":
        return authority.risk.factors
    if path == "pre_conditions":
        return authority.preconditions
    if path == "post_conditions":
        return authority.postconditions
    if path == "output_schema":
        return authority.output_schema
    if path == "guards":
        return authority.guards
    if path == "workflow":
        return authority.workflow
    raise PolicyValidationError(
        f"No typed authority accessor is registered for {path}",
        code="RESTRICTION_SEMANTICS_MISSING",
        details={"path": path},
    )


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


def compare_protocol_capabilities(
    parent: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> None:
    """Prove candidate protocol capabilities are equal or more restrictive."""
    unknown_families = sorted(
        set(candidate) - _PROTOCOL_FAMILIES - {"local"},
    )
    if unknown_families:
        raise PolicyValidationError(
            "Protocol constraints contain an unsupported family",
            details={"unknown_protocol_families": unknown_families},
        )

    if "local" in candidate:
        candidate_local = candidate["local"]
        parent_local = parent.get("local", {})
        if not isinstance(candidate_local, Mapping) or not isinstance(
            parent_local,
            Mapping,
        ):
            raise PolicyValidationError(
                "Local protocol constraints must be mappings",
                details={"family": "local"},
            )
        if not _same(parent_local, candidate_local):
            raise PolicyValidationError(
                "Local protocol capabilities have no registered narrowing semantics",
                details={"family": "local"},
            )

    for family in sorted(_PROTOCOL_FAMILIES):
        if family not in candidate:
            # Removing a protocol family makes that protocol unavailable.
            continue
        parent_family = parent.get(family, {})
        candidate_family = candidate[family]
        if not isinstance(parent_family, Mapping) or not isinstance(
            candidate_family,
            Mapping,
        ):
            raise PolicyValidationError(
                "Protocol family constraints must be mappings",
                details={"family": family},
            )

        prefix = f"{family}."
        family_rules = {
            path.removeprefix(prefix): rule
            for path, rule in PROTOCOL_CAPABILITY_RULES.items()
            if path.startswith(prefix)
        }
        unknown_fields = sorted(set(candidate_family) - set(family_rules))
        if unknown_fields:
            raise PolicyValidationError(
                "Protocol constraints contain unsupported capability fields",
                details={
                    "family": family,
                    "unknown_capability_fields": unknown_fields,
                },
            )

        for field, rule in family_rules.items():
            parent_value = parent_family.get(field, rule.default)
            candidate_value = candidate_family.get(field, rule.default)
            if rule.direction == "require":
                widens = bool(parent_value) and not bool(candidate_value)
            elif rule.direction == "allow":
                widens = not bool(parent_value) and bool(candidate_value)
            elif rule.direction == "subset":
                widens = not set(candidate_value) <= set(parent_value)
            elif rule.direction == "exact":
                widens = not _same(parent_value, candidate_value)
            else:  # pragma: no cover - guarded by the registry fitness test
                widens = True
            if widens:
                raise PolicyValidationError(
                    "Protocol capability widens runtime authority",
                    details={
                        "family": family,
                        "key": field,
                        "direction": rule.direction,
                        "base": _plain(parent_value),
                        "merged": _plain(candidate_value),
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

    def _configured(self, value: Any) -> bool:
        if isinstance(value, CompiledToolPolicy):
            return value.configured
        return value not in (_MISSING, None)

    def _limits(self, value: Any) -> dict[str, int]:
        if value in (_MISSING, None):
            return {}
        if isinstance(value, CompiledToolPolicy):
            value = value.allowed_tools
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
        if not self._configured(parent):
            return
        if not self._configured(candidate):
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
        if isinstance(value, tuple):
            if all(isinstance(item, CompiledPrecondition) for item in value):
                return {item.name: item for item in value}
            return value
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
        remaining = list(candidate_items)
        for item in parent:
            if item not in remaining:
                _raise_widening(
                    path=path,
                    phase=phase,
                    parent=parent,
                    candidate=candidate,
                    reason="candidate removes an inherited guard",
                )
            remaining.remove(item)


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
        from aegis._internal.policy_loader import (
            _merge_policies,
            _validate_composition_restriction,
        )

        parent_policy = {
            "workflow": (
                {}
                if parent in (_MISSING, None)
                else _plain(parent)
            ),
        }
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


def protocol_capability_schema_fields(
    schema: Mapping[str, Any],
) -> frozenset[str]:
    """Return every explicitly modeled workflow protocol capability path."""
    node: Any = schema
    for part in ("workflow", "protocol_constraints"):
        properties = node.get("properties") if isinstance(node, Mapping) else None
        node = properties.get(part) if isinstance(properties, Mapping) else None
    families = node.get("properties") if isinstance(node, Mapping) else None
    result: set[str] = set()
    if not isinstance(families, Mapping):
        return frozenset()
    for family, family_schema in families.items():
        fields = (
            family_schema.get("properties")
            if isinstance(family_schema, Mapping)
            else None
        )
        if isinstance(fields, Mapping):
            result.update(f"{family}.{field}" for field in fields)
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
        parent: AuthorityEnvelope,
        candidate: AuthorityEnvelope | Mapping[str, Any],
        *,
        phase: str,
    ) -> None:
        for path in sorted(self._registry.fields):
            self._registry.compare(
                _authority_value(parent, path),
                (
                    _authority_value(candidate, path)
                    if isinstance(candidate, AuthorityEnvelope)
                    else _path_value(candidate, path)
                ),
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
            parent.authority,
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
            loaded_authority,
            candidate.authority,
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
            key in {
                "allowed_tools",
                "participants",
                "required_sequence",
                "roles",
            }
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
