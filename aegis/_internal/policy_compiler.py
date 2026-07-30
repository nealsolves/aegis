"""Compile schema-valid policy mappings into immutable authorization values."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft7Validator

from aegis._internal.compiled_policy import (
    AuthorityEnvelope,
    CompiledGuard,
    CompiledPolicy,
    CompiledPrecondition,
    CompiledRetryPolicy,
    CompiledRiskFactor,
    CompiledRiskPolicy,
    CompiledToolLimit,
    freeze,
)
from aegis._internal.errors import PolicyLoadError, PolicyValidationError
from aegis._internal.patterns import compile_pattern
from aegis._internal.schema_compiler import compile_output_schema


POLICY_CONTRACT_VERSION = "2.0"
PATTERN_ENGINE = "google-re2"
CANONICALIZATION_PROFILE = "aegis-json-v2"
CRITICAL_RISK_CEILING = 0.90
DEFAULT_COMPILED_RISK_THRESHOLD = CRITICAL_RISK_CEILING
MAX_RETRIES = 10
MAX_BACKOFF_MS = 60_000
VALID_RISK_MODES = ("strict", "risk_scored", "warn_only")
BUILTIN_RISK_CONDITIONS = frozenset(
    {
        "no_output_schema",
        "broad_roles",
        "no_preconditions",
        "high_tool_count",
        "missing_guards",
        "external_model",
    }
)
_RISK_MODE_STRICTNESS = {
    "warn_only": 0,
    "risk_scored": 1,
    "strict": 2,
}
_SCHEMA_DRAFT_07 = "http://json-schema.org/draft-07/schema#"
_POLICY_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "policy_dsl.schema.json"
_REGISTERED_AUTHORITY_FIELDS = frozenset(
    {
        "roles",
        "tools",
        "risk",
        "retry_policy",
        "guards",
        "pre_conditions",
        "output_schema",
    }
)


def require_finite_number(
    value: object,
    *,
    path: str,
    minimum: float,
    maximum: float,
) -> float:
    """Return a finite built-in number inside a closed security range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyValidationError(
            "Security number must be numeric",
            code="RISK_NUMBER_INVALID",
            details={"path": path},
        )
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise PolicyValidationError(
            "Security number out of range",
            code="RISK_NUMBER_INVALID",
            details={
                "path": path,
                "minimum": minimum,
                "maximum": maximum,
            },
        ) from exc
    if (
        not math.isfinite(normalized)
        or not minimum <= normalized <= maximum
    ):
        raise PolicyValidationError(
            "Security number out of range",
            code="RISK_NUMBER_INVALID",
            details={
                "path": path,
                "minimum": minimum,
                "maximum": maximum,
            },
        )
    return normalized


def _require_bounded_integer(
    value: object,
    *,
    path: str,
    minimum: int,
    maximum: int,
) -> int:
    """Return a non-coerced built-in integer inside a closed range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyValidationError(
            "Security number must be an integer",
            code="RISK_NUMBER_INVALID",
            details={"path": path},
        )
    if not minimum <= value <= maximum:
        raise PolicyValidationError(
            "Security number out of range",
            code="RISK_NUMBER_INVALID",
            details={
                "path": path,
                "minimum": minimum,
                "maximum": maximum,
            },
        )
    return value


def _require_integer_minimum(
    value: object,
    *,
    path: str,
    minimum: int,
) -> int:
    """Validate an integer limit whose schema deliberately has no upper cap."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyValidationError(
            "Security number must be an integer",
            code="RISK_NUMBER_INVALID",
            details={"path": path},
        )
    if value < minimum:
        raise PolicyValidationError(
            "Security number out of range",
            code="RISK_NUMBER_INVALID",
            details={"path": path, "minimum": minimum},
        )
    return value


def _require_finite_security_number(value: object, *, path: str) -> None:
    """Reject coercible and non-finite numbers without imposing a range."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or isinstance(value, float)
        and not math.isfinite(value)
    ):
        raise PolicyValidationError(
            "Security number must be finite and numeric",
            code="RISK_NUMBER_INVALID",
            details={"path": path},
        )


def _require_risk_mapping(value: object, *, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyValidationError(
            f"Risk value at {path} must be an object",
            code="RISK_POLICY_INVALID",
            details={"path": path},
        )
    return value


def compile_risk_policy(raw: Mapping[str, Any]) -> CompiledRiskPolicy:
    """Compile one detached, finite risk policy from the closed condition set."""
    detached = copy.deepcopy(dict(raw))
    unknown_fields = sorted(
        set(detached) - {"mode", "threshold", "factors"},
        key=repr,
    )
    if unknown_fields:
        raise PolicyValidationError(
            "Risk policy contains unsupported fields",
            code="RISK_POLICY_INVALID",
            details={"fields": unknown_fields},
        )

    mode = detached.get("mode", "strict")
    if mode not in VALID_RISK_MODES:
        raise PolicyValidationError(
            f"Invalid risk mode: {mode!r}; expected one of {VALID_RISK_MODES}",
            details={
                "invalid_mode": mode,
                "valid_modes": list(VALID_RISK_MODES),
            },
        )

    threshold = require_finite_number(
        detached.get("threshold", DEFAULT_COMPILED_RISK_THRESHOLD),
        path="$.risk.threshold",
        minimum=0.0,
        maximum=1.0,
    )

    raw_factors = detached.get("factors", [])
    if not isinstance(raw_factors, list):
        raise PolicyValidationError(
            "Risk factors must be an array",
            code="RISK_POLICY_INVALID",
            details={"path": "$.risk.factors"},
        )

    factors: list[CompiledRiskFactor] = []
    for index, raw_factor in enumerate(raw_factors):
        factor = _require_risk_mapping(
            raw_factor,
            path=f"$.risk.factors.{index}",
        )
        unknown_factor_fields = sorted(
            set(factor) - {"name", "weight", "condition"},
            key=repr,
        )
        if (
            unknown_factor_fields
            or not {"name", "weight", "condition"} <= set(factor)
        ):
            raise PolicyValidationError(
                "Risk factor has invalid fields",
                code="RISK_POLICY_INVALID",
                details={
                    "path": f"$.risk.factors.{index}",
                    "fields": unknown_factor_fields,
                },
            )
        name = factor["name"]
        condition = factor["condition"]
        if not isinstance(name, str) or not isinstance(condition, str):
            raise PolicyValidationError(
                "Risk factor name and condition must be strings",
                code="RISK_POLICY_INVALID",
                details={"path": f"$.risk.factors.{index}"},
            )
        if condition not in BUILTIN_RISK_CONDITIONS:
            raise PolicyValidationError(
                f"Unknown risk condition: {condition!r}",
                code="RISK_CONDITION_UNKNOWN",
                details={
                    "path": f"$.risk.factors.{index}.condition",
                    "condition": condition,
                },
            )
        factors.append(
            CompiledRiskFactor(
                name=name,
                weight=require_finite_number(
                    factor["weight"],
                    path=f"$.risk.factors.{index}.weight",
                    minimum=0.0,
                    maximum=1.0,
                ),
                condition=condition,
            )
        )

    return CompiledRiskPolicy(
        mode=mode,
        threshold=threshold,
        critical_ceiling=CRITICAL_RISK_CEILING,
        factors=tuple(factors),
    )


def _compile_retry_policy(
    raw: Mapping[str, Any] | None,
) -> CompiledRetryPolicy | None:
    """Compile bounded retry authority after structural validation."""
    if raw is None:
        return None
    return CompiledRetryPolicy(
        max_retries=_require_bounded_integer(
            raw["max_retries"],
            path="$.retry_policy.max_retries",
            minimum=0,
            maximum=MAX_RETRIES,
        ),
        backoff_ms=_require_bounded_integer(
            raw["backoff_ms"],
            path="$.retry_policy.backoff_ms",
            minimum=0,
            maximum=MAX_BACKOFF_MS,
        ),
    )


def _validate_security_numbers(policy: Mapping[str, Any]) -> None:
    """Validate numeric security fields before JSON Schema coercion quirks."""
    raw_risk = policy.get("risk")
    if isinstance(raw_risk, Mapping):
        compile_risk_policy(raw_risk)

    raw_retry = policy.get("retry_policy")
    if isinstance(raw_retry, Mapping):
        for name, maximum in (
            ("max_retries", MAX_RETRIES),
            ("backoff_ms", MAX_BACKOFF_MS),
        ):
            if name in raw_retry:
                _require_bounded_integer(
                    raw_retry[name],
                    path=f"$.retry_policy.{name}",
                    minimum=0,
                    maximum=maximum,
                )

    raw_tools = policy.get("tools")
    allowed_tools = (
        raw_tools.get("allowed_tools")
        if isinstance(raw_tools, Mapping)
        else None
    )
    if isinstance(allowed_tools, list):
        for index, item in enumerate(allowed_tools):
            if isinstance(item, Mapping) and "max_calls" in item:
                _require_integer_minimum(
                    item["max_calls"],
                    path=f"$.tools.allowed_tools.{index}.max_calls",
                    minimum=1,
                )

    raw_preconditions = policy.get("pre_conditions")
    required = (
        raw_preconditions.get("required")
        if isinstance(raw_preconditions, Mapping)
        else None
    )
    if isinstance(required, Mapping):
        for name, specification in required.items():
            if not isinstance(specification, Mapping):
                continue
            for keyword in ("minimum", "maximum"):
                if keyword in specification:
                    _require_finite_security_number(
                        specification[keyword],
                        path=(
                            f"$.pre_conditions.required.{name}.{keyword}"
                        ),
                    )
            for keyword in ("minLength", "maxLength"):
                if keyword in specification:
                    _require_integer_minimum(
                        specification[keyword],
                        path=(
                            f"$.pre_conditions.required.{name}.{keyword}"
                        ),
                        minimum=0,
                    )

    workflow = policy.get("workflow")
    if isinstance(workflow, Mapping):
        for keyword in ("max_steps", "max_total_tool_calls"):
            if keyword in workflow:
                _require_integer_minimum(
                    workflow[keyword],
                    path=f"$.workflow.{keyword}",
                    minimum=1,
                )
        escalation = workflow.get("escalation")
        if (
            isinstance(escalation, Mapping)
            and "require_approval_after_steps" in escalation
        ):
            _require_integer_minimum(
                escalation["require_approval_after_steps"],
                path=(
                    "$.workflow.escalation."
                    "require_approval_after_steps"
                ),
                minimum=1,
            )


def resolve_runtime_risk(
    base: CompiledRiskPolicy,
    override: Mapping[str, Any] | None,
) -> CompiledRiskPolicy:
    """Resolve a runtime risk candidate only when it tightens *base*."""
    if override is None:
        return base

    detached = copy.deepcopy(dict(override))
    if "critical_ceiling" in detached:
        raise PolicyValidationError(
            "The critical risk ceiling is fixed",
            code="RISK_OVERRIDE_WIDENS",
        )
    unknown_fields = sorted(
        set(detached) - {"mode", "threshold", "factors"},
        key=repr,
    )
    if unknown_fields:
        raise PolicyValidationError(
            "Runtime risk override contains unsupported fields",
            code="RISK_OVERRIDE_WIDENS",
            details={"fields": unknown_fields},
        )

    candidate_raw: dict[str, Any] = {
        "mode": detached.get("mode", base.mode),
        "threshold": detached.get("threshold", base.threshold),
        "factors": detached.get(
            "factors",
            [
                {
                    "name": factor.name,
                    "weight": factor.weight,
                    "condition": factor.condition,
                }
                for factor in base.factors
            ],
        ),
    }
    candidate = compile_risk_policy(candidate_raw)
    base_factor_counts = Counter(base.factors)
    candidate_factor_counts = Counter(candidate.factors)

    if (
        _RISK_MODE_STRICTNESS[candidate.mode]
        < _RISK_MODE_STRICTNESS[base.mode]
        or candidate.threshold > base.threshold
        or any(
            candidate_factor_counts[factor] < count
            for factor, count in base_factor_counts.items()
        )
    ):
        raise PolicyValidationError(
            "Runtime risk override widens compiled policy",
            code="RISK_OVERRIDE_WIDENS",
        )
    return candidate


def _path_to_pointer(path: list[Any]) -> str:
    return "$" if not path else "$." + ".".join(str(part) for part in path)


def _validate_policy_schema(policy: Mapping[str, Any], *, allow_legacy: bool) -> None:
    """Validate the detached mapping against the packaged Draft 7 policy schema."""
    preconditions = policy.get("pre_conditions")
    required = (
        preconditions.get("required", {})
        if isinstance(preconditions, Mapping)
        else {}
    )
    if isinstance(required, list) and not allow_legacy:
        raise PolicyValidationError(
            "Bare-string preconditions require explicit legacy authority",
            code="LEGACY_PRECONDITION_FORBIDDEN",
            details={"path": "$.pre_conditions.required"},
        )
    try:
        schema = json.loads(_POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyLoadError(
            "Policy schema file is not valid JSON",
            details={"schema_path": str(_POLICY_SCHEMA_PATH), "error": str(exc)},
        ) from exc

    if schema.get("$schema") != _SCHEMA_DRAFT_07:
        raise PolicyLoadError(
            "Policy schema must declare JSON Schema Draft-07",
            details={"schema_path": str(_POLICY_SCHEMA_PATH)},
        )

    Draft7Validator.check_schema(schema)
    errors = sorted(
        Draft7Validator(schema).iter_errors(policy),
        key=lambda error: _path_to_pointer(list(error.absolute_path)),
    )
    if errors:
        first = errors[0]
        pointer = _path_to_pointer(list(first.absolute_path))
        raise PolicyValidationError(
            f"Policy schema validation failed at {pointer}: {first.message}",
            details={"path": pointer, "validator": first.validator},
        )


def _policy_digest(policy: Mapping[str, Any]) -> str:
    """Hash the detached policy's canonical JSON representation."""
    serialized = json.dumps(
        policy,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _compile_validated_policy(
    policy: Mapping[str, Any],
    *,
    source: str,
    allow_legacy: bool,
) -> CompiledPolicy:
    """Project a schema-valid detached mapping onto the closed value objects."""
    del source  # Reserved for evidence provenance added by the enforcement route.
    roles = tuple(policy.get("roles", ()))
    tool_items = (policy.get("tools") or {}).get("allowed_tools", ())
    tools = tuple(
        CompiledToolLimit(name=item["name"], max_calls=item["max_calls"])
        for item in tool_items
    )

    raw_risk = policy.get("risk") or {}
    risk = compile_risk_policy(raw_risk)
    retry = _compile_retry_policy(policy.get("retry_policy"))

    guards = tuple(
        CompiledGuard(when=freeze(item["when"]), then=freeze(item["then"]))
        for item in policy.get("guards", ())
    )
    raw_preconditions = (policy.get("pre_conditions") or {}).get("required", {})
    preconditions = (
        tuple(
            compile_precondition(
                name,
                specification,
                path=f"$.pre_conditions.required.{name}",
            )
            for name, specification in sorted(raw_preconditions.items())
        )
        if isinstance(raw_preconditions, Mapping)
        else tuple(
            CompiledPrecondition(
                name=name,
                declared_type=None,
                legacy=True,
            )
            for name in raw_preconditions
            if allow_legacy
        )
    )
    output_schema = policy.get("output_schema")
    output_validator = (
        compile_output_schema(output_schema)
        if isinstance(output_schema, Mapping)
        else None
    )
    authority = AuthorityEnvelope(
        roles=frozenset(roles),
        tools=tools,
        risk_mode=risk.mode,
        risk_threshold=risk.threshold,
        critical_ceiling=risk.critical_ceiling,
        registered_fields=_REGISTERED_AUTHORITY_FIELDS,
    )
    return CompiledPolicy(
        policy_digest=_policy_digest(policy),
        policy_contract_version=POLICY_CONTRACT_VERSION,
        pattern_engine=PATTERN_ENGINE,
        canonicalization_profile=CANONICALIZATION_PROFILE,
        roles=roles,
        tools=tools,
        risk=risk,
        retry=retry,
        guards=guards,
        preconditions=preconditions,
        output_validator=output_validator,
        authority=authority,
    )


def compile_policy(
    raw_policy: Mapping[str, Any],
    *,
    source: str,
    allow_legacy: bool = False,
) -> CompiledPolicy:
    """Validate and compile a caller-detached immutable policy snapshot."""
    detached = copy.deepcopy(dict(raw_policy))
    _validate_security_numbers(detached)
    _validate_policy_schema(detached, allow_legacy=allow_legacy)
    return _compile_validated_policy(
        detached,
        source=source,
        allow_legacy=allow_legacy,
    )


def compile_precondition(
    name: str,
    specification: Mapping[str, Any],
    *,
    path: str,
) -> CompiledPrecondition:
    """Compile one structurally valid typed precondition."""
    declared_type = specification.get("type")
    string_keywords = ("pattern", "minLength", "maxLength")
    numeric_keywords = ("minimum", "maximum")

    for keyword in string_keywords:
        if keyword in specification and declared_type != "string":
            raise PolicyValidationError(
                f"{keyword} requires type 'string' at {path}",
                code="PRECONDITION_TYPE_REQUIRED",
                details={"path": f"{path}.{keyword}", "required_type": "string"},
            )
    for keyword in numeric_keywords:
        if (
            keyword in specification
            and declared_type not in ("number", "integer")
        ):
            raise PolicyValidationError(
                f"{keyword} requires type 'number' or 'integer' at {path}",
                code="PRECONDITION_TYPE_REQUIRED",
                details={
                    "path": f"{path}.{keyword}",
                    "required_type": ["number", "integer"],
                },
            )

    has_constraint = (
        declared_type not in (None, "any")
        or "enum" in specification
        or any(
            keyword in specification
            for keyword in string_keywords + numeric_keywords
        )
    )
    if not has_constraint:
        raise PolicyValidationError(
            f"Typed precondition has no semantic constraint at {path}",
            code="PRECONDITION_CONSTRAINT_REQUIRED",
            details={"path": path},
        )

    pattern = (
        compile_pattern(
            specification["pattern"],
            path=f"{path}.pattern",
        )
        if "pattern" in specification
        else None
    )
    enum = (
        tuple(freeze(value) for value in specification["enum"])
        if "enum" in specification
        else None
    )
    return CompiledPrecondition(
        name=name,
        declared_type=declared_type,
        pattern=pattern,
        enum=enum,
        min_length=specification.get("minLength"),
        max_length=specification.get("maxLength"),
        minimum=specification.get("minimum"),
        maximum=specification.get("maximum"),
    )
