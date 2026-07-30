"""Compile schema-valid policy mappings into immutable authorization values."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft7Validator

from aegis._internal.compiled_policy import (
    AuthorityEnvelope,
    CompiledGuard,
    CompiledOutputValidator,
    CompiledPolicy,
    CompiledPrecondition,
    CompiledRiskPolicy,
    CompiledToolLimit,
    freeze,
)
from aegis._internal.errors import PolicyLoadError, PolicyValidationError


POLICY_CONTRACT_VERSION = "2.0"
PATTERN_ENGINE = "google-re2"
CANONICALIZATION_PROFILE = "aegis-json-v2"
CRITICAL_RISK_CEILING = 0.90
_SCHEMA_DRAFT_07 = "http://json-schema.org/draft-07/schema#"
_POLICY_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "policy_dsl.schema.json"
_REGISTERED_AUTHORITY_FIELDS = frozenset(
    {"roles", "tools", "risk", "guards", "pre_conditions", "output_schema"}
)


def _path_to_pointer(path: list[Any]) -> str:
    return "$" if not path else "$." + ".".join(str(part) for part in path)


def _validate_policy_schema(policy: Mapping[str, Any], *, allow_legacy: bool) -> None:
    """Validate the detached mapping against the packaged Draft 7 policy schema."""
    del allow_legacy  # Later compiler stages apply explicit legacy semantics.
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
    policy: Mapping[str, Any], *, source: str
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
    risk = CompiledRiskPolicy(
        mode=raw_risk.get("mode", "strict"),
        threshold=float(raw_risk.get("threshold", CRITICAL_RISK_CEILING)),
        critical_ceiling=CRITICAL_RISK_CEILING,
    )

    guards = tuple(
        CompiledGuard(when=freeze(item["when"]), then=freeze(item["then"]))
        for item in policy.get("guards", ())
    )
    raw_preconditions = (policy.get("pre_conditions") or {}).get("required", {})
    preconditions = (
        tuple(
            CompiledPrecondition(name=name, specification=freeze(specification))
            for name, specification in raw_preconditions.items()
        )
        if isinstance(raw_preconditions, Mapping)
        else tuple(
            CompiledPrecondition(name=name, specification=True)
            for name in raw_preconditions
        )
    )
    output_schema = policy.get("output_schema")
    output_validator = (
        CompiledOutputValidator(schema=freeze(output_schema))
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
    _validate_policy_schema(detached, allow_legacy=allow_legacy)
    return _compile_validated_policy(detached, source=source)
