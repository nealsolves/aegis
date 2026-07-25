#!/usr/bin/env python3
"""Deterministic local policy validation for the modular delivery template."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TECHNICAL_BLOCK_EXIT = 3


def _emit_technical_block(message: str) -> None:
    payload = {
        "valid": False,
        "state": "BLOCKED_TECHNICAL",
        "errors": [f"ERROR: BLOCKED_TECHNICAL: {message}"],
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _bootstrap_dependency_failure(dependency: str) -> None:
    _emit_technical_block(
        f"missing policy dependency {dependency}; install requirements-policy.txt"
    )
    raise SystemExit(TECHNICAL_BLOCK_EXIT)


try:
    import jsonschema
except ModuleNotFoundError:
    if __name__ == "__main__":
        _bootstrap_dependency_failure("jsonschema")
    raise

try:
    import yaml
except ModuleNotFoundError:
    if __name__ == "__main__":
        _bootstrap_dependency_failure("yaml (PyYAML)")
    raise

try:
    from referencing.exceptions import Unresolvable
except ModuleNotFoundError:
    if __name__ == "__main__":
        _bootstrap_dependency_failure("jsonschema dependency referencing")
    raise


CONTROL_FILES = {
    "project": ".claude/project.yaml",
    "routing": ".claude/routing.yaml",
    "policy": ".claude/policy.yaml",
    "lifecycle": ".claude/lifecycle.yaml",
}

SCHEMA_FILES = {
    "project": ".claude/schemas/project.schema.json",
    "routing": ".claude/schemas/routing.schema.json",
    "policy": ".claude/schemas/policy.schema.json",
    "context": ".claude/schemas/context.schema.json",
}

RISK_TIERS = ("low", "moderate", "high", "critical")
AUTHORITY_OUTCOMES = (
    "autonomous",
    "autonomous_with_enhanced_gates",
    "human_required",
    "prohibited",
)
MAX_SCHEMA_NODES = 100_000
MAX_SCHEMA_DEPTH = 512
INVALID_POINTER_ESCAPE = re.compile(r"~(?:[^01]|$)")


class PolicyInputError(ValueError):
    """A stable, user-actionable policy input error."""


class JsonArgumentParser(argparse.ArgumentParser):
    """Convert argparse failures into the CLI's single-JSON response contract."""

    def error(self, message: str) -> None:
        detail = message if message.startswith("argument ") else f"argument {message}"
        raise PolicyInputError(detail)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def canonical_hash(value: Any) -> str:
    """Return a stable SHA-256 digest for a JSON-compatible value."""

    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _error(message: str) -> str:
    return f"ERROR: {message}"


def _unresolved_reference(exc: Unresolvable) -> str:
    reference = str(getattr(exc, "ref", None) or exc)
    return f"#{reference}" if reference.startswith("/") else reference


def _read_text(path: Path, label: str) -> str:
    if not path.is_file():
        raise PolicyInputError(f"{label}: file does not exist: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PolicyInputError(f"{label}: cannot read {path}: {exc}") from exc


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = yaml.load(_read_text(path, label), Loader=UniqueKeyLoader)
    except RecursionError as exc:
        raise PolicyInputError(f"{label}: YAML nesting exceeds runtime limit") from exc
    except MemoryError as exc:
        raise PolicyInputError(f"{label}: YAML input exceeds memory limit") from exc
    except yaml.YAMLError as exc:
        detail = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise PolicyInputError(f"{label}: invalid YAML: {detail}") from exc
    if not isinstance(value, dict):
        raise PolicyInputError(f"{label}: YAML document must be an object")
    return value


def _json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PolicyInputError(f"schema: duplicate JSON key {key!r}")
        value[key] = item
    return value


def _load_schema(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_text(path, label), object_pairs_hook=_json_object_pairs
        )
    except RecursionError as exc:
        raise PolicyInputError(f"{label}: JSON nesting exceeds runtime limit") from exc
    except MemoryError as exc:
        raise PolicyInputError(f"{label}: JSON input exceeds memory limit") from exc
    except json.JSONDecodeError as exc:
        raise PolicyInputError(
            f"{label}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise PolicyInputError(f"{label}: JSON document must be an object")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_text(path, label), object_pairs_hook=_json_object_pairs
        )
    except json.JSONDecodeError as exc:
        raise PolicyInputError(
            f"{label}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise PolicyInputError(f"{label}: JSON document must be an object")
    return value


def load_control_plane(root: Path) -> dict[str, Any]:
    """Load the four controls and four schemas rooted at ``root``."""

    root = Path(root).resolve()
    if not root.is_dir():
        raise PolicyInputError(f"root directory does not exist: {root}")

    bundle: dict[str, Any] = {"root": root}
    for name, relative_path in CONTROL_FILES.items():
        bundle[name] = _load_yaml(root / relative_path, name)
    bundle["schemas"] = {
        name: _load_schema(root / relative_path, f"{name} schema")
        for name, relative_path in SCHEMA_FILES.items()
    }
    return bundle


def _json_path(parts: Iterable[Any]) -> str:
    path = ""
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += ("." if path else "") + str(part)
    return path


def _pointer_fragment(path: tuple[Any, ...]) -> str:
    if not path:
        return "#"
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in path]
    return "#/" + "/".join(encoded)


def _resolve_schema_ref(
    name: str, schema: dict[str, Any], reference: Any, location: str
) -> tuple[tuple[Any, ...], dict[str, Any] | bool]:
    label = f"{name} schema"
    if not isinstance(reference, str):
        raise PolicyInputError(f"{label}: $ref at {location} must be a string")
    if not reference.startswith("#"):
        raise PolicyInputError(
            f"{label}: unsupported non-local reference {reference!r} at {location}"
        )
    if reference != "#" and not reference.startswith("#/"):
        raise PolicyInputError(
            f"{label}: unsupported local non-pointer reference {reference!r} "
            f"at {location}"
        )
    if reference == "#":
        return (), schema

    current: Any = schema
    resolved_path: list[Any] = []
    for raw_token in reference[2:].split("/"):
        if INVALID_POINTER_ESCAPE.search(raw_token):
            raise PolicyInputError(
                f"{label}: invalid local JSON Pointer {reference!r} at {location}"
            )
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                break
            current = current[token]
            resolved_path.append(token)
            continue
        if isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                break
            item_index = int(token)
            if item_index >= len(current):
                break
            current = current[item_index]
            resolved_path.append(item_index)
            continue
        break
    else:
        if isinstance(current, (dict, bool)):
            return tuple(resolved_path), current
        raise PolicyInputError(
            f"{label}: local reference {reference} at {location} "
            "does not target a schema"
        )
    raise PolicyInputError(
        f"{label}: unresolved local reference {reference} at {location}"
    )


def _schema_reference_errors(name: str, schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    work: list[
        tuple[tuple[Any, ...], Any, tuple[tuple[Any, ...], ...]]
    ] = [((), schema, ())]
    visited_nodes = 0
    while work:
        path, value, active_targets = work.pop()
        visited_nodes += 1
        if (
            visited_nodes > MAX_SCHEMA_NODES
            or len(path) > MAX_SCHEMA_DEPTH
            or len(active_targets) > MAX_SCHEMA_DEPTH
        ):
            return [_error(f"{name} schema: validation resource limit exceeded")]

        if isinstance(value, dict) and "$ref" in value:
            reference = value["$ref"]
            location = _pointer_fragment(path + ("$ref",))
            try:
                target_path, target = _resolve_schema_ref(
                    name, schema, reference, location
                )
            except PolicyInputError as exc:
                errors.append(_error(str(exc)))
            else:
                if target_path in active_targets:
                    index = active_targets.index(target_path)
                    cycle = active_targets[index:] + (target_path,)
                    rendered = " -> ".join(
                        _pointer_fragment(item) for item in cycle
                    )
                    errors.append(
                        _error(f"{name} schema: reference cycle detected: {rendered}")
                    )
                    return sorted(set(errors))
                work.append((target_path, target, active_targets + (target_path,)))

        if isinstance(value, dict):
            for key, child in reversed(list(value.items())):
                if key != "$ref":
                    work.append((path + (key,), child, active_targets))
        elif isinstance(value, list):
            for index in range(len(value) - 1, -1, -1):
                work.append((path + (index,), value[index], active_targets))
    return sorted(set(errors))


def _schema_validation_errors(
    name: str, value: dict[str, Any], schema: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except (RecursionError, MemoryError):
        return [_error(f"{name} schema: validation resource limit exceeded")]
    except jsonschema.SchemaError as exc:
        return [_error(f"{name} schema: invalid Draft 2020-12 schema: {exc.message}")]

    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    try:
        validation_errors = sorted(
            validator.iter_errors(value),
            key=lambda item: tuple(str(p) for p in item.path),
        )
    except Unresolvable as exc:
        reference = _unresolved_reference(exc)
        return [_error(f"{name}: unresolved schema reference: {reference}")]
    except (RecursionError, MemoryError):
        return [_error(f"{name} schema: validation resource limit exceeded")]
    for validation_error in validation_errors:
        location = _json_path(validation_error.path)
        label = f"{name}.{location}" if location else name
        errors.append(_error(f"{label}: {validation_error.message}"))
    return errors


def _control_schema_errors(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    schemas = bundle["schemas"]
    reference_errors = {
        name: _schema_reference_errors(name, schema)
        for name, schema in schemas.items()
    }
    for schema_errors in reference_errors.values():
        errors.extend(schema_errors)
    for name in ("project", "routing", "policy"):
        if not reference_errors[name]:
            errors.extend(
                _schema_validation_errors(name, bundle[name], schemas[name])
            )

    if not reference_errors["policy"]:
        policy_schema = schemas["policy"]
        try:
            jsonschema.Draft202012Validator.check_schema(policy_schema)
            lifecycle_validator = jsonschema.Draft202012Validator(
                policy_schema, format_checker=jsonschema.FormatChecker()
            ).evolve(schema={"$ref": "#/$defs/lifecycle"})
            lifecycle_errors = sorted(
                lifecycle_validator.iter_errors(bundle["lifecycle"]),
                key=lambda item: tuple(str(p) for p in item.path),
            )
        except Unresolvable as exc:
            reference = _unresolved_reference(exc)
            errors.append(
                _error(f"lifecycle: unresolved schema reference: {reference}")
            )
            lifecycle_errors = []
        except (RecursionError, MemoryError):
            errors.append(_error("policy schema: validation resource limit exceeded"))
            lifecycle_errors = []
        except jsonschema.SchemaError as exc:
            errors.append(
                _error(
                    f"policy schema: invalid Draft 2020-12 schema: {exc.message}"
                )
            )
            lifecycle_errors = []
        for validation_error in lifecycle_errors:
            location = _json_path(validation_error.path)
            label = f"lifecycle.{location}" if location else "lifecycle"
            errors.append(_error(f"{label}: {validation_error.message}"))

    # The context schema is a contract even when no live context is supplied.
    if not reference_errors["context"]:
        try:
            jsonschema.Draft202012Validator.check_schema(schemas["context"])
        except (RecursionError, MemoryError):
            errors.append(_error("context schema: validation resource limit exceeded"))
        except jsonschema.SchemaError as exc:
            errors.append(
                _error(f"context schema: invalid Draft 2020-12 schema: {exc.message}")
            )
    return errors


def _routing_reference_errors(bundle: dict[str, Any]) -> list[str]:
    routing = bundle["routing"]
    policy = bundle["policy"]
    facts = routing.get("facts")
    routes = routing.get("routes")
    classification_rules = routing.get("classification_rules")
    overlay_rules = routing.get("overlay_rules")
    action_routes = routing.get("action_routes")
    if not isinstance(facts, dict) or not isinstance(routes, dict):
        return []

    errors: list[str] = []
    if isinstance(classification_rules, list):
        for index, rule in enumerate(classification_rules):
            if not isinstance(rule, dict):
                continue
            fact = rule.get("fact")
            if isinstance(fact, str) and fact not in facts:
                errors.append(
                    _error(
                        f"routing.classification_rules[{index}].fact: unknown fact {fact!r}"
                    )
                )
            additions = rule.get("add")
            if isinstance(additions, list):
                for route in additions:
                    if isinstance(route, str) and route not in routes:
                        errors.append(
                            _error(
                                f"routing.classification_rules[{index}].add: unknown route {route!r}"
                            )
                        )

    if isinstance(overlay_rules, list):
        for index, rule in enumerate(overlay_rules):
            if not isinstance(rule, dict):
                continue
            additions = rule.get("add")
            if isinstance(additions, list):
                for route in additions:
                    if isinstance(route, str) and route not in routes:
                        errors.append(
                            _error(
                                f"routing.overlay_rules[{index}].add: unknown route {route!r}"
                            )
                        )

    if isinstance(action_routes, dict):
        known_actions = policy.get("authority", {}).get("actions", {})
        if not isinstance(known_actions, dict):
            known_actions = {}
        for action, additions in action_routes.items():
            if action not in known_actions:
                errors.append(
                    _error(f"routing.action_routes: unknown action {action!r}")
                )
            if not isinstance(additions, list):
                continue
            for route in additions:
                if isinstance(route, str) and route not in routes:
                    errors.append(
                        _error(
                            f"routing.action_routes.{action}: unknown route {route!r}"
                        )
                    )

    risk = policy.get("risk")
    if isinstance(risk, dict):
        factor_names = risk.get("factors")
        if isinstance(factor_names, dict):
            for fact in factor_names:
                if fact not in facts:
                    errors.append(_error(f"policy.risk.factors: unknown fact {fact!r}"))
        automatic = risk.get("automatic_critical")
        if isinstance(automatic, list):
            for fact in automatic:
                if isinstance(fact, str) and fact not in facts:
                    errors.append(
                        _error(f"policy.risk.automatic_critical: unknown fact {fact!r}")
                    )
        escalation = risk.get("escalation")
        if isinstance(escalation, list):
            for index, rule in enumerate(escalation):
                if not isinstance(rule, dict):
                    continue
                for fact in rule.get("when_all", []):
                    if isinstance(fact, str) and fact not in facts:
                        errors.append(
                            _error(
                                f"policy.risk.escalation[{index}].when_all: unknown fact {fact!r}"
                            )
                        )
    authority = policy.get("authority")
    if isinstance(authority, dict):
        fact_outcomes = authority.get("fact_outcomes")
        if isinstance(fact_outcomes, dict):
            for fact in fact_outcomes:
                if fact not in facts:
                    errors.append(
                        _error(
                            f"policy.authority.fact_outcomes: unknown fact {fact!r}"
                        )
                    )
    return errors


def _markdown_reference_errors(bundle: dict[str, Any]) -> list[str]:
    routing = bundle["routing"]
    root = bundle["root"]
    references: list[str] = []

    always = routing.get("always")
    if isinstance(always, dict) and isinstance(always.get("rules"), list):
        references.extend(always["rules"])
    workflow_rules = routing.get("workflow_rules")
    if isinstance(workflow_rules, dict):
        references.extend(workflow_rules.values())
    routes = routing.get("routes")
    if isinstance(routes, dict):
        for route in routes.values():
            if not isinstance(route, dict):
                continue
            for key in ("rules", "workflows"):
                values = route.get(key)
                if isinstance(values, list):
                    references.extend(values)

    errors: list[str] = []
    seen: set[str] = set()
    instruction_system = bundle["project"].get("instruction_system", {})
    module_state = (
        instruction_system.get("module_state")
        if isinstance(instruction_system, dict)
        else None
    )
    for reference in references:
        if not isinstance(reference, str) or reference in seen:
            continue
        seen.add(reference)
        namespace = reference.partition("/")[0]
        namespace_root = root / ".claude" / namespace
        namespace_is_enforced = (
            module_state == "complete" or namespace_root.is_dir()
        )
        if namespace_is_enforced and not (root / ".claude" / reference).is_file():
            errors.append(
                _error(f"routing markdown path does not exist: .claude/{reference}")
            )
    return errors


def _profile_reference_errors(bundle: dict[str, Any]) -> list[str]:
    routing = bundle["routing"]
    project = bundle["project"]
    profile_paths = routing.get("profile_paths")
    if not isinstance(profile_paths, dict):
        return []
    base_paths = profile_paths.get("base")
    overlay_paths = profile_paths.get("overlays")
    if not isinstance(base_paths, dict) or not isinstance(overlay_paths, dict):
        return []

    errors: list[str] = []
    project_schema = bundle["schemas"]["project"]
    try:
        base_vocabulary = set(
            project_schema["properties"]["delivery"]["properties"][
                "base_profile"
            ]["enum"]
        )
    except (KeyError, TypeError):
        base_vocabulary = set()
    missing_base = sorted(base_vocabulary - set(base_paths))
    if missing_base:
        errors.append(
            _error(
                "routing.profile_paths.base: missing project base profiles: "
                + ", ".join(missing_base)
            )
        )

    delivery = project.get("delivery")
    if isinstance(delivery, dict):
        selected_base = delivery.get("base_profile")
        if isinstance(selected_base, str) and selected_base not in base_paths:
            errors.append(
                _error(
                    "project.delivery.base_profile: unknown or unmapped base "
                    f"profile {selected_base!r}"
                )
            )

    overlay_rules = routing.get("overlay_rules")
    overlay_rule_names: set[str] = set()
    if isinstance(overlay_rules, list):
        for index, rule in enumerate(overlay_rules):
            if not isinstance(rule, dict):
                continue
            overlay = rule.get("overlay")
            if not isinstance(overlay, str):
                continue
            overlay_rule_names.add(overlay)
            if overlay not in overlay_paths:
                errors.append(
                    _error(
                        f"routing.overlay_rules[{index}].overlay: missing "
                        f"profile mapping for {overlay!r}"
                    )
                )

    if isinstance(delivery, dict) and isinstance(delivery.get("overlays"), list):
        for overlay in delivery["overlays"]:
            if not isinstance(overlay, str):
                continue
            if overlay not in overlay_paths or overlay not in overlay_rule_names:
                errors.append(
                    _error(
                        "project.delivery.overlays: unknown or unmapped overlay "
                        f"{overlay!r}"
                    )
                )

    module_state = project.get("instruction_system", {}).get("module_state")
    namespace_root = bundle["root"] / ".claude/profiles"
    namespace_is_enforced = module_state == "complete" or namespace_root.is_dir()
    if namespace_is_enforced:
        references = list(base_paths.values()) + list(overlay_paths.values())
        seen: set[str] = set()
        for reference in references:
            if not isinstance(reference, str) or reference in seen:
                continue
            seen.add(reference)
            if not (bundle["root"] / ".claude" / reference).is_file():
                errors.append(
                    _error(
                        "routing profile path does not exist: "
                        f".claude/{reference}"
                    )
                )
    return errors


def _vocabulary_errors(bundle: dict[str, Any]) -> list[str]:
    context_properties = bundle["schemas"]["context"].get("properties")
    if not isinstance(context_properties, dict):
        return []

    comparisons = (
        (
            "workflow_family",
            bundle["routing"].get("workflow_rules"),
            context_properties.get("workflow_family"),
        ),
        (
            "action",
            bundle["policy"].get("authority", {}).get("actions"),
            context_properties.get("action"),
        ),
    )
    errors: list[str] = []
    for name, configured_mapping, schema_property in comparisons:
        if not isinstance(configured_mapping, dict) or not isinstance(
            schema_property, dict
        ):
            continue
        schema_values = schema_property.get("enum")
        if not isinstance(schema_values, list) or not all(
            isinstance(value, str) for value in schema_values
        ):
            continue
        configured = set(configured_mapping)
        declared = set(schema_values)
        configured_only = sorted(configured - declared)
        schema_only = sorted(declared - configured)
        if configured_only:
            errors.append(
                _error(
                    f"vocabulary.{name}: configured-only values: {', '.join(configured_only)}"
                )
            )
        if schema_only:
            errors.append(
                _error(
                    f"vocabulary.{name}: schema-only values: {', '.join(schema_only)}"
                )
            )
    return errors


def _is_not_applicable_project_value(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "not_applicable"


def _is_unresolved_project_value(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return True
    normalized = value.strip().casefold()
    return normalized == "unknown" or _is_not_applicable_project_value(value) or (
        normalized.startswith("<") and normalized.endswith(">")
    )


def _is_resolved_or_not_applicable(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    return _is_not_applicable_project_value(value) or not _is_unresolved_project_value(value)


def _parent_permission_errors(project: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    child_permissions = {
        "remote_actions": (
            "push_branch",
            "open_pull_request",
            "update_pull_request",
            "merge_pull_request",
            "create_release",
        ),
        "production_actions": ("deploy", "rollback"),
    }
    for section_name, children in child_permissions.items():
        section = project.get(section_name)
        if not isinstance(section, dict) or section.get("enabled") is not False:
            continue
        enabled_children = [name for name in children if section.get(name) is True]
        if enabled_children:
            errors.append(
                _error(
                    f"project.{section_name}: parent enabled: false conflicts "
                    "with enabled child permissions: " + ", ".join(enabled_children)
                )
            )
    return errors


def _configured_project_errors(bundle: dict[str, Any]) -> list[str]:
    """Reject configured authority whose permission-bearing inputs are unresolved."""

    project = bundle["project"]
    identity = project.get("project")
    if not isinstance(identity, dict) or identity.get("lifecycle") != "configured":
        return []

    delivery = project.get("delivery")
    delivery = delivery if isinstance(delivery, dict) else {}
    data = project.get("data")
    data = data if isinstance(data, dict) else {}
    remote = project.get("remote_actions")
    remote = remote if isinstance(remote, dict) else {}
    production = project.get("production_actions")
    production = production if isinstance(production, dict) else {}
    environments = project.get("environments")
    environments = environments if isinstance(environments, dict) else {}
    commands = project.get("commands")
    commands = commands if isinstance(commands, dict) else {}
    spec_kit = project.get("spec_kit")
    spec_kit = spec_kit if isinstance(spec_kit, dict) else {}

    errors = _parent_permission_errors(project)
    required_values = (
        ("project.project.name", identity.get("name")),
        ("project.project.repository", identity.get("repository")),
        ("project.delivery.owner", delivery.get("owner")),
        (
            "project.delivery.escalation_owner",
            delivery.get("escalation_owner"),
        ),
        (
            "project.remote_actions.repository",
            remote.get("repository"),
        ),
        (
            "project.data.regulated_data",
            data.get("regulated_data"),
        ),
        (
            "project.spec_kit.design_reference",
            spec_kit.get("design_reference"),
        ),
    )
    for label, value in required_values:
        if _is_unresolved_project_value(value):
            errors.append(_error(f"{label}: configured project value must be resolved"))

    for name in ("install", "test", "lint", "typecheck", "build", "release"):
        if not _is_resolved_or_not_applicable(commands.get(name)):
            errors.append(
                _error(
                    f"project.commands.{name}: configured project command must "
                    "be concrete or not_applicable"
                )
            )

    for name in ("tested_version", "minimum_version"):
        value = spec_kit.get(name)
        if spec_kit.get("enabled") is True:
            invalid = _is_unresolved_project_value(value)
            requirement = "must be concrete when Spec Kit is enabled"
        else:
            invalid = not _is_resolved_or_not_applicable(value)
            requirement = "must be concrete or not_applicable when Spec Kit is disabled"
        if invalid:
            errors.append(_error(f"project.spec_kit.{name}: {requirement}"))

    classifications = data.get("classifications")
    if not isinstance(classifications, list) or not classifications or any(
        _is_unresolved_project_value(value) for value in classifications
    ):
        errors.append(
            _error(
                "project.data.classifications: configured project data posture "
                "must contain resolved classifications"
            )
        )

    if remote.get("enabled") is True:
        repository = remote.get("repository")
        if _is_unresolved_project_value(repository):
            errors.append(
                _error(
                    "project.remote_actions.repository: enabled remote authority "
                    "requires a resolved repository"
                )
            )
        elif repository != identity.get("repository"):
            errors.append(
                _error(
                    "project.remote_actions.repository: must match "
                    "project.project.repository when remote authority is enabled"
                )
            )

    if (
        production.get("enabled") is True
        or production.get("deploy") is True
        or production.get("rollback") is True
    ):
        target = production.get("target")
        if _is_unresolved_project_value(target):
            errors.append(
                _error(
                    "project.production_actions.target: production authority "
                    "requires a resolved target"
                )
            )
        configured_environments = environments.get("configured")
        if not isinstance(configured_environments, list) or not configured_environments:
            errors.append(
                _error(
                    "project.environments.configured: production authority "
                    "requires at least one configured environment"
                )
            )
        elif (
            not _is_unresolved_project_value(target)
            and target not in configured_environments
        ):
            errors.append(
                _error(
                    "project.production_actions.target: target must name a "
                    "configured environment"
                )
            )
        if production.get("rollback") is not True:
            errors.append(
                _error(
                    "project.production_actions.rollback: production authority "
                    "requires rollback permission"
                )
            )
        for name in ("deploy_command", "rollback_command"):
            if _is_unresolved_project_value(production.get(name)):
                errors.append(
                    _error(
                        f"project.production_actions.{name}: production authority "
                        "requires a concrete mechanism"
                    )
                )
    return errors


def _project_safety_errors(bundle: dict[str, Any]) -> list[str]:
    """Reject inconsistent authority and unsafe configured/unconfigured projects."""

    project = bundle["project"]
    identity = project.get("project")
    if not isinstance(identity, dict):
        return []

    errors = _parent_permission_errors(project)
    if identity.get("lifecycle") == "configured":
        errors.extend(_configured_project_errors(bundle))
        return sorted(set(errors))
    if identity.get("lifecycle") != "unconfigured":
        return sorted(set(errors))

    guarded_sections = {
        "remote_actions": (
            "enabled",
            "push_branch",
            "open_pull_request",
            "update_pull_request",
            "merge_pull_request",
            "create_release",
        ),
        "production_actions": ("enabled", "deploy", "rollback"),
    }
    for section_name, permission_names in guarded_sections.items():
        section = project.get(section_name)
        if not isinstance(section, dict):
            continue
        enabled = [name for name in permission_names if section.get(name) is True]
        if enabled:
            errors.append(
                _error(
                    f"project.{section_name}: unconfigured repositories must "
                    "disable all authority-bearing actions; enabled: "
                    + ", ".join(enabled)
                )
            )
    return sorted(set(errors))


def _lifecycle_errors(bundle: dict[str, Any]) -> list[str]:
    lifecycle = bundle["lifecycle"]
    normal_states = lifecycle.get("normal_states")
    exceptional_states = lifecycle.get("exceptional_states")
    transitions = lifecycle.get("transitions")
    paths = lifecycle.get("paths")
    if not all(
        isinstance(item, expected)
        for item, expected in (
            (normal_states, list),
            (exceptional_states, list),
            (transitions, list),
            (paths, dict),
        )
    ):
        return []

    errors: list[str] = []
    declared_states = set(normal_states) | set(exceptional_states)
    edges: set[tuple[str, str]] = set()
    adjacency: dict[str, set[str]] = {state: set() for state in declared_states}
    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            continue
        source = transition.get("from")
        target = transition.get("to")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        edge = (source, target)
        if edge in edges:
            errors.append(
                _error(
                    f"lifecycle.transitions[{index}]: duplicate transition {source} -> {target}"
                )
            )
        edges.add(edge)
        if source not in declared_states:
            errors.append(
                _error(f"lifecycle.transitions[{index}].from: undeclared state {source}")
            )
        if target not in declared_states:
            errors.append(
                _error(f"lifecycle.transitions[{index}].to: undeclared state {target}")
            )
        adjacency.setdefault(source, set()).add(target)

    for path_name, states in paths.items():
        if not isinstance(states, list) or not states:
            continue
        if states[0] != "UNCLASSIFIED":
            errors.append(
                _error(f"lifecycle.paths.{path_name}: path must start at UNCLASSIFIED")
            )
        if states[-1] != "COMPLETE":
            errors.append(
                _error(f"lifecycle.paths.{path_name}: path must end at COMPLETE")
            )
        for source, target in zip(states, states[1:]):
            if (source, target) not in edges:
                errors.append(
                    _error(
                        f"lifecycle.paths.{path_name}: transition {source} -> {target} is not declared"
                    )
                )

    reachable: set[str] = set()
    queue: deque[str] = deque(["UNCLASSIFIED"])
    while queue:
        state = queue.popleft()
        if state in reachable:
            continue
        reachable.add(state)
        queue.extend(adjacency.get(state, set()) - reachable)
    for state in normal_states:
        if state not in reachable:
            errors.append(_error(f"lifecycle.normal_states: state {state} is unreachable"))

    reverse_adjacency: dict[str, set[str]] = {
        state: set() for state in declared_states
    }
    for source, target in edges:
        reverse_adjacency.setdefault(target, set()).add(source)
    can_complete: set[str] = set()
    queue = deque(["COMPLETE"])
    while queue:
        state = queue.popleft()
        if state in can_complete:
            continue
        can_complete.add(state)
        queue.extend(reverse_adjacency.get(state, set()) - can_complete)
    for state in normal_states:
        if state not in can_complete:
            errors.append(
                _error(
                    f"lifecycle.normal_states: state {state} cannot reach COMPLETE"
                )
            )
    return errors


def _resolve_context_path(root: Path, context_path: Path) -> Path:
    context_path = Path(context_path)
    return context_path if context_path.is_absolute() else root / context_path


def _context_errors(bundle: dict[str, Any], context_path: Path) -> list[str]:
    root = bundle["root"]
    context = _load_yaml(_resolve_context_path(root, context_path), "context")
    return _context_value_errors(bundle, context)


def _context_value_errors(
    bundle: dict[str, Any], context: dict[str, Any]
) -> list[str]:
    errors = _schema_validation_errors(
        "context", context, bundle["schemas"]["context"]
    )
    if errors:
        return errors

    routing = bundle["routing"]
    policy = bundle["policy"]
    lifecycle = bundle["lifecycle"]
    known_facts = set(routing["facts"])
    for fact in context["facts"]:
        if fact not in known_facts:
            errors.append(_error(f"context.facts: unknown fact {fact!r}"))
    workflow = context["workflow_family"]
    if workflow not in routing["workflow_rules"]:
        errors.append(
            _error(f"context.workflow_family: unknown workflow family {workflow!r}")
        )
    action = context["action"]
    if action not in policy["authority"]["actions"]:
        errors.append(_error(f"context.action: unknown authority action {action!r}"))
    states = set(lifecycle["normal_states"]) | set(lifecycle["exceptional_states"])
    if context["current_state"] not in states:
        errors.append(
            _error(f"context.current_state: undeclared state {context['current_state']!r}")
        )
    return errors


def validate_bundle(root: Path, context_path: Path | None) -> list[str]:
    """Validate configuration, references, lifecycle, and an optional context."""

    try:
        bundle = load_control_plane(Path(root))
        errors = _control_schema_errors(bundle)
        errors.extend(_routing_reference_errors(bundle))
        errors.extend(_markdown_reference_errors(bundle))
        errors.extend(_profile_reference_errors(bundle))
        errors.extend(_vocabulary_errors(bundle))
        errors.extend(_project_safety_errors(bundle))
        errors.extend(_lifecycle_errors(bundle))
        if context_path is not None:
            errors.extend(_context_errors(bundle, Path(context_path)))
        return sorted(set(errors))
    except PolicyInputError as exc:
        return [_error(str(exc))]
    except Unresolvable as exc:
        reference = _unresolved_reference(exc)
        return [_error(f"unresolved schema reference: {reference}")]
    except (RecursionError, MemoryError):
        return [_error("schema validation resource limit exceeded")]
    except (KeyError, TypeError, ValueError) as exc:
        # Malformed user data should remain a stable validation result, not a traceback.
        return [_error(f"invalid control-plane structure: {exc}")]


def _raise_evaluation_errors(errors: Iterable[str]) -> None:
    unique = sorted(set(errors))
    if unique:
        detail = "; ".join(
            error.removeprefix("ERROR: ") for error in unique
        )
        raise PolicyInputError(detail)


def _evaluation_configuration_errors(bundle: dict[str, Any]) -> list[str]:
    errors = _control_schema_errors(bundle)
    errors.extend(_routing_reference_errors(bundle))
    errors.extend(_profile_reference_errors(bundle))
    errors.extend(_vocabulary_errors(bundle))
    errors.extend(_project_safety_errors(bundle))
    errors.extend(_lifecycle_errors(bundle))
    return errors


def _resolve_evidence_reference(root: Path, source_ref: str, label: str) -> Path:
    reference = Path(source_ref)
    if reference.is_absolute():
        raise PolicyInputError(f"{label}: evidence reference must be root-relative")
    resolved_root = root.resolve()
    resolved = (resolved_root / reference).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise PolicyInputError(
            f"{label}: evidence reference escapes repository root: {source_ref}"
        ) from exc
    if not resolved.is_file():
        raise PolicyInputError(
            f"{label}: evidence file does not exist: {source_ref}"
        )
    return resolved


def _validated_fact_values(
    bundle: dict[str, Any], context: dict[str, Any]
) -> dict[str, bool | str]:
    root = Path(bundle["root"])
    catalog = bundle["routing"]["facts"]
    change_hash = context["change_hash"]
    values: dict[str, bool | str] = {}

    for fact_name, record in context["facts"].items():
        if fact_name not in catalog:
            raise PolicyInputError(f"context.facts: unknown fact {fact_name!r}")
        value = record["value"]
        values[fact_name] = value
        if record["observed_at_change"] != change_hash:
            raise PolicyInputError(
                f"context.facts.{fact_name}: stale evidence; observed_at_change "
                "does not match change_hash"
            )
        primary_path = _resolve_evidence_reference(
            root, record["source_ref"], f"context.facts.{fact_name}"
        )
        corroboration = record["corroboration"]
        independent_corroboration = False
        for index, source in enumerate(corroboration):
            if source["observed_at_change"] != change_hash:
                raise PolicyInputError(
                    f"context.facts.{fact_name}.corroboration[{index}]: stale "
                    "evidence; observed_at_change does not match change_hash"
                )
            corroboration_path = _resolve_evidence_reference(
                root,
                source["source_ref"],
                f"context.facts.{fact_name}.corroboration[{index}]",
            )
            if corroboration_path != primary_path:
                independent_corroboration = True

        definition = catalog[fact_name]
        if value == "unknown" and definition.get("material", False):
            raise PolicyInputError(
                f"context.facts: material fact {fact_name!r} is unknown"
            )
        if (
            value is False
            and definition.get("corroborate_when_false", False)
            and not independent_corroboration
        ):
            raise PolicyInputError(
                f"context.facts.{fact_name}: negative claim requires independent corroboration"
            )

    true_facts = {name for name, value in values.items() if value is True}
    if "documentation_only" in true_facts and len(true_facts) > 1:
        conflicting = ", ".join(sorted(true_facts - {"documentation_only"}))
        raise PolicyInputError(
            "context.facts.documentation_only contradicts true change facts: "
            f"{conflicting}"
        )
    return values


def _validate_lifecycle_evidence(
    bundle: dict[str, Any], context: dict[str, Any]
) -> None:
    root = Path(bundle["root"])
    for evidence_name, evidence in context["evidence"].items():
        _resolve_evidence_reference(
            root,
            evidence["source_ref"],
            f"context.evidence.{evidence_name}",
        )


def _append_unique(target: list[str], values: Iterable[str]) -> None:
    seen = set(target)
    for value in values:
        if value not in seen:
            target.append(value)
            seen.add(value)


def _evaluate_routing(
    bundle: dict[str, Any], context: dict[str, Any], fact_values: dict[str, Any]
) -> tuple[list[str], list[str], list[str]]:
    routing = bundle["routing"]
    classifications: list[str] = []
    for rule in routing["classification_rules"]:
        if fact_values.get(rule["fact"]) == rule["equals"]:
            _append_unique(classifications, rule["add"])
    active_overlays = set(bundle["project"]["delivery"]["overlays"])
    for rule in routing["overlay_rules"]:
        if rule["overlay"] in active_overlays:
            _append_unique(classifications, rule["add"])
    _append_unique(classifications, routing["action_routes"].get(context["action"], []))

    modules: list[str] = []
    _append_unique(modules, routing["always"]["rules"])
    workflows = [routing["workflow_rules"][context["workflow_family"]]]
    for classification in classifications:
        route = routing["routes"][classification]
        _append_unique(modules, route.get("rules", []))
        _append_unique(workflows, route.get("workflows", []))
    return classifications, modules, workflows


def _evaluate_profiles(bundle: dict[str, Any]) -> list[str]:
    delivery = bundle["project"]["delivery"]
    paths = bundle["routing"]["profile_paths"]
    profiles = [paths["base"][delivery["base_profile"]]]
    for overlay in delivery["overlays"]:
        _append_unique(profiles, [paths["overlays"][overlay]])
    return profiles


def _evaluate_risk(
    bundle: dict[str, Any], fact_values: dict[str, Any]
) -> dict[str, Any]:
    risk_policy = bundle["policy"]["risk"]
    tiers = RISK_TIERS
    tier_index = {tier: index for index, tier in enumerate(tiers)}
    inherent: list[dict[str, str]] = []
    current_index = 0
    for fact_name, tier in risk_policy["factors"].items():
        if fact_values.get(fact_name) is True:
            inherent.append({"fact": fact_name, "tier": tier})
            current_index = max(current_index, tier_index[tier])

    modifiers: list[dict[str, Any]] = []
    for rule in risk_policy["escalation"]:
        if all(fact_values.get(name) is True for name in rule["when_all"]):
            if "raise_by" in rule:
                amount = rule["raise_by"]
                current_index = min(len(tiers) - 1, current_index + amount)
                modifiers.append({"rule": rule["id"], "raise_by": amount})
            else:
                minimum = rule["minimum"]
                current_index = max(current_index, tier_index[minimum])
                modifiers.append({"rule": rule["id"], "minimum": minimum})

    critical_overrides = [
        fact_name
        for fact_name in risk_policy["automatic_critical"]
        if fact_values.get(fact_name) is True
    ]
    if critical_overrides:
        current_index = tier_index["critical"]
    return {
        "tier": tiers[current_index],
        "inherent_factors": inherent,
        "modifiers": modifiers,
        "critical_overrides": critical_overrides,
    }


def _policy_hash(bundle: dict[str, Any]) -> str:
    return canonical_hash(
        {
            "controls": {
                name: bundle[name]
                for name in ("project", "routing", "policy", "lifecycle")
            },
            "schemas": bundle["schemas"],
        }
    )


def _context_hash(context: dict[str, Any]) -> str:
    hash_input = copy.deepcopy(context)
    for generated_key in (
        "decision",
        "decisions",
        "evaluation",
    ):
        hash_input.pop(generated_key, None)
    evidence = hash_input.get("evidence")
    if isinstance(evidence, dict):
        for record in evidence.values():
            if isinstance(record, dict):
                record.pop("hashes", None)
    responses = hash_input.get("responses")
    if isinstance(responses, list):
        for response in responses:
            if isinstance(response, dict):
                response.pop("hashes", None)
    open_escalation = hash_input.get("open_escalation")
    if isinstance(open_escalation, dict):
        open_escalation.pop("hashes", None)
    return canonical_hash(hash_input)


def _decision_hashes(bundle: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    return {
        "policy_hash": _policy_hash(bundle),
        "context_hash": _context_hash(context),
        "change_hash": context["change_hash"],
    }


def _parse_expiration(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyInputError(f"{label}: invalid expiration timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyInputError(f"{label}: expiration timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def _evaluate_exceptions(
    bundle: dict[str, Any], context: dict[str, Any], now: datetime
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    results: list[dict[str, Any]] = []
    authority: list[dict[str, str]] = []
    policy = bundle["policy"]["exceptions"]
    current_time = now.astimezone(timezone.utc)
    for index, exception in enumerate(context["exceptions"]):
        exception_id = exception.get("id", f"exception-{index + 1}")
        tier = exception["tier"]
        exception_policy = policy[tier]
        expiration = _parse_expiration(
            exception["expires_at"], f"exception {exception_id}"
        )
        if expiration <= current_time:
            raise PolicyInputError(f"exception {exception_id} is expired")
        for required in exception_policy.get("required", []):
            if required not in exception:
                raise PolicyInputError(
                    f"exception {exception_id} is missing required field {required}"
                )
            if required.startswith("no_") and exception[required] is not True:
                raise PolicyInputError(
                    f"exception {exception_id} requires {required}=true"
                )
        max_days = exception_policy.get("max_duration_days")
        if max_days is not None and (expiration - current_time).total_seconds() > (
            max_days * 86400
        ):
            raise PolicyInputError(
                f"exception {exception_id} exceeds maximum duration of {max_days} days"
            )

        if not exception_policy["allowed"]:
            outcome = exception_policy.get("outcome", "prohibited")
        elif exception_policy["autonomous"]:
            outcome = "autonomous"
        else:
            outcome = exception_policy.get("outcome", "human_required")
        results.append(
            {
                "id": exception_id,
                "tier": tier,
                "status": "active",
                "expires_at": exception["expires_at"],
                "outcome": outcome,
            }
        )
        authority.append(
            {
                "source": "project",
                "outcome": outcome,
                "rule": f"risk_exception:{exception_id}",
            }
        )
    return results, authority


def _escalation_resume_state(
    bundle: dict[str, Any], context: dict[str, Any]
) -> str:
    normal_states = set(bundle["lifecycle"]["normal_states"])
    current_state = context["current_state"]
    if current_state in normal_states:
        return current_state
    if current_state == "HUMAN_DECISION_REQUIRED":
        packet = context.get("open_escalation")
        if isinstance(packet, dict) and packet.get("status") == "open":
            resume_state = packet.get("resume_state")
            if resume_state in normal_states:
                return resume_state
        raise PolicyInputError(
            "open_escalation.resume_state: an open human decision must preserve "
            "a declared normal resume state"
        )
    raise PolicyInputError(
        f"context.current_state: cannot generate a human decision packet from "
        f"{current_state}"
    )


def _material_escalation_packet(
    bundle: dict[str, Any],
    context: dict[str, Any],
    clarification: dict[str, Any],
    index: int,
    hashes: dict[str, str],
) -> dict[str, Any]:
    clarification_id = clarification.get("id", f"clarification-{index + 1}")
    options = copy.deepcopy(clarification["options"])
    option_ids = [option["id"] for option in options]
    if len(set(option_ids)) != len(option_ids):
        raise PolicyInputError(
            f"clarification {clarification_id}: option IDs must be unique"
        )
    recommended = clarification["recommended_option"]
    if recommended not in option_ids:
        raise PolicyInputError(
            f"clarification {clarification_id}: recommended_option {recommended!r} "
            "does not name a supplied option"
        )
    evidence = [record["source_ref"] for record in context["facts"].values()]
    return {
        "decision_id": f"DEC-{context['change_id']}-{clarification_id}",
        "decision": {
            "clarification_id": clarification_id,
            "question": clarification["question"],
        },
        "resume_state": _escalation_resume_state(bundle, context),
        "policy_trigger": "clarifications.material_business",
        "reason": "No deterministic repository evidence or bounded default can resolve this material business decision.",
        "evidence_collected": list(dict.fromkeys(evidence)),
        "options": options,
        "recommended_option": recommended,
        "required_response": [
            "decision_id",
            "selected_option",
            "decided_by",
            "authority_basis",
            "timestamp",
            "hashes",
        ],
        "hashes": hashes,
        "status": "open",
    }


def _authority_escalation_packet(
    bundle: dict[str, Any],
    context: dict[str, Any],
    authority: dict[str, Any],
    risk: dict[str, Any],
    hashes: dict[str, str],
) -> dict[str, Any]:
    human_rules = list(
        dict.fromkeys(
            item["rule"]
            for item in authority["applicable"]
            if item["outcome"] == "human_required"
        )
    )
    if not human_rules:
        raise PolicyInputError(
            "human_required authority outcome has no applicable human rule"
        )
    decision_id = f"DEC-{context['change_id']}-AUTH-{context['action']}"
    conditions = [
        f"change_id={context['change_id']}",
        f"action={context['action']}",
        "rules=" + ",".join(human_rules),
    ]
    evidence = [record["source_ref"] for record in context["facts"].values()]
    return {
        "decision_id": decision_id,
        "decision": {
            "kind": "authority",
            "action": context["action"],
            "risk_tier": risk["tier"],
            "rules": human_rules,
        },
        "resume_state": _escalation_resume_state(bundle, context),
        "policy_trigger": "authority." + authority["selected"]["rule"],
        "reason": (
            "Deterministic policy requires human authority for: "
            + ", ".join(human_rules)
        ),
        "evidence_collected": list(dict.fromkeys(evidence)),
        "options": [
            {
                "id": "authorize_once",
                "label": "Authorize once",
                "consequence": (
                    "Authorize only the listed rules for this action, policy, "
                    "context, and change; enhanced gates still apply."
                ),
                "outcome": "autonomous_with_enhanced_gates",
                "conditions": conditions,
            }
        ],
        "recommended_option": "authorize_once",
        "required_response": [
            "decision_id",
            "selected_option",
            "decided_by",
            "authority_basis",
            "timestamp",
            "hashes",
        ],
        "hashes": hashes,
        "status": "open",
    }


def _evaluate_clarifications(
    bundle: dict[str, Any], context: dict[str, Any], hashes: dict[str, str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    policy = bundle["policy"]["clarifications"]
    results: list[dict[str, Any]] = []
    escalations: list[dict[str, Any]] = []
    for index, clarification in enumerate(context["clarifications"]):
        clarification_id = clarification.get("id", f"clarification-{index + 1}")
        kind = clarification["class"]
        action = policy[kind]
        record: dict[str, Any] = {
            "id": clarification_id,
            "class": kind,
            "action": action,
        }
        if kind == "inferable":
            if "resolution" not in clarification or "source_ref" not in clarification:
                raise PolicyInputError(
                    f"clarification {clarification_id}: inferable resolution and source_ref are required"
                )
            _resolve_evidence_reference(
                Path(bundle["root"]),
                clarification["source_ref"],
                f"clarification {clarification_id}",
            )
            record.update(
                {
                    "status": "resolved",
                    "resolution": clarification["resolution"],
                    "source_ref": clarification["source_ref"],
                }
            )
        elif kind == "reversible_default":
            if "configured_default" not in clarification or "reversal_path" not in clarification:
                raise PolicyInputError(
                    f"clarification {clarification_id}: configured_default and reversal_path are required"
                )
            record.update(
                {
                    "status": "default_applied",
                    "resolution": clarification["configured_default"],
                    "reversal_path": clarification["reversal_path"],
                }
            )
        else:
            packet = _material_escalation_packet(
                bundle, context, clarification, index, hashes
            )
            if "resolution" in clarification:
                option_ids = [option["id"] for option in packet["options"]]
                if clarification["resolution"] not in option_ids:
                    raise PolicyInputError(
                        f"clarification {clarification_id}: resolution does not name "
                        "a supplied option"
                    )
                record.update(
                    {
                        "status": "resolved",
                        "resolution": clarification["resolution"],
                    }
                )
            else:
                escalations.append(packet)
                record.update(
                    {
                        "status": "human_decision_required",
                        "decision_id": packet["decision_id"],
                    }
                )
        results.append(record)
    return results, escalations


def _evaluate_resources(
    bundle: dict[str, Any], context: dict[str, Any]
) -> dict[str, Any]:
    usage = context["resources"]
    limits = bundle["policy"]["resources"]
    exhausted: list[str] = []
    if usage["repair_attempts"] >= limits["max_repair_cycles"]:
        exhausted.append("repair_attempts")
    if usage["ci_reruns"] >= limits["max_ci_reruns_per_change"]:
        exhausted.append("ci_reruns")
    if usage.get("elapsed_minutes", 0) >= limits["max_elapsed_minutes"]:
        exhausted.append("elapsed_minutes")
    return {"usage": copy.deepcopy(usage), "limits": copy.deepcopy(limits), "exhausted": exhausted}


def _project_authority_outcomes(
    bundle: dict[str, Any], context: dict[str, Any]
) -> list[dict[str, str]]:
    project = bundle["project"]
    action = context["action"]
    outcomes: list[dict[str, str]] = []
    remote_actions = {
        "push_branch",
        "open_pull_request",
        "update_pull_request",
        "merge_pull_request",
        "create_release",
    }
    unconfigured = project["project"]["lifecycle"] == "unconfigured"
    if action in remote_actions:
        remote = project["remote_actions"]
        if unconfigured:
            outcomes.append(
                {
                    "source": "project",
                    "outcome": "prohibited",
                    "rule": "unconfigured_remote_actions_disabled",
                }
            )
        if not remote["enabled"] or not remote[action]:
            outcomes.append(
                {
                    "source": "project",
                    "outcome": "prohibited",
                    "rule": "remote_actions_disabled",
                }
            )
        if action == "create_release" and _is_not_applicable_project_value(
            project["commands"]["release"]
        ):
            outcomes.append(
                {
                    "source": "project",
                    "outcome": "prohibited",
                    "rule": "release_command_not_applicable",
                }
            )
    if action == "deploy_production":
        production = project["production_actions"]
        if unconfigured:
            outcomes.append(
                {
                    "source": "project",
                    "outcome": "prohibited",
                    "rule": "unconfigured_production_actions_disabled",
                }
            )
        if not production["enabled"] or not production["deploy"]:
            outcomes.append(
                {
                    "source": "project",
                    "outcome": "prohibited",
                    "rule": "production_actions_disabled",
                }
            )
    if action == "risk_exception" and unconfigured:
        outcomes.append(
            {
                "source": "project",
                "outcome": "prohibited",
                "rule": "unconfigured_risk_exceptions_disabled",
            }
        )
    elif context["exceptions"] and unconfigured:
        outcomes.append(
            {
                "source": "project",
                "outcome": "prohibited",
                "rule": "unconfigured_risk_exceptions_disabled",
            }
        )
    return outcomes


def _valid_authority_approval(
    bundle: dict[str, Any],
    context: dict[str, Any],
    constraint: dict[str, Any],
) -> bool:
    approval = constraint.get("approval")
    if not isinstance(approval, dict):
        return False
    if (
        constraint.get("source") != "constitution"
        or constraint.get("action") != context["action"]
        or constraint.get("outcome") != "autonomous_with_enhanced_gates"
    ):
        return False

    decision_id = approval.get("decision_id")
    packet = context.get("open_escalation")
    if (
        not isinstance(packet, dict)
        or packet.get("decision_id") != decision_id
        or packet.get("status") != "resolved"
        or packet.get("decision", {}).get("kind") != "authority"
        or packet.get("decision", {}).get("action") != context["action"]
    ):
        return False
    approved_rules = approval.get("rules")
    packet_rules = packet.get("decision", {}).get("rules")
    if not isinstance(approved_rules, list) or approved_rules != packet_rules:
        return False

    matching_constraints = [
        item
        for item in context["authority_constraints"]
        if item.get("approval", {}).get("decision_id") == decision_id
    ]
    matching_responses = [
        item for item in context["responses"] if item.get("decision_id") == decision_id
    ]
    if len(matching_constraints) != 1 or len(matching_responses) != 1:
        return False
    response = matching_responses[0]
    hashes = approval.get("hashes")
    if (
        not isinstance(hashes, dict)
        or hashes != response.get("hashes")
        or hashes != packet.get("hashes")
        or response.get("selected_option") != "authorize_once"
        or hashes.get("policy_hash") != _policy_hash(bundle)
        or hashes.get("change_hash") != context["change_hash"]
    ):
        return False

    reconstructed = copy.deepcopy(context)
    reconstructed["authority_constraints"] = [
        item
        for item in reconstructed["authority_constraints"]
        if item.get("approval", {}).get("decision_id") != decision_id
    ]
    reconstructed["responses"] = [
        item for item in reconstructed["responses"] if item.get("decision_id") != decision_id
    ]
    reconstructed_packet = copy.deepcopy(packet)
    reconstructed_packet["status"] = "open"
    reconstructed["open_escalation"] = reconstructed_packet
    reconstructed["current_state"] = "HUMAN_DECISION_REQUIRED"
    return _context_hash(reconstructed) == hashes.get("context_hash")


def _evaluate_authority(
    bundle: dict[str, Any], context: dict[str, Any], risk: dict[str, Any],
    clarification_escalations: list[dict[str, Any]],
    exception_outcomes: list[dict[str, str]], resources: dict[str, Any],
    fact_values: dict[str, Any]
) -> dict[str, Any]:
    authority_policy = bundle["policy"]["authority"]
    action = context["action"]
    applicable: list[dict[str, str]] = [
        {
            "source": "workflow",
            "outcome": authority_policy["actions"][action][risk["tier"]],
            "rule": f"action_matrix:{action}:{risk['tier']}",
        }
    ]
    applicable.extend(_project_authority_outcomes(bundle, context))
    for fact_name, outcome in authority_policy["fact_outcomes"].items():
        if fact_values.get(fact_name) is True:
            applicable.append(
                {
                    "source": "constitution",
                    "outcome": outcome,
                    "rule": f"fact_outcome:{fact_name}",
                }
            )
    valid_approvals: list[dict[str, Any]] = []
    for constraint in context["authority_constraints"]:
        if constraint.get("action") not in (None, action):
            continue
        if _valid_authority_approval(bundle, context, constraint):
            valid_approvals.append(constraint)
            continue
        item = {
            "source": constraint["source"],
            "outcome": constraint["outcome"],
            "rule": constraint.get("rule", "context_authority_constraint"),
        }
        if "reason" in constraint:
            item["reason"] = constraint["reason"]
        applicable.append(item)
    applicable.extend(exception_outcomes)
    if clarification_escalations:
        applicable.append(
            {
                "source": "constitution",
                "outcome": "human_required",
                "rule": "material_business_clarification",
            }
        )
    if resources["exhausted"]:
        applicable.append(
            {
                "source": "constitution",
                "outcome": "human_required",
                "rule": "resource_limit_exhausted",
            }
        )
    if (
        fact_values.get("instruction_system_change") is True
        and bundle["project"]["instruction_system"]["module_state"] != "bootstrapping"
    ):
        applicable.append(
            {
                "source": "constitution",
                "outcome": "human_required",
                "rule": "post_bootstrap_instruction_system_change",
            }
        )

    for approval_constraint in valid_approvals:
        approved_rules = set(approval_constraint["approval"]["rules"])
        applicable = [
            item
            for item in applicable
            if not (
                item["outcome"] == "human_required"
                and item["rule"] in approved_rules
            )
        ]
        applicable.append(
            {
                "source": "constitution",
                "outcome": "autonomous_with_enhanced_gates",
                "rule": approval_constraint["rule"],
                "reason": approval_constraint["reason"],
            }
        )

    outcomes = AUTHORITY_OUTCOMES
    outcome_rank = {outcome: index for index, outcome in enumerate(outcomes)}
    precedence = authority_policy["source_precedence"]
    source_rank = {
        source: len(precedence) - index for index, source in enumerate(precedence)
    }
    selected = max(
        applicable,
        key=lambda item: (
            outcome_rank[item["outcome"]],
            source_rank[item["source"]],
        ),
    )
    return {
        "action": action,
        "outcome": selected["outcome"],
        "selected": copy.deepcopy(selected),
        "applicable": applicable,
    }


def evaluate(
    bundle: dict[str, Any], context: dict[str, Any], *, now: datetime | None = None
) -> dict[str, Any]:
    """Evaluate one validated context into a deterministic decision record."""

    try:
        _raise_evaluation_errors(_evaluation_configuration_errors(bundle))
        _raise_evaluation_errors(_context_value_errors(bundle, context))
        fact_values = _validated_fact_values(bundle, context)
        _validate_lifecycle_evidence(bundle, context)
        classifications, modules, workflows = _evaluate_routing(
            bundle, context, fact_values
        )
        profiles = _evaluate_profiles(bundle)
        risk = _evaluate_risk(bundle, fact_values)
        hashes = _decision_hashes(bundle, context)
        clarifications, escalations = _evaluate_clarifications(
            bundle, context, hashes
        )
        exceptions, exception_authority = _evaluate_exceptions(
            bundle, context, now or datetime.now(timezone.utc)
        )
        resources = _evaluate_resources(bundle, context)
        authority = _evaluate_authority(
            bundle,
            context,
            risk,
            escalations,
            exception_authority,
            resources,
            fact_values,
        )
        if authority["outcome"] == "human_required" and not escalations:
            escalations = [
                _authority_escalation_packet(
                    bundle, context, authority, risk, hashes
                )
            ]
        return {
            "valid": True,
            "change_id": context["change_id"],
            "classifications": classifications,
            "profiles": profiles,
            "modules": modules,
            "workflows": workflows,
            "risk": risk,
            "authority": authority,
            "clarifications": clarifications,
            "exceptions": exceptions,
            "resources": resources,
            "escalations": escalations,
            "hashes": hashes,
        }
    except PolicyInputError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyInputError(f"invalid evaluation input: {exc}") from exc


def _require_fresh_hashes(
    label: str, supplied: Any, current: dict[str, str]
) -> None:
    if not isinstance(supplied, dict):
        raise PolicyInputError(f"{label}: hashes must be an object")
    for key in ("policy_hash", "context_hash", "change_hash"):
        if supplied.get(key) != current[key]:
            raise PolicyInputError(f"{label}.{key}: stale decision hash")


def _lifecycle_path_name(context: dict[str, Any]) -> str:
    facts = context.get("facts", {})
    deploys = facts.get("deploys_to_production", {})
    if context["action"] == "deploy_production" or deploys.get("value") is True:
        return "deployment"
    if context["action"] == "create_release" or context["workflow_family"] == "release":
        return "release"
    if context["action"] == "instruction_system_change":
        return "code"
    if context["workflow_family"] == "maintenance":
        return "maintenance"
    return "code"


def transition(
    bundle: dict[str, Any],
    context: dict[str, Any],
    decision: dict[str, Any],
    target_state: str,
) -> dict[str, Any]:
    """Authorize one declared lifecycle edge using current evidence and hashes."""

    try:
        current = evaluate(bundle, context)
        _require_fresh_hashes("decision.hashes", decision.get("hashes"), current["hashes"])
        authority_outcome = current["authority"]["outcome"]
        if authority_outcome not in (
            "autonomous",
            "autonomous_with_enhanced_gates",
        ):
            raise PolicyInputError(
                f"current action authority is {authority_outcome}; a fresh permitted "
                "authority decision is required before transition"
            )

        source_state = context["current_state"]
        path_name = _lifecycle_path_name(context)
        path = bundle["lifecycle"]["paths"][path_name]
        active_edges = set(zip(path, path[1:]))
        if (source_state, target_state) not in active_edges:
            raise PolicyInputError(
                f"transition {source_state} -> {target_state} is not on the active "
                f"{path_name} path"
            )

        matches = [
            item
            for item in bundle["lifecycle"]["transitions"]
            if item["from"] == source_state and item["to"] == target_state
        ]
        if len(matches) != 1:
            raise PolicyInputError(
                f"transition {source_state} -> {target_state} must match exactly "
                f"one declaration; found {len(matches)}"
            )

        required = matches[0]["requires"]
        for evidence_name in required:
            evidence = context["evidence"].get(evidence_name)
            if evidence is None:
                raise PolicyInputError(
                    f"transition evidence {evidence_name}: required evidence is missing"
                )
            if evidence.get("satisfied") is not True:
                raise PolicyInputError(
                    f"transition evidence {evidence_name}: evidence is not satisfied"
                )
            _resolve_evidence_reference(
                Path(bundle["root"]),
                evidence["source_ref"],
                f"transition evidence {evidence_name}",
            )
            _require_fresh_hashes(
                f"transition evidence {evidence_name}.hashes",
                evidence.get("hashes"),
                current["hashes"],
            )

        updated_context = copy.deepcopy(context)
        updated_context["current_state"] = target_state
        result = evaluate(bundle, updated_context)
        result.update(
            {
                "previous_state": source_state,
                "current_state": target_state,
                "context": updated_context,
                "transition": {
                    "from": source_state,
                    "to": target_state,
                    "workflow_path": path_name,
                    "required_evidence": copy.deepcopy(required),
                    "authorized_by_hashes": copy.deepcopy(current["hashes"]),
                },
            }
        )
        return result
    except PolicyInputError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyInputError(f"invalid transition input: {exc}") from exc


def _response_schema_errors(
    bundle: dict[str, Any], response: dict[str, Any]
) -> list[str]:
    schema = bundle["schemas"]["context"]
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).evolve(schema={"$ref": "#/$defs/response"})
    try:
        errors = sorted(
            validator.iter_errors(response),
            key=lambda item: tuple(str(part) for part in item.path),
        )
    except Unresolvable as exc:
        return [_error(f"response: unresolved schema reference: {_unresolved_reference(exc)}")]
    return [
        _error(
            f"response.{_json_path(error.path)}: {error.message}"
            if error.path
            else f"response: {error.message}"
        )
        for error in errors
    ]


def respond(
    bundle: dict[str, Any],
    context: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    """Apply one bounded human response to a copy and reevaluate it."""

    try:
        _raise_evaluation_errors(_evaluation_configuration_errors(bundle))
        _raise_evaluation_errors(_context_value_errors(bundle, context))
        _raise_evaluation_errors(_response_schema_errors(bundle, response))
        if context["current_state"] != "HUMAN_DECISION_REQUIRED":
            raise PolicyInputError(
                "context.current_state: response requires HUMAN_DECISION_REQUIRED"
            )
        recovery = bundle["lifecycle"]["recoveries"].get(
            "HUMAN_DECISION_REQUIRED"
        )
        if recovery != "validated_response":
            raise PolicyInputError(
                "lifecycle recovery for HUMAN_DECISION_REQUIRED must be "
                "validated_response"
            )

        packet = context.get("open_escalation")
        if not isinstance(packet, dict) or packet.get("status") != "open":
            raise PolicyInputError("open_escalation: exactly one open packet is required")
        resume_state = packet.get("resume_state")
        if resume_state not in set(bundle["lifecycle"]["normal_states"]):
            raise PolicyInputError(
                "open_escalation.resume_state: must be a declared normal state"
            )
        current = evaluate(bundle, context)
        if response["decision_id"] != packet.get("decision_id"):
            raise PolicyInputError("response.decision_id: does not match the open packet")
        _require_fresh_hashes("open_escalation.hashes", packet.get("hashes"), current["hashes"])
        _require_fresh_hashes("response.hashes", response.get("hashes"), current["hashes"])

        matching_packets = [
            item
            for item in current["escalations"]
            if item["decision_id"] == response["decision_id"]
        ]
        if len(matching_packets) != 1 or packet != matching_packets[0]:
            raise PolicyInputError(
                "open_escalation: packet does not match exactly one current decision"
            )
        path_name = _lifecycle_path_name(context)
        if resume_state == "COMPLETE":
            raise PolicyInputError(
                "open_escalation.resume_state: terminal state COMPLETE cannot be resumed"
            )
        if resume_state not in bundle["lifecycle"]["paths"][path_name]:
            raise PolicyInputError(
                f"open_escalation.resume_state: {resume_state} is not on the active "
                f"{path_name} path"
            )
        if current["authority"]["outcome"] == "prohibited":
            raise PolicyInputError("current action is prohibited")

        options = [
            option
            for option in packet["options"]
            if option["id"] == response["selected_option"]
        ]
        if len(options) != 1:
            raise PolicyInputError(
                "response.selected_option: does not match exactly one packet option"
            )
        option = options[0]
        if option.get("outcome") == "prohibited":
            raise PolicyInputError("response.selected_option: prohibited outcome")
        selected_conditions = copy.deepcopy(option.get("conditions", []))
        if "conditions" in response and response["conditions"] != selected_conditions:
            raise PolicyInputError(
                "response.conditions: must match the selected option conditions"
            )

        updated_context = copy.deepcopy(context)
        decision = packet["decision"]
        clarification_id = decision.get("clarification_id")
        decision_kind = decision.get("kind")
        if clarification_id is not None:
            clarifications = [
                item
                for index, item in enumerate(updated_context["clarifications"])
                if item.get("id", f"clarification-{index + 1}") == clarification_id
            ]
            if len(clarifications) != 1:
                raise PolicyInputError(
                    "open_escalation.decision: clarification must match exactly "
                    "one context item"
                )
            clarifications[0]["resolution"] = option["id"]
        elif decision_kind == "authority":
            rules = decision.get("rules")
            if (
                decision.get("action") != updated_context["action"]
                or not isinstance(rules, list)
                or not rules
                or option["id"] != "authorize_once"
            ):
                raise PolicyInputError(
                    "open_escalation.decision: authority packet scope is invalid"
                )
        else:
            raise PolicyInputError(
                "open_escalation.decision: unsupported decision kind"
            )

        recorded_response = copy.deepcopy(response)
        recorded_response["conditions"] = selected_conditions
        updated_context["responses"].append(recorded_response)
        resolved_packet = copy.deepcopy(packet)
        resolved_packet["status"] = "resolved"
        updated_context["open_escalation"] = resolved_packet
        updated_context["current_state"] = resume_state

        outcome = option.get("outcome")
        if outcome is not None:
            reason = f"Human response selected {option['id']} for {packet['decision_id']}."
            if selected_conditions:
                reason += " Conditions: " + ", ".join(selected_conditions)
            constraint: dict[str, Any] = {
                "source": "constitution",
                "action": updated_context["action"],
                "outcome": outcome,
                "rule": f"human_response:{packet['decision_id']}:{option['id']}",
                "reason": reason,
            }
            if decision_kind == "authority":
                constraint["approval"] = {
                    "decision_id": packet["decision_id"],
                    "rules": copy.deepcopy(decision["rules"]),
                    "hashes": copy.deepcopy(response["hashes"]),
                }
            updated_context["authority_constraints"].append(constraint)

        reevaluated = evaluate(bundle, updated_context)
        return {
            "valid": True,
            "response": recorded_response,
            "resolved_escalation": resolved_packet,
            "context": updated_context,
            "decision": reevaluated,
        }
    except PolicyInputError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PolicyInputError(f"invalid response input: {exc}") from exc


def _build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate_parser = commands.add_parser("validate", help="validate policy files")
    validate_parser.add_argument("--root", required=True, type=Path)
    validate_parser.add_argument("--context", type=Path)
    evaluate_parser = commands.add_parser(
        "evaluate", help="evaluate routing, risk, and authority"
    )
    evaluate_parser.add_argument("--root", required=True, type=Path)
    evaluate_parser.add_argument("--context", required=True, type=Path)
    evaluate_parser.add_argument("--output", type=Path)
    transition_parser = commands.add_parser(
        "transition", help="authorize one lifecycle transition"
    )
    transition_parser.add_argument("--root", required=True, type=Path)
    transition_parser.add_argument("--context", required=True, type=Path)
    transition_parser.add_argument("--decision", required=True, type=Path)
    transition_parser.add_argument("--to", required=True)
    transition_parser.add_argument("--output", type=Path)
    respond_parser = commands.add_parser(
        "respond", help="apply a bounded human decision response"
    )
    respond_parser.add_argument("--root", required=True, type=Path)
    respond_parser.add_argument("--context", required=True, type=Path)
    respond_parser.add_argument("--response", required=True, type=Path)
    respond_parser.add_argument("--output", type=Path)
    return parser


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")


def _write_decision(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.write_text(
            json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, UnicodeError) as exc:
        raise PolicyInputError(f"cannot write output {path}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _build_parser().parse_args(argv)
        if arguments.command == "validate":
            errors = validate_bundle(arguments.root, arguments.context)
            payload = {"valid": not errors, "errors": errors}
            _emit(payload)
            return 0 if not errors else 1

        bundle = load_control_plane(arguments.root)
        context_path = _resolve_context_path(bundle["root"], arguments.context)
        context = _load_yaml(context_path, "context")
        if arguments.command == "evaluate":
            payload = evaluate(bundle, context)
        elif arguments.command == "transition":
            decision = _load_json(arguments.decision, "decision")
            payload = transition(bundle, context, decision, arguments.to)
        else:
            response = _load_yaml(arguments.response, "response")
            payload = respond(bundle, context, response)
        if arguments.output is None:
            _emit(payload)
        else:
            _write_decision(arguments.output, payload)
            sys.stdout.write(f"{arguments.output}\n")
        return 0
    except PolicyInputError as exc:
        _emit({"valid": False, "errors": [_error(str(exc))]})
        return 1
    except (RecursionError, MemoryError):
        _emit_technical_block("runtime resource limit exceeded while processing CLI input")
        return TECHNICAL_BLOCK_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
