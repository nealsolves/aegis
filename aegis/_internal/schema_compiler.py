"""Safe, detached Draft 7 output-schema compilation."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from threading import RLock
from typing import Any, Iterator, Mapping
from urllib.parse import unquote

from jsonschema import Draft7Validator, SchemaError, ValidationError, validators
from referencing import Registry
from referencing.exceptions import Unresolvable

from aegis._internal.compiled_policy import (
    CompiledOutputValidator,
    freeze,
)
from aegis._internal.errors import (
    AIGCError,
    PolicyValidationError,
    SchemaValidationError,
)
from aegis._internal.patterns import (
    CompiledPattern,
    PatternInputTooLargeError,
    compile_pattern,
    verify_pattern_runtime,
)


_SCHEMA_DRAFT_07 = "http://json-schema.org/draft-07/schema#"
_SINGLE_SCHEMA_KEYWORDS = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "else",
        "if",
        "not",
        "propertyNames",
        "then",
    }
)
_SCHEMA_ARRAY_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf"})
_SCHEMA_MAPPING_KEYWORDS = frozenset(
    {"definitions", "dependencies", "patternProperties", "properties"}
)
_PROGRAM_DIGEST_DOMAIN = b"aegis.output-validation-program.v1\x00"
_RUNTIME_CACHE_MAX_ENTRIES = 256
_UNRESOLVED_POINTER = object()
_ACTIVE_PATTERNS: ContextVar[Mapping[str, CompiledPattern] | None] = ContextVar(
    "aegis_output_schema_patterns",
    default=None,
)


@dataclass(slots=True)
class _ValidationRuntime:
    """Private mutable runtime derived from one immutable program."""

    program_bytes: bytes
    validator: Any
    registry: Registry
    patterns: Mapping[str, CompiledPattern]
    pattern_sources: tuple[str, ...]


_RUNTIME_CACHE: OrderedDict[str, _ValidationRuntime] = OrderedDict()
_RUNTIME_CACHE_LOCK = RLock()


def _active_pattern(source: str) -> CompiledPattern:
    patterns = _ACTIVE_PATTERNS.get()
    if patterns is None or source not in patterns:
        raise SchemaValidationError(
            "Output validator pattern context is unavailable",
            code="OUTPUT_SCHEMA_VALIDATOR_ERROR",
        )
    return patterns[source]


def _re2_pattern(
    validator: Any,
    source: str,
    instance: Any,
    schema: Mapping[str, Any],
) -> Iterator[ValidationError]:
    del schema
    if validator.is_type(instance, "string") and not _active_pattern(source).search(
        instance
    ):
        yield ValidationError(f"{instance!r} does not match {source!r}")


def _re2_pattern_properties(
    validator: Any,
    pattern_properties: Mapping[str, Any],
    instance: Any,
    schema: Mapping[str, Any],
) -> Iterator[ValidationError]:
    del schema
    if not validator.is_type(instance, "object"):
        return
    for source, subschema in pattern_properties.items():
        pattern = _active_pattern(source)
        for key, value in instance.items():
            if pattern.search(key):
                yield from validator.descend(
                    value,
                    subschema,
                    path=key,
                    schema_path=source,
                )


def _re2_additional_properties(
    validator: Any,
    additional_properties: Any,
    instance: Any,
    schema: Mapping[str, Any],
) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "object"):
        return

    declared_properties = schema.get("properties", {})
    pattern_sources = schema.get("patternProperties", {})
    extras = []
    for key in instance:
        if key in declared_properties:
            continue
        if any(
            _active_pattern(source).search(key)
            for source in pattern_sources
        ):
            continue
        extras.append(key)

    if validator.is_type(additional_properties, "object"):
        for extra in extras:
            yield from validator.descend(
                instance[extra],
                additional_properties,
                path=extra,
            )
    elif not additional_properties and extras:
        unexpected = ", ".join(repr(extra) for extra in sorted(extras, key=str))
        yield ValidationError(
            f"Additional properties are not allowed ({unexpected} unexpected)"
        )


_RE2_DRAFT_7_VALIDATOR = validators.extend(
    Draft7Validator,
    {
        "additionalProperties": _re2_additional_properties,
        "pattern": _re2_pattern,
        "patternProperties": _re2_pattern_properties,
    },
)


def _child_path(path: str, part: object) -> str:
    return f"{path}.{part}"


def _plain_schema(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _plain_schema(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_plain_schema(item) for item in value]
    return value


def _program_bytes(schema: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _plain_schema(schema),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _program_digest(program_bytes: bytes) -> str:
    return hashlib.sha256(
        _PROGRAM_DIGEST_DOMAIN + program_bytes,
    ).hexdigest()


def _resolve_local_pointer(
    root: Mapping[str, Any],
    reference: str,
) -> tuple[Any, str]:
    if reference == "#":
        return root, "$"
    if not reference.startswith("#/"):
        return _UNRESOLVED_POINTER, reference

    current: Any = root
    display_path = "$"
    for raw_segment in unquote(reference[2:]).split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        display_path = _child_path(display_path, segment)
        try:
            if isinstance(current, Mapping):
                current = current[segment]
            elif isinstance(current, list):
                current = current[int(segment)]
            else:
                return _UNRESOLVED_POINTER, display_path
        except (KeyError, IndexError, TypeError, ValueError):
            return _UNRESOLVED_POINTER, display_path
    return current, display_path


def _inspect_schema(
    value: Any,
    *,
    path: str,
    patterns: dict[str, CompiledPattern],
    root: Mapping[str, Any],
    active_targets: frozenset[int],
) -> None:
    if isinstance(value, Mapping):
        schema_uri = value.get("$schema")
        if isinstance(schema_uri, str) and schema_uri != _SCHEMA_DRAFT_07:
            raise PolicyValidationError(
                f"Unsupported output-schema dialect at {_child_path(path, '$schema')}",
                code="OUTPUT_SCHEMA_DIALECT_UNSUPPORTED",
                details={"path": _child_path(path, "$schema")},
            )

        reference = value.get("$ref")
        if isinstance(reference, str) and not reference.startswith("#"):
            ref_path = _child_path(path, "$ref")
            raise PolicyValidationError(
                f"External output-schema reference at {ref_path}",
                code="OUTPUT_SCHEMA_EXTERNAL_REF",
                details={"path": ref_path},
            )
        if isinstance(reference, str) and reference.startswith("#"):
            target, target_path = _resolve_local_pointer(root, reference)
            if (
                target is not _UNRESOLVED_POINTER
                and isinstance(target, (bool, Mapping))
            ):
                target_id = id(target)
                if target_id not in active_targets:
                    _inspect_schema(
                        target,
                        path=target_path,
                        patterns=patterns,
                        root=root,
                        active_targets=active_targets | {target_id},
                    )

        schema_id = value.get("$id")
        if isinstance(schema_id, str) and not schema_id.startswith("#"):
            id_path = _child_path(path, "$id")
            raise PolicyValidationError(
                f"Output-schema base URI is not same-document at {id_path}",
                code="OUTPUT_SCHEMA_EXTERNAL_REF",
                details={"path": id_path},
            )

        source = value.get("pattern")
        if isinstance(source, str) and source not in patterns:
            pattern_path = _child_path(path, "pattern")
            patterns[source] = compile_pattern(source, path=pattern_path)

        pattern_properties = value.get("patternProperties")
        if isinstance(pattern_properties, Mapping):
            for pattern_source in pattern_properties:
                if (
                    isinstance(pattern_source, str)
                    and pattern_source not in patterns
                ):
                    pattern_path = _child_path(
                        _child_path(path, "patternProperties"),
                        pattern_source,
                    )
                    patterns[pattern_source] = compile_pattern(
                        pattern_source,
                        path=pattern_path,
                    )

        for keyword in _SINGLE_SCHEMA_KEYWORDS:
            child = value.get(keyword)
            if isinstance(child, (bool, Mapping)):
                _inspect_schema(
                    child,
                    path=_child_path(path, keyword),
                    patterns=patterns,
                    root=root,
                    active_targets=active_targets,
                )

        items = value.get("items")
        if isinstance(items, (bool, Mapping)):
            _inspect_schema(
                items,
                path=_child_path(path, "items"),
                patterns=patterns,
                root=root,
                active_targets=active_targets,
            )
        elif isinstance(items, list):
            for index, child in enumerate(items):
                if isinstance(child, (bool, Mapping)):
                    _inspect_schema(
                        child,
                        path=_child_path(_child_path(path, "items"), index),
                        patterns=patterns,
                        root=root,
                        active_targets=active_targets,
                    )

        for keyword in _SCHEMA_ARRAY_KEYWORDS:
            children = value.get(keyword)
            if not isinstance(children, list):
                continue
            for index, child in enumerate(children):
                if isinstance(child, (bool, Mapping)):
                    _inspect_schema(
                        child,
                        path=_child_path(_child_path(path, keyword), index),
                        patterns=patterns,
                        root=root,
                        active_targets=active_targets,
                    )

        for keyword in _SCHEMA_MAPPING_KEYWORDS:
            children = value.get(keyword)
            if not isinstance(children, Mapping):
                continue
            for name, child in children.items():
                if not isinstance(child, (bool, Mapping)):
                    continue
                _inspect_schema(
                    child,
                    path=_child_path(_child_path(path, keyword), name),
                    patterns=patterns,
                    root=root,
                    active_targets=active_targets,
                )


def _new_runtime(
    detached: Mapping[str, Any],
    patterns: Mapping[str, CompiledPattern],
    program_bytes: bytes,
) -> _ValidationRuntime:
    registry = Registry()
    return _ValidationRuntime(
        program_bytes=program_bytes,
        validator=_RE2_DRAFT_7_VALIDATOR(
            detached,
            registry=registry,
        ),
        registry=registry,
        patterns=MappingProxyType(dict(patterns)),
        pattern_sources=tuple(sorted(patterns)),
    )


def _store_runtime(
    digest: str,
    runtime: _ValidationRuntime,
) -> None:
    with _RUNTIME_CACHE_LOCK:
        _RUNTIME_CACHE[digest] = runtime
        _RUNTIME_CACHE.move_to_end(digest)
        while len(_RUNTIME_CACHE) > _RUNTIME_CACHE_MAX_ENTRIES:
            _RUNTIME_CACHE.popitem(last=False)


def _rebuild_runtime(program_bytes: bytes) -> _ValidationRuntime:
    detached = json.loads(program_bytes)
    patterns: dict[str, CompiledPattern] = {}
    _inspect_schema(
        detached,
        path="$",
        patterns=patterns,
        root=detached,
        active_targets=frozenset(),
    )
    Draft7Validator.check_schema(detached)
    return _new_runtime(detached, patterns, program_bytes)


def _runtime_for(
    compiled: CompiledOutputValidator,
    program_bytes: bytes,
) -> _ValidationRuntime:
    with _RUNTIME_CACHE_LOCK:
        runtime = _RUNTIME_CACHE.get(compiled.program_digest)
        if runtime is not None:
            _RUNTIME_CACHE.move_to_end(compiled.program_digest)

    if runtime is None:
        runtime = _rebuild_runtime(program_bytes)
        _store_runtime(compiled.program_digest, runtime)

    try:
        runtime_schema_bytes = _program_bytes(runtime.validator.schema)
    except (TypeError, ValueError):
        runtime_schema_bytes = b""
    try:
        for source, pattern in runtime.patterns.items():
            if pattern.source != source:
                raise ValueError("pattern source key mismatch")
            verify_pattern_runtime(pattern)
        patterns_intact = True
    except (AIGCError, TypeError, ValueError):
        patterns_intact = False
    if (
        runtime.program_bytes != program_bytes
        or runtime_schema_bytes != program_bytes
        or runtime.pattern_sources != compiled.pattern_sources
        or tuple(sorted(runtime.patterns)) != compiled.pattern_sources
        or not patterns_intact
        or type(runtime.validator) is not _RE2_DRAFT_7_VALIDATOR
        or runtime.validator._registry is not runtime.registry
        or runtime.registry != Registry()
    ):
        raise SchemaValidationError(
            "Output validation program runtime integrity check failed",
            code="OUTPUT_SCHEMA_PROGRAM_INTEGRITY_ERROR",
        )
    return runtime


def compile_output_schema(
    schema: Mapping[str, Any],
) -> CompiledOutputValidator:
    """Compile one detached Draft 7 schema with a non-retrieving registry."""
    if not isinstance(schema, Mapping):
        raise PolicyValidationError(
            "Output schema must be a mapping",
            code="OUTPUT_SCHEMA_INVALID",
        )
    detached = copy.deepcopy(dict(schema))
    patterns: dict[str, CompiledPattern] = {}
    _inspect_schema(
        detached,
        path="$",
        patterns=patterns,
        root=detached,
        active_targets=frozenset(),
    )
    try:
        Draft7Validator.check_schema(detached)
    except SchemaError as exc:
        raise PolicyValidationError(
            "Output schema is not valid Draft 7",
            code="OUTPUT_SCHEMA_INVALID",
            details={
                "path": _path_to_pointer(list(exc.absolute_path)),
                "validator": exc.validator,
            },
        ) from exc

    try:
        program_bytes = _program_bytes(detached)
    except (TypeError, ValueError) as exc:
        raise PolicyValidationError(
            "Output schema is not canonical JSON",
            code="OUTPUT_SCHEMA_INVALID",
        ) from exc
    digest = _program_digest(program_bytes)
    runtime = _new_runtime(detached, patterns, program_bytes)
    _store_runtime(digest, runtime)
    return CompiledOutputValidator(
        schema=freeze(detached),
        program_digest=digest,
        pattern_sources=runtime.pattern_sources,
    )


def _path_to_pointer(path: list[Any]) -> str:
    return "$" if not path else "$." + ".".join(str(part) for part in path)


def _error_sort_key(error: ValidationError) -> tuple[Any, ...]:
    return (
        tuple((type(part).__name__, str(part)) for part in error.absolute_path),
        tuple(
            (type(part).__name__, str(part))
            for part in error.absolute_schema_path
        ),
        str(error.validator),
        error.message,
    )


def validate_compiled_output(
    compiled: CompiledOutputValidator,
    value: Any,
) -> None:
    """Run a compiled validator and map its first deterministic failure."""
    try:
        program_bytes = _program_bytes(compiled.schema)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(
            "Output validation program is not canonical JSON",
            code="OUTPUT_SCHEMA_PROGRAM_INTEGRITY_ERROR",
        ) from exc
    if _program_digest(program_bytes) != compiled.program_digest:
        raise SchemaValidationError(
            "Output validation program digest mismatch",
            code="OUTPUT_SCHEMA_PROGRAM_INTEGRITY_ERROR",
        )
    runtime = _runtime_for(compiled, program_bytes)
    token = _ACTIVE_PATTERNS.set(runtime.patterns)
    try:
        try:
            errors = sorted(
                runtime.validator.iter_errors(value),
                key=_error_sort_key,
            )
        except PatternInputTooLargeError as exc:
            raise SchemaValidationError(
                "Output schema pattern input exceeds the UTF-8 byte limit",
                code="PATTERN_INPUT_TOO_LARGE",
                details=exc.details,
            ) from exc
        except Unresolvable as exc:
            raise SchemaValidationError(
                "Output schema same-document reference could not be resolved",
                code="OUTPUT_SCHEMA_REFERENCE_ERROR",
            ) from exc
    finally:
        _ACTIVE_PATTERNS.reset(token)

    if errors:
        first = errors[0]
        pointer = _path_to_pointer(list(first.absolute_path))
        raise SchemaValidationError(
            f"Output schema validation failed at {pointer}: {first.message}",
            details={"path": pointer, "validator": first.validator},
        )
