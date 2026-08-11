"""Strict, resource-bounded YAML handling for public demo inputs."""

from __future__ import annotations

import json
import math
from typing import TypeAlias, cast

import yaml
from yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    DocumentStartEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode

from demo_errors import (
    DemoPublicError,
    current_request_id,
    log_internal_failure,
    safe_demo_message,
)
from demo_limits import (
    YAML_MAX_ALIASES,
    YAML_MAX_ANCHORS,
    YAML_MAX_COLLECTIONS,
    YAML_MAX_ENCODED_BYTES,
    YAML_MAX_EXPANDED_NODES,
    YAML_MAX_EXPANDED_SCALAR_BYTES,
    YAML_MAX_NESTING_DEPTH,
    YAML_MAX_SCALARS,
    YAML_RESPONSE_MAX_BYTES,
)


JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_ALLOWED_EXPLICIT_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:null",
    }
)


class _YamlUnsupported(Exception):
    pass


class _YamlCycle(Exception):
    pass


class _YamlLimit(Exception):
    pass


class _StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, object]:
        if not isinstance(node, MappingNode):
            raise _YamlUnsupported

        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.value == "<<":
                raise _YamlUnsupported
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise _YamlUnsupported
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _raise_public(code: str, status_code: int = 422) -> None:
    raise DemoPublicError(code, safe_demo_message(code), status_code)


def _scan_events(text: str) -> None:
    anchors = 0
    aliases = 0
    scalars = 0
    collections = 0
    documents = 0
    frames: list[list[object]] = []

    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    _raise_public("YAML_INVALID")
                continue

            if isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                if frames:
                    frames.pop()
                continue

            is_node = isinstance(
                event,
                (ScalarEvent, AliasEvent, MappingStartEvent, SequenceStartEvent),
            )
            if not is_node:
                continue

            if frames and frames[-1][0] == "mapping":
                is_mapping_key = bool(frames[-1][1])
                if is_mapping_key and isinstance(event, ScalarEvent) and event.value == "<<":
                    _raise_public("YAML_UNSUPPORTED_VALUE")
                frames[-1][1] = not is_mapping_key

            if isinstance(event, AliasEvent):
                aliases += 1
                if aliases > YAML_MAX_ALIASES:
                    raise _YamlLimit
                continue

            tag = getattr(event, "tag", None)
            if tag is not None and tag not in _ALLOWED_EXPLICIT_TAGS:
                raise _YamlUnsupported

            if getattr(event, "anchor", None) is not None:
                anchors += 1
                if anchors > YAML_MAX_ANCHORS:
                    raise _YamlLimit

            if isinstance(event, ScalarEvent):
                scalars += 1
                if scalars > YAML_MAX_SCALARS:
                    raise _YamlLimit
                continue

            if isinstance(event, CollectionStartEvent):
                collections += 1
                if collections > YAML_MAX_COLLECTIONS:
                    raise _YamlLimit
                frame_kind = "mapping" if isinstance(event, MappingStartEvent) else "sequence"
                frames.append([frame_kind, True])
                if len(frames) > YAML_MAX_NESTING_DEPTH:
                    raise _YamlLimit
    except DemoPublicError:
        raise
    except _YamlUnsupported:
        _raise_public("YAML_UNSUPPORTED_VALUE")
    except _YamlLimit:
        _raise_public("YAML_LIMIT_EXCEEDED")
    except yaml.YAMLError as error:
        log_internal_failure(
            request_id=current_request_id(),
            operation="yaml_event_scan",
            error=error,
            public_code="YAML_INVALID",
        )
        _raise_public("YAML_INVALID")

    if documents != 1:
        _raise_public("YAML_INVALID")


def _construct(text: str) -> object:
    loader = _StrictSafeLoader(text)
    try:
        return loader.get_single_data()
    except _YamlUnsupported:
        _raise_public("YAML_UNSUPPORTED_VALUE")
    except yaml.YAMLError as error:
        log_internal_failure(
            request_id=current_request_id(),
            operation="yaml_construction",
            error=error,
            public_code="YAML_INVALID",
        )
        _raise_public("YAML_INVALID")
    finally:
        loader.dispose()


def _scalar_size(value: object) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if value is None:
        return 4
    if isinstance(value, bool):
        return 4 if value else 5
    if type(value) in (int, float):
        return len(str(value).encode("utf-8"))
    raise _YamlUnsupported


def _validate_expanded_graph(value: object) -> None:
    nodes = 0
    scalar_bytes = 0
    active_containers: set[int] = set()
    stack: list[tuple[bool, object]] = [(False, value)]

    try:
        while stack:
            exiting, current = stack.pop()
            if exiting:
                active_containers.remove(id(current))
                continue

            nodes += 1
            if nodes > YAML_MAX_EXPANDED_NODES:
                raise _YamlLimit

            if isinstance(current, dict):
                identity = id(current)
                if identity in active_containers:
                    raise _YamlCycle
                active_containers.add(identity)
                stack.append((True, current))
                for key, item in reversed(tuple(current.items())):
                    if not isinstance(key, str):
                        raise _YamlUnsupported
                    stack.append((False, item))
                    stack.append((False, key))
                continue

            if isinstance(current, list):
                identity = id(current)
                if identity in active_containers:
                    raise _YamlCycle
                active_containers.add(identity)
                stack.append((True, current))
                for item in reversed(current):
                    stack.append((False, item))
                continue

            if isinstance(current, bool) or current is None:
                scalar_bytes += _scalar_size(current)
            elif isinstance(current, str) or type(current) in (int, float):
                if isinstance(current, float) and not math.isfinite(current):
                    raise _YamlUnsupported
                scalar_bytes += _scalar_size(current)
            else:
                raise _YamlUnsupported

            if scalar_bytes > YAML_MAX_EXPANDED_SCALAR_BYTES:
                raise _YamlLimit
    except _YamlCycle:
        _raise_public("YAML_CYCLE_REJECTED")
    except _YamlLimit:
        _raise_public("YAML_LIMIT_EXCEEDED")
    except (UnicodeError, _YamlUnsupported):
        _raise_public("YAML_UNSUPPORTED_VALUE")


def load_bounded_yaml(
    text: str,
    *,
    require_mapping: bool = True,
) -> dict[str, JsonValue] | JsonValue:
    """Parse one YAML document under strict syntax, type, and resource limits."""

    if not isinstance(text, str):
        _raise_public("YAML_UNSUPPORTED_VALUE")
    try:
        encoded_size = len(text.encode("utf-8"))
    except UnicodeEncodeError:
        _raise_public("YAML_INVALID")
    if encoded_size > YAML_MAX_ENCODED_BYTES:
        _raise_public("YAML_LIMIT_EXCEEDED")

    _scan_events(text)
    loaded = _construct(text)
    _validate_expanded_graph(loaded)
    if require_mapping and not isinstance(loaded, dict):
        _raise_public("YAML_UNSUPPORTED_VALUE")
    return cast(dict[str, JsonValue] | JsonValue, loaded)


def ensure_bounded_json_response(
    payload: JsonValue,
    *,
    max_bytes: int = YAML_RESPONSE_MAX_BYTES,
) -> None:
    """Reject a JSON response before allocating an oversized encoded string."""

    encoder = json.JSONEncoder(
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    total = 0
    try:
        for chunk in encoder.iterencode(payload):
            total += len(chunk.encode("utf-8"))
            if total > max_bytes:
                _raise_public("RESPONSE_TOO_LARGE")
    except DemoPublicError:
        raise
    except (TypeError, ValueError, UnicodeError) as error:
        log_internal_failure(
            request_id=current_request_id(),
            operation="json_response_preflight",
            error=error,
            public_code="DEMO_OPERATION_FAILED",
        )
        _raise_public("DEMO_OPERATION_FAILED", status_code=500)
