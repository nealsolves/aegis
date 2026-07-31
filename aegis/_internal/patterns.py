"""Bounded compilation and evaluation for policy-supplied RE2 patterns."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Any
from weakref import WeakKeyDictionary

import re2

from aegis._internal.errors import AIGCError, PolicyValidationError


PATTERN_MAX_BYTES = 256
PATTERN_INPUT_MAX_BYTES = 16_384
_PROGRAM_DIGEST_DOMAIN = b"aegis.pattern-program.v1\x00"
_RUNTIME_CACHE_MAX_ENTRIES = 512
_RE2_PATTERN_TYPE = type(re2.compile(""))
_NO_CANDIDATE = object()


class PatternInputTooLargeError(AIGCError):
    """Raised before RE2 sees a candidate which exceeds the runtime bound."""

    def __init__(
        self,
        message: str = "Pattern candidate exceeds the UTF-8 byte limit",
        *,
        code: str = "PATTERN_INPUT_TOO_LARGE",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class PatternProgramIntegrityError(AIGCError):
    """Raised when immutable metadata cannot authenticate its RE2 runtime."""

    def __init__(
        self,
        message: str = "Pattern program integrity check failed",
        *,
        code: str = "PATTERN_PROGRAM_INTEGRITY_ERROR",
        details: dict | None = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


@dataclass(frozen=True, slots=True)
class _PatternRuntime:
    """Private immutable RE2 runtime derived from authenticated metadata."""

    program_bytes: bytes
    compiled: Any


@dataclass(frozen=True, slots=True)
class _PatternSnapshot:
    """Authenticated immutable metadata expected for one pattern object."""

    source: str
    path: str
    program_digest: str
    source_max_bytes: int
    input_max_bytes: int
    program_bytes: bytes


@dataclass(frozen=True, slots=True)
class _PatternAttestation:
    """Trusted metadata and strong RE2 identity for one pattern object."""

    expected: _PatternSnapshot
    compiled: Any
    options_fingerprint: tuple[tuple[str, object], ...]
    program_fingerprint: tuple[object, ...]


_RUNTIME_CACHE: OrderedDict[str, _PatternRuntime] = OrderedDict()
_PATTERN_ATTESTATIONS: WeakKeyDictionary[
    CompiledPattern,
    _PatternAttestation,
] = WeakKeyDictionary()
_RUNTIME_CACHE_LOCK = RLock()


def _program_bytes(
    *,
    source: str,
    path: str,
    source_max_bytes: int,
    input_max_bytes: int,
) -> bytes:
    return json.dumps(
        {
            "input_max_bytes": input_max_bytes,
            "path": path,
            "source": source,
            "source_max_bytes": source_max_bytes,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _program_digest(program_bytes: bytes) -> str:
    return hashlib.sha256(
        _PROGRAM_DIGEST_DOMAIN + program_bytes,
    ).hexdigest()


def _option_value(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return repr(value)


def _options_fingerprint(options: object) -> tuple[tuple[str, object], ...]:
    return tuple(
        (name, _option_value(getattr(options, name)))
        for name in re2.Options.NAMES
    )


_DEFAULT_OPTIONS_FINGERPRINT = _options_fingerprint(re2.Options())


def _program_fingerprint(compiled: Any) -> tuple[object, ...]:
    return (
        compiled.programsize,
        tuple(compiled.programfanout),
        compiled.reverseprogramsize,
        tuple(compiled.reverseprogramfanout),
        compiled.groups,
        tuple(sorted(compiled.groupindex.items())),
    )


def _store_runtime(digest: str, runtime: _PatternRuntime) -> None:
    with _RUNTIME_CACHE_LOCK:
        _RUNTIME_CACHE[digest] = runtime
        _RUNTIME_CACHE.move_to_end(digest)
        while len(_RUNTIME_CACHE) > _RUNTIME_CACHE_MAX_ENTRIES:
            _RUNTIME_CACHE.popitem(last=False)


def _attestation_from_compiled(
    expected: _PatternSnapshot,
    compiled: Any,
) -> _PatternAttestation:
    if (
        type(compiled) is not _RE2_PATTERN_TYPE
        or compiled.pattern != expected.source
        or _options_fingerprint(compiled.options)
        != _DEFAULT_OPTIONS_FINGERPRINT
    ):
        raise PatternProgramIntegrityError(
            "Internally compiled pattern identity is invalid",
        )
    return _PatternAttestation(
        expected=expected,
        compiled=compiled,
        options_fingerprint=_options_fingerprint(compiled.options),
        program_fingerprint=_program_fingerprint(compiled),
    )


class _WeakPatternIdentity:
    """Supply a cross-version weak-reference slot to slotted subclasses."""

    __slots__ = ("__weakref__",)


@dataclass(frozen=True, slots=True, eq=False)
class CompiledPattern(_WeakPatternIdentity):
    """Immutable authenticated pattern metadata with no reachable RE2 handle."""

    source: str
    path: str
    program_digest: str
    source_max_bytes: int = PATTERN_MAX_BYTES
    input_max_bytes: int = PATTERN_INPUT_MAX_BYTES

    def fullmatch(self, candidate: str) -> bool:
        """Return whether *candidate* fully matches, or fail closed on its bound."""
        return _evaluate(self, candidate, operation="fullmatch")

    def search(self, candidate: str) -> bool:
        """Apply JSON Schema search semantics with the same candidate bound."""
        return _evaluate(self, candidate, operation="search")


def _read_pattern_snapshot(pattern: CompiledPattern) -> _PatternSnapshot:
    """Read caller-visible fields once; callers must hold the runtime lock."""
    try:
        source = pattern.source
        path = pattern.path
        program_digest = pattern.program_digest
        source_max_bytes = pattern.source_max_bytes
        input_max_bytes = pattern.input_max_bytes
    except (AttributeError, TypeError) as exc:
        raise PatternProgramIntegrityError() from exc
    try:
        program_bytes = _program_bytes(
            source=source,
            path=path,
            source_max_bytes=source_max_bytes,
            input_max_bytes=input_max_bytes,
        )
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise PatternProgramIntegrityError() from exc
    return _PatternSnapshot(
        source=source,
        path=path,
        program_digest=program_digest,
        source_max_bytes=source_max_bytes,
        input_max_bytes=input_max_bytes,
        program_bytes=program_bytes,
    )


def _snapshot_intact(snapshot: object) -> bool:
    if (
        type(snapshot) is not _PatternSnapshot
        or type(snapshot.source) is not str
        or type(snapshot.path) is not str
        or type(snapshot.program_digest) is not str
        or type(snapshot.source_max_bytes) is not int
        or type(snapshot.input_max_bytes) is not int
        or type(snapshot.program_bytes) is not bytes
        or snapshot.source_max_bytes != PATTERN_MAX_BYTES
        or snapshot.input_max_bytes != PATTERN_INPUT_MAX_BYTES
    ):
        return False
    try:
        source_length = len(snapshot.source.encode("utf-8"))
        expected_bytes = _program_bytes(
            source=snapshot.source,
            path=snapshot.path,
            source_max_bytes=snapshot.source_max_bytes,
            input_max_bytes=snapshot.input_max_bytes,
        )
    except (TypeError, UnicodeEncodeError, ValueError):
        return False
    return (
        source_length <= snapshot.source_max_bytes
        and expected_bytes == snapshot.program_bytes
        and _program_digest(expected_bytes) == snapshot.program_digest
    )


def _snapshot_matches(
    current: _PatternSnapshot,
    expected: _PatternSnapshot,
) -> bool:
    return (
        type(current.source) is str
        and current.source == expected.source
        and type(current.path) is str
        and current.path == expected.path
        and type(current.program_digest) is str
        and current.program_digest == expected.program_digest
        and type(current.source_max_bytes) is int
        and current.source_max_bytes == expected.source_max_bytes
        and type(current.input_max_bytes) is int
        and current.input_max_bytes == expected.input_max_bytes
        and type(current.program_bytes) is bytes
        and current.program_bytes == expected.program_bytes
    )


def _bounded_candidate(
    candidate: object,
    expected: _PatternSnapshot,
) -> str | None:
    if not isinstance(candidate, str):
        return None
    try:
        encoded_length = len(candidate.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PatternInputTooLargeError(
            "Pattern candidate is not valid UTF-8",
            details={"path": expected.path},
        ) from exc
    if encoded_length > expected.input_max_bytes:
        raise PatternInputTooLargeError(
            details={
                "path": expected.path,
                "max_bytes": expected.input_max_bytes,
            }
        )
    return candidate


def _runtime_intact(
    runtime: object,
    *,
    compiled: Any,
    program_bytes: bytes,
) -> bool:
    return (
        type(runtime) is _PatternRuntime
        and runtime.program_bytes == program_bytes
        and runtime.compiled is compiled
    )


def _attestation_intact(
    attestation: object,
    expected: _PatternSnapshot,
    compiled: Any,
    options_fingerprint: tuple[tuple[str, object], ...],
    program_fingerprint: tuple[object, ...],
) -> bool:
    if (
        type(attestation) is not _PatternAttestation
        or not _snapshot_intact(expected)
        or type(compiled) is not _RE2_PATTERN_TYPE
        or compiled.pattern != expected.source
        or options_fingerprint != _DEFAULT_OPTIONS_FINGERPRINT
    ):
        return False
    try:
        return (
            _options_fingerprint(compiled.options) == options_fingerprint
            and _program_fingerprint(compiled) == program_fingerprint
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _register_trusted_pattern(
    pattern: CompiledPattern,
    expected: _PatternSnapshot,
    compiled: Any,
) -> None:
    """Register compiler-authenticated identity without caller-field trust."""
    if type(pattern) is not CompiledPattern or not _snapshot_intact(expected):
        raise PatternProgramIntegrityError()
    attestation = _attestation_from_compiled(expected, compiled)
    with _RUNTIME_CACHE_LOCK:
        current = _read_pattern_snapshot(pattern)
        if not _snapshot_matches(current, expected):
            raise PatternProgramIntegrityError(
                details={"path": expected.path},
            )
        _PATTERN_ATTESTATIONS[pattern] = attestation
        _store_runtime(
            expected.program_digest,
            _PatternRuntime(
                program_bytes=expected.program_bytes,
                compiled=compiled,
            ),
        )


def _use_verified_runtime_locked(
    pattern: CompiledPattern,
    *,
    candidate: object = _NO_CANDIDATE,
    operation: str | None = None,
) -> bool | None:
    """Verify, optionally evaluate, and never return the cached RE2 handle."""
    if type(pattern) is not CompiledPattern:
        raise PatternProgramIntegrityError()
    attestation = _PATTERN_ATTESTATIONS.get(pattern)
    if type(attestation) is not _PatternAttestation:
        raise PatternProgramIntegrityError()

    expected = attestation.expected
    compiled = attestation.compiled
    options_fingerprint = attestation.options_fingerprint
    program_fingerprint = attestation.program_fingerprint
    current = _read_pattern_snapshot(pattern)
    if not _snapshot_matches(current, expected):
        raise PatternProgramIntegrityError(
            details={"path": expected.path},
        )
    if not _attestation_intact(
        attestation,
        expected,
        compiled,
        options_fingerprint,
        program_fingerprint,
    ):
        raise PatternProgramIntegrityError(
            details={"path": expected.path},
        )

    runtime = _RUNTIME_CACHE.get(expected.program_digest)
    if runtime is not None:
        _RUNTIME_CACHE.move_to_end(expected.program_digest)

    if not _runtime_intact(
        runtime,
        compiled=compiled,
        program_bytes=expected.program_bytes,
    ):
        runtime = _PatternRuntime(
            program_bytes=expected.program_bytes,
            compiled=compiled,
        )
        _store_runtime(expected.program_digest, runtime)

    if not _runtime_intact(
        runtime,
        compiled=compiled,
        program_bytes=expected.program_bytes,
    ) or not _attestation_intact(
        attestation,
        expected,
        compiled,
        options_fingerprint,
        program_fingerprint,
    ):
        raise PatternProgramIntegrityError(
            details={"path": expected.path},
        )
    if operation is None:
        return None
    if candidate is _NO_CANDIDATE:
        raise PatternProgramIntegrityError(
            "Pattern evaluation candidate is missing",
            details={"path": expected.path},
        )
    bounded = _bounded_candidate(candidate, expected)
    if bounded is None:
        return False
    if operation == "fullmatch":
        return compiled.fullmatch(bounded) is not None
    if operation == "search":
        return compiled.search(bounded) is not None
    raise PatternProgramIntegrityError(
        "Unknown pattern evaluation operation",
        details={"path": expected.path, "operation": operation},
    )


def _evaluate(
    pattern: CompiledPattern,
    candidate: object,
    *,
    operation: str,
) -> bool:
    with _RUNTIME_CACHE_LOCK:
        result = _use_verified_runtime_locked(
            pattern,
            candidate=candidate,
            operation=operation,
        )
    if result is None:
        raise PatternProgramIntegrityError(
            "Pattern evaluation did not produce a decision",
        )
    return result


def verify_pattern_runtime(pattern: CompiledPattern) -> None:
    """Verify or safely rebuild one private runtime without exposing it."""
    with _RUNTIME_CACHE_LOCK:
        _use_verified_runtime_locked(pattern)


def compile_pattern(source: str, *, path: str) -> CompiledPattern:
    """Compile one bounded policy pattern with no fallback engine."""
    if not isinstance(source, str):
        raise PolicyValidationError(
            "Invalid pattern length",
            code="PATTERN_INVALID",
            details={"path": path, "max_bytes": PATTERN_MAX_BYTES},
        )
    try:
        encoded_length = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PolicyValidationError(
            "Pattern source is not valid UTF-8",
            code="PATTERN_INVALID",
            details={"path": path},
        ) from exc
    if encoded_length > PATTERN_MAX_BYTES:
        raise PolicyValidationError(
            "Invalid pattern length",
            code="PATTERN_INVALID",
            details={"path": path, "max_bytes": PATTERN_MAX_BYTES},
        )
    try:
        compiled = re2.compile(source)
    except re2.error as exc:
        raise PolicyValidationError(
            f"Unsupported policy pattern at {path}",
            code="PATTERN_UNSUPPORTED",
            details={"path": path},
        ) from exc
    program_bytes = _program_bytes(
        source=source,
        path=path,
        source_max_bytes=PATTERN_MAX_BYTES,
        input_max_bytes=PATTERN_INPUT_MAX_BYTES,
    )
    digest = _program_digest(program_bytes)
    expected = _PatternSnapshot(
        source,
        path,
        digest,
        PATTERN_MAX_BYTES,
        PATTERN_INPUT_MAX_BYTES,
        program_bytes,
    )
    pattern = CompiledPattern(
        source=source,
        path=path,
        program_digest=digest,
    )
    _register_trusted_pattern(pattern, expected, compiled)
    return pattern


def restore_compiled_pattern(
    *,
    source: object,
    path: object,
    program_digest: object,
    source_max_bytes: object,
    input_max_bytes: object,
) -> CompiledPattern:
    """Register metadata after its enclosing DTO has been authenticated."""
    if (
        type(source) is not str
        or type(path) is not str
        or type(program_digest) is not str
        or type(source_max_bytes) is not int
        or type(input_max_bytes) is not int
    ):
        raise PatternProgramIntegrityError(
            "Pattern program metadata has invalid types",
        )
    try:
        program_bytes = _program_bytes(
            source=source,
            path=path,
            source_max_bytes=source_max_bytes,
            input_max_bytes=input_max_bytes,
        )
        source_length = len(source.encode("utf-8"))
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise PatternProgramIntegrityError(
            "Pattern program metadata is not canonical",
        ) from exc
    expected = _PatternSnapshot(
        source=source,
        path=path,
        program_digest=program_digest,
        source_max_bytes=source_max_bytes,
        input_max_bytes=input_max_bytes,
        program_bytes=program_bytes,
    )
    if source_length > source_max_bytes or not _snapshot_intact(expected):
        raise PatternProgramIntegrityError(
            "Pattern program metadata failed content verification",
            details={"path": path},
        )
    try:
        compiled = re2.compile(expected.source)
    except re2.error as exc:
        raise PatternProgramIntegrityError(
            "Authenticated pattern source no longer compiles",
            details={"path": expected.path},
        ) from exc
    pattern = CompiledPattern(
        source=source,
        path=path,
        program_digest=program_digest,
        source_max_bytes=source_max_bytes,
        input_max_bytes=input_max_bytes,
    )
    _register_trusted_pattern(pattern, expected, compiled)
    return pattern
