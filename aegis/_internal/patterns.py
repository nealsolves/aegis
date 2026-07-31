"""Bounded compilation and evaluation for policy-supplied RE2 patterns."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass
from threading import RLock
from typing import Any

import re2

from aegis._internal.errors import AIGCError, PolicyValidationError


PATTERN_MAX_BYTES = 256
PATTERN_INPUT_MAX_BYTES = 16_384
_PROGRAM_DIGEST_DOMAIN = b"aegis.pattern-program.v1\x00"
_RUNTIME_CACHE_MAX_ENTRIES = 512
_RE2_PATTERN_TYPE = type(re2.compile(""))


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
class _PatternAttestation:
    """Strong-reference identity for one internally compiled RE2 program."""

    program_bytes: bytes
    compiled: Any
    options_fingerprint: tuple[tuple[str, object], ...]
    program_fingerprint: tuple[object, ...]


_RUNTIME_CACHE: OrderedDict[str, _PatternRuntime] = OrderedDict()
_ATTESTED_PROGRAMS: OrderedDict[str, _PatternAttestation] = OrderedDict()
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


def _store_attestation(
    digest: str,
    attestation: _PatternAttestation,
) -> None:
    with _RUNTIME_CACHE_LOCK:
        _ATTESTED_PROGRAMS[digest] = attestation
        _ATTESTED_PROGRAMS.move_to_end(digest)
        while len(_ATTESTED_PROGRAMS) > _RUNTIME_CACHE_MAX_ENTRIES:
            _ATTESTED_PROGRAMS.popitem(last=False)


def _attestation_from_compiled(
    source: str,
    program_bytes: bytes,
    compiled: Any,
) -> _PatternAttestation:
    if (
        type(compiled) is not _RE2_PATTERN_TYPE
        or compiled.pattern != source
        or _options_fingerprint(compiled.options)
        != _DEFAULT_OPTIONS_FINGERPRINT
    ):
        raise PatternProgramIntegrityError(
            "Internally compiled pattern identity is invalid",
        )
    return _PatternAttestation(
        program_bytes=program_bytes,
        compiled=compiled,
        options_fingerprint=_options_fingerprint(compiled.options),
        program_fingerprint=_program_fingerprint(compiled),
    )


def _new_attestation(
    source: str,
    program_bytes: bytes,
) -> _PatternAttestation:
    try:
        compiled = re2.compile(source)
    except re2.error as exc:
        raise PatternProgramIntegrityError(
            "Authenticated pattern source no longer compiles",
        ) from exc
    return _attestation_from_compiled(
        source,
        program_bytes,
        compiled,
    )


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """Immutable authenticated pattern metadata with no reachable RE2 handle."""

    source: str
    path: str
    program_digest: str
    source_max_bytes: int = PATTERN_MAX_BYTES
    input_max_bytes: int = PATTERN_INPUT_MAX_BYTES

    def _require_bounded_string(self, candidate: object) -> str | None:
        if not isinstance(candidate, str):
            return None
        try:
            encoded_length = len(candidate.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise PatternInputTooLargeError(
                "Pattern candidate is not valid UTF-8",
                details={"path": self.path},
            ) from exc
        if encoded_length > self.input_max_bytes:
            raise PatternInputTooLargeError(
                details={
                    "path": self.path,
                    "max_bytes": self.input_max_bytes,
                }
            )
        return candidate

    def fullmatch(self, candidate: str) -> bool:
        """Return whether *candidate* fully matches, or fail closed on its bound."""
        bounded = self._require_bounded_string(candidate)
        if bounded is None:
            return False
        return _evaluate(self, bounded, operation="fullmatch")

    def search(self, candidate: str) -> bool:
        """Apply JSON Schema search semantics with the same candidate bound."""
        bounded = self._require_bounded_string(candidate)
        if bounded is None:
            return False
        return _evaluate(self, bounded, operation="search")


def _authenticated_program_bytes(pattern: CompiledPattern) -> bytes:
    try:
        program_bytes = _program_bytes(
            source=pattern.source,
            path=pattern.path,
            source_max_bytes=pattern.source_max_bytes,
            input_max_bytes=pattern.input_max_bytes,
        )
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise PatternProgramIntegrityError(
            details={"path": pattern.path},
        ) from exc
    if (
        pattern.source_max_bytes != PATTERN_MAX_BYTES
        or pattern.input_max_bytes != PATTERN_INPUT_MAX_BYTES
        or _program_digest(program_bytes) != pattern.program_digest
    ):
        raise PatternProgramIntegrityError(
            details={"path": pattern.path},
        )
    return program_bytes


def _runtime_intact(
    runtime: object,
    *,
    attestation: _PatternAttestation,
    program_bytes: bytes,
) -> bool:
    return (
        type(runtime) is _PatternRuntime
        and runtime.program_bytes == program_bytes
        and runtime.compiled is attestation.compiled
    )


def _attestation_intact(
    attestation: object,
    *,
    program_bytes: bytes,
    source: str,
) -> bool:
    if (
        type(attestation) is not _PatternAttestation
        or attestation.program_bytes != program_bytes
        or type(attestation.compiled) is not _RE2_PATTERN_TYPE
        or attestation.compiled.pattern != source
        or attestation.options_fingerprint
        != _DEFAULT_OPTIONS_FINGERPRINT
    ):
        return False
    try:
        return (
            _options_fingerprint(attestation.compiled.options)
            == attestation.options_fingerprint
            and _program_fingerprint(attestation.compiled)
            == attestation.program_fingerprint
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _use_verified_runtime_locked(
    pattern: CompiledPattern,
    program_bytes: bytes,
    *,
    candidate: str | None = None,
    operation: str | None = None,
) -> bool | None:
    """Verify, optionally evaluate, and never return the cached RE2 handle."""
    attestation = _ATTESTED_PROGRAMS.get(pattern.program_digest)
    if attestation is not None:
        _ATTESTED_PROGRAMS.move_to_end(pattern.program_digest)
    if not _attestation_intact(
        attestation,
        program_bytes=program_bytes,
        source=pattern.source,
    ):
        attestation = _new_attestation(pattern.source, program_bytes)
        _store_attestation(pattern.program_digest, attestation)

    runtime = _RUNTIME_CACHE.get(pattern.program_digest)
    if runtime is not None:
        _RUNTIME_CACHE.move_to_end(pattern.program_digest)

    if not _runtime_intact(
        runtime,
        attestation=attestation,
        program_bytes=program_bytes,
    ):
        runtime = _PatternRuntime(
            program_bytes=program_bytes,
            compiled=attestation.compiled,
        )
        _store_runtime(pattern.program_digest, runtime)

    if not _runtime_intact(
        runtime,
        attestation=attestation,
        program_bytes=program_bytes,
    ) or not _attestation_intact(
        attestation,
        program_bytes=program_bytes,
        source=pattern.source,
    ):
        raise PatternProgramIntegrityError(
            details={"path": pattern.path},
        )
    if operation is None:
        return None
    if candidate is None:
        raise PatternProgramIntegrityError(
            "Pattern evaluation candidate is missing",
            details={"path": pattern.path},
        )
    compiled = runtime.compiled
    if operation == "fullmatch":
        return compiled.fullmatch(candidate) is not None
    if operation == "search":
        return compiled.search(candidate) is not None
    raise PatternProgramIntegrityError(
        "Unknown pattern evaluation operation",
        details={"path": pattern.path, "operation": operation},
    )


def _evaluate(
    pattern: CompiledPattern,
    candidate: str,
    *,
    operation: str,
) -> bool:
    program_bytes = _authenticated_program_bytes(pattern)
    with _RUNTIME_CACHE_LOCK:
        result = _use_verified_runtime_locked(
            pattern,
            program_bytes,
            candidate=candidate,
            operation=operation,
        )
    if result is None:
        raise PatternProgramIntegrityError(
            "Pattern evaluation did not produce a decision",
            details={"path": pattern.path},
        )
    return result


def verify_pattern_runtime(pattern: CompiledPattern) -> None:
    """Verify or safely rebuild one private runtime without exposing it."""
    program_bytes = _authenticated_program_bytes(pattern)
    with _RUNTIME_CACHE_LOCK:
        _use_verified_runtime_locked(pattern, program_bytes)


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
    attestation = _attestation_from_compiled(
        source,
        program_bytes,
        compiled,
    )
    with _RUNTIME_CACHE_LOCK:
        _store_attestation(digest, attestation)
        _store_runtime(
            digest,
            _PatternRuntime(
                program_bytes=program_bytes,
                compiled=attestation.compiled,
            ),
        )
    return CompiledPattern(
        source=source,
        path=path,
        program_digest=digest,
    )


def restore_compiled_pattern(
    *,
    source: object,
    path: object,
    program_digest: object,
    source_max_bytes: object,
    input_max_bytes: object,
) -> CompiledPattern:
    """Restore authenticated compiled metadata without reopening raw policy."""
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
    pattern = CompiledPattern(
        source=source,
        path=path,
        program_digest=program_digest,
        source_max_bytes=source_max_bytes,
        input_max_bytes=input_max_bytes,
    )
    verify_pattern_runtime(pattern)
    return pattern
