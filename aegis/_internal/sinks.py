"""
Audit sink registry and built-in sink implementations.

Sinks receive every audit artifact after enforcement completes (PASS and FAIL).
Sink failure behavior is configurable: raise or log.

Note: The "queue" failure mode was deprecated in v0.3.0 and will be removed
in a future release. It now behaves identically to "log" mode.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any, Callable

from aegis._internal.errors import AuditSinkError

logger = logging.getLogger("aegis.sinks")

_registered_sink: AuditSink | None = None
_sink_failure_mode: str = "log"
_SENTINEL = object()  # distinguish "not passed" from explicit None
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", None)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_SECURE_SINK_ERROR = "Secure JSONL audit delivery failed"


def _raise_secure_sink_error() -> None:
    raise AuditSinkError(_SECURE_SINK_ERROR) from None


def _open_secure_append_descriptor(path: Path) -> int:
    """Open *path* for secure append without following an unsafe target."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_NONBLOCK
    expected_identity: tuple[int, int] | None = None

    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except (OSError, ValueError):
        _raise_secure_sink_error()

    if existing is not None and not stat.S_ISREG(existing.st_mode):
        _raise_secure_sink_error()

    if _O_NOFOLLOW is None:
        if existing is None:
            _raise_secure_sink_error()
        expected_identity = (existing.st_dev, existing.st_ino)
    else:
        flags |= _O_NOFOLLOW

    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _raise_secure_sink_error()

        if expected_identity is not None:
            current = os.lstat(path)
            identities = {
                expected_identity,
                (opened.st_dev, opened.st_ino),
                (current.st_dev, current.st_ino),
            }
            if not stat.S_ISREG(current.st_mode) or len(identities) != 1:
                _raise_secure_sink_error()

        result = descriptor
        descriptor = None
        return result
    except (OSError, ValueError, AuditSinkError):
        _raise_secure_sink_error()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


class AuditSink(abc.ABC):
    """Abstract base class for audit artifact consumers."""

    @abc.abstractmethod
    def emit(self, audit_artifact: dict[str, Any]) -> None:
        """
        Receive a completed audit artifact.

        Implementations must be synchronous.  Failures should raise exceptions
        (the registry catches them and handles per failure mode).
        """


class JsonFileAuditSink(AuditSink):
    """Securely appends one JSON line per audit artifact to a regular file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def emit(self, audit_artifact: dict[str, Any]) -> None:
        line = json.dumps(audit_artifact) + "\n"
        descriptor = _open_secure_append_descriptor(self._path)
        try:
            with os.fdopen(descriptor, "a", encoding="utf-8", newline="") as fh:
                descriptor = -1
                fh.write(line)
                fh.flush()
        except (OSError, ValueError):
            _raise_secure_sink_error()
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


class CallbackAuditSink(AuditSink):
    """Calls a user-provided function with each audit artifact."""

    def __init__(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self._callback = callback

    def emit(self, audit_artifact: dict[str, Any]) -> None:
        self._callback(audit_artifact)


def set_audit_sink(sink: AuditSink | None) -> None:
    """
    Register the global audit sink.

    .. deprecated::
        Global sink registration is a compatibility path retained for
        existing code. New integrations should use instance-scoped
        ``AEGIS(sink=...)`` instead, which is thread-safe and avoids
        shared mutable state. Global registration will be removed in
        a future major release.

    Pass ``None`` to clear the registered sink (default: no sink).
    Not thread-safe; register once at application startup.
    """
    global _registered_sink
    _registered_sink = sink


def get_audit_sink() -> AuditSink | None:
    """Return the currently registered audit sink, or None."""
    return _registered_sink


def set_sink_failure_mode(mode: str) -> None:
    """Set the global sink failure mode: 'raise' or 'log'.

    The 'queue' mode is deprecated since v0.3.0 and will be removed in
    a future release.  When 'queue' is passed, a DeprecationWarning is
    emitted and the effective mode falls back to 'log'.
    """
    import warnings

    if mode == "queue":
        warnings.warn(
            "Sink failure mode 'queue' is deprecated since v0.3.0 "
            "and will be removed in a future release. "
            "Falling back to 'log' mode.",
            DeprecationWarning,
            stacklevel=2,
        )
        mode = "log"
    if mode not in ("raise", "log"):
        raise ValueError(f"Invalid sink failure mode: {mode}")
    global _sink_failure_mode
    _sink_failure_mode = mode


def get_sink_failure_mode() -> str:
    """Return the current sink failure mode."""
    return _sink_failure_mode


def emit_to_sink(
    audit_artifact: dict[str, Any],
    *,
    sink: AuditSink | None = _SENTINEL,
    failure_mode: str | None = None,
) -> None:
    """
    Emit an audit artifact to a sink.

    The artifact is deep-copied before being handed to the sink, so sinks
    cannot mutate the caller's artifact object (Invariant C).

    :param audit_artifact: Audit artifact dict to emit
    :param sink: Explicit sink to use. When omitted (sentinel), falls back
        to the module-global ``_registered_sink``.  Pass ``None`` explicitly
        to skip emission.
    :param failure_mode: Explicit failure mode (``"raise"``/``"log"``).
        When ``None``, falls back to the module-global ``_sink_failure_mode``.
    """
    effective_sink = _registered_sink if sink is _SENTINEL else sink
    if effective_sink is None:
        return
    effective_mode = failure_mode if failure_mode is not None else _sink_failure_mode
    from aegis._internal.evidence_finalizer import (
        finalize_legacy_invocation_artifact,
    )

    finalize_legacy_invocation_artifact(
        audit_artifact,
        sink=effective_sink,
        failure_mode=effective_mode,
        entry_point="legacy.emit_to_sink",
        mode="legacy_delivery",
    )
