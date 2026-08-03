"""Public API wrapper for audit sink registry."""

from aegis._internal.sinks import (
    AuditSink,
    CallbackAuditSink,
    JsonFileAuditSink,
    get_audit_sink,
    set_audit_sink,
)

__all__ = [
    "AuditSink",
    "CallbackAuditSink",
    "JsonFileAuditSink",
    "get_audit_sink",
    "set_audit_sink",
]
