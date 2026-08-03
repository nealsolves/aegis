"""Suite-wide host configuration for the fail-closed module API."""

from __future__ import annotations

import functools

import pytest

from aegis._internal.enforcement import (
    AEGIS,
    _reset_module_enforcement_for_test,
    configure_module_enforcement,
)
from aegis._internal.sinks import (
    AuditSink,
    get_audit_sink,
    get_sink_failure_mode,
)


class _RegisteredTestSink(AuditSink):
    """Bridge legacy sink-focused tests into an explicitly configured host."""

    def emit(self, audit_artifact):
        selected = get_audit_sink()
        if selected is None:
            return
        try:
            selected.emit(audit_artifact)
        except Exception:  # noqa: BLE001 - exercises legacy compatibility
            if get_sink_failure_mode() == "raise":
                raise


class _DiscardTestSink(AuditSink):
    def emit(self, audit_artifact):
        del audit_artifact


@pytest.fixture(autouse=True)
def _configured_evidence_runtime(monkeypatch):
    original_init = AEGIS.__init__

    @functools.wraps(original_init)
    def initialized_with_test_sink(self, *args, **kwargs):
        if "sink" not in kwargs:
            kwargs["sink"] = _DiscardTestSink()
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(AEGIS, "__init__", initialized_with_test_sink)
    _reset_module_enforcement_for_test()
    configure_module_enforcement(sink=_RegisteredTestSink())
    yield
    _reset_module_enforcement_for_test()
