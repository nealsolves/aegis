"""Non-recursive last-resort diagnostics for evidence loss."""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass


logger = logging.getLogger("aegis.evidence_diagnostics")

_SAFE_STAGE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_SAFE_REASON_CODE = re.compile(r"^[A-Z0-9_]{1,128}$")


@dataclass(frozen=True, slots=True)
class EvidenceDiagnosticsSnapshot:
    """Read-only snapshot of evidence-loss counters."""

    evidence_finalization_failures_total: int
    evidence_delivery_failures_total: int


def _safe_stage(value: object) -> str:
    return value if isinstance(value, str) and _SAFE_STAGE.fullmatch(value) else "unknown"


def _safe_reason_code(value: object) -> str:
    return (
        value
        if isinstance(value, str) and _SAFE_REASON_CODE.fullmatch(value)
        else "UNKNOWN"
    )


def _safe_attempt_id(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else -1


class EvidenceDiagnostics:
    """Count and log failures without attempting to produce more evidence."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._finalization_failures = 0
        self._delivery_failures = 0

    def record_finalization_failure(
        self, attempt_id: int, stage: str, reason_code: str
    ) -> None:
        with self._lock:
            self._finalization_failures += 1
        logger.error(
            "evidence_finalization_failure attempt_id=%d stage=%s reason_code=%s",
            _safe_attempt_id(attempt_id),
            _safe_stage(stage),
            _safe_reason_code(reason_code),
        )

    def record_delivery_failure(
        self, attempt_id: int, stage: str, reason_code: str
    ) -> None:
        with self._lock:
            self._delivery_failures += 1
        logger.error(
            "evidence_delivery_failure attempt_id=%d stage=%s reason_code=%s",
            _safe_attempt_id(attempt_id),
            _safe_stage(stage),
            _safe_reason_code(reason_code),
        )

    def snapshot(self) -> EvidenceDiagnosticsSnapshot:
        with self._lock:
            return EvidenceDiagnosticsSnapshot(
                evidence_finalization_failures_total=self._finalization_failures,
                evidence_delivery_failures_total=self._delivery_failures,
            )
