"""Shared result contracts for chain and workflow verification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Completeness(str, Enum):
    UNPROVEN = "unproven"
    CHECKPOINT_PROVEN = "checkpoint_proven"
    CONTRADICTED = "contradicted"


@dataclass(frozen=True, slots=True)
class VerificationError:
    code: str
    message: str
    index: int | None = None
