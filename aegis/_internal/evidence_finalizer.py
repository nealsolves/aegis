"""Single checksum, signing, schema-validation, and delivery boundary."""

from __future__ import annotations

import copy
import hashlib
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol

from aegis._internal.attempts import AttemptEnvelope
from aegis._internal.canonicalization import (
    CANONICALIZATION_PROFILE_V2,
    canonicalize_v2,
    normalize_json_v2,
)
from aegis._internal.errors import AuditSinkError, EvidenceFinalizationError
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.outcomes import FailureRecord, TerminalClass
from aegis._internal.signing import (
    FINALIZER_INVOCATION_DOMAIN,
    FINALIZER_WORKFLOW_DOMAIN,
    FinalizerSigner,
)
from aegis._internal.sinks import AuditSink


_FINALIZATION_FIELDS = frozenset(
    {
        "audit_schema_version",
        "canonicalization_profile",
        "checksum",
        "signature",
        "signature_metadata",
        "signature_status",
        "workflow_schema_version",
    }
)


class SchemaValidator(Protocol):
    def validate(self, artifact: object) -> None: ...


class _DraftClaim:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._claimed = False

    def claim(self) -> bool:
        with self._lock:
            if self._claimed:
                return False
            self._claimed = True
            return True


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _frozen_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("evidence draft mappings must be mappings")
    normalized = normalize_json_v2(dict(value))
    if type(normalized) is not dict:  # pragma: no cover - fixed root input
        raise TypeError("evidence draft mapping did not normalize to an object")
    return _freeze_json(normalized)


@dataclass(frozen=True, slots=True)
class EvidenceDraft:
    attempt: AttemptEnvelope
    terminal: TerminalClass
    artifact_type: Literal["invocation", "workflow"]
    body: Mapping[str, Any]
    failures: tuple[FailureRecord, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    workflow_correlation: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )
    chain_eligible: bool = True
    _claim: _DraftClaim = field(
        default_factory=_DraftClaim,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.attempt, AttemptEnvelope):
            raise TypeError("attempt must be an AttemptEnvelope")
        if type(self.terminal) is not TerminalClass:
            raise TypeError("terminal must be a TerminalClass")
        if self.artifact_type not in {"invocation", "workflow"}:
            raise ValueError("artifact_type must be invocation or workflow")
        if type(self.failures) is not tuple or not all(
            isinstance(item, FailureRecord) for item in self.failures
        ):
            raise TypeError("failures must be a tuple of FailureRecord values")
        object.__setattr__(self, "body", _frozen_mapping(self.body))
        object.__setattr__(self, "metadata", _frozen_mapping(self.metadata))
        object.__setattr__(
            self,
            "workflow_correlation",
            _frozen_mapping(self.workflow_correlation),
        )


class _DeliveryCapability:
    __slots__ = ()


_DELIVERY_CAPABILITY = _DeliveryCapability()


@dataclass(frozen=True, slots=True)
class EvidenceFinalizerConfig:
    sink: AuditSink
    signer: FinalizerSigner | None
    schema_validator: SchemaValidator
    failure_mode: Literal["raise"] = "raise"
    clock: Callable[[], int | float] = time.time
    delivery_capability: _DeliveryCapability = field(
        default=_DELIVERY_CAPABILITY,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.sink, AuditSink):
            raise TypeError("sink must be an AuditSink")
        if self.failure_mode != "raise":
            raise ValueError("v2 evidence delivery failure mode must be 'raise'")
        if self.delivery_capability is not _DELIVERY_CAPABILITY:
            raise ValueError("invalid evidence delivery capability")
        if not hasattr(self.schema_validator, "validate"):
            raise TypeError("schema_validator must provide validate()")


def _json_checksum(value: object) -> str:
    return hashlib.sha256(canonicalize_v2(_plain_json(value)).data).hexdigest()


def _failure_dict(failure: FailureRecord) -> dict[str, Any]:
    return {
        "code": failure.code,
        "message": failure.message,
        "field": failure.field,
    }


class EvidenceFinalizer:
    """Own the only acknowledged transition from draft to final evidence."""

    def __init__(self, config: EvidenceFinalizerConfig) -> None:
        if not isinstance(config, EvidenceFinalizerConfig):
            raise TypeError("config must be EvidenceFinalizerConfig")
        self._config = config

    def _build_invocation(self, draft: EvidenceDraft) -> dict[str, Any]:
        body = _plain_json(draft.body)
        supplied = sorted(_FINALIZATION_FIELDS.intersection(body))
        if supplied:
            raise EvidenceFinalizationError(
                "Evidence draft contains finalization-owned fields"
            )
        metadata = body.pop("metadata", {})
        if type(metadata) is not dict:
            raise EvidenceFinalizationError("Evidence metadata must be an object")
        metadata.update(_plain_json(draft.metadata))
        if draft.workflow_correlation:
            metadata["workflow_correlation"] = _plain_json(
                draft.workflow_correlation
            )
        attempt = draft.attempt
        failures = [_failure_dict(item) for item in draft.failures]
        allows = draft.terminal in {TerminalClass.ALLOW, TerminalClass.WARN}
        return {
            **body,
            "audit_schema_version": "2.0",
            "canonicalization_profile": CANONICALIZATION_PROFILE_V2,
            "policy_file": attempt.policy_file,
            "policy_schema_version": body.get("policy_schema_version", "unknown"),
            "policy_version": body.get("policy_version", "unknown"),
            "model_provider": attempt.model_provider,
            "model_identifier": attempt.model_identifier,
            "role": attempt.role,
            "enforcement_result": "PASS" if allows else "FAIL",
            "failures": failures,
            "failure_gate": body.get(
                "failure_gate",
                None if allows else "invocation_validation",
            ),
            "failure_reason": body.get(
                "failure_reason",
                None if allows or not failures else failures[0]["message"],
            ),
            "input_checksum": body.get(
                "input_checksum", _json_checksum(attempt.input)
            ),
            "output_checksum": body.get(
                "output_checksum", _json_checksum(attempt.output)
            ),
            "timestamp": body.get("timestamp", attempt.started_at),
            "context": body.get("context", _plain_json(attempt.context)),
            "metadata": metadata,
            "risk_score": body.get("risk_score"),
            "provenance": body.get("provenance"),
        }

    def _build_workflow(self, draft: EvidenceDraft) -> dict[str, Any]:
        body = _plain_json(draft.body)
        supplied = sorted(_FINALIZATION_FIELDS.intersection(body))
        if supplied:
            raise EvidenceFinalizationError(
                "Evidence draft contains finalization-owned fields"
            )
        metadata = body.pop("metadata", {})
        if type(metadata) is not dict:
            raise EvidenceFinalizationError("Evidence metadata must be an object")
        metadata.update(_plain_json(draft.metadata))
        return {
            **body,
            "workflow_schema_version": "2.0",
            "canonicalization_profile": CANONICALIZATION_PROFILE_V2,
            "metadata": metadata,
        }

    def _sign_or_mark_unsigned(
        self,
        artifact: dict[str, Any],
        draft: EvidenceDraft,
    ) -> dict[str, Any]:
        if self._config.signer is None:
            return {
                **artifact,
                "signature_status": "unsigned",
                "signature": None,
            }
        domain = (
            FINALIZER_INVOCATION_DOMAIN
            if draft.artifact_type == "invocation"
            else FINALIZER_WORKFLOW_DOMAIN
        )
        try:
            return self._config.signer.sign(
                artifact,
                domain=domain,
                signed_at=int(self._config.clock()),
            )
        except Exception as exc:
            raise EvidenceFinalizationError(
                "Configured evidence signer failed"
            ) from exc

    def _emit_acknowledged(self, artifact: dict[str, Any]) -> None:
        if self._config.delivery_capability is not _DELIVERY_CAPABILITY:
            raise EvidenceFinalizationError("Evidence delivery capability is invalid")
        try:
            self._config.sink.emit(copy.deepcopy(artifact))
        except Exception as exc:
            raise AuditSinkError(
                "Finalized evidence delivery failed",
                code="AUDIT_DELIVERY_FAILED",
            ) from exc

    def finalize(self, draft: EvidenceDraft) -> dict[str, Any]:
        if not isinstance(draft, EvidenceDraft):
            raise EvidenceFinalizationError("Evidence draft is invalid")
        if not draft._claim.claim():
            raise EvidenceFinalizationError("Evidence draft was already finalized")
        try:
            built = (
                self._build_invocation(draft)
                if draft.artifact_type == "invocation"
                else self._build_workflow(draft)
            )
            normalized = normalize_json_v2(built)
            checksummed = build_content_checksum_v2(normalized)
            signed = self._sign_or_mark_unsigned(checksummed, draft)
            normalized_final = normalize_json_v2(signed)
            if type(normalized_final) is not dict:  # pragma: no cover
                raise EvidenceFinalizationError("Final evidence is not an object")
            self._config.schema_validator.validate(normalized_final)
        except (AuditSinkError, EvidenceFinalizationError):
            raise
        except Exception as exc:
            raise EvidenceFinalizationError(
                "Evidence normalization or schema validation failed"
            ) from exc
        self._emit_acknowledged(normalized_final)
        return copy.deepcopy(normalized_final)
