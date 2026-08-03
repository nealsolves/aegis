"""Single checksum, signing, schema-validation, and delivery boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol

from jsonschema import Draft7Validator

from aegis._internal.attempts import AttemptEnvelope, AttemptFactory
from aegis._internal.canonicalization import (
    CANONICALIZATION_PROFILE_V2,
    CanonicalizationError,
    canonicalize_v2,
    normalize_json_v2,
)
from aegis._internal.errors import AuditSinkError, EvidenceFinalizationError
from aegis._internal.evidence_diagnostics import EvidenceDiagnostics
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.outcomes import FailureRecord, TerminalClass
from aegis._internal.signing import (
    ArtifactSigner,
    ArtifactSignerAdapter,
    FINALIZER_INVOCATION_DOMAIN,
    FINALIZER_WORKFLOW_DOMAIN,
    FinalizerSigner,
    HMACSigner,
)
from aegis._internal.signature_models import SignatureEncoding, SignerIdentity
from aegis._internal.sinks import AuditSink


logger = logging.getLogger("aegis.evidence_finalizer")


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

        def attempt_or_body(attempt_value: str, field_name: str) -> Any:
            if attempt_value != "unknown":
                return attempt_value
            return body.get(field_name, "unknown")

        return {
            **body,
            "audit_schema_version": "2.0",
            "canonicalization_profile": CANONICALIZATION_PROFILE_V2,
            "policy_file": attempt_or_body(attempt.policy_file, "policy_file"),
            "policy_schema_version": body.get("policy_schema_version", "unknown"),
            "policy_version": body.get("policy_version", "unknown"),
            "model_provider": attempt_or_body(
                attempt.model_provider,
                "model_provider",
            ),
            "model_identifier": attempt_or_body(
                attempt.model_identifier,
                "model_identifier",
            ),
            "role": attempt_or_body(attempt.role, "role"),
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


# Compatibility bridge for pre-B2 artifact builders. Delivery and all
# finalization-owned fields still cross the one finalizer above; v2 entry points
# require acknowledged sinks, while narrowly authorized legacy log behavior is
# isolated in the adapter below.
_LEGACY_SINK_UNSET = object()
_LEGACY_ATTEMPTS = AttemptFactory()
_CURRENT_ATTEMPT: ContextVar[AttemptEnvelope | None] = ContextVar(
    "aegis_current_evidence_attempt",
    default=None,
)
_CURRENT_RUNTIME: ContextVar[
    tuple[object, object, str | None, EvidenceDiagnostics | None] | None
] = (
    ContextVar("aegis_current_evidence_runtime", default=None)
)
_AUDIT_VALIDATOR: Draft7Validator | None = None
_WORKFLOW_VALIDATOR: Draft7Validator | None = None
_AUDIT_VALIDATOR_LOCK = threading.Lock()


class _DiscardAuditSink(AuditSink):
    def emit(self, audit_artifact: dict[str, Any]) -> None:
        del audit_artifact


class _LegacyLogAuditSink(AuditSink):
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def emit(self, audit_artifact: dict[str, Any]) -> None:
        try:
            self._sink.emit(audit_artifact)
        except Exception:  # noqa: BLE001 - compatibility boundary
            logger.warning("Audit sink emit failed in authorized legacy log mode")


class _EvidenceAbort(BaseException):
    """Unwind legacy exception handlers without exposing raw sink failures."""

    def __init__(self, error: AuditSinkError | EvidenceFinalizationError) -> None:
        self.error = error


@contextmanager
def evidence_attempt(
    attempt: AttemptEnvelope,
    *,
    sink: object = _LEGACY_SINK_UNSET,
    signer: object = None,
    failure_mode: str | None = None,
    diagnostics: EvidenceDiagnostics | None = None,
):
    """Bind one preallocated attempt to all finalization in this call path."""
    attempt_token = _CURRENT_ATTEMPT.set(attempt)
    runtime_token = _CURRENT_RUNTIME.set(
        (sink, signer, failure_mode, diagnostics)
    )
    try:
        yield
    finally:
        _CURRENT_RUNTIME.reset(runtime_token)
        _CURRENT_ATTEMPT.reset(attempt_token)


def _audit_validator() -> Draft7Validator:
    global _AUDIT_VALIDATOR
    with _AUDIT_VALIDATOR_LOCK:
        if _AUDIT_VALIDATOR is None:
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / (
                "audit_artifact.schema.json"
            )
            _AUDIT_VALIDATOR = Draft7Validator(
                json.loads(schema_path.read_text(encoding="utf-8"))
            )
        return _AUDIT_VALIDATOR


def _workflow_validator() -> Draft7Validator:
    global _WORKFLOW_VALIDATOR
    with _AUDIT_VALIDATOR_LOCK:
        if _WORKFLOW_VALIDATOR is None:
            schema_path = Path(__file__).resolve().parents[1] / "schemas" / (
                "workflow_artifact.schema.json"
            )
            _WORKFLOW_VALIDATOR = Draft7Validator(
                json.loads(schema_path.read_text(encoding="utf-8"))
            )
        return _WORKFLOW_VALIDATOR


def _legacy_sink(sink: object, failure_mode: str | None) -> AuditSink:
    from aegis._internal.sinks import get_sink_failure_mode

    if sink is _LEGACY_SINK_UNSET:
        from aegis._internal.sinks import get_audit_sink

        selected = get_audit_sink()
    else:
        selected = sink
    if selected is None:
        return _DiscardAuditSink()
    if not isinstance(selected, AuditSink):
        raise TypeError("sink must be an AuditSink")
    effective_mode = get_sink_failure_mode() if failure_mode is None else failure_mode
    if effective_mode == "log":
        return _LegacyLogAuditSink(selected)
    return selected


def _legacy_finalizer_signer(
    signer: ArtifactSigner | FinalizerSigner | None,
) -> FinalizerSigner | None:
    if signer is None:
        return None
    if isinstance(signer, ArtifactSigner):
        if isinstance(signer, HMACSigner):
            identity = SignerIdentity(
                algorithm="HMAC-SHA256",
                signature_encoding=SignatureEncoding.HEX,
                key_reference="local://legacy-artifact-signer",
                key_version="1",
            )
        else:
            identity_provider = getattr(signer, "signer_identity", None)
            identity = identity_provider() if callable(identity_provider) else None
            if not isinstance(identity, SignerIdentity):
                raise EvidenceFinalizationError(
                    "Configured legacy signer does not declare v2 identity"
                )
        return ArtifactSignerAdapter(
            signer,
            identity,
        )
    if not hasattr(signer, "sign"):
        raise TypeError("signer must provide sign()")
    return signer


def finalize_legacy_invocation_artifact(
    artifact: Mapping[str, Any],
    *,
    invocation: object | None = None,
    attempt: AttemptEnvelope | None = None,
    entry_point: str = "enforcement",
    mode: str = "unified",
    sink: object = _LEGACY_SINK_UNSET,
    failure_mode: str | None = None,
    signer: ArtifactSigner | FinalizerSigner | None = None,
) -> dict[str, Any]:
    """Finalize a detached legacy builder result through the v2 boundary."""
    runtime = _CURRENT_RUNTIME.get()
    if runtime is not None:
        (
            runtime_sink,
            runtime_signer,
            runtime_failure_mode,
            runtime_diagnostics,
        ) = runtime
        if sink is _LEGACY_SINK_UNSET:
            sink = runtime_sink
        if signer is None:
            signer = runtime_signer  # type: ignore[assignment]
        if failure_mode is None:
            failure_mode = runtime_failure_mode
    else:
        runtime_diagnostics = None
    detached = copy.deepcopy(dict(artifact))
    source_invocation = invocation
    if source_invocation is None:
        source_invocation = {
            "policy_file": detached.get("policy_file"),
            "model_provider": detached.get("model_provider"),
            "model_identifier": detached.get("model_identifier"),
            "role": detached.get("role"),
            "input": {},
            "output": {},
            "context": detached.get("context", {}),
        }
    envelope = attempt or _CURRENT_ATTEMPT.get()
    if envelope is None:
        envelope = _LEGACY_ATTEMPTS.allocate(
            entry_point,
            mode,
            source_invocation,
        )
    raw_failures = detached.pop("failures", [])
    failures: list[FailureRecord] = []
    if isinstance(raw_failures, list):
        for raw in raw_failures:
            if not isinstance(raw, Mapping):
                continue
            failures.append(
                FailureRecord(
                    code=str(raw.get("code", "UNKNOWN")),
                    message=str(raw.get("message", ""))[:1024],
                    field=(
                        str(raw["field"])
                        if raw.get("field") is not None
                        else None
                    ),
                )
            )
    terminal = (
        TerminalClass.ALLOW
        if detached.get("enforcement_result") == "PASS"
        else TerminalClass.DENY
    )
    for field_name in _FINALIZATION_FIELDS:
        detached.pop(field_name, None)
    detached.pop("enforcement_result", None)
    try:
        finalizer = EvidenceFinalizer(
            EvidenceFinalizerConfig(
                sink=_legacy_sink(sink, failure_mode),
                signer=_legacy_finalizer_signer(signer),
                schema_validator=_audit_validator(),
            )
        )
        finalized = finalizer.finalize(
            EvidenceDraft(
                attempt=envelope,
                terminal=terminal,
                artifact_type="invocation",
                body=detached,
                failures=tuple(failures),
            )
        )
    except AuditSinkError as exc:
        if runtime_diagnostics is not None:
            runtime_diagnostics.record_delivery_failure(
                envelope.attempt_id,
                "emit",
                exc.code,
            )
            raise _EvidenceAbort(exc) from exc
        raise
    except EvidenceFinalizationError as exc:
        if runtime_diagnostics is not None:
            runtime_diagnostics.record_finalization_failure(
                envelope.attempt_id,
                "finalize",
                exc.code,
            )
            raise _EvidenceAbort(exc) from exc
        raise
    except CanonicalizationError as exc:
        if runtime_diagnostics is not None:
            runtime_diagnostics.record_finalization_failure(
                envelope.attempt_id,
                "canonicalize",
                exc.code,
            )
            raise _EvidenceAbort(exc) from exc
        raise
    except Exception as exc:
        bounded = EvidenceFinalizationError(
            "Evidence finalizer setup failed"
        )
        if runtime_diagnostics is not None:
            runtime_diagnostics.record_finalization_failure(
                envelope.attempt_id,
                "setup",
                bounded.code,
            )
            raise _EvidenceAbort(bounded) from exc
        raise bounded from exc
    if isinstance(artifact, dict):
        artifact.clear()
        artifact.update(copy.deepcopy(finalized))
        return artifact
    return finalized


def finalize_legacy_workflow_artifact(
    artifact: Mapping[str, Any],
    *,
    attempt: AttemptEnvelope | None = None,
    diagnostics: EvidenceDiagnostics | None = None,
    sink: object = _LEGACY_SINK_UNSET,
    failure_mode: str | None = None,
    signer: ArtifactSigner | FinalizerSigner | None = None,
) -> dict[str, Any]:
    """Finalize a detached workflow builder result through the v2 boundary."""
    detached = copy.deepcopy(dict(artifact))
    envelope = attempt or _LEGACY_ATTEMPTS.allocate(
        "governance_session.finalize",
        "workflow",
        {"policy_file": detached.get("policy_file")},
    )
    status = detached.get("status")
    terminal = (
        TerminalClass.ALLOW
        if status == "COMPLETED"
        else TerminalClass.EXECUTION_FAILURE
    )
    for field_name in _FINALIZATION_FIELDS:
        detached.pop(field_name, None)
    try:
        finalizer = EvidenceFinalizer(
            EvidenceFinalizerConfig(
                sink=_legacy_sink(sink, failure_mode),
                signer=_legacy_finalizer_signer(signer),
                schema_validator=_workflow_validator(),
            )
        )
        finalized = finalizer.finalize(
            EvidenceDraft(
                attempt=envelope,
                terminal=terminal,
                artifact_type="workflow",
                body=detached,
                chain_eligible=False,
            )
        )
    except AuditSinkError as exc:
        if diagnostics is not None:
            diagnostics.record_delivery_failure(
                envelope.attempt_id,
                "emit",
                exc.code,
            )
        raise
    except EvidenceFinalizationError as exc:
        if diagnostics is not None:
            diagnostics.record_finalization_failure(
                envelope.attempt_id,
                "finalize",
                exc.code,
            )
        raise
    except Exception as exc:
        bounded = EvidenceFinalizationError(
            "Evidence finalizer setup failed"
        )
        if diagnostics is not None:
            diagnostics.record_finalization_failure(
                envelope.attempt_id,
                "setup",
                bounded.code,
            )
        raise bounded from exc
    if isinstance(artifact, dict):
        artifact.clear()
        artifact.update(copy.deepcopy(finalized))
        return artifact
    return finalized
