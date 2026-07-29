"""Provider-neutral public-contract checks for external signing recipes."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import logging
from typing import Any, Callable, Iterator, Sequence

import pytest

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.signing import (
    AnchorStatus,
    ArtifactVerificationResult,
    SignatureMetadata,
    SignatureStatus,
    SigningReceipt,
    VerificationReasonCode,
    sign_artifact_with_metadata,
    verify_artifact_detailed,
)


class SignerScenario(str, Enum):
    """Provider-neutral signer behaviors required by the public contract."""

    NORMAL = "normal"
    IDENTITY_ERROR = "identity_error"
    IDENTITY_UNEXPECTED = "identity_unexpected"
    MALFORMED_IDENTITY = "malformed_identity"
    SIGNING_ERROR = "signing_error"
    SIGNING_UNEXPECTED = "signing_unexpected"
    MALFORMED_RECEIPT = "malformed_receipt"


class VerifierScenario(str, Enum):
    """Provider-neutral verifier behaviors required by the public contract."""

    NORMAL = "normal"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    MALFORMED_COMBINATION = "malformed_combination"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True)
class SignerFixture:
    """A signer plus independent checks for its externally produced signatures."""

    signer: object
    recorded_payloads: Callable[[], Sequence[bytes]]
    verify_signature: Callable[[bytes, SigningReceipt], bool]


@dataclass(frozen=True)
class SignedArtifactFixture:
    """A signed artifact and its recorded canonical external-signing payload."""

    artifact: dict[str, Any]
    canonical_payload: bytes


SignerFactory = Callable[[SignerScenario], SignerFixture]
SignedArtifactFactory = Callable[[str], SignedArtifactFixture]
VerifierFactory = Callable[[VerifierScenario], object]

_REDACTION_CORPUS = (
    "AKIAIOSFODNN7EXAMPLE",
    "Bearer provider-token-123",
    "super-secret-key-material",
    "raw-signature-deadbeef",
    '{"audit_schema_version":"1.4","private":"payload-fragment"}',
    "https://provider.invalid/raw/response?id=credential",
)


class _RecordingVerifier:
    """Record exact core-supplied payloads while preserving an opaque verifier."""

    def __init__(self, verifier: object) -> None:
        self._verifier = verifier
        self.payloads: list[bytes] = []

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> object:
        self.payloads.append(payload)
        return self._verifier.verify(  # type: ignore[attr-defined]
            payload,
            signature,
            metadata,
        )


def _exact_verifier_payloads(
    verifier: _RecordingVerifier,
    *,
    expected_calls: int = 1,
) -> tuple[bytes, ...]:
    assert len(verifier.payloads) == expected_calls
    return tuple(verifier.payloads)


class _LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(logging.Formatter("%(message)s"))
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


@contextmanager
def _capture_logs() -> Iterator[_LogCapture]:
    """Capture and discard only logs emitted by one conformance scenario."""
    root_logger = logging.getLogger()
    previous_level = root_logger.level
    capture = _LogCapture()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(capture)
    try:
        yield capture
    finally:
        root_logger.removeHandler(capture)
        root_logger.setLevel(previous_level)


def _artifact() -> dict[str, Any]:
    return {
        "audit_schema_version": "1.4",
        "event": "external signing conformance",
        "signature": None,
    }


def _assert_not_redacted(
    rendered: str,
    *,
    payloads: Sequence[bytes] = (),
    raw_signature: object = None,
) -> None:
    for sensitive_value in _REDACTION_CORPUS:
        assert sensitive_value not in rendered
    for payload in payloads:
        assert payload.decode("utf-8", "replace") not in rendered
    if isinstance(raw_signature, str):
        assert raw_signature not in rendered


def _assert_safe_error(
    error: BaseException,
    logs: _LogCapture | str,
    *,
    payloads: Sequence[bytes] = (),
    raw_signature: object = None,
) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert getattr(error, "details", {}) in ({}, {"field": "signature"})
    log_text = logs if isinstance(logs, str) else logs.text
    rendered = "\n".join(
        (
            str(error),
            repr(getattr(error, "details", {})),
            repr(error.__cause__),
            repr(error.__context__),
            log_text,
        )
    )
    _assert_not_redacted(
        rendered,
        payloads=payloads,
        raw_signature=raw_signature,
    )


def _assert_safe_result(
    result: object,
    logs: _LogCapture | str,
    *,
    payloads: Sequence[bytes] = (),
    raw_signature: object = None,
) -> None:
    assert isinstance(result, ArtifactVerificationResult)
    log_text = logs if isinstance(logs, str) else logs.text
    rendered = "\n".join(
        (
            str(result.signature_status),
            str(result.anchor_status),
            str(result.reason_code),
            result.message,
            log_text,
        )
    )
    _assert_not_redacted(
        rendered,
        payloads=payloads,
        raw_signature=raw_signature,
    )


def _assert_unchanged(artifact: dict[str, Any], snapshot: dict[str, Any]) -> None:
    assert artifact == snapshot


def _make_signed_artifact(
    signed_artifact_factory: SignedArtifactFactory, key_version: str
) -> SignedArtifactFixture:
    with _capture_logs() as logs:
        fixture = signed_artifact_factory(key_version)
    _assert_not_redacted(
        logs.text,
        payloads=(fixture.canonical_payload,),
        raw_signature=fixture.artifact["signature"],
    )
    return fixture


def assert_external_signer_conformance(signer_factory: SignerFactory) -> None:
    """Assert the public signing contract through provider-neutral scenarios."""
    with _capture_logs() as setup_logs:
        fixture = signer_factory(SignerScenario.NORMAL)
    _assert_not_redacted(setup_logs.text)
    signer = fixture.signer
    with _capture_logs() as logs:
        identity = signer.signer_identity()  # type: ignore[attr-defined]
    _assert_not_redacted(logs.text)
    with _capture_logs() as logs:
        repeated_identity = signer.signer_identity()  # type: ignore[attr-defined]
    _assert_not_redacted(logs.text)
    assert identity == repeated_identity

    payload = b"external signing conformance payload\x00exact bytes"
    with _capture_logs() as logs:
        receipt = signer.sign(payload, identity)  # type: ignore[attr-defined]
    _assert_not_redacted(logs.text, payloads=(payload,), raw_signature=receipt.signature)
    with _capture_logs() as logs:
        repeated_receipt = signer.sign(payload, identity)  # type: ignore[attr-defined]
    _assert_not_redacted(
        logs.text,
        payloads=(payload,),
        raw_signature=repeated_receipt.signature,
    )
    with _capture_logs() as logs:
        changed_receipt = signer.sign(payload + b"!", identity)  # type: ignore[attr-defined]
    _assert_not_redacted(
        logs.text,
        payloads=(payload + b"!",),
        raw_signature=changed_receipt.signature,
    )
    assert fixture.verify_signature(payload, receipt) is True
    assert fixture.verify_signature(payload, repeated_receipt) is True
    assert fixture.verify_signature(payload + b"!", receipt) is False
    assert fixture.verify_signature(payload, changed_receipt) is False
    assert fixture.verify_signature(payload + b"!", changed_receipt) is True
    assert receipt.algorithm == identity.algorithm
    assert receipt.signature_encoding is identity.signature_encoding
    assert receipt.key_reference == identity.key_reference
    assert receipt.key_version == identity.key_version

    for scenario, error_type in (
        (SignerScenario.IDENTITY_ERROR, ArtifactSigningError),
        (SignerScenario.IDENTITY_UNEXPECTED, ArtifactSigningError),
        (SignerScenario.MALFORMED_IDENTITY, SigningContractError),
        (SignerScenario.SIGNING_ERROR, ArtifactSigningError),
        (SignerScenario.SIGNING_UNEXPECTED, ArtifactSigningError),
        (SignerScenario.MALFORMED_RECEIPT, SigningContractError),
    ):
        artifact = _artifact()
        snapshot = deepcopy(artifact)
        with _capture_logs() as setup_logs:
            fixture = signer_factory(scenario)
        with _capture_logs() as logs:
            with pytest.raises(error_type) as caught:
                sign_artifact_with_metadata(artifact, fixture.signer, signed_at=123)
        _assert_safe_error(
            caught.value,
            setup_logs.text + logs.text,
            payloads=tuple(fixture.recorded_payloads()),
        )
        _assert_unchanged(artifact, snapshot)


def assert_external_verifier_conformance(
    signed_artifact_factory: SignedArtifactFactory,
    verifier_factory: VerifierFactory,
) -> None:
    """Assert exact-version verification and safe public verification outcomes."""
    unsigned = _artifact()
    snapshot = deepcopy(unsigned)
    with _capture_logs() as logs:
        recording_verifier = _RecordingVerifier(
            verifier_factory(VerifierScenario.NORMAL)
        )
        result = verify_artifact_detailed(
            unsigned,
            verifier=recording_verifier,
        )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.UNSIGNED,
    )
    _assert_safe_result(
        result,
        logs,
        payloads=_exact_verifier_payloads(
            recording_verifier,
            expected_calls=0,
        ),
    )
    _assert_unchanged(unsigned, snapshot)

    cases = (
        (
            "version/current",
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
        ),
        (
            "version/historical",
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        ),
        (
            "version/revoked",
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.KEY_REVOKED,
        ),
        (
            "version/invalid-anchor",
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            VerificationReasonCode.ANCHOR_INVALID,
        ),
    )
    for version, status, anchor, reason in cases:
        fixture = _make_signed_artifact(signed_artifact_factory, version)
        artifact = fixture.artifact
        snapshot = deepcopy(artifact)
        with _capture_logs() as logs:
            recording_verifier = _RecordingVerifier(
                verifier_factory(VerifierScenario.NORMAL)
            )
            result = verify_artifact_detailed(
                artifact,
                verifier=recording_verifier,
            )
        assert (result.signature_status, result.anchor_status, result.reason_code) == (
            status,
            anchor,
            reason,
        )
        _assert_safe_result(
            result,
            logs,
            payloads=_exact_verifier_payloads(recording_verifier),
            raw_signature=artifact["signature"],
        )
        _assert_unchanged(artifact, snapshot)

    fixture = _make_signed_artifact(
        signed_artifact_factory, "version/current"
    )
    unknown = fixture.artifact
    unknown["signature_metadata"]["key_version"] = "version/unknown"
    snapshot = deepcopy(unknown)
    with _capture_logs() as logs:
        recording_verifier = _RecordingVerifier(
            verifier_factory(VerifierScenario.NORMAL)
        )
        result = verify_artifact_detailed(
            unknown,
            verifier=recording_verifier,
        )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_UNKNOWN,
    )
    _assert_safe_result(
        result,
        logs,
        payloads=_exact_verifier_payloads(recording_verifier),
        raw_signature=unknown["signature"],
    )
    _assert_unchanged(unknown, snapshot)

    fixture = _make_signed_artifact(
        signed_artifact_factory, "version/current"
    )
    invalid_signature = fixture.artifact
    invalid_signature["signature"] = "00" * 32
    snapshot = deepcopy(invalid_signature)
    with _capture_logs() as logs:
        recording_verifier = _RecordingVerifier(
            verifier_factory(VerifierScenario.NORMAL)
        )
        result = verify_artifact_detailed(
            invalid_signature,
            verifier=recording_verifier,
        )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.SIGNATURE_INVALID,
    )
    _assert_safe_result(
        result,
        logs,
        payloads=_exact_verifier_payloads(recording_verifier),
        raw_signature=invalid_signature["signature"],
    )
    _assert_unchanged(invalid_signature, snapshot)

    fixture = _make_signed_artifact(
        signed_artifact_factory, "version/current"
    )
    algorithm_denied = fixture.artifact
    algorithm_denied["signature_metadata"]["algorithm"] = "RSA-SHA256"
    snapshot = deepcopy(algorithm_denied)
    with _capture_logs() as logs:
        recording_verifier = _RecordingVerifier(
            verifier_factory(VerifierScenario.NORMAL)
        )
        result = verify_artifact_detailed(
            algorithm_denied,
            verifier=recording_verifier,
        )
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
    )
    _assert_safe_result(
        result,
        logs,
        payloads=_exact_verifier_payloads(recording_verifier),
        raw_signature=algorithm_denied["signature"],
    )
    _assert_unchanged(algorithm_denied, snapshot)

    fixture = _make_signed_artifact(
        signed_artifact_factory, "version/current"
    )
    unavailable = fixture.artifact
    snapshot = deepcopy(unavailable)
    with _capture_logs() as logs:
        result = verify_artifact_detailed(unavailable)
    assert (result.signature_status, result.anchor_status, result.reason_code) == (
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
    )
    _assert_safe_result(
        result,
        logs,
        payloads=(fixture.canonical_payload,),
        raw_signature=unavailable["signature"],
    )
    _assert_unchanged(unavailable, snapshot)

    fixture = _make_signed_artifact(
        signed_artifact_factory, "version/current"
    )
    unavailable = fixture.artifact
    snapshot = deepcopy(unavailable)
    with _capture_logs() as logs:
        recording_verifier = _RecordingVerifier(
            verifier_factory(VerifierScenario.UNAVAILABLE)
        )
        result = verify_artifact_detailed(
            unavailable,
            verifier=recording_verifier,
        )
    assert result.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE
    _assert_safe_result(
        result,
        logs,
        payloads=_exact_verifier_payloads(recording_verifier),
        raw_signature=unavailable["signature"],
    )
    _assert_unchanged(unavailable, snapshot)

    for scenario in (
        VerifierScenario.MALFORMED,
        VerifierScenario.MALFORMED_COMBINATION,
        VerifierScenario.UNEXPECTED,
    ):
        fixture = _make_signed_artifact(
            signed_artifact_factory, "version/current"
        )
        artifact = fixture.artifact
        snapshot = deepcopy(artifact)
        with _capture_logs() as logs:
            recording_verifier = _RecordingVerifier(verifier_factory(scenario))
            with pytest.raises(VerificationContractError) as caught:
                verify_artifact_detailed(
                    artifact,
                    verifier=recording_verifier,
                )
        _assert_safe_error(
            caught.value,
            logs,
            payloads=_exact_verifier_payloads(recording_verifier),
            raw_signature=artifact["signature"],
        )
        _assert_unchanged(artifact, snapshot)
