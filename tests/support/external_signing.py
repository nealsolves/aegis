"""Deterministic, test-only external signing doubles.

These deliberately use only the standard library.  They model external key
versions and trust anchors without an SDK, network connection, or provider
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest, new
from types import MappingProxyType
from typing import Mapping

from aegis.errors import ArtifactSigningError
from aegis.signing import (
    AnchorStatus,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
)


SENSITIVE_CORPUS = (
    "AKIAIOSFODNN7EXAMPLE",
    "Bearer provider-token-123",
    "super-secret-key-material",
    "raw-signature-deadbeef",
    '{"audit_schema_version":"1.4","private":"payload-fragment"}',
    "https://provider.invalid/raw/response?id=credential",
)
_SENSITIVE_MESSAGE = " | ".join(SENSITIVE_CORPUS)
_DEFAULT_KEY_REFERENCE = "deterministic-audit-key"
_DEFAULT_ALGORITHM = "HMAC-SHA256"


@dataclass(frozen=True)
class DeterministicKeyRecord:
    """An immutable test record for one externally managed key version."""

    key_reference: str
    key_version: str
    key_material: bytes
    anchor_status: AnchorStatus
    revoked: bool = False


def default_key_records() -> Mapping[str, DeterministicKeyRecord]:
    """Return independent immutable records for current and historical keys."""
    return MappingProxyType(
        {
            "version/current": DeterministicKeyRecord(
                _DEFAULT_KEY_REFERENCE,
                "version/current",
                b"current deterministic key material",
                AnchorStatus.ANCHORED,
            ),
            "version/historical": DeterministicKeyRecord(
                _DEFAULT_KEY_REFERENCE,
                "version/historical",
                b"historical deterministic key material",
                AnchorStatus.UNANCHORED,
            ),
            "version/revoked": DeterministicKeyRecord(
                _DEFAULT_KEY_REFERENCE,
                "version/revoked",
                b"revoked deterministic key material",
                AnchorStatus.NOT_EVALUATED,
                revoked=True,
            ),
            "version/invalid-anchor": DeterministicKeyRecord(
                _DEFAULT_KEY_REFERENCE,
                "version/invalid-anchor",
                b"invalid anchor deterministic key material",
                AnchorStatus.INVALID,
            ),
        }
    )


def verify_deterministic_hmac_sha256_signature(
    payload: bytes,
    receipt: SigningReceipt,
) -> bool:
    """Verify a deterministic receipt independently, without invoking a signer."""
    if not isinstance(receipt, SigningReceipt):
        return False
    record = default_key_records().get(receipt.key_version)
    if (
        record is None
        or receipt.algorithm != _DEFAULT_ALGORITHM
        or receipt.signature_encoding is not SignatureEncoding.HEX
        or receipt.key_reference != record.key_reference
    ):
        return False
    expected = new(record.key_material, payload, sha256).hexdigest()
    return compare_digest(expected, receipt.signature)


class DeterministicExternalSigner:
    """A no-I/O HMAC signer whose modes model external signer failures."""

    def __init__(
        self,
        *,
        key_records: Mapping[str, DeterministicKeyRecord] | None = None,
        key_version: str = "version/current",
        mode: str = "normal",
    ) -> None:
        self._key_records = MappingProxyType(dict(key_records or default_key_records()))
        self._key_version = key_version
        self._mode = mode
        self.payloads: list[bytes] = []

    def signer_identity(self) -> SignerIdentity:
        if self._mode == "identity_error":
            raise ArtifactSigningError(_SENSITIVE_MESSAGE)
        if self._mode == "identity_unexpected":
            raise RuntimeError(_SENSITIVE_MESSAGE)
        if self._mode == "malformed_identity":
            return object()  # type: ignore[return-value]
        record = self._key_records[self._key_version]
        return SignerIdentity(
            _DEFAULT_ALGORITHM,
            SignatureEncoding.HEX,
            record.key_reference,
            record.key_version,
        )

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        self.payloads.append(payload)
        if self._mode == "signing_error":
            raise ArtifactSigningError(_SENSITIVE_MESSAGE)
        if self._mode == "signing_unexpected":
            raise RuntimeError(_SENSITIVE_MESSAGE)
        if self._mode == "malformed_receipt":
            return object()  # type: ignore[return-value]

        record = self._key_records.get(identity.key_version)
        if record is None or identity != SignerIdentity(
            _DEFAULT_ALGORITHM,
            SignatureEncoding.HEX,
            record.key_reference,
            record.key_version,
        ):
            raise ArtifactSigningError("External signer does not recognize key identity")
        signature = new(record.key_material, payload, sha256).hexdigest()
        receipt_version = (
            "version/rotated" if self._mode == "rotate_receipt" else identity.key_version
        )
        return SigningReceipt(
            signature,
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            receipt_version,
        )


class DeterministicExternalVerifier:
    """A deterministic verifier with exact-version lookup and trust outcomes."""

    def __init__(
        self,
        *,
        key_records: Mapping[tuple[str, str], DeterministicKeyRecord] | None = None,
        allowed_algorithms: frozenset[str] = frozenset({_DEFAULT_ALGORITHM}),
        mode: str = "normal",
    ) -> None:
        records = key_records or {
            (record.key_reference, record.key_version): record
            for record in default_key_records().values()
        }
        self._key_records = MappingProxyType(dict(records))
        self._allowed_algorithms = frozenset(allowed_algorithms)
        self._mode = mode

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        if self._mode == "unavailable":
            return ExternalVerificationOutcome(
                SignatureStatus.INDETERMINATE,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.VERIFIER_UNAVAILABLE,
                _SENSITIVE_MESSAGE,
            )
        if self._mode == "unexpected":
            raise RuntimeError(_SENSITIVE_MESSAGE)
        if self._mode == "malformed":
            return object()  # type: ignore[return-value]
        if self._mode == "malformed_combination":
            outcome = object.__new__(ExternalVerificationOutcome)
            object.__setattr__(outcome, "signature_status", SignatureStatus.VALID)
            object.__setattr__(outcome, "anchor_status", AnchorStatus.ANCHORED)
            object.__setattr__(outcome, "reason_code", VerificationReasonCode.KEY_UNKNOWN)
            object.__setattr__(outcome, "message", _SENSITIVE_MESSAGE)
            return outcome
        if metadata.algorithm not in self._allowed_algorithms:
            return self._outcome(
                SignatureStatus.INVALID,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
            )

        record = self._key_records.get((metadata.key_reference, metadata.key_version))
        if record is None:
            return self._outcome(
                SignatureStatus.UNKNOWN_KEY,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.KEY_UNKNOWN,
            )
        if record.revoked:
            return self._outcome(
                SignatureStatus.REVOKED,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.KEY_REVOKED,
            )
        expected = new(record.key_material, payload, sha256).hexdigest()
        if not compare_digest(expected, signature):
            return self._outcome(
                SignatureStatus.INVALID,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.SIGNATURE_INVALID,
            )
        if record.anchor_status is AnchorStatus.ANCHORED:
            return self._outcome(
                SignatureStatus.VALID,
                AnchorStatus.ANCHORED,
                VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
            )
        if record.anchor_status is AnchorStatus.INVALID:
            return self._outcome(
                SignatureStatus.VALID,
                AnchorStatus.INVALID,
                VerificationReasonCode.ANCHOR_INVALID,
            )
        return self._outcome(
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        )

    @staticmethod
    def _outcome(
        signature_status: SignatureStatus,
        anchor_status: AnchorStatus,
        reason_code: VerificationReasonCode,
    ) -> ExternalVerificationOutcome:
        return ExternalVerificationOutcome(
            signature_status,
            anchor_status,
            reason_code,
            _SENSITIVE_MESSAGE,
        )
