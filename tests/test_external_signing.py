"""Contract tests for external artifact signing boundaries."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from aegis._internal.errors import (
    ArtifactSigningError,
    SignatureMetadataError,
    SigningContractError,
    VerificationContractError,
)
from aegis._internal.external_signing import (
    ExternalArtifactSigner,
    ExternalArtifactVerifier,
    _metadata_from_identity,
    _metadata_signing_payload,
    sign_artifact_with_metadata,
    verify_artifact_detailed,
)
from aegis._internal.signing import ArtifactSigner, HMACSigner, sign_artifact
from aegis._internal.signature_models import (
    AnchorStatus,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
)


def _metadata(**changes: object) -> SignatureMetadata:
    values: dict[str, object] = {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": EvidenceType.AUDIT_ARTIFACT,
        "algorithm": "HSM-SHA256",
        "signature_encoding": SignatureEncoding.HEX,
        "key_reference": "audit-key",
        "key_version": "version/7",
        "signed_at": 123,
    }
    values.update(changes)
    return SignatureMetadata(**values)  # type: ignore[arg-type]


def test_metadata_signing_payload_matches_frozen_profile():
    artifact = {"audit_schema_version": "1.4", "signature": None}
    metadata = _metadata()
    expected_json = (
        b'{"audit_schema_version":"1.4","signature_metadata":{'
        b'"algorithm":"HSM-SHA256",'
        b'"canonicalization_version":"aegis-canonical-json-v1",'
        b'"key_reference":"audit-key","key_version":"version/7",'
        b'"payload_type":"audit_artifact","schema_version":"1",'
        b'"signature_encoding":"hex","signed_at":123,'
        b'"signing_profile":"aegis-signature-v1"}}'
    )
    expected = (
        b"AEGIS-SIGNATURE\x00"
        b"aegis-signature-v1\x00"
        b"audit_artifact\x00"
        + expected_json
    )
    assert _metadata_signing_payload(artifact, metadata) == expected


def test_metadata_signing_payload_preserves_artifact_and_replaces_temporary_metadata():
    artifact = {
        "audit_schema_version": "1.4",
        "signature": "deadbeef",
        "signature_metadata": {"temporary": True},
    }
    original = deepcopy(artifact)

    payload = _metadata_signing_payload(artifact, _metadata())

    assert artifact == original
    assert b'"signature":' not in payload
    assert b'"signature_metadata":{"algorithm":"HSM-SHA256"' in payload
    assert b'"temporary":true' not in payload


def test_metadata_signing_payload_rejects_unvalidated_metadata_objects():
    class FakeMetadata:
        def to_dict(self):
            return {
                "signing_profile": "attacker-profile",
                "payload_type": "attacker-payload",
            }

    with pytest.raises(SigningContractError):
        _metadata_signing_payload(
            {"audit_schema_version": "1.4", "signature": None}, FakeMetadata()
        )


@pytest.mark.parametrize(
    "artifact, metadata",
    [
        ({"audit_schema_version": "1.5", "signature": None}, _metadata()),
        (
            {"audit_schema_version": "1.4", "signature": None, "extra": "changed"},
            _metadata(),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(algorithm="RSA-SHA256"),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(signature_encoding=SignatureEncoding.BASE64),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(key_reference="other-key"),
        ),
        (
            {"audit_schema_version": "1.4", "signature": None},
            _metadata(key_version="version/8"),
        ),
        ({"audit_schema_version": "1.4", "signature": None}, _metadata(signed_at=124)),
    ],
)
def test_metadata_signing_payload_changes_when_signed_inputs_change(artifact, metadata):
    baseline = _metadata_signing_payload(
        {"audit_schema_version": "1.4", "signature": None}, _metadata()
    )
    assert _metadata_signing_payload(artifact, metadata) != baseline


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema_version", "2"),
        ("signing_profile", "other-profile"),
        ("canonicalization_version", "other-canonicalization"),
        ("payload_type", None),
    ],
)
def test_unsupported_fixed_metadata_values_are_rejected_before_payload_construction(
    field, value
):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


def test_metadata_from_identity_uses_fixed_profile_and_identity_values():
    identity = SignerIdentity(
        algorithm="HSM-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="audit-key",
        key_version="version/7",
    )

    assert _metadata_from_identity(identity, 123) == _metadata()


@pytest.mark.parametrize(
    "identity, signed_at",
    [
        (object(), 123),
        (None, 123),
        (
            SignerIdentity(
                "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
            ),
            True,
        ),
    ],
)
def test_metadata_from_identity_rejects_invalid_inputs(identity, signed_at):
    with pytest.raises(SigningContractError):
        _metadata_from_identity(identity, signed_at)


def test_structural_signer_and_verifier_doubles_satisfy_runtime_protocols():
    class SignerDouble:
        def signer_identity(self) -> SignerIdentity:
            return SignerIdentity(
                "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
            )

        def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
            return SigningReceipt(
                "aa",
                identity.algorithm,
                identity.signature_encoding,
                identity.key_reference,
                identity.key_version,
            )

    class VerifierDouble:
        def verify(
            self, payload: bytes, signature: str, metadata: SignatureMetadata
        ) -> ExternalVerificationOutcome:
            return ExternalVerificationOutcome(
                SignatureStatus.UNSIGNED,
                AnchorStatus.NOT_EVALUATED,
                VerificationReasonCode.UNSIGNED,
                "unsigned",
            )

    assert isinstance(SignerDouble(), ExternalArtifactSigner)
    assert isinstance(VerifierDouble(), ExternalArtifactVerifier)


class RecordingSigner:
    def __init__(
        self, *, identity: SignerIdentity | None = None, receipt: object | None = None
    ) -> None:
        self.identity = identity or SignerIdentity(
            "HSM-SHA256", SignatureEncoding.HEX, "audit-key", "version/7"
        )
        self.receipt = receipt or SigningReceipt(
            "aa",
            self.identity.algorithm,
            self.identity.signature_encoding,
            self.identity.key_reference,
            self.identity.key_version,
        )
        self.payload: bytes | None = None

    def signer_identity(self) -> SignerIdentity:
        return self.identity

    def sign(self, payload: bytes, identity: SignerIdentity) -> object:
        self.payload = payload
        return self.receipt


class DigestSigner(RecordingSigner):
    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        self.payload = payload
        return SigningReceipt(
            sha256(payload).hexdigest(),
            identity.algorithm,
            identity.signature_encoding,
            identity.key_reference,
            identity.key_version,
        )


class DigestVerifier:
    def accepts(self, payload: bytes, signature: str) -> bool:
        return sha256(payload).hexdigest() == signature


class LegacyDigestSigner(ArtifactSigner):
    def sign(self, payload: bytes) -> str:
        return sha256(payload).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return signature == self.sign(payload)


class ExplodingLegacySigner(ArtifactSigner):
    def sign(self, payload: bytes) -> str:
        return "unused"

    def verify(self, payload: bytes, signature: str) -> bool:
        raise RuntimeError("legacy verifier secret")


class ExplodingExternalVerifier:
    def verify(
        self, payload: bytes, signature: str, metadata: SignatureMetadata
    ) -> ExternalVerificationOutcome:
        raise AssertionError("external verifier should not be called")


class RecordingExternalVerifier:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[bytes, str, SignatureMetadata]] = []

    def verify(
        self, payload: bytes, signature: str, metadata: SignatureMetadata
    ) -> object:
        self.calls.append((payload, signature, metadata))
        return self.response


def _metadata_artifact(
    *,
    key_version: str = "version/7",
) -> dict[str, object]:
    return {
        "audit_schema_version": "1.4",
        "nested": {"items": ["one", "two"]},
        "signature_metadata": _metadata(key_version=key_version).to_dict(),
        "signature": "aa",
    }


def _unchecked_outcome(
    signature_status: object,
    anchor_status: object,
    reason_code: object,
    message: object = "provider-controlled-message",
) -> ExternalVerificationOutcome:
    outcome = object.__new__(ExternalVerificationOutcome)
    object.__setattr__(outcome, "signature_status", signature_status)
    object.__setattr__(outcome, "anchor_status", anchor_status)
    object.__setattr__(outcome, "reason_code", reason_code)
    object.__setattr__(outcome, "message", message)
    return outcome


def _hostile_outcome() -> ExternalVerificationOutcome:
    class HostileOutcome(ExternalVerificationOutcome):
        def __getattribute__(self, name: str) -> object:
            if name == "signature_status":
                raise ArtifactSigningError("provider secret from outcome")
            return super().__getattribute__(name)

    outcome = object.__new__(HostileOutcome)
    object.__setattr__(outcome, "signature_status", SignatureStatus.VALID)
    object.__setattr__(outcome, "anchor_status", AnchorStatus.UNANCHORED)
    object.__setattr__(
        outcome,
        "reason_code",
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
    )
    object.__setattr__(outcome, "message", "provider secret from outcome")
    return outcome


def _legacy_artifact() -> dict[str, object]:
    return {
        "audit_schema_version": "1.4",
        "nested": {"items": ["one", "two"]},
        "signature": None,
    }


@pytest.mark.parametrize("has_signature_field", [True, False])
def test_detailed_verification_of_unsigned_artifact_skips_verifiers_and_preserves_input(
    has_signature_field,
):
    artifact = _legacy_artifact()
    if not has_signature_field:
        artifact.pop("signature")
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(
        artifact,
        legacy_signer=ExplodingLegacySigner(),
        verifier=ExplodingExternalVerifier(),
    )

    assert result.signature_status is SignatureStatus.UNSIGNED
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.UNSIGNED
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_verification_of_valid_hmac_legacy_signature_is_unanchored():
    signer = HMACSigner(key=b"legacy-key")
    artifact = _legacy_artifact()
    sign_artifact(artifact, signer)  # type: ignore[arg-type]
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact, legacy_signer=signer)

    assert result.signature_status is SignatureStatus.VALID
    assert result.anchor_status is AnchorStatus.UNANCHORED
    assert result.reason_code is VerificationReasonCode.LEGACY_SIGNATURE_VALID
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_verification_of_invalid_hmac_legacy_signature_is_not_evaluated():
    signer = HMACSigner(key=b"legacy-key")
    artifact = _legacy_artifact()
    sign_artifact(artifact, signer)  # type: ignore[arg-type]
    artifact["nested"] = {"items": ["tampered"]}
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact, legacy_signer=signer)

    assert result.signature_status is SignatureStatus.INVALID
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.LEGACY_SIGNATURE_INVALID
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_verification_of_valid_custom_legacy_signature_does_not_infer_anchor():
    signer = LegacyDigestSigner()
    artifact = _legacy_artifact()
    sign_artifact(artifact, signer)  # type: ignore[arg-type]
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact, legacy_signer=signer)

    assert result.signature_status is SignatureStatus.VALID
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.LEGACY_SIGNATURE_VALID
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_verification_of_invalid_custom_legacy_signature_is_not_evaluated():
    signer = LegacyDigestSigner()
    artifact = _legacy_artifact()
    sign_artifact(artifact, signer)  # type: ignore[arg-type]
    artifact["nested"] = {"items": ["tampered"]}
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact, legacy_signer=signer)

    assert result.signature_status is SignatureStatus.INVALID
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.LEGACY_SIGNATURE_INVALID
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_verification_requires_legacy_signer_when_metadata_is_missing():
    artifact = _legacy_artifact()
    artifact["signature"] = "present-but-unverified"
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact)

    assert result.signature_status is SignatureStatus.INDETERMINATE
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.SIGNATURE_METADATA_MISSING
    assert result.signature_metadata is None
    assert artifact == snapshot


def test_detailed_legacy_verification_sanitizes_unexpected_verifier_errors():
    artifact = _legacy_artifact()
    artifact["signature"] = "present-but-unverified"
    snapshot = deepcopy(artifact)

    with pytest.raises(VerificationContractError) as error:
        verify_artifact_detailed(artifact, legacy_signer=ExplodingLegacySigner())

    assert str(error.value) == "Legacy signature verification failed"
    assert error.value.details == {}
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "secret" not in str(error.value)
    assert artifact == snapshot


@pytest.mark.parametrize(
    "signature_status, anchor_status, reason_code, safe_message",
    [
        (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
            "Signature is valid but not externally anchored",
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
            "Signature is valid and externally anchored",
        ),
        (
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            VerificationReasonCode.ANCHOR_INVALID,
            "The external anchor is invalid",
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.SIGNATURE_INVALID,
            "Signature is invalid",
        ),
        (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
            "The configured key does not permit the declared algorithm",
        ),
        (
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.KEY_UNKNOWN,
            "The configured verifier does not recognize the key version",
        ),
        (
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.KEY_REVOKED,
            "The configured verifier reports the key version as revoked",
        ),
        (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
            "External verification is unavailable",
        ),
    ],
)
def test_detailed_metadata_outcomes_are_normalized_with_core_owned_messages(
    signature_status,
    anchor_status,
    reason_code,
    safe_message,
):
    artifact = _metadata_artifact()
    snapshot = deepcopy(artifact)
    outcome = ExternalVerificationOutcome(
        signature_status,
        anchor_status,
        reason_code,
        "provider credential=top-secret",
    )
    verifier = RecordingExternalVerifier(outcome)

    result = verify_artifact_detailed(artifact, verifier=verifier)

    assert result.signature_status is signature_status
    assert result.anchor_status is anchor_status
    assert result.reason_code is reason_code
    assert result.message == safe_message
    assert "top-secret" not in result.message
    assert result.signature_metadata == _metadata()
    assert result.signature_metadata is not artifact["signature_metadata"]
    assert result.is_signature_valid is (signature_status is SignatureStatus.VALID)
    assert result.is_anchored is (anchor_status is AnchorStatus.ANCHORED)
    assert len(verifier.calls) == 1
    assert artifact == snapshot


@pytest.mark.parametrize("key_version", ["version/current", "version/6"])
def test_detailed_metadata_verifier_receives_exact_immutable_key_version(key_version):
    artifact = _metadata_artifact(key_version=key_version)
    snapshot = deepcopy(artifact)
    outcome = ExternalVerificationOutcome(
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_UNKNOWN,
        "unknown",
    )
    verifier = RecordingExternalVerifier(outcome)

    result = verify_artifact_detailed(artifact, verifier=verifier)

    expected_metadata = _metadata(key_version=key_version)
    assert result.signature_status is SignatureStatus.UNKNOWN_KEY
    assert len(verifier.calls) == 1
    payload, signature, parsed_metadata = verifier.calls[0]
    assert signature == "aa"
    assert parsed_metadata == expected_metadata
    assert parsed_metadata.key_version == key_version
    assert parsed_metadata is not artifact["signature_metadata"]
    assert payload == _metadata_signing_payload(dict(artifact), expected_metadata)
    assert artifact == snapshot


def test_detailed_metadata_without_verifier_returns_fixed_unavailable_outcome():
    artifact = _metadata_artifact()
    snapshot = deepcopy(artifact)

    result = verify_artifact_detailed(artifact)

    assert result.signature_status is SignatureStatus.INDETERMINATE
    assert result.anchor_status is AnchorStatus.NOT_EVALUATED
    assert result.reason_code is VerificationReasonCode.VERIFIER_UNAVAILABLE
    assert result.message == "External verification is unavailable"
    assert result.signature_metadata == _metadata()
    assert artifact == snapshot


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema_version", "2"),
        ("signing_profile", "other-profile"),
        ("canonicalization_version", "other-canonicalization"),
        ("payload_type", "other-payload"),
        ("algorithm", ""),
        ("algorithm", "a" * 129),
        ("key_reference", ""),
        ("key_reference", "k" * 513),
        ("key_version", ""),
        ("key_version", "v" * 129),
        ("signed_at", -1),
        ("signed_at", True),
    ],
)
def test_detailed_metadata_validation_rejects_versions_and_bounds_before_verifier(
    field, value
):
    artifact = _metadata_artifact()
    artifact["signature_metadata"][field] = value
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    with pytest.raises(SignatureMetadataError) as error:
        verify_artifact_detailed(artifact, verifier=verifier)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert verifier.calls == []
    assert artifact == snapshot


@pytest.mark.parametrize("shape", ["not_mapping", "missing", "extra", "hostile"])
def test_detailed_metadata_validation_rejects_invalid_shape_before_verifier(shape):
    artifact = _metadata_artifact()
    if shape == "not_mapping":
        artifact["signature_metadata"] = None
    elif shape == "missing":
        artifact["signature_metadata"].pop("algorithm")
    elif shape == "extra":
        artifact["signature_metadata"]["provider_hint"] = "attacker-resolver"
    else:
        class HostileMetadata(dict):
            def keys(self):
                raise ArtifactSigningError("provider secret from metadata")

        artifact["signature_metadata"] = HostileMetadata(
            artifact["signature_metadata"]
        )
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    with pytest.raises(SignatureMetadataError) as error:
        verify_artifact_detailed(artifact, verifier=verifier)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "provider secret" not in str(error.value)
    assert verifier.calls == []
    assert artifact == snapshot


@pytest.mark.parametrize(
    "signature, encoding",
    [
        ("", "hex"),
        ("AA", "hex"),
        ("a", "hex"),
        ("a" * 16_385, "hex"),
        ("Zm 9v", "base64"),
        ("Zh==", "base64"),
    ],
)
def test_detailed_metadata_validation_rejects_bad_signature_before_verifier(
    signature, encoding
):
    artifact = _metadata_artifact()
    artifact["signature"] = signature
    artifact["signature_metadata"]["signature_encoding"] = encoding
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    with pytest.raises(SignatureMetadataError) as error:
        verify_artifact_detailed(artifact, verifier=verifier)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert verifier.calls == []
    assert artifact == snapshot


def test_detailed_metadata_validation_rejects_non_string_signature_before_verifier():
    artifact = _metadata_artifact()
    artifact["signature"] = 123
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    with pytest.raises(SignatureMetadataError):
        verify_artifact_detailed(artifact, verifier=verifier)

    assert verifier.calls == []
    assert artifact == snapshot


_EXTERNAL_OUTCOME_ROWS = {
    (
        SignatureStatus.VALID,
        AnchorStatus.UNANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.INVALID,
        VerificationReasonCode.ANCHOR_INVALID,
    ),
    (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.SIGNATURE_INVALID,
    ),
    (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
    ),
    (
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_UNKNOWN,
    ),
    (
        SignatureStatus.REVOKED,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_REVOKED,
    ),
    (
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.VERIFIER_UNAVAILABLE,
    ),
}
_IMPOSSIBLE_EXTERNAL_OUTCOME_ROWS = [
    (signature_status, anchor_status, reason_code)
    for signature_status in SignatureStatus
    for anchor_status in AnchorStatus
    for reason_code in VerificationReasonCode
    if (signature_status, anchor_status, reason_code) not in _EXTERNAL_OUTCOME_ROWS
]


@pytest.mark.parametrize(
    "signature_status, anchor_status, reason_code",
    _IMPOSSIBLE_EXTERNAL_OUTCOME_ROWS,
)
def test_detailed_metadata_verifier_rejects_every_impossible_external_outcome(
    signature_status, anchor_status, reason_code
):
    artifact = _metadata_artifact()
    snapshot = deepcopy(artifact)
    outcome = _unchecked_outcome(signature_status, anchor_status, reason_code)
    verifier = RecordingExternalVerifier(outcome)

    with pytest.raises(VerificationContractError):
        verify_artifact_detailed(artifact, verifier=verifier)

    assert len(verifier.calls) == 1
    assert artifact == snapshot


@pytest.mark.parametrize("response", [None, {}, object(), _hostile_outcome()])
def test_detailed_metadata_verifier_rejects_non_outcome_response(response):
    artifact = _metadata_artifact()
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(response)

    with pytest.raises(VerificationContractError) as error:
        verify_artifact_detailed(artifact, verifier=verifier)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "provider secret" not in str(error.value)
    assert len(verifier.calls) == 1
    assert artifact == snapshot


@pytest.mark.parametrize(
    "exception",
    [
        RuntimeError("credential=top-secret payload=do-not-disclose"),
        ArtifactSigningError("adapter-created AEGIS error with top-secret"),
    ],
)
def test_detailed_metadata_verifier_sanitizes_every_adapter_exception(exception):
    class FailingVerifier:
        def __init__(self) -> None:
            self.calls = 0

        def verify(
            self, payload: bytes, signature: str, metadata: SignatureMetadata
        ) -> ExternalVerificationOutcome:
            self.calls += 1
            raise exception

    artifact = _metadata_artifact()
    snapshot = deepcopy(artifact)
    verifier = FailingVerifier()

    with pytest.raises(
        VerificationContractError, match="External verifier failed unexpectedly"
    ) as error:
        verify_artifact_detailed(artifact, verifier=verifier)

    assert error.value.details == {}
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "top-secret" not in str(error.value)
    assert verifier.calls == 1
    assert artifact == snapshot


def test_detailed_metadata_removal_never_downgrades_to_external_verifier():
    artifact = _metadata_artifact()
    artifact.pop("signature_metadata")
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    result = verify_artifact_detailed(artifact, verifier=verifier)

    assert result.signature_status is SignatureStatus.INDETERMINATE
    assert result.reason_code is VerificationReasonCode.SIGNATURE_METADATA_MISSING
    assert verifier.calls == []
    assert artifact == snapshot


def test_detailed_metadata_signature_copied_to_legacy_artifact_does_not_validate():
    metadata_artifact = {"audit_schema_version": "1.4", "signature": None}
    sign_artifact_with_metadata(metadata_artifact, DigestSigner(), signed_at=123)
    legacy_artifact = _legacy_artifact()
    legacy_artifact["signature"] = metadata_artifact["signature"]
    snapshot = deepcopy(legacy_artifact)
    verifier = RecordingExternalVerifier(object())

    result = verify_artifact_detailed(
        legacy_artifact,
        legacy_signer=HMACSigner(key=b"legacy-key"),
        verifier=verifier,
    )

    assert result.signature_status is SignatureStatus.INVALID
    assert result.reason_code is VerificationReasonCode.LEGACY_SIGNATURE_INVALID
    assert verifier.calls == []
    assert legacy_artifact == snapshot


@pytest.mark.parametrize(
    "field, value",
    [
        ("payload_type", "other-payload"),
        ("signing_profile", "other-profile"),
        ("canonicalization_version", "other-canonicalization"),
    ],
)
def test_detailed_metadata_contract_changes_do_not_retry_or_fall_back(field, value):
    artifact = _metadata_artifact()
    artifact["signature_metadata"][field] = value
    snapshot = deepcopy(artifact)
    verifier = RecordingExternalVerifier(object())

    with pytest.raises(SignatureMetadataError):
        verify_artifact_detailed(
            artifact,
            legacy_signer=ExplodingLegacySigner(),
            verifier=verifier,
        )

    assert verifier.calls == []
    assert artifact == snapshot


def test_detailed_metadata_verifier_receives_parsed_value_not_caller_dictionary():
    artifact = _metadata_artifact()
    caller_metadata = artifact["signature_metadata"]
    snapshot = deepcopy(artifact)
    outcome = ExternalVerificationOutcome(
        SignatureStatus.REVOKED,
        AnchorStatus.NOT_EVALUATED,
        VerificationReasonCode.KEY_REVOKED,
        "revoked",
    )
    verifier = RecordingExternalVerifier(outcome)

    verify_artifact_detailed(artifact, verifier=verifier)

    assert len(verifier.calls) == 1
    parsed_metadata = verifier.calls[0][2]
    assert isinstance(parsed_metadata, SignatureMetadata)
    assert parsed_metadata.to_dict() == caller_metadata
    assert parsed_metadata is not caller_metadata
    assert artifact == snapshot


def test_detailed_metadata_artifact_hints_cannot_select_another_resolver():
    artifact = _metadata_artifact()
    artifact.update(
        resolver="https://attacker.invalid/keys",
        provider="attacker-provider",
        retry=True,
    )
    snapshot = deepcopy(artifact)
    outcome = ExternalVerificationOutcome(
        SignatureStatus.VALID,
        AnchorStatus.UNANCHORED,
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        "valid",
    )
    verifier = RecordingExternalVerifier(outcome)

    result = verify_artifact_detailed(artifact, verifier=verifier)

    assert result.signature_status is SignatureStatus.VALID
    assert len(verifier.calls) == 1
    assert artifact == snapshot


def _unsigned_artifact() -> dict[str, object]:
    return {"audit_schema_version": "1.4", "signature": None}


def test_sign_artifact_with_metadata_binds_identity_receipt_and_payload_atomically():
    artifact = _unsigned_artifact()
    signer = RecordingSigner()

    result = sign_artifact_with_metadata(artifact, signer, signed_at=1_721_600_000)

    assert result is artifact
    assert artifact["signature_metadata"] == {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": "audit_artifact",
        "algorithm": "HSM-SHA256",
        "signature_encoding": "hex",
        "key_reference": "audit-key",
        "key_version": "version/7",
        "signed_at": 1_721_600_000,
    }
    assert artifact["signature"] == signer.receipt.signature  # type: ignore[union-attr]
    assert signer.payload == _metadata_signing_payload(
        {"audit_schema_version": "1.4", "signature": None},
        SignatureMetadata.from_dict(artifact["signature_metadata"]),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    "artifact",
    [
        {"audit_schema_version": "1.4", "signature": "aa"},
        {
            "audit_schema_version": "1.4",
            "signature": None,
            "signature_metadata": {"stale": True},
        },
    ],
)
def test_sign_artifact_with_metadata_rejects_existing_signature_state_without_mutation(
    artifact,
):
    original = deepcopy(artifact)

    with pytest.raises(ArtifactSigningError):
        sign_artifact_with_metadata(artifact, RecordingSigner(), signed_at=1)

    assert artifact == original


def test_sign_artifact_with_metadata_rejects_invalid_timestamp_without_mutation():
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(SigningContractError):
        sign_artifact_with_metadata(artifact, RecordingSigner(), signed_at=True)

    assert artifact == original


def test_sign_artifact_with_metadata_redacts_identity_errors_without_mutation():
    class FailingIdentitySigner(RecordingSigner):
        def signer_identity(self) -> SignerIdentity:
            raise RuntimeError("credential=top-secret payload=do-not-disclose")

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="External signer could not prepare identity"
    ) as error:
        sign_artifact_with_metadata(artifact, FailingIdentitySigner(), signed_at=1)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "top-secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_non_identity_without_mutation():
    class InvalidIdentitySigner(RecordingSigner):
        def signer_identity(self) -> object:
            return object()

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(SigningContractError, match="Signer returned an invalid identity"):
        sign_artifact_with_metadata(artifact, InvalidIdentitySigner(), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "exception",
    [
        ArtifactSigningError("provider credential=top-secret"),
        RuntimeError("credential=top-secret payload=do-not-disclose"),
    ],
)
def test_sign_artifact_with_metadata_redacts_signer_errors_without_mutation(exception):
    class FailingSigner(RecordingSigner):
        def sign(self, payload: bytes, identity: SignerIdentity) -> object:
            raise exception

    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="External signer did not produce a signature"
    ) as error:
        sign_artifact_with_metadata(artifact, FailingSigner(), signed_at=1)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "top-secret" not in str(error.value)
    assert "do-not-disclose" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_non_receipt_without_mutation():
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=object()), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "field, value",
    [
        ("algorithm", "RSA-SHA256"),
        ("signature_encoding", SignatureEncoding.BASE64),
        ("key_reference", "other-key"),
        ("key_version", "version/8"),
    ],
)
def test_sign_artifact_with_metadata_rejects_receipt_identity_mismatch_without_mutation(
    field, value
):
    signer = RecordingSigner()
    receipt = SigningReceipt(
        "aa",
        signer.identity.algorithm,
        signer.identity.signature_encoding,
        signer.identity.key_reference,
        signer.identity.key_version,
    )
    object.__setattr__(receipt, field, value)
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=receipt), signed_at=1)

    assert artifact == original


@pytest.mark.parametrize(
    "signature, encoding",
    [
        ("", SignatureEncoding.HEX),
        ("a" * 16_385, SignatureEncoding.HEX),
        ("AA", SignatureEncoding.HEX),
        ("a", SignatureEncoding.HEX),
        ("0xaa", SignatureEncoding.HEX),
        ("Zm 9v", SignatureEncoding.BASE64),
        ("Zh==", SignatureEncoding.BASE64),
    ],
)
def test_sign_artifact_with_metadata_redacts_invalid_encoded_signature_without_mutation(
    signature, encoding
):
    identity = SignerIdentity(
        "HSM-SHA256", encoding, "audit-key", "version/7"
    )
    receipt = SigningReceipt(
        "aa" if encoding is SignatureEncoding.HEX else "YWE=",
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    object.__setattr__(receipt, "signature", signature)
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="Signer returned an invalid encoded signature"
    ) as error:
        sign_artifact_with_metadata(
            artifact, RecordingSigner(identity=identity, receipt=receipt), signed_at=1
        )

    assert error.value.details == {}
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert artifact == original


def test_sign_artifact_with_metadata_rejects_alias_rotation_without_mutation():
    signer = RecordingSigner()
    receipt = SigningReceipt(
        "aa",
        signer.identity.algorithm,
        signer.identity.signature_encoding,
        signer.identity.key_reference,
        "version/8",
    )
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ):
        sign_artifact_with_metadata(artifact, RecordingSigner(receipt=receipt), signed_at=1)

    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_identity_fields_without_mutation():
    class HostileAlgorithm(str):
        def __len__(self) -> int:
            raise ArtifactSigningError("provider secret from identity")

    signer = RecordingSigner()
    object.__setattr__(signer.identity, "algorithm", HostileAlgorithm("HSM-SHA256"))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signer returned an invalid identity"
    ) as error:
        sign_artifact_with_metadata(artifact, signer, signed_at=1)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "provider secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_receipt_fields_without_mutation():
    class HostileKeyVersion(str):
        def __eq__(self, other: object) -> bool:
            raise ArtifactSigningError("provider secret from receipt")

    signer = RecordingSigner()
    receipt = signer.receipt
    object.__setattr__(receipt, "key_version", HostileKeyVersion("version/7"))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        SigningContractError, match="Signing receipt does not match prepared identity"
    ) as error:
        sign_artifact_with_metadata(artifact, signer, signed_at=1)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "provider secret" not in str(error.value)
    assert artifact == original


def test_sign_artifact_with_metadata_redacts_hostile_signature_without_mutation():
    class HostileBase64Signature(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise ArtifactSigningError("provider secret from signature")

    identity = SignerIdentity(
        "HSM-SHA256", SignatureEncoding.BASE64, "audit-key", "version/7"
    )
    receipt = SigningReceipt(
        "YWE=",
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    object.__setattr__(receipt, "signature", HostileBase64Signature("YWE="))
    artifact = _unsigned_artifact()
    original = deepcopy(artifact)

    with pytest.raises(
        ArtifactSigningError, match="Signer returned an invalid encoded signature"
    ) as error:
        sign_artifact_with_metadata(
            artifact, RecordingSigner(identity=identity, receipt=receipt), signed_at=1
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "provider secret" not in str(error.value)
    assert artifact == original


@pytest.mark.parametrize(
    "mutate",
    [
        lambda artifact: artifact.update(audit_schema_version="1.5"),
        lambda artifact: artifact["signature_metadata"].update(algorithm="RSA-SHA256"),
        lambda artifact: artifact["signature_metadata"].update(key_reference="other-key"),
        lambda artifact: artifact["signature_metadata"].update(key_version="version/8"),
        lambda artifact: artifact["signature_metadata"].update(signed_at=1_721_600_001),
        lambda artifact: artifact["signature_metadata"].update(payload_type="other"),
        lambda artifact: artifact["signature_metadata"].update(signing_profile="other"),
        lambda artifact: artifact["signature_metadata"].update(canonicalization_version="other"),
    ],
)
def test_metadata_aware_signature_payload_detects_signed_artifact_tampering(mutate):
    artifact = _unsigned_artifact()
    signer = DigestSigner()
    sign_artifact_with_metadata(artifact, signer, signed_at=1_721_600_000)
    signed_payload = signer.payload
    verifier = DigestVerifier()

    assert verifier.accepts(signed_payload, artifact["signature"])

    mutate(artifact)
    try:
        tampered_payload = _metadata_signing_payload(
            artifact, SignatureMetadata.from_dict(artifact["signature_metadata"])
        )
    except SignatureMetadataError:
        tampered_payload = None

    assert not verifier.accepts(tampered_payload or b"", artifact["signature"])
