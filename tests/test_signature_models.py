"""Contract tests for typed signature and trust-anchor values."""

from dataclasses import FrozenInstanceError

import pytest

from aegis._internal.errors import (
    AIGCError,
    ArtifactSigningError,
    SignatureMetadataError,
    SigningContractError,
    VerificationContractError,
)
from aegis._internal.signature_models import (
    ALLOWED_VERIFICATION_OUTCOMES,
    CANONICALIZATION_VERSION,
    MAX_SIGNATURE_LENGTH,
    MAX_VERIFICATION_MESSAGE_LENGTH,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    AnchorStatus,
    ArtifactVerificationResult,
    EvidenceType,
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignatureStatus,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
    validate_encoded_signature,
    validate_verification_outcome,
)


def _metadata(**changes):
    value = {
        "schema_version": SIGNATURE_METADATA_SCHEMA_VERSION,
        "signing_profile": SIGNING_PROFILE,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "payload_type": EvidenceType.AUDIT_ARTIFACT,
        "algorithm": "HSM-SHA256",
        "signature_encoding": SignatureEncoding.BASE64,
        "key_reference": "production/audit-key",
        "key_version": "version/17",
        "signed_at": 1_725_000_000,
    }
    value.update(changes)
    return SignatureMetadata(**value)


def test_contract_error_codes_are_stable():
    cases = [
        (SignatureMetadataError, "SIGNATURE_METADATA_INVALID"),
        (ArtifactSigningError, "ARTIFACT_SIGNING_ERROR"),
        (SigningContractError, "SIGNING_CONTRACT_ERROR"),
        (VerificationContractError, "VERIFICATION_CONTRACT_ERROR"),
    ]
    for error_type, code in cases:
        error = error_type("safe message")
        assert isinstance(error, AIGCError)
        assert error.code == code
        assert error.details == {}


def test_constants_and_enum_values_are_stable():
    assert SIGNATURE_METADATA_SCHEMA_VERSION == "1"
    assert SIGNING_PROFILE == "aegis-signature-v1"
    assert CANONICALIZATION_VERSION == "aegis-canonical-json-v1"
    assert EvidenceType.AUDIT_ARTIFACT.value == "audit_artifact"
    assert SignatureEncoding.HEX.value == "hex"
    assert SignatureEncoding.BASE64.value == "base64"
    assert {item.value for item in SignatureStatus} == {
        "unsigned", "valid", "invalid", "unknown_key", "revoked", "indeterminate"
    }
    assert {item.value for item in AnchorStatus} == {
        "not_evaluated", "unanchored", "anchored", "invalid"
    }
    assert {item.value for item in VerificationReasonCode} == {
        "unsigned", "legacy_signature_valid", "legacy_signature_invalid",
        "signature_valid_unanchored", "signature_valid_anchored", "signature_invalid",
        "signature_metadata_missing", "algorithm_not_allowed", "key_unknown",
        "key_revoked", "verifier_unavailable", "anchor_invalid",
    }


def test_signer_identity_is_frozen_and_typed():
    identity = SignerIdentity(
        algorithm="HSM-SHA256",
        signature_encoding=SignatureEncoding.BASE64,
        key_reference="production/audit-key",
        key_version="version/17",
    )
    assert identity.signature_encoding is SignatureEncoding.BASE64
    with pytest.raises(FrozenInstanceError):
        identity.key_version = "version/18"


@pytest.mark.parametrize("field, value", [
    ("algorithm", ""), ("algorithm", "x" * 129), ("algorithm", "bad algorithm"),
    ("key_reference", ""), ("key_reference", "x" * 513), ("key_reference", "bad\nkey"),
    ("key_version", ""), ("key_version", "x" * 129), ("key_version", "bad version"),
])
def test_signer_identity_rejects_invalid_identity_fields(field, value):
    values = {
        "algorithm": "HSM-SHA256",
        "signature_encoding": SignatureEncoding.HEX,
        "key_reference": "key/reference",
        "key_version": "version/17",
    }
    values[field] = value
    with pytest.raises(SigningContractError):
        SignerIdentity(**values)


@pytest.mark.parametrize("field, value", [
    ("signature_encoding", "hex"),
    ("payload_type", "audit_artifact"),
])
def test_metadata_rejects_raw_string_enums(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


@pytest.mark.parametrize("field, value", [
    ("algorithm", ""), ("algorithm", "x" * 129), ("algorithm", "bad algorithm"),
    ("key_reference", ""), ("key_reference", "x" * 513), ("key_reference", "bad\x00key"),
    ("key_version", ""), ("key_version", "x" * 129), ("key_version", "bad version"),
    ("signed_at", True), ("signed_at", "1"), ("signed_at", -1),
])
def test_metadata_rejects_invalid_fields(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


def test_metadata_accepts_identity_boundaries():
    metadata = _metadata(
        algorithm="a" * 128,
        key_reference="r" * 512,
        key_version="v" * 128,
        signed_at=0,
    )
    assert metadata.algorithm == "a" * 128


def test_metadata_accepts_minimum_identity_boundaries():
    metadata = _metadata(algorithm="a", key_reference="r", key_version="v")
    assert (metadata.algorithm, metadata.key_reference, metadata.key_version) == ("a", "r", "v")


@pytest.mark.parametrize("field, value", [
    ("schema_version", "2"),
    ("signing_profile", "other-profile"),
    ("canonicalization_version", "other-canonicalization"),
])
def test_metadata_requires_supported_contract_values(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


def test_metadata_serializes_all_fields_in_declared_order_and_round_trips():
    metadata = _metadata()
    serialized = metadata.to_dict()
    assert list(serialized) == [
        "schema_version", "signing_profile", "canonicalization_version", "payload_type",
        "algorithm", "signature_encoding", "key_reference", "key_version", "signed_at",
    ]
    assert serialized == {
        "schema_version": "1",
        "signing_profile": "aegis-signature-v1",
        "canonicalization_version": "aegis-canonical-json-v1",
        "payload_type": "audit_artifact",
        "algorithm": "HSM-SHA256",
        "signature_encoding": "base64",
        "key_reference": "production/audit-key",
        "key_version": "version/17",
        "signed_at": 1_725_000_000,
    }
    assert SignatureMetadata.from_dict(serialized) == metadata


def test_metadata_from_dict_does_not_mutate_input():
    value = _metadata().to_dict()
    original = value.copy()
    SignatureMetadata.from_dict(value)
    assert value == original


@pytest.mark.parametrize("mutate", [
    lambda value: value.pop("algorithm"),
    lambda value: value.__setitem__("unexpected", "value"),
    lambda value: value.__setitem__("signature_encoding", "not-an-encoding"),
])
def test_metadata_from_dict_rejects_wrong_shape_or_enum(mutate):
    value = _metadata().to_dict()
    mutate(value)
    with pytest.raises(SignatureMetadataError) as exc_info:
        SignatureMetadata.from_dict(value)
    assert set(exc_info.value.details).issubset({"field", "missing", "extra"})


@pytest.mark.parametrize("signature, encoding", [
    ("", SignatureEncoding.HEX), ("a" * (MAX_SIGNATURE_LENGTH + 1), SignatureEncoding.HEX),
    ("A0", SignatureEncoding.HEX), ("a", SignatureEncoding.HEX), ("gg", SignatureEncoding.HEX),
    ("Zm9v\n", SignatureEncoding.BASE64), ("not-base64!", SignatureEncoding.BASE64),
    ("Zg", SignatureEncoding.BASE64),
])
def test_encoded_signature_rejects_invalid_content(signature, encoding):
    with pytest.raises(SigningContractError):
        validate_encoded_signature(signature, encoding)


def test_encoded_signature_accepts_boundaries_and_canonical_base64():
    assert validate_encoded_signature("aa", SignatureEncoding.HEX) is None
    assert validate_encoded_signature("a" * MAX_SIGNATURE_LENGTH, SignatureEncoding.HEX) is None
    assert validate_encoded_signature("Zm9v", SignatureEncoding.BASE64) is None


@pytest.mark.parametrize("encoding, signature", [
    (SignatureEncoding.HEX, "aa"),
    (SignatureEncoding.BASE64, "Zm9v"),
])
def test_signing_receipt_validates_identity_and_signature(encoding, signature):
    receipt = SigningReceipt(signature, "HSM-SHA256", encoding, "key/ref", "version/17")
    assert receipt.signature == signature


def test_signing_receipt_rejects_raw_encoding():
    with pytest.raises(SigningContractError):
        SigningReceipt("aa", "HSM-SHA256", "hex", "key/ref", "version/17")


def test_every_allowed_verification_outcome_constructs_successfully():
    for (signature_status, anchor_status), reasons in ALLOWED_VERIFICATION_OUTCOMES.items():
        for reason in reasons:
            outcome = ExternalVerificationOutcome(signature_status, anchor_status, reason, "safe")
            result = ArtifactVerificationResult(
                signature_status, anchor_status, reason, "safe", None
            )
            assert outcome.reason_code is reason
            assert result.reason_code is reason


def test_verification_matrix_rejects_every_unlisted_status_axis_pair():
    allowed_pairs = set(ALLOWED_VERIFICATION_OUTCOMES)
    for signature_status in SignatureStatus:
        for anchor_status in AnchorStatus:
            if (signature_status, anchor_status) not in allowed_pairs:
                with pytest.raises(VerificationContractError):
                    validate_verification_outcome(
                        signature_status, anchor_status, VerificationReasonCode.UNSIGNED
                    )


def test_verification_matrix_rejects_every_contradictory_reason():
    for (signature_status, anchor_status), allowed_reasons in ALLOWED_VERIFICATION_OUTCOMES.items():
        for reason_code in set(VerificationReasonCode) - allowed_reasons:
            with pytest.raises(VerificationContractError):
                validate_verification_outcome(signature_status, anchor_status, reason_code)


@pytest.mark.parametrize("message", [None, 1, "x" * (MAX_VERIFICATION_MESSAGE_LENGTH + 1)])
def test_verification_values_reject_invalid_messages(message):
    with pytest.raises(VerificationContractError):
        ExternalVerificationOutcome(
            SignatureStatus.UNSIGNED,
            AnchorStatus.NOT_EVALUATED,
            VerificationReasonCode.UNSIGNED,
            message,
        )


def test_verification_result_convenience_properties_follow_own_axes():
    result = ArtifactVerificationResult(
        SignatureStatus.VALID,
        AnchorStatus.INVALID,
        VerificationReasonCode.ANCHOR_INVALID,
        "anchor failure",
        _metadata(),
    )
    assert result.is_signature_valid is True
    assert result.is_anchored is False
