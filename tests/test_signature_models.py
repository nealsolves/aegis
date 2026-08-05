"""Contract tests for typed signature and trust-anchor values."""

from dataclasses import FrozenInstanceError
from itertools import product

import pytest

from aegis._internal.errors import (
    AIGCError,
    ArtifactSigningError,
    SignatureMetadataError,
    SigningContractError,
    VerificationContractError,
)
from aegis._internal.signature_models import (
    CANONICALIZATION_VERSION,
    CHECKPOINT_CANONICALIZATION_VERSION,
    CHAIN_CHECKPOINT_SIGNING_PROFILE,
    MAX_SIGNATURE_LENGTH,
    MAX_VERIFICATION_MESSAGE_LENGTH,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
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
    _require_enum,
    validate_encoded_signature,
    validate_verification_outcome,
)


_ALLOWED_VERIFICATION_OUTCOMES = (
    (
        SignatureStatus.UNSIGNED,
        AnchorStatus.NOT_EVALUATED,
        (VerificationReasonCode.UNSIGNED,),
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.NOT_EVALUATED,
        (VerificationReasonCode.LEGACY_SIGNATURE_VALID,),
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.UNANCHORED,
        (
            VerificationReasonCode.LEGACY_SIGNATURE_VALID,
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
        ),
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.ANCHORED,
        (VerificationReasonCode.SIGNATURE_VALID_ANCHORED,),
    ),
    (
        SignatureStatus.VALID,
        AnchorStatus.INVALID,
        (VerificationReasonCode.ANCHOR_INVALID,),
    ),
    (
        SignatureStatus.INVALID,
        AnchorStatus.NOT_EVALUATED,
        (
            VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
            VerificationReasonCode.SIGNATURE_INVALID,
            VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
        ),
    ),
    (
        SignatureStatus.UNKNOWN_KEY,
        AnchorStatus.NOT_EVALUATED,
        (VerificationReasonCode.KEY_UNKNOWN,),
    ),
    (
        SignatureStatus.REVOKED,
        AnchorStatus.NOT_EVALUATED,
        (VerificationReasonCode.KEY_REVOKED,),
    ),
    (
        SignatureStatus.INDETERMINATE,
        AnchorStatus.NOT_EVALUATED,
        (
            VerificationReasonCode.SIGNATURE_METADATA_MISSING,
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
        ),
    ),
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


CHECKPOINT_CASES = (
    (
        EvidenceType.CHAIN_CHECKPOINT,
        "aegis-chain-checkpoint-v1",
        "aegis-json-v2",
    ),
    (
        EvidenceType.WORKFLOW_CHECKPOINT,
        "aegis-workflow-checkpoint-v1",
        "aegis-json-v2",
    ),
)


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
    assert CHAIN_CHECKPOINT_SIGNING_PROFILE == "aegis-chain-checkpoint-v1"
    assert WORKFLOW_CHECKPOINT_SIGNING_PROFILE == "aegis-workflow-checkpoint-v1"
    assert CHECKPOINT_CANONICALIZATION_VERSION == "aegis-json-v2"
    assert EvidenceType.AUDIT_ARTIFACT.value == "audit_artifact"
    assert EvidenceType.CHAIN_CHECKPOINT.value == "chain_checkpoint"
    assert EvidenceType.WORKFLOW_CHECKPOINT.value == "workflow_checkpoint"
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


def test_metadata_rejects_noncanonical_evidence_type_instance():
    forged_payload_type = str.__new__(EvidenceType, "audit_artifact")

    assert forged_payload_type == EvidenceType.AUDIT_ARTIFACT
    assert forged_payload_type is not EvidenceType.AUDIT_ARTIFACT
    with pytest.raises(SignatureMetadataError) as error:
        _metadata(payload_type=forged_payload_type)

    assert error.value.details == {"field": "payload_type"}


def test_models_reject_noncanonical_signature_encoding_instances():
    forged = str.__new__(SignatureEncoding, "base64")

    assert forged == SignatureEncoding.BASE64
    assert forged is not SignatureEncoding.BASE64
    with pytest.raises(SigningContractError) as error:
        SignerIdentity(
            algorithm="HSM-SHA256",
            signature_encoding=forged,
            key_reference="production/audit-key",
            key_version="version/17",
        )

    assert error.value.details == {"field": "signature_encoding"}


@pytest.mark.parametrize(
    ("field", "enum_type", "canonical"),
    (
        ("signature_status", SignatureStatus, SignatureStatus.UNSIGNED),
        ("anchor_status", AnchorStatus, AnchorStatus.NOT_EVALUATED),
        ("reason_code", VerificationReasonCode, VerificationReasonCode.UNSIGNED),
    ),
)
def test_verification_rejects_every_noncanonical_closed_enum_instance(
    field,
    enum_type,
    canonical,
):
    forged = str.__new__(enum_type, canonical.value)
    values = {
        "signature_status": SignatureStatus.UNSIGNED,
        "anchor_status": AnchorStatus.NOT_EVALUATED,
        "reason_code": VerificationReasonCode.UNSIGNED,
    }
    values[field] = forged

    assert forged == canonical
    assert forged is not canonical
    with pytest.raises(VerificationContractError) as error:
        validate_verification_outcome(**values)

    assert error.value.details == {"field": field}


@pytest.mark.parametrize(
    ("enum_type", "canonical", "error_type"),
    (
        (EvidenceType, EvidenceType.AUDIT_ARTIFACT, SignatureMetadataError),
        (SignatureEncoding, SignatureEncoding.HEX, SigningContractError),
        (SignatureStatus, SignatureStatus.INVALID, VerificationContractError),
        (AnchorStatus, AnchorStatus.NOT_EVALUATED, VerificationContractError),
        (
            VerificationReasonCode,
            VerificationReasonCode.SIGNATURE_INVALID,
            VerificationContractError,
        ),
    ),
)
def test_enum_authenticity_is_independent_of_mutable_enum_registries(
    enum_type,
    canonical,
    error_type,
):
    member_map = enum_type._member_map_
    member_names = enum_type._member_names_
    value_map = enum_type._value2member_map_
    original_map = member_map.copy()
    original_names = list(member_names)
    original_values = value_map.copy()
    forged = str.__new__(enum_type, canonical.value)
    object.__setattr__(forged, "_name_", "FORGED")
    object.__setattr__(forged, "_value_", canonical.value)
    try:
        member_map["FORGED"] = forged
        member_names.append("FORGED")
        value_map[canonical.value] = forged
        with pytest.raises(error_type) as error:
            _require_enum(forged, enum_type, "field", error_type)
        assert error.value.details == {"field": "field"}

        member_map.clear()
        member_names.clear()
        value_map.clear()
        assert _require_enum(canonical, enum_type, "field", error_type) is None
    finally:
        member_map.clear()
        member_map.update(original_map)
        member_names[:] = original_names
        value_map.clear()
        value_map.update(original_values)


def test_metadata_enum_parsing_is_independent_of_mutable_enum_registries():
    registries = []
    for enum_type in (EvidenceType, SignatureEncoding):
        registries.append((
            enum_type,
            enum_type._member_map_.copy(),
            list(enum_type._member_names_),
            enum_type._value2member_map_.copy(),
        ))
    value = _metadata().to_dict()
    try:
        for enum_type, _, _, _ in registries:
            enum_type._member_map_.clear()
            enum_type._member_names_.clear()
            enum_type._value2member_map_.clear()
        parsed = SignatureMetadata.from_dict(value)
        assert parsed.payload_type is EvidenceType.AUDIT_ARTIFACT
        assert parsed.signature_encoding is SignatureEncoding.BASE64
    finally:
        for enum_type, member_map, member_names, value_map in registries:
            enum_type._member_map_.clear()
            enum_type._member_map_.update(member_map)
            enum_type._member_names_[:] = member_names
            enum_type._value2member_map_.clear()
            enum_type._value2member_map_.update(value_map)


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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("algorithm", "HSM-SHA256\n"),
        ("key_version", "version/17\n"),
        ("key_reference", "key\u2028reference"),
        ("key_reference", "cl\u00e9"),
    ],
    ids=[
        "algorithm-terminal-newline",
        "key-version-terminal-newline",
        "key-reference-u2028",
        "key-reference-non-ascii-printable",
    ],
)
def test_metadata_rejects_values_outside_exact_ascii_lexical_contract(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


def test_identity_models_accept_exact_allowed_boundary_characters():
    identity = SignerIdentity(
        algorithm="A0._-",
        signature_encoding=SignatureEncoding.HEX,
        key_reference=" ~",
        key_version="A0._:/-",
    )
    metadata = _metadata(
        algorithm=identity.algorithm,
        signature_encoding=identity.signature_encoding,
        key_reference=identity.key_reference,
        key_version=identity.key_version,
    )

    assert metadata.key_reference == " ~"


@pytest.mark.parametrize("field, value", [
    ("schema_version", "2"),
    ("signing_profile", "other-profile"),
    ("canonicalization_version", "other-canonicalization"),
])
def test_metadata_requires_supported_contract_values(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("signing_profile", []),
        ("signing_profile", {}),
        ("canonicalization_version", []),
        ("canonicalization_version", {}),
    ],
)
def test_metadata_rejects_unhashable_profile_discriminators(field, value):
    with pytest.raises(SignatureMetadataError):
        _metadata(**{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("signing_profile", []),
        ("signing_profile", {}),
        ("canonicalization_version", []),
        ("canonicalization_version", {}),
    ],
)
def test_metadata_from_dict_rejects_unhashable_profile_discriminators(field, value):
    metadata = _metadata().to_dict()
    metadata[field] = value

    with pytest.raises(SignatureMetadataError):
        SignatureMetadata.from_dict(metadata)


class ValueEqualString(str):
    pass


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("signing_profile", ValueEqualString("aegis-signature-v1"), "aegis-signature-v1"),
        (
            "canonicalization_version",
            ValueEqualString("aegis-canonical-json-v1"),
            "aegis-canonical-json-v1",
        ),
    ],
)
def test_metadata_rejects_value_equal_string_subclass_discriminators(
    field, value, expected
):
    assert value == expected
    assert type(value) is not str

    with pytest.raises(SignatureMetadataError) as error:
        _metadata(**{field: value})

    assert error.value.details == {"field": field}


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("signing_profile", ValueEqualString("aegis-signature-v1"), "aegis-signature-v1"),
        (
            "canonicalization_version",
            ValueEqualString("aegis-canonical-json-v1"),
            "aegis-canonical-json-v1",
        ),
    ],
)
def test_metadata_from_dict_rejects_value_equal_string_subclass_discriminators(
    field, value, expected
):
    assert value == expected
    assert type(value) is not str
    metadata = _metadata().to_dict()
    metadata[field] = value

    with pytest.raises(SignatureMetadataError) as error:
        SignatureMetadata.from_dict(metadata)

    assert error.value.details == {"field": field}


@pytest.mark.parametrize("payload_type,profile,canonicalization", CHECKPOINT_CASES)
def test_metadata_accepts_only_closed_checkpoint_tuple(
    payload_type, profile, canonicalization
):
    metadata = _metadata(
        payload_type=payload_type,
        signing_profile=profile,
        canonicalization_version=canonicalization,
    )
    assert SignatureMetadata.from_dict(metadata.to_dict()) == metadata


@pytest.mark.parametrize("payload_type,profile,canonicalization", [
    (EvidenceType.AUDIT_ARTIFACT, "aegis-chain-checkpoint-v1", "aegis-json-v2"),
    (EvidenceType.CHAIN_CHECKPOINT, "aegis-signature-v1", "aegis-json-v2"),
    (EvidenceType.CHAIN_CHECKPOINT, "aegis-chain-checkpoint-v1",
     "aegis-canonical-json-v1"),
    (EvidenceType.WORKFLOW_CHECKPOINT, "aegis-chain-checkpoint-v1", "aegis-json-v2"),
])
def test_metadata_rejects_cross_profile_tuple(
    payload_type, profile, canonicalization
):
    with pytest.raises(SignatureMetadataError):
        _metadata(
            payload_type=payload_type,
            signing_profile=profile,
            canonicalization_version=canonicalization,
        )


def test_metadata_accepts_exactly_the_closed_signature_profile_matrix():
    payload_types = tuple(EvidenceType)
    signing_profiles = (
        SIGNING_PROFILE,
        CHAIN_CHECKPOINT_SIGNING_PROFILE,
        WORKFLOW_CHECKPOINT_SIGNING_PROFILE,
    )
    canonicalization_versions = (
        CANONICALIZATION_VERSION,
        CHECKPOINT_CANONICALIZATION_VERSION,
    )
    supported = {
        (EvidenceType.AUDIT_ARTIFACT, "aegis-signature-v1", "aegis-canonical-json-v1"),
        *CHECKPOINT_CASES,
    }

    for metadata_tuple in product(
        payload_types, signing_profiles, canonicalization_versions
    ):
        payload_type, profile, canonicalization = metadata_tuple
        if metadata_tuple in supported:
            assert _metadata(
                payload_type=payload_type,
                signing_profile=profile,
                canonicalization_version=canonicalization,
            ).payload_type is payload_type
        else:
            with pytest.raises(SignatureMetadataError):
                _metadata(
                    payload_type=payload_type,
                    signing_profile=profile,
                    canonicalization_version=canonicalization,
                )


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
    assert set(exc_info.value.details).issubset(
        {"field", "missing_count", "extra_count"}
    )


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
    for signature_status, anchor_status, reasons in _ALLOWED_VERIFICATION_OUTCOMES:
        for reason in reasons:
            outcome = ExternalVerificationOutcome(signature_status, anchor_status, reason, "safe")
            result = ArtifactVerificationResult(
                signature_status, anchor_status, reason, "safe", None
            )
            assert outcome.reason_code is reason
            assert result.reason_code is reason


def test_verification_matrix_rejects_every_unlisted_status_axis_pair():
    allowed_pairs = {
        (signature_status, anchor_status)
        for signature_status, anchor_status, _ in _ALLOWED_VERIFICATION_OUTCOMES
    }
    for signature_status in SignatureStatus:
        for anchor_status in AnchorStatus:
            if (signature_status, anchor_status) not in allowed_pairs:
                with pytest.raises(VerificationContractError):
                    validate_verification_outcome(
                        signature_status, anchor_status, VerificationReasonCode.UNSIGNED
                    )


def test_verification_matrix_rejects_every_contradictory_reason():
    for (
        signature_status,
        anchor_status,
        allowed_reasons,
    ) in _ALLOWED_VERIFICATION_OUTCOMES:
        for reason_code in set(VerificationReasonCode) - set(allowed_reasons):
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
