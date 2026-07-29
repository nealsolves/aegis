"""Strict private-boundary tests for the provider-neutral KMS helpers."""

import hashlib

import pytest

import aegis.integrations
from aegis.errors import SigningContractError, VerificationContractError
from aegis.integrations._kms_common import (
    MAX_CRC32C,
    MAX_RAW_SIGNATURE_BYTES,
    _USE_PROVIDER_DEFAULT,
    _canonical_b64decode,
    _canonical_b64encode,
    _normalize_crc32c,
    _normalize_timeout,
    _outcome,
    _sha256_digest,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    AnchorStatus,
    SignatureStatus,
    VerificationReasonCode,
)


def test_kms_dispositions_are_the_frozen_host_trust_policy_values():
    """Changing a host policy value would misclassify a successful signature."""
    assert {member.name: member.value for member in KmsKeyDisposition} == {
        "ANCHORED": "anchored",
        "UNANCHORED": "unanchored",
        "INVALID_ANCHOR": "invalid_anchor",
        "REVOKED": "revoked",
    }


def test_integrations_namespace_has_no_provider_classes_or_reexports():
    """A convenience re-export would make provider dependencies import eagerly."""
    assert {
        "AwsKmsArtifactSigner",
        "AwsKmsArtifactVerifier",
        "AwsKmsVerificationTarget",
        "GoogleCloudKmsArtifactSigner",
        "GoogleCloudKmsArtifactVerifier",
        "GoogleCloudKmsVerificationTarget",
        "KmsKeyDisposition",
    }.isdisjoint(aegis.integrations.__dict__)


@pytest.mark.parametrize(
    ("reason_code", "signature_status", "anchor_status", "message"),
    [
        (
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED,
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            "Signature is valid and externally anchored",
        ),
        (
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED,
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            "Signature is valid but not externally anchored",
        ),
        (
            VerificationReasonCode.ANCHOR_INVALID,
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            "The external anchor is invalid",
        ),
        (
            VerificationReasonCode.KEY_REVOKED,
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier reports the key version as revoked",
        ),
        (
            VerificationReasonCode.KEY_UNKNOWN,
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier does not recognize the key version",
        ),
        (
            VerificationReasonCode.ALGORITHM_NOT_ALLOWED,
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "The configured key does not permit the declared algorithm",
        ),
        (
            VerificationReasonCode.SIGNATURE_INVALID,
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "Signature is invalid",
        ),
        (
            VerificationReasonCode.VERIFIER_UNAVAILABLE,
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            "External verification is unavailable",
        ),
    ],
)
def test_outcome_uses_only_the_provider_neutral_closed_matrix(
    reason_code, signature_status, anchor_status, message
):
    """Wrong status pairs would violate the #44 verification contract."""
    outcome = _outcome(reason_code)

    assert outcome.signature_status is signature_status
    assert outcome.anchor_status is anchor_status
    assert outcome.reason_code is reason_code
    assert outcome.message == message


@pytest.mark.parametrize(
    "reason_code",
    [
        VerificationReasonCode.UNSIGNED,
        VerificationReasonCode.LEGACY_SIGNATURE_VALID,
        VerificationReasonCode.LEGACY_SIGNATURE_INVALID,
        VerificationReasonCode.SIGNATURE_METADATA_MISSING,
    ],
)
def test_outcome_rejects_reason_codes_outside_the_kms_matrix(reason_code):
    """Accepting a legacy outcome would widen the KMS verifier's state space."""
    with pytest.raises(ValueError, match="verification outcome reason is invalid"):
        _outcome(reason_code)


def test_sha256_digest_hashes_the_exact_bytes_given():
    """A text coercion would sign different bytes than the artifact contains."""
    payload = b"\x00A\xff\n"

    assert _sha256_digest(payload) == hashlib.sha256(payload).digest()


@pytest.mark.parametrize("value", [bytearray(b"payload"), memoryview(b"payload"), "payload"])
def test_sha256_digest_rejects_non_exact_bytes(value):
    """Accepting a bytes lookalike would weaken the artifact boundary."""
    with pytest.raises(ValueError, match="payload is invalid") as error:
        _sha256_digest(value)

    assert repr(value) not in str(error.value)


def test_canonical_base64_round_trips_exact_bytes():
    """A noncanonical encoder would create a signature the verifier rejects."""
    raw = b"\x00A\xff\n"

    encoded = _canonical_b64encode(raw)

    assert encoded == "AEH/Cg=="
    assert _canonical_b64decode(encoded, max_raw_bytes=MAX_RAW_SIGNATURE_BYTES) == raw


class _BytesSubclass(bytes):
    pass


class _StringSubclass(str):
    pass


@pytest.mark.parametrize("value", [b"", _BytesSubclass(b"value"), bytearray(b"value")])
def test_canonical_base64_encode_rejects_empty_or_non_exact_bytes(value):
    """An empty or subclassed signature response must not become trusted data."""
    with pytest.raises(ValueError, match="base64 value is invalid") as error:
        _canonical_b64encode(value)

    assert repr(value) not in str(error.value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "YQ==\n",
        "YQ== ",
        "YQ",
        "YQ===",
        "YQ-_",
        _StringSubclass("YQ=="),
        b"YQ==",
    ],
)
def test_canonical_base64_decode_rejects_noncanonical_or_non_exact_strings(value):
    """Alternate encodings could bypass the signature metadata's canonical form."""
    with pytest.raises(ValueError, match="base64 value is invalid") as error:
        _canonical_b64decode(value, max_raw_bytes=MAX_RAW_SIGNATURE_BYTES)

    assert repr(value) not in str(error.value)


def test_canonical_base64_decode_accepts_the_raw_signature_limit():
    """The allowed maximum must remain usable by supported KMS algorithms."""
    raw = b"x" * MAX_RAW_SIGNATURE_BYTES
    encoded = _canonical_b64encode(raw)

    assert _canonical_b64decode(encoded, max_raw_bytes=MAX_RAW_SIGNATURE_BYTES) == raw


def test_canonical_base64_decode_rejects_a_decoded_value_past_the_limit():
    """An off-by-one limit could exceed the signed metadata size contract."""
    encoded = _canonical_b64encode(b"x" * (MAX_RAW_SIGNATURE_BYTES + 1))

    with pytest.raises(ValueError, match="base64 value is invalid"):
        _canonical_b64decode(encoded, max_raw_bytes=MAX_RAW_SIGNATURE_BYTES)


@pytest.mark.parametrize("value", [True, -1, MAX_CRC32C + 1])
def test_normalize_crc32c_rejects_out_of_range_or_non_exact_integer(value):
    """Boolean and oversized checksums could falsely satisfy a provider response."""
    with pytest.raises(ValueError, match="crc32c is invalid") as error:
        _normalize_crc32c(value)

    assert repr(value) not in str(error.value)


def test_normalize_crc32c_accepts_the_inclusive_uint32_range():
    """The checksum field is an unsigned 32-bit integer, including both ends."""
    assert _normalize_crc32c(0) == 0
    assert _normalize_crc32c(MAX_CRC32C) == MAX_CRC32C


def test_normalize_timeout_distinguishes_omission_from_explicit_none():
    """Omitted SDK parameters and explicit None have intentionally different calls."""
    assert _normalize_timeout(
        _USE_PROVIDER_DEFAULT, error_type=SigningContractError
    ) is _USE_PROVIDER_DEFAULT
    assert _normalize_timeout(None, error_type=SigningContractError) is None
    assert _USE_PROVIDER_DEFAULT is not None


@pytest.mark.parametrize("value", [True, 0, -1, 0.0, -0.5, float("nan"), float("inf")])
def test_normalize_timeout_rejects_nonpositive_or_nonfinite_values(value):
    """Invalid timeout values must fail before an SDK receives them."""
    with pytest.raises(VerificationContractError, match="timeout is invalid") as error:
        _normalize_timeout(value, error_type=VerificationContractError)

    assert repr(value) not in str(error.value)


@pytest.mark.parametrize("value", [1, 0.5])
def test_normalize_timeout_preserves_exact_positive_builtin_numbers(value):
    """Valid timeout values must reach the provider without coercion."""
    assert _normalize_timeout(value, error_type=SigningContractError) == value
