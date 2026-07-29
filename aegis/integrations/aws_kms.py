"""AWS KMS artifact signing with immutable concrete-ARN binding."""

from __future__ import annotations

from dataclasses import dataclass
import re

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations._kms_common import (
    MAX_AWS_RAW_SIGNATURE_BYTES,
    _canonical_b64encode,
    _sha256_digest,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    SignatureEncoding,
    SignerIdentity,
    SigningReceipt,
)


_AWS_ALGORITHMS = {
    "RSASSA_PSS_SHA_256": frozenset(
        {"RSA_2048", "RSA_3072", "RSA_4096"}
    ),
    "ECDSA_SHA_256": frozenset(
        {"ECC_NIST_P256", "ECC_SECG_P256K1"}
    ),
}

_AWS_SIGNING_ALGORITHMS = frozenset(
    {
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
        "ECDSA_SHA_256",
        "ECDSA_SHA_384",
        "ECDSA_SHA_512",
        "SM2DSA",
        "ML_DSA_SHAKE_256",
        "ED25519_SHA_512",
        "ED25519_PH_SHA_512",
    }
)

_AWS_KEY_ARN_PATTERN = re.compile(
    r"\Aarn:aws(?:-[a-z0-9]+)*:kms:"
    r"[a-z0-9]+(?:-[a-z0-9]+)*:[0-9]{12}:key/"
    r"(?:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32}"
    r")\Z",
    re.ASCII,
)

__all__ = [
    "AwsKmsArtifactSigner",
    "AwsKmsVerificationTarget",
]


@dataclass(frozen=True)
class AwsKmsVerificationTarget:
    """Host-approved AWS KMS verification policy for one concrete key ARN."""

    key_arn: str
    allowed_algorithms: frozenset[str]
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED

    def __post_init__(self) -> None:
        valid = (
            _is_concrete_key_arn(self.key_arn)
            and type(self.allowed_algorithms) is frozenset
            and bool(self.allowed_algorithms)
            and all(
                type(algorithm) is str and algorithm in _AWS_ALGORITHMS
                for algorithm in self.allowed_algorithms
            )
            and type(self.disposition) is KmsKeyDisposition
        )
        if not valid:
            raise VerificationContractError(
                "AWS KMS verification target is invalid",
                details={},
            ) from None


@dataclass(frozen=True)
class _AwsKeyDescription:
    key_arn: str
    key_spec: str


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class AwsKmsArtifactSigner:
    """Sign exact artifact bytes using a host-injected AWS KMS client."""

    _client: object
    _key_id: str
    _signing_algorithm: str

    def __init__(
        self,
        client: object,
        *,
        key_id: str,
        signing_algorithm: str,
    ) -> None:
        if (
            client is None
            or not _is_key_reference(key_id)
            or type(signing_algorithm) is not str
            or signing_algorithm not in _AWS_ALGORITHMS
        ):
            raise SigningContractError(
                "AWS KMS signer configuration is invalid",
                details={},
            ) from None
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_key_id", key_id)
        object.__setattr__(self, "_signing_algorithm", signing_algorithm)

    def signer_identity(self) -> SignerIdentity:
        """Resolve the configured selector to one eligible concrete key ARN."""
        failed = False
        identity = None
        try:
            response = self._client.describe_key(KeyId=self._key_id)  # type: ignore[attr-defined]
            description = _normalize_key_description(
                response,
                signing_algorithm=self._signing_algorithm,
            )
            identity = SignerIdentity(
                self._signing_algorithm,
                SignatureEncoding.BASE64,
                self._key_id,
                description.key_arn,
            )
        except Exception:
            failed = True

        if failed or identity is None:
            raise SigningContractError(
                "AWS KMS signer could not prepare identity",
                details={},
            ) from None
        return identity

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        """Sign a SHA-256 digest through the identity's immutable key ARN."""
        failed = False
        receipt = None
        try:
            if type(payload) is not bytes:
                raise ValueError
            normalized_identity = _normalize_signing_identity(
                identity,
                key_reference=self._key_id,
                signing_algorithm=self._signing_algorithm,
            )
            response = self._client.describe_key(KeyId=self._key_id)  # type: ignore[attr-defined]
            description = _normalize_key_description(
                response,
                signing_algorithm=self._signing_algorithm,
            )
            if description.key_arn != normalized_identity.key_version:
                raise ValueError
            digest = _sha256_digest(payload)
            sign_response = self._client.sign(  # type: ignore[attr-defined]
                KeyId=normalized_identity.key_version,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm=normalized_identity.algorithm,
            )
            signature = _normalize_sign_response(
                sign_response,
                key_arn=normalized_identity.key_version,
                signing_algorithm=normalized_identity.algorithm,
            )
            receipt = SigningReceipt(
                _canonical_b64encode(signature),
                normalized_identity.algorithm,
                normalized_identity.signature_encoding,
                normalized_identity.key_reference,
                normalized_identity.key_version,
            )
        except Exception:
            failed = True

        if failed or receipt is None:
            raise ArtifactSigningError(
                "AWS KMS signer could not produce a signature",
                details={},
            ) from None
        return receipt


def _is_key_reference(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and all("\x20" <= character <= "\x7e" for character in value)
    )


def _is_concrete_key_arn(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and _AWS_KEY_ARN_PATTERN.fullmatch(value) is not None
    )


def _normalize_key_description(
    response: object,
    *,
    signing_algorithm: str,
) -> _AwsKeyDescription:
    if type(response) is not dict:
        raise ValueError
    metadata = dict.get(response, "KeyMetadata")
    if type(metadata) is not dict:
        raise ValueError

    key_arn = dict.get(metadata, "Arn")
    key_usage = dict.get(metadata, "KeyUsage")
    key_state = dict.get(metadata, "KeyState")
    enabled = dict.get(metadata, "Enabled")
    key_spec = dict.get(metadata, "KeySpec")
    signing_algorithms = dict.get(metadata, "SigningAlgorithms")

    if (
        not _is_concrete_key_arn(key_arn)
        or type(key_usage) is not str
        or key_usage != "SIGN_VERIFY"
        or type(key_state) is not str
        or key_state != "Enabled"
        or type(enabled) is not bool
        or enabled is not True
        or type(key_spec) is not str
        or key_spec not in _AWS_ALGORITHMS[signing_algorithm]
        or type(signing_algorithms) is not list
        or not signing_algorithms
        or any(
            type(algorithm) is not str
            or algorithm not in _AWS_SIGNING_ALGORITHMS
            for algorithm in signing_algorithms
        )
        or len(signing_algorithms) != len(set(signing_algorithms))
        or signing_algorithm not in signing_algorithms
    ):
        raise ValueError
    return _AwsKeyDescription(key_arn, key_spec)


def _normalize_signing_identity(
    identity: object,
    *,
    key_reference: str,
    signing_algorithm: str,
) -> SignerIdentity:
    if type(identity) is not SignerIdentity:
        raise ValueError
    normalized = SignerIdentity(
        identity.algorithm,
        identity.signature_encoding,
        identity.key_reference,
        identity.key_version,
    )
    if (
        type(normalized.algorithm) is not str
        or normalized.algorithm != signing_algorithm
        or normalized.signature_encoding is not SignatureEncoding.BASE64
        or type(normalized.key_reference) is not str
        or normalized.key_reference != key_reference
        or not _is_concrete_key_arn(normalized.key_version)
    ):
        raise ValueError
    return normalized


def _normalize_sign_response(
    response: object,
    *,
    key_arn: str,
    signing_algorithm: str,
) -> bytes:
    if type(response) is not dict:
        raise ValueError
    response_key_arn = dict.get(response, "KeyId")
    response_algorithm = dict.get(response, "SigningAlgorithm")
    signature = dict.get(response, "Signature")
    if (
        type(response_key_arn) is not str
        or response_key_arn != key_arn
        or type(response_algorithm) is not str
        or response_algorithm != signing_algorithm
        or type(signature) is not bytes
        or not signature
        or len(signature) > MAX_AWS_RAW_SIGNATURE_BYTES
    ):
        raise ValueError
    return signature
