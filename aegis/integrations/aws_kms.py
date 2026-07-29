"""AWS KMS artifact signing with immutable concrete-ARN binding."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations._kms_common import (
    MAX_AWS_RAW_SIGNATURE_BYTES,
    _canonical_b64decode,
    _canonical_b64encode,
    _outcome,
    _sha256_digest,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
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

_AWS_KMS_PARTITIONS = frozenset(
    {
        "aws",
        "aws-cn",
        "aws-us-gov",
        "aws-iso",
        "aws-iso-b",
        "aws-iso-e",
        "aws-iso-f",
        "aws-eusc",
    }
)

_AWS_VERIFY_AVAILABILITY_EXCEPTION_NAMES = (
    "AccessDeniedException",
    "DependencyTimeoutException",
    "DisabledException",
    "KMSInternalException",
    "KMSInvalidStateException",
    "KeyUnavailableException",
    "NotFoundException",
    "ThrottlingException",
)

_AWS_VERIFY_AVAILABILITY_ERROR_CODES = frozenset(
    {
        "AccessDeniedException",
        "DependencyTimeoutException",
        "DisabledException",
        "InternalFailure",
        "KMSInternalException",
        "KMSInvalidStateException",
        "KeyUnavailableException",
        "NotFoundException",
        "NotAuthorized",
        "RequestTimeoutException",
        "ServiceUnavailable",
        "ThrottlingException",
    }
)

_AWS_KEY_ARN_PATTERN = re.compile(
    r"\Aarn:(?P<partition>[a-z0-9-]+):kms:"
    r"[a-z0-9]+(?:-[a-z0-9]+)*:[0-9]{12}:key/"
    r"(?:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32}"
    r")\Z",
    re.ASCII,
)

__all__ = [
    "AwsKmsArtifactSigner",
    "AwsKmsArtifactVerifier",
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


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class AwsKmsArtifactVerifier:
    """Verify artifacts only through a host-approved exact AWS KMS key ARN."""

    _client: object
    _resolver: Callable[
        [str, str],
        AwsKmsVerificationTarget | None,
    ]

    def __init__(
        self,
        client: object,
        *,
        resolver: Callable[
            [str, str],
            AwsKmsVerificationTarget | None,
        ],
    ) -> None:
        if client is None or not callable(resolver):
            raise VerificationContractError(
                "AWS KMS verifier configuration is invalid",
                details={},
            ) from None
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_resolver", resolver)

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        """Verify one exact payload without retaining mutable call state."""
        request_failed = False
        metadata_algorithm = None
        metadata_key_reference = None
        metadata_key_version = None
        decoded_signature = None
        try:
            if type(payload) is not bytes or type(metadata) is not SignatureMetadata:
                raise ValueError
            metadata_algorithm = metadata.algorithm
            metadata_encoding = metadata.signature_encoding
            metadata_key_reference = metadata.key_reference
            metadata_key_version = metadata.key_version
            if (
                not _is_metadata_algorithm(metadata_algorithm)
                or metadata_encoding is not SignatureEncoding.BASE64
                or not _is_key_reference(metadata_key_reference)
                or not _is_metadata_key_version(metadata_key_version)
            ):
                raise ValueError
            decoded_signature = _canonical_b64decode(
                signature,
                max_raw_bytes=MAX_AWS_RAW_SIGNATURE_BYTES,
            )
        except Exception:
            request_failed = True

        if (
            request_failed
            or metadata_algorithm is None
            or metadata_key_reference is None
            or metadata_key_version is None
            or decoded_signature is None
        ):
            raise VerificationContractError(
                "AWS KMS verification request is invalid",
                details={},
            ) from None

        if metadata_algorithm not in _AWS_ALGORITHMS:
            return _outcome(VerificationReasonCode.ALGORITHM_NOT_ALLOWED)

        resolver_failed = False
        resolved = None
        try:
            resolved = self._resolver(
                metadata_key_reference,
                metadata_key_version,
            )
        except Exception:
            resolver_failed = True

        if resolver_failed:
            raise VerificationContractError(
                "AWS KMS resolver failed",
                details={},
            ) from None
        if resolved is None:
            return _outcome(VerificationReasonCode.KEY_UNKNOWN)

        target_failed = False
        target = None
        try:
            if type(resolved) is not AwsKmsVerificationTarget:
                raise ValueError
            resolved_key_arn = resolved.key_arn
            resolved_algorithms = resolved.allowed_algorithms
            resolved_disposition = resolved.disposition
            if (
                type(resolved_key_arn) is not str
                or type(resolved_algorithms) is not frozenset
                or not resolved_algorithms
                or any(type(item) is not str for item in resolved_algorithms)
                or type(resolved_disposition) is not KmsKeyDisposition
            ):
                raise ValueError
            target = AwsKmsVerificationTarget(
                key_arn=str.__new__(str, resolved_key_arn),
                allowed_algorithms=frozenset(
                    str.__new__(str, item)
                    for item in resolved_algorithms
                ),
                disposition=resolved_disposition,
            )
            if target.key_arn != metadata_key_version:
                raise ValueError
        except Exception:
            target_failed = True

        if target_failed or target is None:
            raise VerificationContractError(
                "AWS KMS resolver returned an invalid target",
                details={},
            ) from None
        if target.disposition is KmsKeyDisposition.REVOKED:
            return _outcome(VerificationReasonCode.KEY_REVOKED)
        if metadata_algorithm not in target.allowed_algorithms:
            return _outcome(VerificationReasonCode.ALGORITHM_NOT_ALLOWED)

        digest_failed = False
        digest = None
        try:
            digest = _sha256_digest(payload)
        except Exception:
            digest_failed = True
        if digest_failed or digest is None:
            raise VerificationContractError(
                "AWS KMS verification request is invalid",
                details={},
            ) from None

        response = None
        provider_error = None
        try:
            response = self._client.verify(  # type: ignore[attr-defined]
                KeyId=target.key_arn,
                Message=digest,
                MessageType="DIGEST",
                Signature=decoded_signature,
                SigningAlgorithm=metadata_algorithm,
            )
        except Exception as error:
            provider_error = error

        if provider_error is not None:
            classification_failed = False
            classification = None
            try:
                classification = _classify_verify_error(
                    self._client,
                    provider_error,
                )
            except Exception:
                classification_failed = True
            if not classification_failed and classification is not None:
                return _outcome(classification)
            raise VerificationContractError(
                "AWS KMS verifier returned an invalid response",
                details={},
            ) from None

        response_failed = False
        signature_valid = None
        try:
            if type(response) is not dict:
                raise ValueError
            response_key_arn = dict.get(response, "KeyId")
            response_algorithm = dict.get(response, "SigningAlgorithm")
            signature_valid = dict.get(response, "SignatureValid")
            if (
                type(response_key_arn) is not str
                or response_key_arn != target.key_arn
                or type(response_algorithm) is not str
                or response_algorithm != metadata_algorithm
                or type(signature_valid) is not bool
            ):
                raise ValueError
        except Exception:
            response_failed = True

        if response_failed or signature_valid is None:
            raise VerificationContractError(
                "AWS KMS verifier returned an invalid response",
                details={},
            ) from None
        if signature_valid is False:
            return _outcome(VerificationReasonCode.SIGNATURE_INVALID)
        return _successful_verification_outcome(target.disposition)


def _is_key_reference(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 512
        and all("\x20" <= character <= "\x7e" for character in value)
    )


def _is_metadata_algorithm(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and all(
            character.isascii()
            and (
                character.isalnum()
                or character in "._-"
            )
            for character in value
        )
    )


def _is_metadata_key_version(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and all(
            character.isascii()
            and (
                character.isalnum()
                or character in "._:/-"
            )
            for character in value
        )
    )


def _is_concrete_key_arn(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 128:
        return False
    match = _AWS_KEY_ARN_PATTERN.fullmatch(value)
    return (
        match is not None
        and match.group("partition") in _AWS_KMS_PARTITIONS
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


def _classify_verify_error(
    client: object,
    error: BaseException,
) -> VerificationReasonCode | None:
    exceptions = None
    try:
        exceptions = client.exceptions  # type: ignore[attr-defined]
    except Exception:
        pass
    if exceptions is not None:
        invalid_signature_type = _client_exception_type(
            exceptions,
            "KMSInvalidSignatureException",
        )
        if (
            invalid_signature_type is not None
            and type(error) is invalid_signature_type
        ):
            return VerificationReasonCode.SIGNATURE_INVALID

        for exception_name in _AWS_VERIFY_AVAILABILITY_EXCEPTION_NAMES:
            exception_type = _client_exception_type(
                exceptions,
                exception_name,
            )
            if exception_type is not None and type(error) is exception_type:
                return VerificationReasonCode.VERIFIER_UNAVAILABLE

    client_error_code = _botocore_client_error_code(error)
    if client_error_code in _AWS_VERIFY_AVAILABILITY_ERROR_CODES:
        return VerificationReasonCode.VERIFIER_UNAVAILABLE
    return None


def _client_exception_type(
    exceptions: object,
    name: str,
) -> type[BaseException] | None:
    try:
        candidate = getattr(exceptions, name)
    except Exception:
        return None
    if (
        type(candidate) is not type
        or candidate.__name__ != name
        or not issubclass(candidate, BaseException)
        or candidate is BaseException
        or candidate is Exception
    ):
        return None
    return candidate


def _botocore_client_error_code(error: BaseException) -> str | None:
    try:
        from botocore.exceptions import ClientError
    except (ImportError, ModuleNotFoundError):
        return None
    if type(ClientError) is not type or type(error) is not ClientError:
        return None
    try:
        response = error.response
        if type(response) is not dict:
            return None
        error_fields = dict.get(response, "Error")
        if type(error_fields) is not dict:
            return None
        code = dict.get(error_fields, "Code")
        if type(code) is not str:
            return None
        return code
    except Exception:
        return None


def _successful_verification_outcome(
    disposition: KmsKeyDisposition,
) -> ExternalVerificationOutcome:
    reason_by_disposition = {
        KmsKeyDisposition.ANCHORED: (
            VerificationReasonCode.SIGNATURE_VALID_ANCHORED
        ),
        KmsKeyDisposition.UNANCHORED: (
            VerificationReasonCode.SIGNATURE_VALID_UNANCHORED
        ),
        KmsKeyDisposition.INVALID_ANCHOR: (
            VerificationReasonCode.ANCHOR_INVALID
        ),
    }
    reason = reason_by_disposition.get(disposition)
    if reason is None:
        raise VerificationContractError(
            "AWS KMS resolver returned an invalid target",
            details={},
        ) from None
    return _outcome(reason)
