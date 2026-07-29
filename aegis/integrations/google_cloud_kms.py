"""Google Cloud KMS artifact signing with exact-version CRC32C binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from aegis.errors import (
    ArtifactSigningError,
    SigningContractError,
    VerificationContractError,
)
from aegis.integrations._kms_common import (
    MAX_PUBLIC_KEY_PEM_BYTES,
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
    ExternalVerificationOutcome,
    SignatureEncoding,
    SignatureMetadata,
    SignerIdentity,
    SigningReceipt,
    VerificationReasonCode,
)


_GOOGLE_ALGORITHMS = {
    "RSA_SIGN_PSS_2048_SHA256": ("rsa", 2048),
    "RSA_SIGN_PSS_3072_SHA256": ("rsa", 3072),
    "RSA_SIGN_PSS_4096_SHA256": ("rsa", 4096),
    "EC_SIGN_P256_SHA256": ("ec", 256),
}

_VERSION_SEPARATOR = "/cryptoKeyVersions/"
_MAX_KEY_REFERENCE_LENGTH = 512
_MAX_KEY_VERSION_LENGTH = 128
_MAX_CRYPTO_KEY_VERSION_NAME_LENGTH = 659

__all__ = [
    "GoogleCloudKmsArtifactSigner",
    "GoogleCloudKmsArtifactVerifier",
    "GoogleCloudKmsVerificationTarget",
]


@dataclass(frozen=True, repr=False)
class GoogleCloudKmsVerificationTarget:
    """Host-approved Google KMS verification policy for one exact version."""

    crypto_key_version_name: str
    algorithm: str
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED
    public_key_pem: bytes | None = None

    def __post_init__(self) -> None:
        failed = False
        try:
            if (
                _parse_crypto_key_version_name(
                    self.crypto_key_version_name
                ) is None
                or type(self.algorithm) is not str
                or self.algorithm not in _GOOGLE_ALGORITHMS
                or type(self.disposition) is not KmsKeyDisposition
                or (
                    self.public_key_pem is not None
                    and (
                        type(self.public_key_pem) is not bytes
                        or not self.public_key_pem
                        or len(self.public_key_pem)
                        > MAX_PUBLIC_KEY_PEM_BYTES
                    )
                )
            ):
                raise ValueError
            if self.public_key_pem is not None:
                _load_validated_public_key(
                    self.public_key_pem,
                    self.algorithm,
                )
        except Exception:
            failed = True
        if failed:
            raise VerificationContractError(
                "Google Cloud KMS verification target is invalid",
                details={},
            ) from None


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class GoogleCloudKmsArtifactSigner:
    """Sign exact artifact bytes through a host-injected Google KMS client."""

    _client: object
    _crypto_key_version_name: str
    _key_reference: str
    _key_version: str
    _retry: object
    _timeout: object

    def __init__(
        self,
        client: object,
        *,
        crypto_key_version_name: str,
        retry: object = _USE_PROVIDER_DEFAULT,
        timeout: object = _USE_PROVIDER_DEFAULT,
    ) -> None:
        resource = _parse_crypto_key_version_name(crypto_key_version_name)
        if client is None or resource is None:
            raise SigningContractError(
                "Google Cloud KMS signer configuration is invalid",
                details={},
            ) from None
        normalized_timeout = _normalize_timeout(
            timeout,
            error_type=SigningContractError,
        )
        key_reference, key_version = resource
        object.__setattr__(self, "_client", client)
        object.__setattr__(
            self,
            "_crypto_key_version_name",
            crypto_key_version_name,
        )
        object.__setattr__(self, "_key_reference", key_reference)
        object.__setattr__(self, "_key_version", key_version)
        object.__setattr__(self, "_retry", retry)
        object.__setattr__(self, "_timeout", normalized_timeout)

    def signer_identity(self) -> SignerIdentity:
        """Prepare an identity from one exact enabled CryptoKeyVersion."""
        failed = False
        identity = None
        try:
            kms_v1, _google_crc32c = _load_google_dependencies()
            version = self._get_crypto_key_version(kms_v1)
            algorithm = _normalize_crypto_key_version(
                kms_v1,
                version,
                expected_name=self._crypto_key_version_name,
            )
            identity = SignerIdentity(
                algorithm,
                SignatureEncoding.BASE64,
                self._key_reference,
                self._key_version,
            )
        except Exception:
            failed = True

        if failed or identity is None:
            raise SigningContractError(
                "Google Cloud KMS signer could not prepare identity",
                details={},
            ) from None
        return identity

    def sign(self, payload: bytes, identity: SignerIdentity) -> SigningReceipt:
        """Sign a SHA-256 digest after rechecking the exact key version."""
        failed = False
        receipt = None
        try:
            if type(payload) is not bytes:
                raise ValueError
            normalized_identity = _normalize_signing_identity(
                identity,
                crypto_key_version_name=self._crypto_key_version_name,
                key_reference=self._key_reference,
                key_version=self._key_version,
            )
            kms_v1, google_crc32c = _load_google_dependencies()
            version = self._get_crypto_key_version(kms_v1)
            algorithm = _normalize_crypto_key_version(
                kms_v1,
                version,
                expected_name=self._crypto_key_version_name,
            )
            if algorithm != normalized_identity.algorithm:
                raise ValueError

            digest = _sha256_digest(payload)
            digest_crc32c = _crc32c(google_crc32c, digest)
            request = kms_v1.AsymmetricSignRequest(
                name=self._crypto_key_version_name,
                digest=kms_v1.Digest(sha256=digest),
                digest_crc32c=digest_crc32c,
            )
            response = self._client.asymmetric_sign(  # type: ignore[attr-defined]
                **self._call_kwargs(request)
            )
            signature = _normalize_asymmetric_sign_response(
                google_crc32c,
                response,
                expected_name=self._crypto_key_version_name,
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
                "Google Cloud KMS signer could not produce a signature",
                details={},
            ) from None
        return receipt

    def _get_crypto_key_version(self, kms_v1: object) -> object:
        request = kms_v1.GetCryptoKeyVersionRequest(  # type: ignore[attr-defined]
            name=self._crypto_key_version_name,
        )
        return self._client.get_crypto_key_version(  # type: ignore[attr-defined]
            **self._call_kwargs(request)
        )

    def _call_kwargs(self, request: object) -> dict[str, object]:
        kwargs = {"request": request}
        if self._retry is not _USE_PROVIDER_DEFAULT:
            kwargs["retry"] = self._retry
        if self._timeout is not _USE_PROVIDER_DEFAULT:
            kwargs["timeout"] = self._timeout
        return kwargs


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class GoogleCloudKmsArtifactVerifier:
    """Verify through one resolver-approved version or retained public key."""

    _client: object | None
    _resolver: Callable[
        [str, str],
        GoogleCloudKmsVerificationTarget | None,
    ]
    _retry: object
    _timeout: object

    def __init__(
        self,
        client: object | None,
        *,
        resolver: Callable[
            [str, str],
            GoogleCloudKmsVerificationTarget | None,
        ],
        retry: object = _USE_PROVIDER_DEFAULT,
        timeout: object = _USE_PROVIDER_DEFAULT,
    ) -> None:
        if not callable(resolver):
            raise VerificationContractError(
                "Google Cloud KMS verifier configuration is invalid",
                details={},
            ) from None
        normalized_timeout = _normalize_timeout(
            timeout,
            error_type=VerificationContractError,
        )
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_resolver", resolver)
        object.__setattr__(self, "_retry", retry)
        object.__setattr__(self, "_timeout", normalized_timeout)

    def verify(
        self,
        payload: bytes,
        signature: str,
        metadata: SignatureMetadata,
    ) -> ExternalVerificationOutcome:
        """Verify exact bytes without retaining mutable per-call state."""
        request_failed = False
        metadata_algorithm = None
        metadata_key_reference = None
        metadata_key_version = None
        decoded_signature = None
        try:
            if type(payload) is not bytes or type(metadata) is not SignatureMetadata:
                raise ValueError
            algorithm = metadata.algorithm
            encoding = metadata.signature_encoding
            key_reference = metadata.key_reference
            key_version = metadata.key_version
            if (
                not _is_metadata_algorithm(algorithm)
                or encoding is not SignatureEncoding.BASE64
                or not _is_key_reference(key_reference)
                or not _is_metadata_key_version(key_version)
            ):
                raise ValueError
            metadata_algorithm = str.__new__(str, algorithm)
            metadata_key_reference = str.__new__(str, key_reference)
            metadata_key_version = str.__new__(str, key_version)
            decoded_signature = _canonical_b64decode(
                signature,
                max_raw_bytes=MAX_RAW_SIGNATURE_BYTES,
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
                "Google Cloud KMS verification request is invalid",
                details={},
            ) from None

        if metadata_algorithm not in _GOOGLE_ALGORITHMS:
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
                "Google Cloud KMS resolver failed",
                details={},
            ) from None
        if resolved is None:
            return _outcome(VerificationReasonCode.KEY_UNKNOWN)

        target_failed = False
        target = None
        retained_pem = None
        try:
            if type(resolved) is not GoogleCloudKmsVerificationTarget:
                raise ValueError
            resolved_name = resolved.crypto_key_version_name
            resolved_algorithm = resolved.algorithm
            resolved_disposition = resolved.disposition
            resolved_pem = resolved.public_key_pem
            if (
                type(resolved_name) is not str
                or type(resolved_algorithm) is not str
                or type(resolved_disposition) is not KmsKeyDisposition
                or (
                    resolved_pem is not None
                    and (
                        type(resolved_pem) is not bytes
                        or not resolved_pem
                        or len(resolved_pem) > MAX_PUBLIC_KEY_PEM_BYTES
                    )
                )
            ):
                raise ValueError
            copied_name = str.__new__(str, resolved_name)
            copied_algorithm = str.__new__(str, resolved_algorithm)
            copied_pem = (
                None if resolved_pem is None else bytes(resolved_pem)
            )
            target = GoogleCloudKmsVerificationTarget(
                copied_name,
                copied_algorithm,
                resolved_disposition,
            )
            parsed_target = _parse_crypto_key_version_name(
                target.crypto_key_version_name
            )
            if parsed_target != (
                metadata_key_reference,
                metadata_key_version,
            ):
                raise ValueError
            retained_pem = copied_pem
        except Exception:
            target_failed = True
        if target_failed or target is None:
            raise VerificationContractError(
                "Google Cloud KMS resolver returned an invalid target",
                details={},
            ) from None

        if target.disposition is KmsKeyDisposition.REVOKED:
            return _outcome(VerificationReasonCode.KEY_REVOKED)
        if target.algorithm != metadata_algorithm:
            return _outcome(VerificationReasonCode.ALGORITHM_NOT_ALLOWED)

        if retained_pem is not None:
            validated_target_failed = False
            try:
                target = GoogleCloudKmsVerificationTarget(
                    target.crypto_key_version_name,
                    target.algorithm,
                    target.disposition,
                    retained_pem,
                )
            except Exception:
                validated_target_failed = True
            if validated_target_failed:
                raise VerificationContractError(
                    "Google Cloud KMS resolver returned an invalid target",
                    details={},
                ) from None
        elif self._client is None:
            return _outcome(VerificationReasonCode.VERIFIER_UNAVAILABLE)

        if retained_pem is None:
            public_key_pem_or_outcome = self._fetch_public_key(
                target,
            )
            if type(public_key_pem_or_outcome) is ExternalVerificationOutcome:
                return public_key_pem_or_outcome
            if type(public_key_pem_or_outcome) is not bytes:
                raise VerificationContractError(
                    "Google Cloud KMS verifier returned an invalid response",
                    details={},
                ) from None
            public_key_pem = public_key_pem_or_outcome
        else:
            public_key_pem = retained_pem

        digest_failed = False
        digest = None
        public_key = None
        try:
            digest = _sha256_digest(payload)
            public_key = _load_validated_public_key(
                public_key_pem,
                metadata_algorithm,
            )
        except Exception:
            digest_failed = True
        if digest_failed or digest is None or public_key is None:
            raise VerificationContractError(
                "Google Cloud KMS verifier returned an invalid response",
                details={},
            ) from None

        return _verify_local_signature(
            public_key,
            digest,
            decoded_signature,
            metadata_algorithm,
            target.disposition,
        )

    def _fetch_public_key(
        self,
        target: GoogleCloudKmsVerificationTarget,
    ) -> bytes | ExternalVerificationOutcome:
        setup_failed = False
        kms_v1 = None
        google_crc32c = None
        request = None
        try:
            kms_v1, google_crc32c = _load_google_dependencies()
            pem_format = kms_v1.PublicKey.PublicKeyFormat.PEM  # type: ignore[attr-defined]
            request = kms_v1.GetPublicKeyRequest(  # type: ignore[attr-defined]
                name=target.crypto_key_version_name,
                public_key_format=pem_format,
            )
        except Exception:
            setup_failed = True
        if (
            setup_failed
            or kms_v1 is None
            or google_crc32c is None
            or request is None
        ):
            raise VerificationContractError(
                "Google Cloud KMS verifier returned an invalid response",
                details={},
            ) from None

        response = None
        provider_error = None
        try:
            response = self._client.get_public_key(  # type: ignore[union-attr]
                **self._call_kwargs(request)
            )
        except Exception as error:
            provider_error = error
        if provider_error is not None:
            if _is_google_availability_error(provider_error):
                return _outcome(VerificationReasonCode.VERIFIER_UNAVAILABLE)
            raise VerificationContractError(
                "Google Cloud KMS verifier returned an invalid response",
                details={},
            ) from None

        response_failed = False
        pem = None
        try:
            response_name = response.name  # type: ignore[attr-defined]
            response_algorithm = response.algorithm  # type: ignore[attr-defined]
            response_format = response.public_key_format  # type: ignore[attr-defined]
            checksummed_key = response.public_key  # type: ignore[attr-defined]
            key_data = checksummed_key.data  # type: ignore[attr-defined]
            key_crc32c = checksummed_key.crc32c_checksum  # type: ignore[attr-defined]
            expected_format = kms_v1.PublicKey.PublicKeyFormat.PEM  # type: ignore[attr-defined]
            normalized_algorithm = _google_algorithm_name(
                kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm,  # type: ignore[attr-defined]
                response_algorithm,
            )
            normalized_crc32c = _normalize_crc32c(key_crc32c)
            if (
                type(response_name) is not str
                or response_name != target.crypto_key_version_name
                or normalized_algorithm != target.algorithm
                or type(response_format) is not type(expected_format)
                or response_format != expected_format
                or type(key_data) is not bytes
                or not key_data
                or len(key_data) > MAX_PUBLIC_KEY_PEM_BYTES
                or normalized_crc32c != _crc32c(
                    google_crc32c,
                    key_data,
                )
            ):
                raise ValueError
            pem = bytes(key_data)
        except Exception:
            response_failed = True
        if response_failed or pem is None:
            raise VerificationContractError(
                "Google Cloud KMS verifier returned an invalid response",
                details={},
            ) from None
        return pem

    def _call_kwargs(self, request: object) -> dict[str, object]:
        kwargs = {"request": request}
        if self._retry is not _USE_PROVIDER_DEFAULT:
            kwargs["retry"] = self._retry
        if self._timeout is not _USE_PROVIDER_DEFAULT:
            kwargs["timeout"] = self._timeout
        return kwargs


def _parse_crypto_key_version_name(
    value: object,
) -> tuple[str, str] | None:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_CRYPTO_KEY_VERSION_NAME_LENGTH
    ):
        return None
    parts = value.split("/")
    if (
        len(parts) != 10
        or parts[0] != "projects"
        or parts[2] != "locations"
        or parts[4] != "keyRings"
        or parts[6] != "cryptoKeys"
        or parts[8] != "cryptoKeyVersions"
        or any(not _is_resource_segment(parts[index]) for index in (1, 3, 5, 7, 9))
    ):
        return None
    key_reference = "/".join(parts[:8])
    key_version = parts[9]
    if (
        len(key_reference) > _MAX_KEY_REFERENCE_LENGTH
        or len(key_version) > _MAX_KEY_VERSION_LENGTH
        or (
            key_reference + _VERSION_SEPARATOR + key_version
            != value
        )
    ):
        return None
    return key_reference, key_version


def _is_resource_segment(value: str) -> bool:
    return value not in ("", ".", "..") and all(
        character.isascii()
        and (
            character.isalnum()
            or character in "._:-"
        )
        for character in value
    )


def _load_google_dependencies() -> tuple[object, object]:
    from google.cloud import kms_v1
    import google_crc32c

    return kms_v1, google_crc32c


def _normalize_crypto_key_version(
    kms_v1: object,
    response: object,
    *,
    expected_name: str,
) -> str:
    name = response.name  # type: ignore[attr-defined]
    state = response.state  # type: ignore[attr-defined]
    algorithm = response.algorithm  # type: ignore[attr-defined]
    version_type = kms_v1.CryptoKeyVersion  # type: ignore[attr-defined]
    enabled = version_type.CryptoKeyVersionState.ENABLED
    if (
        type(name) is not str
        or name != expected_name
        or type(state) is not type(enabled)
        or state != enabled
    ):
        raise ValueError
    return _google_algorithm_name(
        version_type.CryptoKeyVersionAlgorithm,
        algorithm,
    )


def _google_algorithm_name(algorithm_type: object, value: object) -> str:
    for name in _GOOGLE_ALGORITHMS:
        constant = getattr(algorithm_type, name)
        if type(value) is type(constant) and value == constant:
            return name
    raise ValueError


def _normalize_signing_identity(
    identity: object,
    *,
    crypto_key_version_name: str,
    key_reference: str,
    key_version: str,
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
        or normalized.algorithm not in _GOOGLE_ALGORITHMS
        or normalized.signature_encoding is not SignatureEncoding.BASE64
        or type(normalized.key_reference) is not str
        or normalized.key_reference != key_reference
        or type(normalized.key_version) is not str
        or normalized.key_version != key_version
        or (
            normalized.key_reference
            + _VERSION_SEPARATOR
            + normalized.key_version
            != crypto_key_version_name
        )
    ):
        raise ValueError
    return normalized


def _crc32c(google_crc32c: object, value: bytes) -> int:
    checksum = google_crc32c.Checksum(value)  # type: ignore[attr-defined]
    digest = checksum.digest()
    if type(digest) is not bytes or len(digest) != 4:
        raise ValueError
    return int.from_bytes(digest, "big")


def _normalize_asymmetric_sign_response(
    google_crc32c: object,
    response: object,
    *,
    expected_name: str,
) -> bytes:
    name = response.name  # type: ignore[attr-defined]
    signature = response.signature  # type: ignore[attr-defined]
    signature_crc32c = response.signature_crc32c  # type: ignore[attr-defined]
    verified_digest_crc32c = response.verified_digest_crc32c  # type: ignore[attr-defined]
    normalized_signature_crc32c = _normalize_crc32c(signature_crc32c)
    if (
        type(name) is not str
        or name != expected_name
        or verified_digest_crc32c is not True
        or type(signature) is not bytes
        or not signature
        or len(signature) > MAX_RAW_SIGNATURE_BYTES
        or normalized_signature_crc32c != _crc32c(google_crc32c, signature)
    ):
        raise ValueError
    return signature


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


def _is_key_reference(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_KEY_REFERENCE_LENGTH
        and all("\x20" <= character <= "\x7e" for character in value)
    )


def _is_metadata_key_version(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_KEY_VERSION_LENGTH
        and all(
            character.isascii()
            and (
                character.isalnum()
                or character in "._:/-"
            )
            for character in value
        )
    )


def _load_cryptography_dependencies() -> tuple[object, ...]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        ec,
        padding,
        rsa,
        utils,
    )

    return (
        InvalidSignature,
        hashes,
        serialization,
        ec,
        padding,
        rsa,
        utils,
    )


def _load_validated_public_key(
    public_key_pem: bytes,
    algorithm: str,
) -> object:
    if (
        type(public_key_pem) is not bytes
        or not public_key_pem
        or len(public_key_pem) > MAX_PUBLIC_KEY_PEM_BYTES
        or type(algorithm) is not str
        or algorithm not in _GOOGLE_ALGORITHMS
    ):
        raise ValueError
    (
        _invalid_signature,
        _hashes,
        serialization,
        ec,
        _padding,
        rsa,
        _utils,
    ) = _load_cryptography_dependencies()
    public_key = serialization.load_pem_public_key(public_key_pem)  # type: ignore[attr-defined]
    key_kind, key_size = _GOOGLE_ALGORITHMS[algorithm]
    if key_kind == "rsa":
        if (
            not isinstance(public_key, rsa.RSAPublicKey)  # type: ignore[attr-defined]
            or type(public_key.key_size) is not int  # type: ignore[attr-defined]
            or public_key.key_size != key_size  # type: ignore[attr-defined]
        ):
            raise ValueError
        return public_key
    if not isinstance(public_key, ec.EllipticCurvePublicKey):  # type: ignore[attr-defined]
        raise ValueError
    curve = public_key.curve  # type: ignore[attr-defined]
    if (
        type(curve) is not ec.SECP256R1  # type: ignore[attr-defined]
        or type(curve.key_size) is not int
        or curve.key_size != key_size
    ):
        raise ValueError
    return public_key


def _verify_local_signature(
    public_key: object,
    digest: bytes,
    signature: bytes,
    algorithm: str,
    disposition: KmsKeyDisposition,
) -> ExternalVerificationOutcome:
    setup_failed = False
    dependencies = None
    try:
        dependencies = _load_cryptography_dependencies()
    except Exception:
        setup_failed = True
    if setup_failed or dependencies is None:
        raise VerificationContractError(
            "Google Cloud KMS verifier could not verify signature",
            details={},
        ) from None
    (
        invalid_signature_type,
        hashes,
        _serialization,
        ec,
        padding,
        _rsa,
        utils,
    ) = dependencies
    if algorithm == "EC_SIGN_P256_SHA256":
        der_error = None
        try:
            utils.decode_dss_signature(signature)  # type: ignore[attr-defined]
        except Exception as error:
            der_error = error
        if der_error is not None:
            if type(der_error) is ValueError:
                return _outcome(VerificationReasonCode.SIGNATURE_INVALID)
            raise VerificationContractError(
                "Google Cloud KMS verifier could not verify signature",
                details={},
            ) from None

    verification_error = None
    try:
        if algorithm.startswith("RSA_SIGN_PSS_"):
            public_key.verify(  # type: ignore[attr-defined]
                signature,
                digest,
                padding.PSS(  # type: ignore[attr-defined]
                    mgf=padding.MGF1(hashes.SHA256()),  # type: ignore[attr-defined]
                    salt_length=hashes.SHA256().digest_size,  # type: ignore[attr-defined]
                ),
                utils.Prehashed(hashes.SHA256()),  # type: ignore[attr-defined]
            )
        elif algorithm == "EC_SIGN_P256_SHA256":
            public_key.verify(  # type: ignore[attr-defined]
                signature,
                digest,
                ec.ECDSA(  # type: ignore[attr-defined]
                    utils.Prehashed(hashes.SHA256()),  # type: ignore[attr-defined]
                ),
            )
        else:
            raise ValueError
    except Exception as error:
        verification_error = error
    if verification_error is not None:
        if type(verification_error) is invalid_signature_type:
            return _outcome(VerificationReasonCode.SIGNATURE_INVALID)
        raise VerificationContractError(
            "Google Cloud KMS verifier could not verify signature",
            details={},
        ) from None
    return _successful_verification_outcome(disposition)


def _is_google_availability_error(error: BaseException) -> bool:
    try:
        from google.api_core import exceptions
    except (ImportError, ModuleNotFoundError):
        return False
    names = (
        "DeadlineExceeded",
        "FailedPrecondition",
        "NotFound",
        "PermissionDenied",
        "ResourceExhausted",
        "ServiceUnavailable",
    )
    allowed_types = []
    try:
        for name in names:
            candidate = getattr(exceptions, name)
            if (
                type(candidate) is not type
                or candidate.__name__ != name
                or not issubclass(candidate, BaseException)
                or candidate in (BaseException, Exception)
            ):
                return False
            allowed_types.append(candidate)
    except Exception:
        return False
    return type(error) in tuple(allowed_types)


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
            "Google Cloud KMS resolver returned an invalid target",
            details={},
        ) from None
    return _outcome(reason)
