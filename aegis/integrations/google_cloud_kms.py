"""Google Cloud KMS artifact signing with exact-version CRC32C binding."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.errors import ArtifactSigningError, SigningContractError
from aegis.integrations._kms_common import (
    MAX_RAW_SIGNATURE_BYTES,
    _USE_PROVIDER_DEFAULT,
    _canonical_b64encode,
    _normalize_crc32c,
    _normalize_timeout,
    _sha256_digest,
)
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import SignatureEncoding, SignerIdentity, SigningReceipt


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
    "GoogleCloudKmsVerificationTarget",
]


@dataclass(frozen=True)
class GoogleCloudKmsVerificationTarget:
    """Host-approved Google KMS verification policy for one exact version."""

    crypto_key_version_name: str
    algorithm: str
    disposition: KmsKeyDisposition = KmsKeyDisposition.ANCHORED
    public_key_pem: bytes | None = None


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
