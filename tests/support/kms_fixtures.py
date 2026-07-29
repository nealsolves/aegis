"""Offline AWS and Google Cloud KMS fixtures backed by generated keys."""

from __future__ import annotations

from enum import Enum
from hashlib import sha256
from types import ModuleType
from types import SimpleNamespace

from tests.support.external_signing import SENSITIVE_CORPUS


AWS_KEY_ARNS = {
    "RSA_2048": "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000002048",
    "RSA_3072": "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000003072",
    "RSA_4096": "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000004096",
    "ECC_NIST_P256": (
        "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000000256"
    ),
    "ECC_SECG_P256K1": (
        "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-4000-8000-000000002561"
    ),
}

AWS_ALGORITHMS_BY_SPEC = {
    "RSA_2048": ["RSASSA_PSS_SHA_256"],
    "RSA_3072": ["RSASSA_PSS_SHA_256"],
    "RSA_4096": ["RSASSA_PSS_SHA_256"],
    "ECC_NIST_P256": ["ECDSA_SHA_256"],
    "ECC_SECG_P256K1": ["ECDSA_SHA_256"],
}


class AwsKmsFixtureError(Exception):
    """Base class for documented fake AWS KMS failures."""


class DependencyTimeoutException(AwsKmsFixtureError):
    pass


class DisabledException(AwsKmsFixtureError):
    pass


class KMSInternalException(AwsKmsFixtureError):
    pass


class KMSInvalidSignatureException(AwsKmsFixtureError):
    pass


class KMSInvalidSignatureSubclass(KMSInvalidSignatureException):
    pass


class KMSInvalidStateException(AwsKmsFixtureError):
    pass


class KeyUnavailableException(AwsKmsFixtureError):
    pass


class NotFoundException(AwsKmsFixtureError):
    pass


class AccessDeniedException(AwsKmsFixtureError):
    pass


class ThrottlingException(AwsKmsFixtureError):
    pass


class ValidationException(AwsKmsFixtureError):
    pass


def generate_aws_private_keys() -> dict[str, object]:
    """Generate every supported AWS private-key shape without import-time crypto."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    return {
        "RSA_2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "RSA_3072": rsa.generate_private_key(public_exponent=65537, key_size=3072),
        "RSA_4096": rsa.generate_private_key(public_exponent=65537, key_size=4096),
        "ECC_NIST_P256": ec.generate_private_key(ec.SECP256R1()),
        "ECC_SECG_P256K1": ec.generate_private_key(ec.SECP256K1()),
    }


def aws_key_metadata(
    *,
    key_spec: str,
    key_arn: str | None = None,
    enabled: object = True,
    key_state: object = "Enabled",
    key_usage: object = "SIGN_VERIFY",
    signing_algorithms: object | None = None,
) -> dict[str, object]:
    """Return a documented-shape DescribeKey response."""
    arn = key_arn or AWS_KEY_ARNS[key_spec]
    algorithms = (
        list(AWS_ALGORITHMS_BY_SPEC[key_spec])
        if signing_algorithms is None
        else signing_algorithms
    )
    return {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": arn.rsplit("/", 1)[-1],
            "Arn": arn,
            "CreationDate": 1_721_600_000.0,
            "Enabled": enabled,
            "Description": "offline generated signing key",
            "KeyUsage": key_usage,
            "KeyState": key_state,
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": key_spec,
            "KeySpec": key_spec,
            "EncryptionAlgorithms": [],
            "SigningAlgorithms": algorithms,
            "MultiRegion": False,
        },
        "ResponseMetadata": {
            "RequestId": "00000000-0000-4000-8000-000000000000",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {},
            "RetryAttempts": 0,
        },
    }


def verify_aws_signature(
    public_key: object,
    *,
    signing_algorithm: str,
    payload: bytes,
    signature: bytes,
) -> bool:
    """Verify one fake AWS signature independently against exact payload bytes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    digest = hashes.Hash(hashes.SHA256())
    digest.update(payload)
    payload_digest = digest.finalize()
    try:
        if signing_algorithm == "RSASSA_PSS_SHA_256":
            public_key.verify(
                signature,
                payload_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        elif signing_algorithm == "ECDSA_SHA_256":
            public_key.verify(
                signature,
                payload_digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


class RecordingAwsKmsClient:
    """Recording KMS client with deterministic provider and malformed modes."""

    exceptions = SimpleNamespace(
        DependencyTimeoutException=DependencyTimeoutException,
        DisabledException=DisabledException,
        KMSInternalException=KMSInternalException,
        KMSInvalidSignatureException=KMSInvalidSignatureException,
        KMSInvalidStateException=KMSInvalidStateException,
        KeyUnavailableException=KeyUnavailableException,
        NotFoundException=NotFoundException,
        AccessDeniedException=AccessDeniedException,
        ThrottlingException=ThrottlingException,
        ValidationException=ValidationException,
    )

    def __init__(
        self,
        private_keys: dict[str, object],
        *,
        key_spec: str = "RSA_2048",
        key_arn: str | None = None,
        mode: str = "normal",
        signing_algorithms: list[str] | None = None,
    ) -> None:
        self.private_keys = dict(private_keys)
        self.key_spec = key_spec
        self._key_arn = key_arn
        self.mode = mode
        self.signing_algorithms = (
            None if signing_algorithms is None else list(signing_algorithms)
        )
        self.describe_calls: list[dict[str, object]] = []
        self.sign_calls: list[dict[str, object]] = []
        self.verify_calls: list[dict[str, object]] = []
        self.verify_error: BaseException | None = None

    @property
    def key_arn(self) -> str:
        return (
            AWS_KEY_ARNS[self.key_spec]
            if self._key_arn is None
            else self._key_arn
        )

    @property
    def signing_algorithm(self) -> str:
        return AWS_ALGORITHMS_BY_SPEC[self.key_spec][0]

    def describe_key(self, **kwargs: object) -> dict[str, object]:
        self.describe_calls.append(dict(kwargs))
        if self.mode == "provider_describe_failure":
            raise DependencyTimeoutException("provider timeout " + SENSITIVE_CORPUS[0])
        if self.mode == "unexpected_describe_failure":
            raise RuntimeError("unexpected response " + " | ".join(SENSITIVE_CORPUS))
        if self.mode == "malformed_describe":
            return {"KeyMetadata": object()}

        key_arn = self.key_arn
        if self.mode == "alias_retarget" and len(self.describe_calls) > 1:
            key_arn = (
                "arn:aws:kms:us-east-1:111122223333:key/"
                "ffffffff-ffff-4fff-8fff-ffffffffffff"
            )
        enabled: object = self.mode not in ("disabled_key", "disabled_enabled_flag")
        key_state: object = (
            "Disabled"
            if self.mode in ("disabled_key", "disabled_key_state")
            else "Enabled"
        )
        key_usage: object = "ENCRYPT_DECRYPT" if self.mode == "wrong_usage" else "SIGN_VERIFY"
        key_spec = "SYMMETRIC_DEFAULT" if self.mode == "wrong_spec" else self.key_spec
        algorithms: object = (
            ["RSASSA_PKCS1_V1_5_SHA_256"]
            if self.mode == "absent_algorithm"
            else list(
                self.signing_algorithms
                if self.signing_algorithms is not None
                else AWS_ALGORITHMS_BY_SPEC[self.key_spec]
            )
        )
        if self.mode == "enum_algorithm":
            algorithms = [_EnumLike(self.signing_algorithm)]
        if self.mode == "malformed_enabled":
            enabled = 1
        if self.mode == "malformed_algorithms":
            algorithms = (self.signing_algorithm,)
        return aws_key_metadata(
            key_spec=key_spec,
            key_arn=key_arn,
            enabled=enabled,
            key_state=key_state,
            key_usage=key_usage,
            signing_algorithms=algorithms,
        )

    def sign(self, **kwargs: object) -> dict[str, object]:
        self.sign_calls.append(dict(kwargs))
        if self.mode == "provider_sign_failure":
            raise KeyUnavailableException("key unavailable " + SENSITIVE_CORPUS[1])
        if self.mode == "unexpected_sign_failure":
            raise RuntimeError("unexpected signing failure " + " | ".join(SENSITIVE_CORPUS))
        if self.mode == "malformed_sign":
            return {"Signature": object()}

        signature = self._sign_digest(
            kwargs["Message"],
            kwargs["SigningAlgorithm"],
        )
        if self.mode == "empty_signature":
            signature = b""
        elif self.mode == "maximum_signature":
            signature = b"x" * 6_144
        elif self.mode == "oversized_signature":
            signature = b"x" * 6_145
        elif self.mode == "signature_subclass":
            signature = _BytesSubclass(signature)

        key_id: object = kwargs["KeyId"]
        algorithm: object = kwargs["SigningAlgorithm"]
        if self.mode == "wrong_sign_key_id":
            key_id = (
                "arn:aws:kms:us-east-1:111122223333:key/"
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
            )
        elif self.mode == "wrong_sign_algorithm":
            algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
        return {
            "KeyId": key_id,
            "Signature": signature,
            "SigningAlgorithm": algorithm,
            "ResponseMetadata": {
                "RequestId": "00000000-0000-4000-8000-000000000001",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        }

    def verify(self, **kwargs: object) -> dict[str, object]:
        self.verify_calls.append(dict(kwargs))
        if self.verify_error is not None:
            raise self.verify_error
        verify_failures = {
            "dependency_timeout": DependencyTimeoutException,
            "disabled_verify": DisabledException,
            "kms_internal": KMSInternalException,
            "invalid_state": KMSInvalidStateException,
            "key_unavailable": KeyUnavailableException,
            "not_found": NotFoundException,
            "access_denied": AccessDeniedException,
            "throttled": ThrottlingException,
            "unexpected_verify_failure": RuntimeError,
            "validation_verify_failure": ValidationException,
        }
        failure_type = verify_failures.get(self.mode)
        if failure_type is not None:
            raise failure_type(
                "provider verify failure " + " | ".join(SENSITIVE_CORPUS)
            )
        if self.mode == "malformed_verify":
            return {"KeyId": object()}

        signature = kwargs.get("Signature")
        digest = kwargs.get("Message")
        algorithm = kwargs.get("SigningAlgorithm")
        valid = False
        if type(signature) is bytes and type(digest) is bytes and type(algorithm) is str:
            valid = self._verify_digest(signature, digest, algorithm)
        if self.mode == "verify_false":
            valid = False
        if not valid and self.mode == "invalid_signature_exception":
            raise KMSInvalidSignatureException("invalid " + SENSITIVE_CORPUS[2])
        if not valid and self.mode == "invalid_signature_subclass":
            raise KMSInvalidSignatureSubclass(
                "invalid subclass " + SENSITIVE_CORPUS[2]
            )
        key_id: object = kwargs.get("KeyId")
        response_algorithm: object = algorithm
        response_validity: object = valid
        if self.mode == "wrong_verify_key_id":
            key_id = (
                "arn:aws:kms:us-east-1:111122223333:key/"
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
            )
        elif self.mode == "wrong_verify_algorithm":
            response_algorithm = "RSASSA_PKCS1_V1_5_SHA_256"
        elif self.mode == "malformed_verify_validity":
            response_validity = 1
        return {
            "KeyId": key_id,
            "SignatureValid": response_validity,
            "SigningAlgorithm": response_algorithm,
            "ResponseMetadata": {
                "RequestId": "00000000-0000-4000-8000-000000000002",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        }

    def _sign_digest(self, digest: object, algorithm: object) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        if type(digest) is not bytes or type(algorithm) is not str:
            raise ValidationException("invalid fake sign request")
        private_key = self.private_keys[self.key_spec]
        if algorithm == "RSASSA_PSS_SHA_256":
            return private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        if algorithm == "ECDSA_SHA_256":
            return private_key.sign(
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        raise ValidationException("invalid fake signing algorithm")

    def _verify_digest(self, signature: bytes, digest: bytes, algorithm: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        public_key = self.private_keys[self.key_spec].public_key()
        try:
            if algorithm == "RSASSA_PSS_SHA_256":
                public_key.verify(
                    signature,
                    digest,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    utils.Prehashed(hashes.SHA256()),
                )
            elif algorithm == "ECDSA_SHA_256":
                public_key.verify(
                    signature,
                    digest,
                    ec.ECDSA(utils.Prehashed(hashes.SHA256())),
                )
            else:
                return False
        except (InvalidSignature, TypeError, ValueError):
            return False
        return True


class _BytesSubclass(bytes):
    pass


class _EnumLike:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


GOOGLE_ALGORITHMS = (
    "RSA_SIGN_PSS_2048_SHA256",
    "RSA_SIGN_PSS_3072_SHA256",
    "RSA_SIGN_PSS_4096_SHA256",
    "EC_SIGN_P256_SHA256",
)

GOOGLE_KEY_VERSION_NAMES = {
    "RSA_SIGN_PSS_2048_SHA256": (
        "projects/aegis-test/locations/us-central1/keyRings/audit/"
        "cryptoKeys/rsa-2048/cryptoKeyVersions/1"
    ),
    "RSA_SIGN_PSS_3072_SHA256": (
        "projects/aegis-test/locations/us-central1/keyRings/audit/"
        "cryptoKeys/rsa-3072/cryptoKeyVersions/2"
    ),
    "RSA_SIGN_PSS_4096_SHA256": (
        "projects/aegis-test/locations/us-central1/keyRings/audit/"
        "cryptoKeys/rsa-4096/cryptoKeyVersions/3"
    ),
    "EC_SIGN_P256_SHA256": (
        "projects/aegis-test/locations/us-central1/keyRings/audit/"
        "cryptoKeys/ec-p256/cryptoKeyVersions/4"
    ),
}


class GoogleKmsFixtureError(Exception):
    """Base class for documented fake Google Cloud KMS failures."""


class DeadlineExceeded(GoogleKmsFixtureError):
    pass


class FailedPrecondition(GoogleKmsFixtureError):
    pass


class NotFound(GoogleKmsFixtureError):
    pass


class PermissionDenied(GoogleKmsFixtureError):
    pass


class ResourceExhausted(GoogleKmsFixtureError):
    pass


class ServiceUnavailable(GoogleKmsFixtureError):
    pass


class _GoogleAlgorithm(Enum):
    RSA_SIGN_PSS_2048_SHA256 = 2
    RSA_SIGN_PSS_3072_SHA256 = 3
    RSA_SIGN_PSS_4096_SHA256 = 4
    RSA_SIGN_PKCS1_2048_SHA256 = 5
    EC_SIGN_P256_SHA256 = 12


class _GoogleVersionState(Enum):
    CRYPTO_KEY_VERSION_STATE_UNSPECIFIED = 0
    PENDING_GENERATION = 5
    ENABLED = 1
    DISABLED = 2
    DESTROYED = 3
    DESTROY_SCHEDULED = 4
    PENDING_IMPORT = 6
    IMPORT_FAILED = 7
    GENERATION_FAILED = 8
    PENDING_EXTERNAL_DESTRUCTION = 9
    EXTERNAL_DESTRUCTION_FAILED = 10


class _GoogleCryptoKeyVersion:
    CryptoKeyVersionAlgorithm = _GoogleAlgorithm
    CryptoKeyVersionState = _GoogleVersionState


class _GoogleGetCryptoKeyVersionRequest:
    def __init__(self, *, name: str) -> None:
        self.name = name


class _GoogleDigest:
    def __init__(self, *, sha256: bytes) -> None:
        self.sha256 = sha256


class _GoogleAsymmetricSignRequest:
    def __init__(
        self,
        *,
        name: str,
        digest: _GoogleDigest,
        digest_crc32c: int,
    ) -> None:
        self.name = name
        self.digest = digest
        self.digest_crc32c = digest_crc32c


class _GoogleEnumLookalike:
    """Render like an SDK enum while comparing unequal to every SDK constant."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return self.name


class _GoogleChecksum:
    def __init__(self, initial_value: bytes = b"") -> None:
        self._value = google_crc32c_value(initial_value)

    def digest(self) -> bytes:
        return self._value.to_bytes(4, "big")


def install_controlled_google_kms_modules(monkeypatch) -> SimpleNamespace:
    """Install documented-shape Google modules for one isolated test."""
    google_module = ModuleType("google")
    cloud_module = ModuleType("google.cloud")
    kms_module = ModuleType("google.cloud.kms_v1")
    crc_module = ModuleType("google_crc32c")

    kms_module.CryptoKeyVersion = _GoogleCryptoKeyVersion
    kms_module.GetCryptoKeyVersionRequest = _GoogleGetCryptoKeyVersionRequest
    kms_module.Digest = _GoogleDigest
    kms_module.AsymmetricSignRequest = _GoogleAsymmetricSignRequest
    crc_module.Checksum = _GoogleChecksum
    cloud_module.kms_v1 = kms_module
    google_module.cloud = cloud_module

    monkeypatch.setitem(__import__("sys").modules, "google", google_module)
    monkeypatch.setitem(__import__("sys").modules, "google.cloud", cloud_module)
    monkeypatch.setitem(
        __import__("sys").modules,
        "google.cloud.kms_v1",
        kms_module,
    )
    monkeypatch.setitem(__import__("sys").modules, "google_crc32c", crc_module)
    return SimpleNamespace(kms_v1=kms_module, google_crc32c=crc_module)


def google_crc32c_value(value: bytes) -> int:
    """Compute CRC32C independently with the reflected Castagnoli polynomial."""
    crc = 0xFFFFFFFF
    for byte in value:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def generate_google_private_keys() -> dict[str, object]:
    """Generate all supported Google signing keys without import-time crypto."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    return {
        "RSA_SIGN_PSS_2048_SHA256": rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        ),
        "RSA_SIGN_PSS_3072_SHA256": rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        ),
        "RSA_SIGN_PSS_4096_SHA256": rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        ),
        "EC_SIGN_P256_SHA256": ec.generate_private_key(ec.SECP256R1()),
    }


def verify_google_signature(
    public_key: object,
    *,
    algorithm: str,
    payload: bytes,
    signature: bytes,
) -> bool:
    """Verify one fake Google signature independently over exact payload bytes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

    payload_digest = sha256(payload).digest()
    try:
        if algorithm.startswith("RSA_SIGN_PSS_"):
            public_key.verify(
                signature,
                payload_digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        elif algorithm == "EC_SIGN_P256_SHA256":
            public_key.verify(
                signature,
                payload_digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


class RecordingGoogleCloudKmsClient:
    """Recording Google KMS client with documented and malformed modes."""

    def __init__(
        self,
        private_keys: dict[str, object],
        *,
        algorithm: str = "RSA_SIGN_PSS_2048_SHA256",
        crypto_key_version_name: str | None = None,
        mode: str = "normal",
    ) -> None:
        self.private_keys = dict(private_keys)
        self.algorithm = algorithm
        self.crypto_key_version_name = (
            GOOGLE_KEY_VERSION_NAMES[algorithm]
            if crypto_key_version_name is None
            else crypto_key_version_name
        )
        self.mode = mode
        self.get_version_calls: list[dict[str, object]] = []
        self.asymmetric_sign_calls: list[dict[str, object]] = []
        self.get_crypto_key_calls: list[dict[str, object]] = []

    def get_crypto_key_version(self, **kwargs: object) -> object:
        self.get_version_calls.append(dict(kwargs))
        if self.mode == "provider_get_failure":
            raise DeadlineExceeded("deadline " + SENSITIVE_CORPUS[0])
        if self.mode == "permission_get_failure":
            raise PermissionDenied("permission " + SENSITIVE_CORPUS[1])
        if self.mode == "unexpected_get_failure":
            raise RuntimeError("unexpected " + " | ".join(SENSITIVE_CORPUS))
        if self.mode == "malformed_version":
            return object()

        call_number = len(self.get_version_calls)
        name: object = self.crypto_key_version_name
        state: object = _GoogleVersionState.ENABLED
        algorithm: object = _GoogleAlgorithm[self.algorithm]
        if self.mode == "wrong_name":
            name = self.crypto_key_version_name + "-wrong"
        elif self.mode == "wrong_name_second" and call_number > 1:
            name = self.crypto_key_version_name + "-wrong"
        elif self.mode == "wrong_state":
            state = _GoogleVersionState.DISABLED
        elif self.mode == "wrong_state_second" and call_number > 1:
            state = _GoogleVersionState.DISABLED
        elif self.mode == "wrong_algorithm":
            algorithm = _GoogleAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
        elif self.mode == "wrong_algorithm_second" and call_number > 1:
            algorithm = _GoogleAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
        elif self.mode == "changed_algorithm_second" and call_number > 1:
            algorithm = _GoogleAlgorithm.EC_SIGN_P256_SHA256
        elif self.mode == "algorithm_string":
            algorithm = self.algorithm
        elif self.mode == "algorithm_lookalike":
            algorithm = _GoogleEnumLookalike(self.algorithm)
        elif self.mode == "state_lookalike":
            state = _GoogleEnumLookalike("ENABLED")
        return SimpleNamespace(
            name=name,
            state=state,
            algorithm=algorithm,
            protection_level=object(),
        )

    def get_crypto_key(self, **kwargs: object) -> object:
        self.get_crypto_key_calls.append(dict(kwargs))
        raise AssertionError("get_crypto_key must not be called")

    def asymmetric_sign(self, **kwargs: object) -> object:
        self.asymmetric_sign_calls.append(dict(kwargs))
        if self.mode == "provider_sign_failure":
            raise ServiceUnavailable("unavailable " + SENSITIVE_CORPUS[2])
        if self.mode == "unexpected_sign_failure":
            raise RuntimeError("unexpected " + " | ".join(SENSITIVE_CORPUS))
        if self.mode == "malformed_sign_response":
            return object()

        request = kwargs["request"]
        signature: object = self._sign_digest(request.digest.sha256)
        if self.mode == "empty_signature":
            signature = b""
        elif self.mode == "maximum_signature":
            signature = b"x" * 12_288
        elif self.mode == "oversized_signature":
            signature = b"x" * 12_289
        elif self.mode == "signature_subclass":
            signature = _BytesSubclass(signature)

        name: object = self.crypto_key_version_name
        verified: object = True
        signature_crc: object = (
            google_crc32c_value(signature)
            if type(signature) is bytes
            else 0
        )
        if self.mode == "wrong_response_name":
            name = self.crypto_key_version_name + "-wrong"
        elif self.mode == "unverified_digest":
            verified = False
        elif self.mode == "nonbool_verified_digest":
            verified = 1
        elif self.mode == "bad_signature_crc":
            signature_crc = (signature_crc + 1) & 0xFFFFFFFF
        elif self.mode == "boolean_signature_crc":
            signature_crc = True
        elif self.mode == "negative_signature_crc":
            signature_crc = -1
        elif self.mode == "oversized_signature_crc":
            signature_crc = 2**32
        elif self.mode == "signature_crc_subclass":
            signature_crc = _IntSubclass(signature_crc)
        if self.mode == "missing_verified_digest":
            return SimpleNamespace(
                name=name,
                signature=signature,
                signature_crc32c=signature_crc,
                protection_level=object(),
            )
        if self.mode == "missing_signature_crc":
            return SimpleNamespace(
                name=name,
                signature=signature,
                verified_digest_crc32c=verified,
                protection_level=object(),
            )
        return SimpleNamespace(
            name=name,
            signature=signature,
            signature_crc32c=signature_crc,
            verified_digest_crc32c=verified,
            protection_level=object(),
        )

    def _sign_digest(self, digest: object) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils

        if type(digest) is not bytes:
            raise FailedPrecondition("invalid fake digest")
        private_key = self.private_keys[self.algorithm]
        if self.algorithm.startswith("RSA_SIGN_PSS_"):
            return private_key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        if self.algorithm == "EC_SIGN_P256_SHA256":
            return private_key.sign(
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        raise FailedPrecondition("invalid fake algorithm")


class _IntSubclass(int):
    pass
