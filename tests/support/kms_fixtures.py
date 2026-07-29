"""Offline AWS and Google Cloud KMS fixtures backed by generated keys."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from enum import IntEnum
from hashlib import sha256
import importlib.machinery
import importlib.util
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


class _GoogleApiCallErrorMeta(type):
    """Mirror google.api_core's non-plain exception-class metaclass."""


class GoogleKmsFixtureError(
    Exception,
    metaclass=_GoogleApiCallErrorMeta,
):
    """Base class for documented fake Google Cloud KMS failures."""


class DeadlineExceeded(GoogleKmsFixtureError):
    pass


class GatewayTimeout(GoogleKmsFixtureError):
    pass


class FailedPrecondition(GoogleKmsFixtureError):
    pass


class BadRequest(GoogleKmsFixtureError):
    def __init__(
        self,
        message: str,
        *,
        response: object | None = None,
    ) -> None:
        super().__init__(message)
        self.response = response


class NotFound(GoogleKmsFixtureError):
    pass


class PermissionDenied(GoogleKmsFixtureError):
    pass


class Forbidden(GoogleKmsFixtureError):
    pass


class ResourceExhausted(GoogleKmsFixtureError):
    pass


class TooManyRequests(GoogleKmsFixtureError):
    pass


class ServiceUnavailable(GoogleKmsFixtureError):
    pass


class RetryError(GoogleKmsFixtureError):
    def __init__(self, message: str, cause: BaseException) -> None:
        super().__init__(message)
        self.cause = cause


class _GoogleRestResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


for _google_exception_type in (
    BadRequest,
    DeadlineExceeded,
    FailedPrecondition,
    Forbidden,
    GatewayTimeout,
    NotFound,
    PermissionDenied,
    ResourceExhausted,
    RetryError,
    ServiceUnavailable,
    TooManyRequests,
):
    _google_exception_type.__module__ = "google.api_core.exceptions"


class _GoogleAlgorithm(IntEnum):
    RSA_SIGN_PSS_2048_SHA256 = 2
    RSA_SIGN_PSS_3072_SHA256 = 3
    RSA_SIGN_PSS_4096_SHA256 = 4
    RSA_SIGN_PKCS1_2048_SHA256 = 5
    EC_SIGN_P256_SHA256 = 12


class _GoogleVersionState(IntEnum):
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


def forged_google_version_state(
    member: _GoogleVersionState,
) -> _GoogleVersionState:
    """Construct an equal, non-canonical IntEnum instance for identity tests."""
    forged = int.__new__(_GoogleVersionState, int(member))
    forged._name_ = member.name
    forged._value_ = member.value
    return forged


class _GooglePublicKeyFormat(IntEnum):
    PUBLIC_KEY_FORMAT_UNSPECIFIED = 0
    PEM = 1


class _GoogleCryptoKeyVersion:
    CryptoKeyVersionAlgorithm = _GoogleAlgorithm
    CryptoKeyVersionState = _GoogleVersionState


class _GooglePublicKey:
    PublicKeyFormat = _GooglePublicKeyFormat

    def __init__(
        self,
        *,
        name: object,
        algorithm: object,
        public_key_format: object,
        public_key: object,
    ) -> None:
        self.name = name
        self.algorithm = algorithm
        self.public_key_format = public_key_format
        self.public_key = public_key


class _GoogleChecksummedData:
    def __init__(
        self,
        *,
        data: object,
        crc32c_checksum: object,
    ) -> None:
        self.data = data
        self.crc32c_checksum = crc32c_checksum


class _GooglePublicKeySubclass(_GooglePublicKey):
    pass


class _GoogleChecksummedDataSubclass(_GoogleChecksummedData):
    pass


class _GoogleGetCryptoKeyVersionRequest:
    def __init__(self, *, name: str) -> None:
        self.name = name


class _GoogleGetPublicKeyRequest:
    def __init__(self, *, name: str, public_key_format: object) -> None:
        self.name = name
        self.public_key_format = public_key_format


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


def install_controlled_google_kms_modules(
    monkeypatch,
    *,
    install_api_core_spoof: bool = False,
) -> SimpleNamespace:
    """Install documented-shape Google modules for one isolated test."""
    google_module = ModuleType("google")
    cloud_module = ModuleType("google.cloud")
    kms_module = ModuleType("google.cloud.kms_v1")
    crc_module = ModuleType("google_crc32c")

    kms_module.CryptoKeyVersion = _GoogleCryptoKeyVersion
    kms_module.PublicKey = _GooglePublicKey
    kms_module.ChecksummedData = _GoogleChecksummedData
    kms_module.GetCryptoKeyVersionRequest = _GoogleGetCryptoKeyVersionRequest
    kms_module.GetPublicKeyRequest = _GoogleGetPublicKeyRequest
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
    api_core_module = ModuleType("google.api_core")
    api_exceptions_module = ModuleType("google.api_core.exceptions")
    api_exceptions_module.DeadlineExceeded = DeadlineExceeded
    api_exceptions_module.GatewayTimeout = GatewayTimeout
    api_exceptions_module.FailedPrecondition = FailedPrecondition
    api_exceptions_module.BadRequest = BadRequest
    api_exceptions_module.NotFound = NotFound
    api_exceptions_module.PermissionDenied = PermissionDenied
    api_exceptions_module.Forbidden = Forbidden
    api_exceptions_module.ResourceExhausted = ResourceExhausted
    api_exceptions_module.TooManyRequests = TooManyRequests
    api_exceptions_module.RetryError = RetryError
    api_exceptions_module.ServiceUnavailable = ServiceUnavailable
    if install_api_core_spoof:
        api_core_module.exceptions = api_exceptions_module
        google_module.api_core = api_core_module
        monkeypatch.setitem(
            __import__("sys").modules,
            "google.api_core",
            api_core_module,
        )
        monkeypatch.setitem(
            __import__("sys").modules,
            "google.api_core.exceptions",
            api_exceptions_module,
        )
    monkeypatch.setitem(__import__("sys").modules, "google_crc32c", crc_module)
    return SimpleNamespace(
        kms_v1=kms_module,
        google_crc32c=crc_module,
        api_exceptions=api_exceptions_module,
    )


def install_copied_provenance_google_api_core(
    monkeypatch,
    tmp_path,
) -> SimpleNamespace:
    """Install synthetic classes carrying valid-looking source provenance."""
    source = b"""
class _GoogleAPICallErrorMeta(type):
    def __new__(mcs, name, bases, class_dict):
        return type.__new__(mcs, name, bases, class_dict)

class GoogleAPIError(Exception):
    pass

class RetryError(GoogleAPIError):
    def __init__(self, message, cause):
        super().__init__(message)
        self._cause = cause

    @property
    def cause(self):
        return self._cause

class GoogleAPICallError(GoogleAPIError, metaclass=_GoogleAPICallErrorMeta):
    def __init__(self, message, errors=(), details=(), response=None):
        super().__init__(message)
        self.response = response

class GatewayTimeout(GoogleAPICallError):
    pass
class DeadlineExceeded(GatewayTimeout):
    pass
class TooManyRequests(GoogleAPICallError):
    pass
class ResourceExhausted(TooManyRequests):
    pass
class Forbidden(GoogleAPICallError):
    pass
class PermissionDenied(Forbidden):
    pass
class ServiceUnavailable(GoogleAPICallError):
    pass
class BadRequest(GoogleAPICallError):
    pass
class FailedPrecondition(BadRequest):
    pass
class NotFound(GoogleAPICallError):
    pass
"""
    source_path = tmp_path / "google" / "api_core" / "exceptions.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(source)
    loader = importlib.machinery.SourceFileLoader(
        "google.api_core.exceptions",
        str(source_path),
    )
    spec = importlib.util.spec_from_file_location(
        "google.api_core.exceptions",
        source_path,
        loader=loader,
    )
    assert spec is not None

    module = ModuleType("google.api_core.exceptions")
    module.__package__ = "google.api_core"
    module.__file__ = str(source_path)
    module.__spec__ = spec
    module.__loader__ = loader

    google_api_error = type(
        "GoogleAPIError",
        (Exception,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "GoogleAPIError",
        },
    )
    api_call_metaclass = type(
        "_GoogleAPICallErrorMeta",
        (type,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "_GoogleAPICallErrorMeta",
        },
    )
    google_api_call_error = api_call_metaclass(
        "GoogleAPICallError",
        (google_api_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "GoogleAPICallError",
        },
    )
    retry_error = type(
        "RetryError",
        (google_api_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "RetryError",
        },
    )
    gateway_timeout = api_call_metaclass(
        "GatewayTimeout",
        (google_api_call_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "GatewayTimeout",
        },
    )
    too_many_requests = api_call_metaclass(
        "TooManyRequests",
        (google_api_call_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "TooManyRequests",
        },
    )
    forbidden = api_call_metaclass(
        "Forbidden",
        (google_api_call_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "Forbidden",
        },
    )
    bad_request = api_call_metaclass(
        "BadRequest",
        (google_api_call_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "BadRequest",
        },
    )
    classes = {
        "GoogleAPIError": google_api_error,
        "_GoogleAPICallErrorMeta": api_call_metaclass,
        "GoogleAPICallError": google_api_call_error,
        "RetryError": retry_error,
        "GatewayTimeout": gateway_timeout,
        "DeadlineExceeded": api_call_metaclass(
            "DeadlineExceeded",
            (gateway_timeout,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "DeadlineExceeded",
            },
        ),
        "TooManyRequests": too_many_requests,
        "ResourceExhausted": api_call_metaclass(
            "ResourceExhausted",
            (too_many_requests,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "ResourceExhausted",
            },
        ),
        "Forbidden": forbidden,
        "PermissionDenied": api_call_metaclass(
            "PermissionDenied",
            (forbidden,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "PermissionDenied",
            },
        ),
        "ServiceUnavailable": api_call_metaclass(
            "ServiceUnavailable",
            (google_api_call_error,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "ServiceUnavailable",
            },
        ),
        "BadRequest": bad_request,
        "FailedPrecondition": api_call_metaclass(
            "FailedPrecondition",
            (bad_request,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "FailedPrecondition",
            },
        ),
        "NotFound": api_call_metaclass(
            "NotFound",
            (google_api_call_error,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": "NotFound",
            },
        ),
    }
    for name, candidate in classes.items():
        setattr(module, name, candidate)

    digest = urlsafe_b64encode(sha256(source).digest()).rstrip(b"=").decode()

    class RecordPath(str):
        hash = SimpleNamespace(mode="sha256", value=digest)
        size = len(source)

    class Distribution:
        metadata = {"Name": "google-api-core"}
        files = (RecordPath("google/api_core/exceptions.py"),)

        def locate_file(self, _entry):
            return source_path

    google_module = ModuleType("google")
    api_core_module = ModuleType("google.api_core")
    google_module.api_core = api_core_module
    api_core_module.exceptions = module
    monkeypatch.setitem(__import__("sys").modules, "google", google_module)
    monkeypatch.setitem(
        __import__("sys").modules,
        "google.api_core",
        api_core_module,
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "google.api_core.exceptions",
        module,
    )
    return SimpleNamespace(
        exceptions=module,
        distribution=Distribution(),
        spec=spec,
    )


def synthetic_google_api_core_with_reused_implementations(
    real_exceptions,
    *,
    clone_functions: bool = False,
) -> ModuleType:
    """Build distinct exception classes from the real implementation descriptors."""
    from types import FunctionType

    module = ModuleType("google.api_core.exceptions")
    module.__package__ = "google.api_core"
    module.__file__ = real_exceptions.__file__
    module.__spec__ = real_exceptions.__spec__
    module.__loader__ = real_exceptions.__loader__
    module._HTTP_CODE_TO_EXCEPTION = {}
    module._GRPC_CODE_TO_EXCEPTION = {}

    def implementation(function):
        if not clone_functions:
            return function
        clone = FunctionType(
            function.__code__,
            vars(module),
            function.__name__,
            function.__defaults__,
            function.__closure__,
        )
        clone.__kwdefaults__ = function.__kwdefaults__
        return clone

    google_api_error = type(
        "GoogleAPIError",
        (Exception,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "GoogleAPIError",
        },
    )
    real_api_call_error = real_exceptions.GoogleAPICallError
    real_api_call_metaclass = type(real_api_call_error)
    real_metaclass_new = vars(real_api_call_metaclass)["__new__"]
    metaclass_new = real_metaclass_new
    if clone_functions:
        metaclass_new = staticmethod(
            implementation(real_metaclass_new.__func__)
        )
    api_call_metaclass = type(
        "_GoogleAPICallErrorMeta",
        (type,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "_GoogleAPICallErrorMeta",
            "__new__": metaclass_new,
        },
    )
    google_api_call_error = api_call_metaclass(
        "GoogleAPICallError",
        (google_api_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "GoogleAPICallError",
            "code": None,
            "grpc_status_code": None,
            "__init__": implementation(
                vars(real_api_call_error)["__init__"]
            ),
        },
    )
    real_retry_error = real_exceptions.RetryError
    real_retry_cause = vars(real_retry_error)["cause"]
    retry_cause = real_retry_cause
    if clone_functions:
        retry_cause = property(
            implementation(real_retry_cause.fget),
            doc=real_retry_cause.__doc__,
        )
    retry_error = type(
        "RetryError",
        (google_api_error,),
        {
            "__module__": "google.api_core.exceptions",
            "__qualname__": "RetryError",
            "__init__": implementation(vars(real_retry_error)["__init__"]),
            "cause": retry_cause,
        },
    )

    def api_call_error(name, base):
        return api_call_metaclass(
            name,
            (base,),
            {
                "__module__": "google.api_core.exceptions",
                "__qualname__": name,
            },
        )

    gateway_timeout = api_call_error("GatewayTimeout", google_api_call_error)
    too_many_requests = api_call_error(
        "TooManyRequests",
        google_api_call_error,
    )
    forbidden = api_call_error("Forbidden", google_api_call_error)
    bad_request = api_call_error("BadRequest", google_api_call_error)
    classes = {
        "GoogleAPIError": google_api_error,
        "_GoogleAPICallErrorMeta": api_call_metaclass,
        "GoogleAPICallError": google_api_call_error,
        "RetryError": retry_error,
        "GatewayTimeout": gateway_timeout,
        "DeadlineExceeded": api_call_error(
            "DeadlineExceeded",
            gateway_timeout,
        ),
        "TooManyRequests": too_many_requests,
        "ResourceExhausted": api_call_error(
            "ResourceExhausted",
            too_many_requests,
        ),
        "Forbidden": forbidden,
        "PermissionDenied": api_call_error(
            "PermissionDenied",
            forbidden,
        ),
        "ServiceUnavailable": api_call_error(
            "ServiceUnavailable",
            google_api_call_error,
        ),
        "BadRequest": bad_request,
        "FailedPrecondition": api_call_error(
            "FailedPrecondition",
            bad_request,
        ),
        "NotFound": api_call_error("NotFound", google_api_call_error),
    }
    for name, candidate in classes.items():
        setattr(module, name, candidate)
    return module


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
        self.get_public_key_calls: list[dict[str, object]] = []
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
        elif self.mode == "forged_state":
            state = forged_google_version_state(_GoogleVersionState.ENABLED)
        elif self.mode == "forged_state_second" and call_number > 1:
            state = forged_google_version_state(_GoogleVersionState.ENABLED)
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

    def get_public_key(self, **kwargs: object) -> object:
        self.get_public_key_calls.append(dict(kwargs))
        failures = {
            "deadline_public_key": DeadlineExceeded,
            "gateway_timeout_public_key": GatewayTimeout,
            "failed_precondition_public_key": FailedPrecondition,
            "not_found_public_key": NotFound,
            "permission_public_key": PermissionDenied,
            "forbidden_public_key": Forbidden,
            "resource_exhausted_public_key": ResourceExhausted,
            "too_many_requests_public_key": TooManyRequests,
            "unavailable_public_key": ServiceUnavailable,
            "unexpected_public_key": RuntimeError,
        }
        failure_type = failures.get(self.mode)
        if failure_type is not None:
            raise failure_type(
                "public key failure " + " | ".join(SENSITIVE_CORPUS)
            )
        if self.mode == "retry_deadline_public_key":
            raise RetryError(
                "retry exhausted " + SENSITIVE_CORPUS[0],
                DeadlineExceeded("deadline " + SENSITIVE_CORPUS[1]),
            )
        if self.mode == "retry_unexpected_public_key":
            raise RetryError(
                "retry exhausted " + SENSITIVE_CORPUS[0],
                RuntimeError("unexpected " + SENSITIVE_CORPUS[1]),
            )
        if self.mode.startswith("bad_request_"):
            payload_by_mode = {
                "bad_request_failed_precondition": {
                    "error": {
                        "status": "FAILED_PRECONDITION",
                        "message": SENSITIVE_CORPUS[2],
                    },
                },
                "bad_request_invalid_argument": {
                    "error": {
                        "status": "INVALID_ARGUMENT",
                        "message": SENSITIVE_CORPUS[2],
                    },
                },
                "bad_request_missing_status": {
                    "error": {
                        "message": SENSITIVE_CORPUS[2],
                    },
                },
                "bad_request_malformed_payload": [SENSITIVE_CORPUS[2]],
            }
            raise BadRequest(
                "bad request " + SENSITIVE_CORPUS[3],
                response=_GoogleRestResponse(
                    payload_by_mode[self.mode]
                ),
            )
        if self.mode == "malformed_public_key_response":
            return object()

        from cryptography.hazmat.primitives import serialization

        pem: object = self.private_keys[self.algorithm].public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        name: object = self.crypto_key_version_name
        algorithm: object = _GoogleAlgorithm[self.algorithm]
        public_key_format: object = _GooglePublicKeyFormat.PEM
        checksum: object = google_crc32c_value(pem)

        if self.mode == "wrong_public_key_name":
            name = self.crypto_key_version_name + "-wrong"
        elif self.mode == "wrong_public_key_algorithm":
            algorithm = _GoogleAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
        elif self.mode == "public_key_algorithm_string":
            algorithm = self.algorithm
        elif self.mode == "public_key_algorithm_lookalike":
            algorithm = _GoogleEnumLookalike(self.algorithm)
        elif self.mode == "forged_public_key_algorithm":
            algorithm = int.__new__(
                _GoogleAlgorithm,
                int(_GoogleAlgorithm[self.algorithm]),
            )
            object.__setattr__(algorithm, "_value_", int(algorithm))
            object.__setattr__(algorithm, "_name_", "FORGED_ALGORITHM")
        elif self.mode == "wrong_public_key_format":
            public_key_format = _GooglePublicKeyFormat.PUBLIC_KEY_FORMAT_UNSPECIFIED
        elif self.mode == "public_key_format_string":
            public_key_format = "PEM"
        elif self.mode == "public_key_format_lookalike":
            public_key_format = _GoogleEnumLookalike("PEM")
        elif self.mode == "forged_public_key_format":
            public_key_format = int.__new__(
                _GooglePublicKeyFormat,
                int(_GooglePublicKeyFormat.PEM),
            )
            object.__setattr__(
                public_key_format,
                "_value_",
                int(public_key_format),
            )
            object.__setattr__(
                public_key_format,
                "_name_",
                "FORGED_PEM",
            )
        elif self.mode == "empty_public_key":
            pem = b""
        elif self.mode == "oversized_public_key":
            pem = b"x" * 65_537
        elif self.mode == "public_key_subclass":
            pem = _BytesSubclass(pem)
        elif self.mode == "bad_public_key_crc":
            checksum = (checksum + 1) & 0xFFFFFFFF
        elif self.mode == "boolean_public_key_crc":
            checksum = True
        elif self.mode == "negative_public_key_crc":
            checksum = -1
        elif self.mode == "oversized_public_key_crc":
            checksum = 2**32
        elif self.mode == "public_key_crc_subclass":
            checksum = _IntSubclass(checksum)
        elif self.mode == "wrong_public_key_type":
            other_algorithm = (
                "EC_SIGN_P256_SHA256"
                if self.algorithm.startswith("RSA_")
                else "RSA_SIGN_PSS_2048_SHA256"
            )
            pem = self.private_keys[other_algorithm].public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            checksum = google_crc32c_value(pem)

        public_key = _GoogleChecksummedData(
            data=pem,
            crc32c_checksum=checksum,
        )
        if self.mode == "checksummed_data_duck":
            public_key = SimpleNamespace(
                data=pem,
                crc32c_checksum=checksum,
            )
        elif self.mode == "checksummed_data_subclass":
            public_key = _GoogleChecksummedDataSubclass(
                data=pem,
                crc32c_checksum=checksum,
            )
        response_type = (
            _GooglePublicKeySubclass
            if self.mode == "public_key_response_subclass"
            else _GooglePublicKey
        )
        response = response_type(
            name=name,
            algorithm=algorithm,
            public_key_format=public_key_format,
            public_key=public_key,
        )
        if self.mode == "public_key_response_duck":
            response = SimpleNamespace(
                name=name,
                algorithm=algorithm,
                public_key_format=public_key_format,
                public_key=public_key,
            )
        if self.mode == "legacy_public_key_only":
            del response.public_key
            response.pem = pem
            response.pem_crc32c = checksum
        elif self.mode == "missing_public_key_crc":
            del public_key.crc32c_checksum
        return response

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
