#!/usr/bin/env python3
"""Validate one installed-artifact KMS optional-extra release lane offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

try:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:  # pragma: no cover - setup-python always supplies pip
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name


EXPECTED_DISTRIBUTION = "aegis-ai-governance"
SUPPORTED_VERSION_KEYS = {
    "boto3",
    "google-cloud-kms",
    "google-crc32c",
    "cryptography",
}
CREDENTIAL_PREFIXES = ("AWS_", "GOOGLE_", "GCP_", "CLOUDSDK_")
CREDENTIAL_NAMES = {"BOTO_CONFIG"}
EXTRAS_BY_LANE = {
    "base": (),
    "aws": ("aws-kms",),
    "gcp": ("gcp-kms",),
    "combined": ("aws-kms", "gcp-kms"),
}
PROVIDER_DISTRIBUTIONS = {
    "aws": {"boto3"},
    "gcp": {"google-cloud-kms", "google-crc32c", "cryptography"},
}
AWS_PROVIDER_FAMILY = frozenset(
    {
        "awscrt",
        "boto3",
        "botocore",
        "jmespath",
        "s3transfer",
    }
)
GCP_PROVIDER_FAMILY = frozenset(
    {
        "cryptography",
        "google-api-core",
        "google-auth",
        "google-cloud-core",
        "google-cloud-kms",
        "google-crc32c",
        "googleapis-common-protos",
        "grpc-google-iam-v1",
        "grpcio",
        "grpcio-status",
        "proto-plus",
    }
)
FORBIDDEN_PROVIDER_FAMILIES = {
    "base": AWS_PROVIDER_FAMILY | GCP_PROVIDER_FAMILY,
    "aws": GCP_PROVIDER_FAMILY,
    "gcp": AWS_PROVIDER_FAMILY,
    "combined": frozenset(),
}
EXPECTED_KMS_REQUIREMENTS = {
    'boto3>=1.43.0; extra == "aws-kms"',
    'google-cloud-kms>=3.15.0; extra == "gcp-kms"',
    'google-crc32c>=1.7.1; extra == "gcp-kms"',
    'cryptography>=45.0.1; extra == "gcp-kms"',
}
KMS_PROVIDER_DISTRIBUTIONS = frozenset(
    {
        "boto3",
        "cryptography",
        "google-cloud-kms",
        "google-crc32c",
    }
)


class OptionalExtrasValidationError(RuntimeError):
    """Raised when an installed-artifact lane fails its contract."""


def _marker_operand_key(operand: object) -> tuple[str, str]:
    kind = type(operand).__name__.lower()
    value = getattr(operand, "value", None)
    if kind not in {"variable", "value"} or type(value) is not str:
        raise OptionalExtrasValidationError(
            "requirement marker operand is invalid"
        )
    return kind, value


def _canonical_marker(node: object) -> object:
    if type(node) is tuple and len(node) == 3:
        left, operator, right = node
        left_key = _marker_operand_key(left)
        right_key = _marker_operand_key(right)
        operator_value = getattr(operator, "value", None)
        if type(operator_value) is not str:
            raise OptionalExtrasValidationError(
                "requirement marker operator is invalid"
            )
        if (
            operator_value in {"==", "!="}
            and left_key[0] == "value"
            and right_key[0] == "variable"
        ):
            left_key, right_key = right_key, left_key
        return left_key, operator_value, right_key
    if type(node) is list:
        canonical = tuple(_canonical_marker(item) for item in node)
        return canonical[0] if len(canonical) == 1 else canonical
    if type(node) is str and node in {"and", "or"}:
        return node
    raise OptionalExtrasValidationError(
        "requirement marker structure is invalid"
    )


def _requirement_key(value: str) -> tuple[object, ...]:
    try:
        requirement = Requirement(value)
        marker = (
            None
            if requirement.marker is None
            else _canonical_marker(requirement.marker._markers)
        )
        return (
            canonicalize_name(requirement.name),
            tuple(
                sorted(canonicalize_name(extra) for extra in requirement.extras)
            ),
            str(requirement.specifier),
            requirement.url,
            marker,
        )
    except OptionalExtrasValidationError:
        raise
    except Exception as error:
        raise OptionalExtrasValidationError(
            f"invalid requirement metadata: {value!r}"
        ) from error


def _validate_kms_requirement_metadata(requirements: object) -> None:
    if not isinstance(requirements, (list, set, tuple)):
        raise OptionalExtrasValidationError(
            "installed distribution requirement metadata is invalid"
        )
    if any(not isinstance(value, str) for value in requirements):
        raise OptionalExtrasValidationError(
            "installed distribution requirement metadata is invalid"
        )
    actual = {
        _requirement_key(str(value))
        for value in requirements
    }
    expected = {
        _requirement_key(value) for value in EXPECTED_KMS_REQUIREMENTS
    }
    actual_provider_requirements = {
        requirement for requirement in actual
        if requirement[0] in KMS_PROVIDER_DISTRIBUTIONS
    }
    if actual_provider_requirements != expected:
        raise OptionalExtrasValidationError(
            "installed KMS provider requirements are not exact: "
            f"{sorted(repr(item) for item in actual_provider_requirements)}"
        )


def _validate_provider_family_isolation(
    lane: str,
    installed_versions: object,
) -> None:
    if type(installed_versions) is not dict:
        raise OptionalExtrasValidationError(
            "installed distribution report is invalid"
        )
    installed = {
        canonicalize_name(name)
        for name in installed_versions
        if type(name) is str
    }
    forbidden = sorted(
        installed.intersection(FORBIDDEN_PROVIDER_FAMILIES[lane])
    )
    if forbidden:
        raise OptionalExtrasValidationError(
            f"{lane} lane contains forbidden provider distributions: "
            f"{forbidden}"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _venv_python(venv_dir: Path) -> Path:
    bindir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    return bindir / ("python.exe" if sys.platform == "win32" else "python")


def _clean_env(venv_dir: Path) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    removed = sorted(
        name for name in env
        if name in CREDENTIAL_NAMES
        or any(name.startswith(prefix) for prefix in CREDENTIAL_PREFIXES)
    )
    for name in removed:
        env.pop(name, None)
    bindir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    env["VIRTUAL_ENV"] = str(venv_dir)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env, removed


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise OptionalExtrasValidationError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result


def _parse_expected_versions(value: str) -> dict[str, str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(
            "expected versions must be valid JSON"
        ) from error
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError(
            "expected versions must be a JSON object"
        )
    if (
        any(
            type(name) is not str
            or name not in SUPPORTED_VERSION_KEYS
            or type(version) is not str
            or not version
            for name, version in parsed.items()
        )
    ):
        raise argparse.ArgumentTypeError(
            "expected versions contain an unsupported package or version"
        )
    return parsed


def _validate_version_scope(
    lane: str,
    expected_versions: dict[str, str],
) -> None:
    allowed: set[str] = set()
    if lane in ("aws", "combined"):
        allowed.update(PROVIDER_DISTRIBUTIONS["aws"])
    if lane in ("gcp", "combined"):
        allowed.update(PROVIDER_DISTRIBUTIONS["gcp"])
    unexpected = set(expected_versions).difference(allowed)
    if unexpected:
        raise OptionalExtrasValidationError(
            f"{lane} lane received out-of-scope pins: {sorted(unexpected)}"
        )


def _artifact_install_spec(artifact: Path, lane: str) -> str:
    extras = EXTRAS_BY_LANE[lane]
    if not extras:
        return str(artifact)
    return f"{artifact}[{','.join(extras)}]"


SMOKE_CODE = r'''
from __future__ import annotations

from hashlib import sha256
from importlib import metadata
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

lane = sys.argv[1]
expected_versions = json.loads(sys.argv[2])
credential_prefixes = ("AWS_", "GOOGLE_", "GCP_", "CLOUDSDK_")
credential_names = {"BOTO_CONFIG"}

import aegis
import aegis.integrations.kms
import aegis.integrations.aws_kms as aws_kms
import aegis.integrations.google_cloud_kms as google_kms
from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    EvidenceType,
    SignatureEncoding,
    SignatureMetadata,
    VerificationReasonCode,
)

if any(
    name in credential_names
    or any(name.startswith(prefix) for prefix in credential_prefixes)
    for name in os.environ
):
    raise AssertionError("cloud credential environment was not removed")

requires_dist = metadata.requires("aegis-ai-governance")
if requires_dist is None:
    raise AssertionError("installed distribution has no dependency metadata")

installed_versions = {
    distribution.metadata["Name"]: distribution.version
    for distribution in metadata.distributions()
    if distribution.metadata["Name"]
}
canonical_versions = {
    name.lower().replace("_", "-"): version
    for name, version in installed_versions.items()
}
for name, version in expected_versions.items():
    if canonical_versions.get(name) != version:
        raise AssertionError(
            f"{name} resolved to {canonical_versions.get(name)!r}, "
            f"expected {version!r}"
        )

def distribution_present(name):
    try:
        metadata.version(name)
    except metadata.PackageNotFoundError:
        return False
    return True

aws_present = distribution_present("boto3")
gcp_presence = {
    name: distribution_present(name)
    for name in ("google-cloud-kms", "google-crc32c", "cryptography")
}
if lane == "base":
    if aws_present or any(gcp_presence.values()):
        raise AssertionError("base lane installed a provider distribution")
elif lane == "aws":
    if not aws_present or any(gcp_presence.values()):
        raise AssertionError("AWS-only lane provider isolation failed")
elif lane == "gcp":
    if aws_present or not all(gcp_presence.values()):
        raise AssertionError("Google-only lane provider isolation failed")
elif lane == "combined":
    if not aws_present or not all(gcp_presence.values()):
        raise AssertionError("combined lane omitted a provider distribution")
else:
    raise AssertionError(f"unknown lane: {lane}")

checks = [
    "installed-metadata",
    "provider-module-imports",
    "provider-distribution-isolation",
    "credential-environment-cleared",
]

def signature_metadata(receipt, *, signed_at):
    return SignatureMetadata(
        SIGNATURE_METADATA_SCHEMA_VERSION,
        SIGNING_PROFILE,
        CANONICALIZATION_VERSION,
        EvidenceType.AUDIT_ARTIFACT,
        receipt.algorithm,
        receipt.signature_encoding,
        receipt.key_reference,
        receipt.key_version,
        signed_at,
    )

def run_aws_cycle():
    import boto3
    from botocore.exceptions import (
        ConnectTimeoutError,
        EndpointConnectionError,
        ReadTimeoutError,
    )

    key_arn = (
        "arn:aws:kms:us-east-1:111122223333:key/"
        "00000000-0000-4000-8000-000000002048"
    )
    algorithm = "RSASSA_PSS_SHA_256"
    raw_signature = b"offline-aws-kms-signature"

    class FakeClient:
        exceptions = SimpleNamespace()

        def describe_key(self, **kwargs):
            if kwargs != {"KeyId": "alias/audit-artifact"}:
                raise AssertionError("unexpected AWS describe request")
            return {
                "KeyMetadata": {
                    "Arn": key_arn,
                    "KeyUsage": "SIGN_VERIFY",
                    "KeyState": "Enabled",
                    "Enabled": True,
                    "KeySpec": "RSA_2048",
                    "SigningAlgorithms": [algorithm],
                }
            }

        def sign(self, **kwargs):
            if (
                kwargs.get("KeyId") != key_arn
                or kwargs.get("MessageType") != "DIGEST"
                or kwargs.get("SigningAlgorithm") != algorithm
                or type(kwargs.get("Message")) is not bytes
                or len(kwargs["Message"]) != sha256().digest_size
            ):
                raise AssertionError("unexpected AWS sign request")
            return {
                "KeyId": key_arn,
                "SigningAlgorithm": algorithm,
                "Signature": raw_signature,
            }

        def verify(self, **kwargs):
            return {
                "KeyId": key_arn,
                "SigningAlgorithm": algorithm,
                "SignatureValid": (
                    kwargs.get("Signature") == raw_signature
                    and kwargs.get("MessageType") == "DIGEST"
                    and type(kwargs.get("Message")) is bytes
                ),
            }

    payload = b"offline AWS installed-extra cycle"
    client = FakeClient()
    signer = aws_kms.AwsKmsArtifactSigner(
        client,
        key_id="alias/audit-artifact",
        signing_algorithm=algorithm,
    )
    identity = signer.signer_identity()
    receipt = signer.sign(payload, identity)
    target = aws_kms.AwsKmsVerificationTarget(
        key_arn,
        frozenset({algorithm}),
        KmsKeyDisposition.ANCHORED,
    )
    verifier = aws_kms.AwsKmsArtifactVerifier(
        client,
        resolver=lambda reference, version: (
            target
            if reference == receipt.key_reference
            and version == receipt.key_version
            else None
        ),
    )
    outcome = verifier.verify(
        payload,
        receipt.signature,
        signature_metadata(receipt, signed_at=1),
    )
    if outcome.reason_code is not VerificationReasonCode.SIGNATURE_VALID_ANCHORED:
        raise AssertionError("AWS fake-client cycle failed")

    for exception_type in (
        ConnectTimeoutError,
        ReadTimeoutError,
        EndpointConnectionError,
    ):
        class TransportClient(FakeClient):
            def verify(self, **kwargs):
                raise exception_type(endpoint_url="https://offline.invalid")

        transport_verifier = aws_kms.AwsKmsArtifactVerifier(
            TransportClient(),
            resolver=lambda _reference, _version: target,
        )
        transport_outcome = transport_verifier.verify(
            payload,
            receipt.signature,
            signature_metadata(receipt, signed_at=2),
        )
        if (
            transport_outcome.reason_code
            is not VerificationReasonCode.VERIFIER_UNAVAILABLE
        ):
            raise AssertionError("real botocore transport class was not mapped")

    return {
        "boto3": boto3.__version__,
        "botocore_transport_classes": [
            ConnectTimeoutError.__name__,
            ReadTimeoutError.__name__,
            EndpointConnectionError.__name__,
        ],
    }

def run_google_cycle():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
    from google.api_core.exceptions import DeadlineExceeded
    from google.cloud import kms_v1
    import google_crc32c

    algorithm = "RSA_SIGN_PSS_2048_SHA256"
    name = (
        "projects/offline/locations/global/keyRings/audit/"
        "cryptoKeys/artifact/cryptoKeyVersions/1"
    )
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    class FakeClient:
        def get_crypto_key_version(self, **kwargs):
            request = kwargs["request"]
            if (
                type(request) is not kms_v1.GetCryptoKeyVersionRequest
                or request.name != name
            ):
                raise AssertionError("unexpected Google version request")
            return kms_v1.CryptoKeyVersion(
                name=name,
                state=kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED,
                algorithm=getattr(
                    kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm,
                    algorithm,
                ),
            )

        def asymmetric_sign(self, **kwargs):
            request = kwargs["request"]
            if (
                type(request) is not kms_v1.AsymmetricSignRequest
                or type(request.digest) is not kms_v1.Digest
                or request.name != name
            ):
                raise AssertionError("unexpected Google sign request")
            signature = private_key.sign(
                request.digest.sha256,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
            checksum = google_crc32c.Checksum(signature)
            return kms_v1.AsymmetricSignResponse(
                name=name,
                signature=signature,
                signature_crc32c=int.from_bytes(checksum.digest(), "big"),
                verified_digest_crc32c=True,
            )

    payload = b"offline Google installed-extra cycle"
    signer = google_kms.GoogleCloudKmsArtifactSigner(
        FakeClient(),
        crypto_key_version_name=name,
    )
    identity = signer.signer_identity()
    receipt = signer.sign(payload, identity)
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    target = google_kms.GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
        KmsKeyDisposition.ANCHORED,
        public_key_pem,
    )
    verifier = google_kms.GoogleCloudKmsArtifactVerifier(
        None,
        resolver=lambda reference, version: (
            target
            if reference == receipt.key_reference
            and version == receipt.key_version
            else None
        ),
    )
    outcome = verifier.verify(
        payload,
        receipt.signature,
        signature_metadata(receipt, signed_at=3),
    )
    if outcome.reason_code is not VerificationReasonCode.SIGNATURE_VALID_ANCHORED:
        raise AssertionError("Google retained-PEM cycle failed")

    checksum = google_crc32c.Checksum(public_key_pem)
    checksummed = kms_v1.ChecksummedData(
        data=public_key_pem,
        crc32c_checksum=int.from_bytes(checksum.digest(), "big"),
    )
    public_key_response = kms_v1.PublicKey(
        name=name,
        algorithm=getattr(
            kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm,
            algorithm,
        ),
        public_key_format=kms_v1.PublicKey.PublicKeyFormat.PEM,
        public_key=checksummed,
    )
    if (
        type(public_key_response) is not kms_v1.PublicKey
        or type(public_key_response.public_key) is not kms_v1.ChecksummedData
    ):
        raise AssertionError("real Google checksummed response classes failed")

    class UnavailableClient:
        def get_public_key(self, **kwargs):
            if type(kwargs["request"]) is not kms_v1.GetPublicKeyRequest:
                raise AssertionError("unexpected Google public-key request")
            raise DeadlineExceeded("offline transport classification")

    unavailable_target = google_kms.GoogleCloudKmsVerificationTarget(
        name,
        algorithm,
    )
    unavailable_verifier = google_kms.GoogleCloudKmsArtifactVerifier(
        UnavailableClient(),
        resolver=lambda _reference, _version: unavailable_target,
    )
    unavailable = unavailable_verifier.verify(
        payload,
        receipt.signature,
        signature_metadata(receipt, signed_at=4),
    )
    if unavailable.reason_code is not VerificationReasonCode.VERIFIER_UNAVAILABLE:
        raise AssertionError("real Google API exception class was not mapped")

    return {
        "google_request_classes": [
            "GetCryptoKeyVersionRequest",
            "AsymmetricSignRequest",
            "Digest",
            "GetPublicKeyRequest",
        ],
        "google_response_classes": [
            "CryptoKeyVersion",
            "AsymmetricSignResponse",
            "PublicKey",
            "ChecksummedData",
        ],
        "google_api_exception_class": DeadlineExceeded.__name__,
    }

provider_checks = {}
if lane in ("aws", "combined"):
    provider_checks["aws"] = run_aws_cycle()
    checks.append("aws-identity-sign-verify")
    checks.append("real-botocore-transport-classes")
if lane in ("gcp", "combined"):
    provider_checks["gcp"] = run_google_cycle()
    checks.append("google-identity-sign-retained-pem-verify")
    checks.append("real-google-sdk-and-api-classes")

import_path = Path(aegis.__file__).resolve()
if not import_path.is_relative_to(Path(sys.prefix).resolve()):
    raise AssertionError(f"aegis imported outside isolated venv: {import_path}")

print(json.dumps({
    "checks": checks,
    "import_path": str(import_path),
    "installed_versions": dict(sorted(installed_versions.items())),
    "provider_checks": provider_checks,
    "requires_dist": requires_dist,
}, sort_keys=True))
'''


def _validate_artifact(
    artifact: Path,
    lane: str,
    expected_versions: dict[str, str],
) -> dict[str, object]:
    _validate_version_scope(lane, expected_versions)
    with tempfile.TemporaryDirectory(prefix="aegis_kms_extra_") as temp:
        root = Path(temp).resolve()
        venv_dir = root / "venv"
        smoke_dir = root / "isolated-smoke"
        smoke_dir.mkdir()
        venv.create(venv_dir, with_pip=True, clear=True)
        python = _venv_python(venv_dir)
        env, removed_credentials = _clean_env(venv_dir)

        if expected_versions:
            pins = [
                f"{name}=={version}"
                for name, version in sorted(expected_versions.items())
            ]
            _run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    *pins,
                ],
                cwd=smoke_dir,
                env=env,
            )

        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                _artifact_install_spec(artifact, lane),
            ],
            cwd=smoke_dir,
            env=env,
        )
        _run(
            [str(python), "-m", "pip", "check"],
            cwd=smoke_dir,
            env=env,
        )
        smoke = _run(
            [
                str(python),
                "-I",
                "-c",
                SMOKE_CODE,
                lane,
                json.dumps(expected_versions, sort_keys=True),
            ],
            cwd=smoke_dir,
            env=env,
        )
        child_report = json.loads(smoke.stdout)
        _validate_kms_requirement_metadata(child_report["requires_dist"])
        _validate_provider_family_isolation(
            lane,
            child_report["installed_versions"],
        )

    return {
        "artifact": str(artifact),
        "artifact_sha256": _sha256(artifact),
        "checks": child_report["checks"],
        "credential_variables_removed": removed_credentials,
        "expected_versions": expected_versions,
        "import_path": child_report["import_path"],
        "installed_versions": child_report["installed_versions"],
        "lane": lane,
        "provider_checks": child_report["provider_checks"],
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument(
        "--lane",
        choices=tuple(EXTRAS_BY_LANE),
        required=True,
    )
    parser.add_argument(
        "--expected-versions",
        type=_parse_expected_versions,
        required=True,
    )
    args = parser.parse_args()

    artifact = args.artifact.resolve()
    if not artifact.is_file():
        parser.error(f"artifact does not exist: {artifact}")
    if not (
        artifact.name.endswith(".whl")
        or artifact.name.endswith(".tar.gz")
    ):
        parser.error("artifact must be a wheel or .tar.gz source distribution")

    try:
        report = _validate_artifact(
            artifact,
            args.lane,
            args.expected_versions,
        )
    except Exception as error:
        print(
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
