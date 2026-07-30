"""Private strict helpers shared by optional KMS provider modules."""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
from types import MappingProxyType

from aegis.integrations.kms import KmsKeyDisposition
from aegis.signing import (
    AnchorStatus,
    ExternalVerificationOutcome,
    SignatureStatus,
    VerificationReasonCode,
)


MAX_RAW_SIGNATURE_BYTES = 12_288
MAX_AWS_RAW_SIGNATURE_BYTES = 6_144
MAX_PUBLIC_KEY_PEM_BYTES = 65_536
MAX_CRC32C = 2**32 - 1

_USE_PROVIDER_DEFAULT = object()

_OUTCOME_FIELDS = MappingProxyType(
    {
        VerificationReasonCode.SIGNATURE_VALID_ANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.ANCHORED,
            "Signature is valid and externally anchored",
        ),
        VerificationReasonCode.SIGNATURE_VALID_UNANCHORED: (
            SignatureStatus.VALID,
            AnchorStatus.UNANCHORED,
            "Signature is valid but not externally anchored",
        ),
        VerificationReasonCode.ANCHOR_INVALID: (
            SignatureStatus.VALID,
            AnchorStatus.INVALID,
            "The external anchor is invalid",
        ),
        VerificationReasonCode.KEY_REVOKED: (
            SignatureStatus.REVOKED,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier reports the key version as revoked",
        ),
        VerificationReasonCode.KEY_UNKNOWN: (
            SignatureStatus.UNKNOWN_KEY,
            AnchorStatus.NOT_EVALUATED,
            "The configured verifier does not recognize the key version",
        ),
        VerificationReasonCode.ALGORITHM_NOT_ALLOWED: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "The configured key does not permit the declared algorithm",
        ),
        VerificationReasonCode.SIGNATURE_INVALID: (
            SignatureStatus.INVALID,
            AnchorStatus.NOT_EVALUATED,
            "Signature is invalid",
        ),
        VerificationReasonCode.VERIFIER_UNAVAILABLE: (
            SignatureStatus.INDETERMINATE,
            AnchorStatus.NOT_EVALUATED,
            "External verification is unavailable",
        ),
    }
)

__all__: list[str] = []


def _sha256_digest(payload: bytes) -> bytes:
    """Hash one exact artifact byte sequence."""
    if type(payload) is not bytes:
        raise ValueError("payload is invalid")
    return hashlib.sha256(payload).digest()


def _canonical_b64encode(value: bytes) -> str:
    """Encode a nonempty exact byte sequence as canonical RFC 4648 base64."""
    if type(value) is not bytes or not value:
        raise ValueError("base64 value is invalid")
    return base64.b64encode(value).decode("ascii")


def _canonical_b64decode(value: str, *, max_raw_bytes: int) -> bytes:
    """Decode bounded canonical RFC 4648 base64 without accepting aliases."""
    if (
        type(value) is not str
        or type(max_raw_bytes) is not int
        or max_raw_bytes < 1
        or not value
        or len(value) > ((max_raw_bytes + 2) // 3) * 4
    ):
        raise ValueError("base64 value is invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise ValueError("base64 value is invalid") from None
    if not decoded or len(decoded) > max_raw_bytes:
        raise ValueError("base64 value is invalid")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("base64 value is invalid")
    return decoded


def _normalize_timeout(value: object, *, error_type: type[Exception]) -> object:
    """Keep explicit SDK timeout values distinct from omitted arguments."""
    if value is _USE_PROVIDER_DEFAULT or value is None:
        return value
    if type(value) is int:
        if value > 0:
            return value
    elif type(value) is float and math.isfinite(value) and value > 0:
        return value
    raise error_type("timeout is invalid") from None


def _normalize_crc32c(value: object) -> int:
    """Require an exact unsigned 32-bit CRC32C value."""
    if type(value) is not int or not 0 <= value <= MAX_CRC32C:
        raise ValueError("crc32c is invalid")
    return value


def _is_canonical_key_disposition(value: object) -> bool:
    """Accept only one of the four declared host-policy enum singletons."""
    return any(value is member for member in KmsKeyDisposition)


def _load_authenticated_module(
    *,
    module_name: str,
    package_name: str,
    distribution_name: str,
    source_entry_name: str,
) -> object | None:
    """Load one installed module only when its distribution RECORD authenticates it."""
    try:
        from base64 import urlsafe_b64encode
        from hashlib import sha256
        import importlib
        import importlib.machinery
        import importlib.metadata
        import importlib.util
        from pathlib import Path
        import sys
        from types import ModuleType

        module = importlib.import_module(module_name)
        if type(module) is not ModuleType:
            return None
        module_file = module.__file__
        module_spec = module.__spec__
        if (
            module.__name__ != module_name
            or module.__package__ != package_name
            or type(module_file) is not str
            or not module_file
            or type(module_spec) is not importlib.machinery.ModuleSpec
            or module_spec.name != module_name
            or type(module_spec.origin) is not str
            or not module_spec.origin
            or module_spec.has_location is not True
            or module_spec.submodule_search_locations is not None
            or module_spec.loader is None
            or module.__loader__ is not module_spec.loader
            or dict.get(sys.modules, module_name) is not module
        ):
            return None

        module_path = Path(module_file).resolve(strict=True)
        if Path(module_spec.origin).resolve(strict=True) != module_path:
            return None
        discovered_spec = importlib.util.find_spec(module_name)
        if (
            type(discovered_spec) is not importlib.machinery.ModuleSpec
            or type(discovered_spec.origin) is not str
            or Path(discovered_spec.origin).resolve(strict=True)
            != module_path
        ):
            return None

        distribution = importlib.metadata.distribution(distribution_name)
        installed_name = distribution.metadata["Name"]
        if (
            type(installed_name) is not str
            or installed_name.lower().replace("_", "-")
            != distribution_name
        ):
            return None
        distribution_files = distribution.files
        if distribution_files is None:
            return None
        source_entries = tuple(
            entry
            for entry in distribution_files
            if str(entry).replace("\\", "/") == source_entry_name
        )
        if len(source_entries) != 1:
            return None
        source_entry = source_entries[0]
        source_path = Path(
            distribution.locate_file(source_entry)
        ).resolve(strict=True)
        if source_path != module_path:
            return None
        source_size = source_entry.size
        source_hash = source_entry.hash
        if (
            type(source_size) is not int
            or not 0 < source_size <= 1_048_576
            or source_hash is None
            or type(source_hash.mode) is not str
            or source_hash.mode != "sha256"
            or type(source_hash.value) is not str
            or not source_hash.value
            or source_path.stat().st_size != source_size
        ):
            return None
        with source_path.open(mode="rb") as source_file:
            source_bytes = source_file.read(source_size + 1)
        if type(source_bytes) is not bytes or len(source_bytes) != source_size:
            return None
        source_digest = (
            urlsafe_b64encode(sha256(source_bytes).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if source_digest != source_hash.value:
            return None
        return module
    except Exception:
        return None


def _outcome(reason_code: VerificationReasonCode) -> ExternalVerificationOutcome:
    """Construct a safe verification result from the closed KMS outcome set."""
    if type(reason_code) is not VerificationReasonCode:
        raise ValueError("verification outcome reason is invalid")
    fields = _OUTCOME_FIELDS.get(reason_code)
    if fields is None:
        raise ValueError("verification outcome reason is invalid")
    signature_status, anchor_status, message = fields
    return ExternalVerificationOutcome(
        signature_status,
        anchor_status,
        reason_code,
        message,
    )
