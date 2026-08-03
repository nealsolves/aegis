"""
Audit artifact signing and verification.

Provides HMAC-SHA256 based signing of audit artifacts with a pluggable
signer interface for alternative implementations.

Signing is applied to the canonical JSON representation of the artifact
(excluding the signature field itself) to ensure deterministic signatures.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import logging
import copy
from typing import Any, Mapping, Protocol

from aegis._internal.canonicalization import (
    CANONICALIZATION_PROFILE_V2,
    canonicalize_v2,
)
from aegis._internal.errors import SigningContractError
from aegis._internal.signature_models import (
    CANONICALIZATION_VERSION,
    SIGNATURE_METADATA_SCHEMA_VERSION,
    SIGNING_PROFILE,
    SignatureEncoding,
    SignerIdentity,
    validate_encoded_signature,
)
from aegis._internal.utils import canonical_json_bytes

logger = logging.getLogger("aegis.signing")

FINALIZER_INVOCATION_DOMAIN = "aegis.invocation.v2"
FINALIZER_WORKFLOW_DOMAIN = "aegis.workflow.v2"
_FINALIZER_PAYLOAD_TYPES = {
    FINALIZER_INVOCATION_DOMAIN: "audit_artifact",
    FINALIZER_WORKFLOW_DOMAIN: "workflow_artifact",
}


class FinalizerSigner(Protocol):
    """Internal signing boundary consumed by the evidence finalizer."""

    def sign(
        self,
        artifact: Mapping[str, Any],
        *,
        domain: str,
        signed_at: int,
    ) -> dict[str, Any]: ...


class ArtifactSigner(abc.ABC):
    """Abstract base class for audit artifact signers."""

    @abc.abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign canonical payload bytes and return signature string.

        :param payload: Canonical JSON bytes of the artifact (without signature)
        :return: Signature string to embed in the artifact
        """

    @abc.abstractmethod
    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a signature against canonical payload bytes.

        :param payload: Canonical JSON bytes of the artifact (without signature)
        :param signature: Signature string from the artifact
        :return: True if signature is valid
        """


class HMACSigner(ArtifactSigner):
    """HMAC-SHA256 based artifact signer.

    Uses a shared secret key for signing and verification.
    Suitable for single-organization SDK deployments where the
    signing key is managed as a deployment secret.

    Usage::

        signer = HMACSigner(key=b"my-secret-key")
        signed_artifact = sign_artifact(artifact, signer)
        assert verify_artifact(signed_artifact, signer)
    """

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("Signing key must be non-empty")
        self._key = key

    def sign(self, payload: bytes) -> str:
        """Produce HMAC-SHA256 signature as hex string."""
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify HMAC-SHA256 signature using constant-time comparison."""
        expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


def _finalizer_metadata(
    identity: SignerIdentity,
    *,
    domain: str,
    signed_at: int,
) -> dict[str, Any]:
    payload_type = _FINALIZER_PAYLOAD_TYPES.get(domain)
    if payload_type is None:
        raise SigningContractError("Finalizer signing domain is unsupported")
    if isinstance(signed_at, bool) or not isinstance(signed_at, int) or signed_at < 0:
        raise SigningContractError(
            "signed_at is invalid", details={"field": "signed_at"}
        )
    return {
        "schema_version": SIGNATURE_METADATA_SCHEMA_VERSION,
        "signing_profile": SIGNING_PROFILE,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "canonicalization_profile": CANONICALIZATION_PROFILE_V2,
        "payload_type": payload_type,
        "algorithm": identity.algorithm,
        "signature_encoding": identity.signature_encoding.value,
        "key_reference": identity.key_reference,
        "key_version": identity.key_version,
        "signed_at": signed_at,
    }


def _finalizer_signing_payload(
    artifact: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    domain: str,
) -> bytes:
    if domain not in _FINALIZER_PAYLOAD_TYPES:
        raise SigningContractError("Finalizer signing domain is unsupported")
    if artifact.get("canonicalization_profile") != CANONICALIZATION_PROFILE_V2:
        raise SigningContractError("Artifact canonicalization profile is invalid")
    if metadata.get("canonicalization_profile") != artifact.get(
        "canonicalization_profile"
    ):
        raise SigningContractError("Signing metadata profile does not match evidence")
    if metadata.get("payload_type") != _FINALIZER_PAYLOAD_TYPES[domain]:
        raise SigningContractError("Signing metadata payload type is invalid")
    signable = copy.deepcopy(dict(artifact))
    signable.pop("signature", None)
    signable["signature_metadata"] = copy.deepcopy(dict(metadata))
    return domain.encode("ascii") + b"\x00" + canonicalize_v2(signable).data


class ArtifactSignerAdapter:
    """Adapt the legacy byte signer to the metadata-aware v2 finalizer."""

    def __init__(self, signer: ArtifactSigner, identity: SignerIdentity) -> None:
        if not isinstance(signer, ArtifactSigner):
            raise TypeError("signer must be an ArtifactSigner")
        if not isinstance(identity, SignerIdentity):
            raise TypeError("identity must be a SignerIdentity")
        self._signer = signer
        self._identity = identity

    def sign(
        self,
        artifact: Mapping[str, Any],
        *,
        domain: str,
        signed_at: int,
    ) -> dict[str, Any]:
        metadata = _finalizer_metadata(
            self._identity,
            domain=domain,
            signed_at=signed_at,
        )
        signed = copy.deepcopy(dict(artifact))
        signed["signature_status"] = "signed"
        payload = _finalizer_signing_payload(signed, metadata, domain=domain)
        signature = self._signer.sign(payload)
        validate_encoded_signature(signature, self._identity.signature_encoding)
        signed.update(signature_metadata=metadata, signature=signature)
        return signed


def verify_finalized_artifact(
    artifact: Mapping[str, Any],
    signer: ArtifactSigner,
    *,
    domain: str,
) -> bool:
    """Verify a metadata-aware v2 artifact without mutating caller state."""
    try:
        if artifact.get("signature_status") != "signed":
            return False
        signature = artifact.get("signature")
        metadata = artifact.get("signature_metadata")
        if not isinstance(signature, str) or type(metadata) is not dict:
            return False
        encoding = SignatureEncoding(metadata.get("signature_encoding"))
        validate_encoded_signature(signature, encoding)
        payload = _finalizer_signing_payload(artifact, metadata, domain=domain)
        verified = signer.verify(payload, signature)
    except Exception:
        return False
    return type(verified) is bool and verified


def _canonical_signing_payload(artifact: dict[str, Any]) -> bytes:
    """Produce canonical bytes for signing (artifact without signature field).

    The signature field is excluded from the payload to avoid circular
    dependency. All other fields are included in sorted-key canonical form.
    """
    signable = {k: v for k, v in artifact.items() if k != "signature"}
    return canonical_json_bytes(signable)


def sign_artifact(
    artifact: dict[str, Any],
    signer: ArtifactSigner,
) -> dict[str, Any]:
    """Sign an audit artifact in place and return it.

    :param artifact: Audit artifact dict (signature field will be set)
    :param signer: Signer implementation
    :return: The artifact with signature field populated
    """
    payload = _canonical_signing_payload(artifact)
    artifact["signature"] = signer.sign(payload)
    logger.debug("Artifact signed: %s", artifact.get("enforcement_result"))
    return artifact


def verify_artifact(
    artifact: dict[str, Any],
    signer: ArtifactSigner,
) -> bool:
    """Verify an audit artifact's signature.

    :param artifact: Audit artifact dict with signature field
    :param signer: Signer implementation (must match the signing key)
    :return: True if signature is valid, False otherwise
    """
    if artifact.get("signature_status") == "signed":
        return verify_finalized_artifact(
            artifact,
            signer,
            domain=FINALIZER_INVOCATION_DOMAIN,
        )
    signature = artifact.get("signature")
    if signature is None:
        logger.warning("Artifact has no signature to verify")
        return False

    payload = _canonical_signing_payload(artifact)
    valid = signer.verify(payload, signature)
    if not valid:
        logger.warning("Artifact signature verification failed")
    return valid
