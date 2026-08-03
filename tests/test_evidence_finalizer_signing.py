import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from aegis._internal.attempts import AttemptFactory
from aegis._internal.evidence_finalizer import (
    EvidenceDraft,
    EvidenceFinalizer,
    EvidenceFinalizerConfig,
)
from aegis._internal.errors import EvidenceFinalizationError
from aegis._internal.external_signing import ExternalArtifactSignerAdapter
from aegis._internal.outcomes import TerminalClass
from aegis._internal.signature_models import (
    SignatureEncoding,
    SignerIdentity,
    SigningReceipt,
)
from aegis._internal.signing import (
    ArtifactSignerAdapter,
    HMACSigner,
    verify_finalized_artifact,
)
from aegis._internal.sinks import CallbackAuditSink


ROOT = Path(__file__).resolve().parents[1]


def _draft():
    attempt = AttemptFactory(clock=lambda: 100).allocate(
        "enforce_invocation",
        "unified",
        {
            "policy_file": "policy.yaml",
            "model_provider": "openai",
            "model_identifier": "gpt-test",
            "role": "planner",
        },
    )
    return EvidenceDraft(
        attempt=attempt,
        terminal=TerminalClass.ALLOW,
        artifact_type="invocation",
        body={
            "policy_schema_version": "http://json-schema.org/draft-07/schema#",
            "policy_version": "1.0",
            "input_checksum": "a" * 64,
            "output_checksum": "b" * 64,
        },
    )


def _validator():
    schema = json.loads((ROOT / "schemas/audit_artifact.schema.json").read_text())
    return Draft7Validator(schema)


def _identity():
    return SignerIdentity(
        algorithm="HMAC-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="local://test",
        key_version="1",
    )


def test_hmac_finalizer_signer_covers_v2_profile():
    raw_signer = HMACSigner(b"test-key")
    signer = ArtifactSignerAdapter(raw_signer, _identity())
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=CallbackAuditSink(lambda artifact: None),
            signer=signer,
            schema_validator=_validator(),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(_draft())

    assert artifact["signature_status"] == "signed"
    assert artifact["signature_metadata"]["canonicalization_profile"] == (
        artifact["canonicalization_profile"]
    )
    assert verify_finalized_artifact(
        artifact,
        raw_signer,
        domain="aegis.invocation.v2",
    )
    artifact["canonicalization_profile"] = "forged"
    assert not verify_finalized_artifact(
        artifact,
        raw_signer,
        domain="aegis.invocation.v2",
    )


class ExternalSigner:
    def __init__(self):
        self.payload = None
        self.identity = None

    def signer_identity(self):
        return _identity()

    def sign(self, payload, identity):
        self.payload = payload
        self.identity = identity
        return SigningReceipt(
            signature="cd" * 32,
            algorithm=identity.algorithm,
            signature_encoding=identity.signature_encoding,
            key_reference=identity.key_reference,
            key_version=identity.key_version,
        )


def test_external_finalizer_signer_uses_same_metadata_contract():
    provider = ExternalSigner()
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=CallbackAuditSink(lambda artifact: None),
            signer=ExternalArtifactSignerAdapter(provider),
            schema_validator=_validator(),
            clock=lambda: 101,
        )
    )

    artifact = finalizer.finalize(_draft())

    assert provider.payload.startswith(b"aegis.invocation.v2\x00")
    assert provider.identity == _identity()
    assert artifact["signature"] == "cd" * 32
    assert artifact["signature_metadata"]["canonicalization_profile"] == (
        "aegis-json-v2"
    )


class BrokenSigner:
    def sign(self, artifact, *, domain, signed_at):
        raise RuntimeError("provider response with secret")


def test_configured_signer_failure_is_bounded_and_typed():
    finalizer = EvidenceFinalizer(
        EvidenceFinalizerConfig(
            sink=CallbackAuditSink(lambda artifact: None),
            signer=BrokenSigner(),
            schema_validator=_validator(),
        )
    )

    with pytest.raises(EvidenceFinalizationError) as captured:
        finalizer.finalize(_draft())

    assert captured.value.code == "EVIDENCE_FINALIZATION_FAILED"
    assert "provider response" not in str(captured.value)
