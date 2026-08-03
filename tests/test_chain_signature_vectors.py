from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.signature_models import (
    AnchorStatus,
    SignatureEncoding,
    SignerIdentity,
)
from aegis._internal.signing import (
    FINALIZER_INVOCATION_DOMAIN,
    ArtifactSignerAdapter,
    HMACSigner,
    verify_finalized_artifact,
)
from aegis.audit_chain import (
    ChainContinuity,
    Completeness,
    verify_chain_detailed,
)


def _identity(version: str) -> SignerIdentity:
    return SignerIdentity(
        algorithm="HMAC-SHA256",
        signature_encoding=SignatureEncoding.HEX,
        key_reference="local://chain-vector",
        key_version=version,
    )


def _chained_artifact(
    index: int,
    previous_checksum: str | None,
) -> dict[str, object]:
    return build_content_checksum_v2(
        {
            "audit_schema_version": "2.0",
            "canonicalization_profile": "aegis-json-v2",
            "chain_id": "chain-vector-1",
            "chain_index": index,
            "previous_audit_checksum": previous_checksum,
            "reservation_id": f"reservation-vector-{index}",
            "body": {"sequence": index},
        }
    )


def test_key_rotation_changes_only_signature_layer():
    first_key = HMACSigner(b"chain-vector-key-one")
    second_key = HMACSigner(b"chain-vector-key-two")
    checksummed = _chained_artifact(7, "f" * 64)

    first_signature = ArtifactSignerAdapter(first_key, _identity("1")).sign(
        checksummed,
        domain=FINALIZER_INVOCATION_DOMAIN,
        signed_at=100,
    )
    rotated_signature = ArtifactSignerAdapter(second_key, _identity("2")).sign(
        first_signature,
        domain=FINALIZER_INVOCATION_DOMAIN,
        signed_at=200,
    )

    stable_fields = (
        "checksum",
        "chain_id",
        "chain_index",
        "previous_audit_checksum",
        "reservation_id",
    )
    assert {field: first_signature[field] for field in stable_fields} == {
        field: rotated_signature[field] for field in stable_fields
    }
    assert first_signature["signature"] != rotated_signature["signature"]
    assert first_signature["signature_metadata"] != rotated_signature[
        "signature_metadata"
    ]
    assert verify_finalized_artifact(
        first_signature,
        first_key,
        domain=FINALIZER_INVOCATION_DOMAIN,
    )
    assert verify_finalized_artifact(
        rotated_signature,
        second_key,
        domain=FINALIZER_INVOCATION_DOMAIN,
    )
    assert not verify_finalized_artifact(
        rotated_signature,
        first_key,
        domain=FINALIZER_INVOCATION_DOMAIN,
    )


def test_supplied_sequence_continuity_never_proves_completeness_without_anchor():
    first = _chained_artifact(0, None)
    second = _chained_artifact(1, first["checksum"])
    third = _chained_artifact(2, second["checksum"])

    complete_supplied_sequence = verify_chain_detailed([first, second, third])
    truncated_valid_prefix = verify_chain_detailed([first, second])
    reordered_sequence = verify_chain_detailed([second, first, third])

    assert complete_supplied_sequence.chain_continuity is ChainContinuity.VALID
    assert truncated_valid_prefix.chain_continuity is ChainContinuity.VALID
    assert reordered_sequence.chain_continuity is ChainContinuity.INVALID
    for report in (
        complete_supplied_sequence,
        truncated_valid_prefix,
        reordered_sequence,
    ):
        assert report.anchor_status is AnchorStatus.NOT_EVALUATED
        assert report.completeness is Completeness.UNPROVEN
