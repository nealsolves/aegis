import copy

import pytest

from aegis._internal.canonicalization import canonicalize_v2
from aegis._internal.evidence_profiles import build_content_checksum_v2
from aegis._internal.signature_models import AnchorStatus, SignatureStatus
from aegis._internal.utils import canonical_json_bytes
from aegis.audit_chain import (
    ChainContinuity,
    Completeness,
    ContentIntegrity,
    verify_chain,
    verify_chain_detailed,
)


def artifact_body(**overrides):
    artifact = {
        "audit_schema_version": "2.0",
        "canonicalization_profile": "aegis-json-v2",
        "body": {"value": "ascii"},
    }
    artifact.update(overrides)
    return artifact


def finalized_artifact(**overrides):
    return build_content_checksum_v2(artifact_body(**overrides))


def valid_prefix():
    first = finalized_artifact(
        chain_id="chain-1",
        chain_index=7,
        previous_audit_checksum="f" * 64,
    )
    second = finalized_artifact(
        chain_id="chain-1",
        chain_index=8,
        previous_audit_checksum=first["checksum"],
    )
    return [first, second]


def test_missing_checksum_is_invalid_by_default():
    report = verify_chain_detailed([artifact_body()])
    assert report.content_integrity is ContentIntegrity.INVALID


def test_valid_prefix_never_claims_completeness():
    report = verify_chain_detailed(valid_prefix())
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.VALID
    assert report.completeness is Completeness.UNPROVEN


def test_checksum_valid_unsigned_chain_is_not_authentic():
    report = verify_chain_detailed(valid_prefix())
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert report.anchor_status is AnchorStatus.NOT_EVALUATED


def test_plain_ascii_v1_v2_byte_coincidence_cannot_promote_signature_assurance():
    legacy = {"audit_schema_version": "1.4", "value": "ascii"}
    assert canonical_json_bytes(legacy) == canonicalize_v2(legacy).data
    promoted = build_content_checksum_v2(
        {
            "audit_schema_version": "2.0",
            "canonicalization_profile": "aegis-json-v2",
            "value": "ascii",
        }
    )
    report = verify_chain_detailed([promoted])
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert report.signature_status is not SignatureStatus.VALID


def test_tampered_body_does_not_change_independent_unsigned_status():
    artifact = finalized_artifact()
    artifact["body"]["value"] = "tampered"
    report = verify_chain_detailed([artifact])
    assert report.content_integrity is ContentIntegrity.INVALID
    assert report.chain_continuity is ChainContinuity.UNCHAINED
    assert report.signature_status is SignatureStatus.UNSIGNED
    assert report.completeness is Completeness.UNPROVEN


@pytest.mark.parametrize("entry", [None, [], "artifact", {1: "bad key"}])
def test_malformed_entries_return_typed_invalid_report(entry):
    report = verify_chain_detailed([entry])
    assert report.content_integrity is ContentIntegrity.INVALID
    assert report.chain_continuity is ChainContinuity.INVALID
    assert report.errors


def test_verification_does_not_mutate_supplied_artifacts():
    artifacts = valid_prefix()
    before = copy.deepcopy(artifacts)
    verify_chain_detailed(artifacts)
    assert artifacts == before


def test_deprecated_wrapper_boolean_means_only_internal_validity():
    with pytest.warns(DeprecationWarning):
        valid, errors = verify_chain(valid_prefix())
    assert valid is True
    assert errors == []
    assert verify_chain_detailed(valid_prefix()).completeness is Completeness.UNPROVEN


def test_deprecated_wrapper_rejects_invalid_content():
    with pytest.warns(DeprecationWarning):
        valid, errors = verify_chain([artifact_body()])
    assert valid is False
    assert errors


def test_unlinked_artifact_reports_unchained_not_invalid():
    report = verify_chain_detailed([finalized_artifact()])
    assert report.content_integrity is ContentIntegrity.VALID
    assert report.chain_continuity is ChainContinuity.UNCHAINED


def test_empty_supplied_set_is_not_evaluated_or_complete():
    report = verify_chain_detailed([])
    assert report.content_integrity is ContentIntegrity.NOT_EVALUATED
    assert report.chain_continuity is ChainContinuity.NOT_EVALUATED
    assert report.completeness is Completeness.UNPROVEN
