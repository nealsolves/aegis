import json

import pytest

from aegis import (
    ChainContinuity,
    Completeness,
    ContentIntegrity,
    LegacyAuthorization,
    LegacyFeature,
    create_legacy_authorization,
    verify_chain_detailed,
)
from aegis._internal.cli import main
from aegis._internal.errors import PolicyValidationError
from aegis._internal.policy_compiler import compile_policy


def legacy_artifact(**overrides):
    artifact = {
        "audit_schema_version": "1.4",
        "policy_version": "legacy",
        "canonicalization_profile": "aegis-canonical-json-v1",
        "body": {"value": "ascii"},
    }
    artifact.update(overrides)
    return artifact


@pytest.mark.parametrize(
    "requested_authority",
    [
        {"policy_version": "legacy"},
        {"canonicalization_profile": "aegis-json-v2"},
        {"guard_effects": {"allow_legacy": True}},
        {"context": {"allow_legacy": True}},
        {"provider": {"legacy_authorization": True}},
    ],
)
def test_artifact_policy_guard_context_and_provider_fields_cannot_grant_legacy(
    requested_authority,
):
    report = verify_chain_detailed([legacy_artifact(**requested_authority)])
    assert report.content_integrity is ContentIntegrity.INVALID
    assert report.completeness is Completeness.UNPROVEN


def test_lookalike_authorization_object_cannot_grant_legacy():
    class ForgedAuthorization:
        features = frozenset(
            {
                LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION.value,
                LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION.value,
            }
        )

    report = verify_chain_detailed(
        [legacy_artifact()], legacy_authorization=ForgedAuthorization()
    )
    assert report.content_integrity is ContentIntegrity.INVALID


def test_legacy_authorization_constructor_rejects_an_untrusted_capability():
    with pytest.raises(TypeError, match="host-created only"):
        LegacyAuthorization(object(), frozenset())


def test_host_authorization_feature_set_is_immutable():
    authorization = create_legacy_authorization(
        LegacyFeature.BARE_STRING_PRECONDITIONS
    )
    with pytest.raises(AttributeError):
        authorization.features = frozenset(
            {LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION.value}
        )


def test_host_authorization_marks_checksum_free_audit_as_legacy_unproven():
    authorization = create_legacy_authorization(
        LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
        LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION,
    )
    report = verify_chain_detailed(
        [legacy_artifact()], legacy_authorization=authorization
    )
    assert report.content_integrity is ContentIntegrity.LEGACY
    assert report.chain_continuity is ChainContinuity.UNCHAINED
    assert report.completeness is Completeness.UNPROVEN


def test_legacy_authorization_is_feature_scoped():
    authorization = create_legacy_authorization(
        LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION
    )
    report = verify_chain_detailed(
        [legacy_artifact()], legacy_authorization=authorization
    )
    assert report.content_integrity is ContentIntegrity.INVALID


def test_workflow_legacy_authority_is_independent_from_audit_authority():
    workflow = {
        "workflow_schema_version": "1.0",
        "artifact_type": "workflow",
    }
    audit_only = create_legacy_authorization(
        LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
        LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION,
    )
    assert (
        verify_chain_detailed(
            [workflow], legacy_authorization=audit_only
        ).content_integrity
        is ContentIntegrity.INVALID
    )
    workflow_authorized = create_legacy_authorization(
        LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
        LegacyFeature.WORKFLOW_SCHEMA_1X_VERIFICATION,
    )
    assert (
        verify_chain_detailed(
            [workflow], legacy_authorization=workflow_authorized
        ).content_integrity
        is ContentIntegrity.LEGACY
    )


def bare_string_policy():
    return {
        "policy_version": "1.0",
        "roles": ["verifier"],
        "pre_conditions": {"required": ["role_declared"]},
    }


def test_boolean_legacy_switch_cannot_replace_the_host_capability():
    with pytest.raises(PolicyValidationError) as exc:
        compile_policy(bare_string_policy(), source="test", allow_legacy=True)
    assert exc.value.code == "LEGACY_AUTHORIZATION_REQUIRED"


def test_host_capability_allows_only_the_selected_compiler_feature():
    authorization = create_legacy_authorization(
        LegacyFeature.BARE_STRING_PRECONDITIONS
    )
    compiled = compile_policy(
        bare_string_policy(),
        source="test",
        legacy_authorization=authorization,
    )
    assert compiled.preconditions[0].legacy is True


def test_policy_content_cannot_embed_a_legacy_capability():
    policy = bare_string_policy()
    policy["legacy_authorization"] = {
        "features": [LegacyFeature.BARE_STRING_PRECONDITIONS.value]
    }
    with pytest.raises(PolicyValidationError):
        compile_policy(policy, source="test")


def test_cli_requires_an_explicit_feature_flag_for_legacy_preconditions(
    tmp_path, capsys
):
    path = tmp_path / "legacy.yaml"
    path.write_text(
        "policy_version: '1.0'\nroles: [verifier]\n"
        "pre_conditions:\n  required: [role_declared]\n",
        encoding="utf-8",
    )
    assert main(["policy", "lint", str(path)]) == 1
    capsys.readouterr()
    assert (
        main(
            [
                "policy",
                "lint",
                str(path),
                "--allow-legacy-preconditions",
            ]
        )
        == 0
    )


def test_legacy_report_does_not_mutate_or_strip_artifact():
    artifact = legacy_artifact(signature=None)
    before = json.loads(json.dumps(artifact))
    authorization = create_legacy_authorization(
        LegacyFeature.CHECKSUM_FREE_CHAIN_VERIFICATION,
        LegacyFeature.AUDIT_SCHEMA_1X_VERIFICATION,
    )
    verify_chain_detailed([artifact], legacy_authorization=authorization)
    assert artifact == before
