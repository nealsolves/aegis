from __future__ import annotations

from datetime import date
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

import scripts.check_compliance_catalog as compliance_check

from scripts.compliance_catalog import (
    CatalogInputError,
    CatalogData,
    baseline_drift,
    catalog_asset_text,
    validate_claims,
    validate_framework_module,
    validate_schema,
    load_yaml,
    load_catalog,
)
from scripts.render_compliance_catalog import render_catalog, render_framework
from scripts.check_compliance_catalog import _manifest_findings, main as check_main


NIST_AI_RMF_CORE_IDS = {
    "GOVERN-1.1", "GOVERN-1.2", "GOVERN-1.3", "GOVERN-1.4", "GOVERN-1.5",
    "GOVERN-1.6", "GOVERN-1.7", "GOVERN-2.1", "GOVERN-2.2", "GOVERN-2.3",
    "GOVERN-3.1", "GOVERN-3.2", "GOVERN-4.1", "GOVERN-4.2", "GOVERN-4.3",
    "GOVERN-5.1", "GOVERN-5.2", "GOVERN-6.1", "GOVERN-6.2",
    "MAP-1.1", "MAP-1.2", "MAP-1.3", "MAP-1.4", "MAP-1.5", "MAP-1.6",
    "MAP-2.1", "MAP-2.2", "MAP-2.3", "MAP-3.1", "MAP-3.2", "MAP-3.3",
    "MAP-3.4", "MAP-3.5", "MAP-4.1", "MAP-4.2", "MAP-5.1", "MAP-5.2",
    "MEASURE-1.1", "MEASURE-1.2", "MEASURE-1.3", "MEASURE-2.1",
    "MEASURE-2.2", "MEASURE-2.3", "MEASURE-2.4", "MEASURE-2.5",
    "MEASURE-2.6", "MEASURE-2.7", "MEASURE-2.8", "MEASURE-2.9",
    "MEASURE-2.10", "MEASURE-2.11", "MEASURE-2.12", "MEASURE-2.13",
    "MEASURE-3.1", "MEASURE-3.2", "MEASURE-3.3", "MEASURE-4.1",
    "MEASURE-4.2", "MEASURE-4.3", "MANAGE-1.1", "MANAGE-1.2",
    "MANAGE-1.3", "MANAGE-1.4", "MANAGE-2.1", "MANAGE-2.2",
    "MANAGE-2.3", "MANAGE-2.4", "MANAGE-3.1", "MANAGE-3.2",
    "MANAGE-4.1", "MANAGE-4.2", "MANAGE-4.3",
}

EU_AI_ACT_CITATION_IDS = {
    "ART-4(1)",
    "ART-9(1)", "ART-9(2)", "ART-9(6)", "ART-9(8)",
    "ART-10(2)", "ART-11(1)", "ART-12(1)", "ART-13(1)",
    "ART-14(1)", "ART-14(4)",
    "ART-15(1)", "ART-15(4)", "ART-15(5)",
    "ART-17(1)", "ART-18(1)", "ART-19(1)", "ART-21(1)",
    "ART-26(1)", "ART-26(2)", "ART-26(4)", "ART-26(5)", "ART-26(6)",
    "ART-26(9)", "ART-27(1)",
    "ART-50(1)", "ART-50(2)", "ART-50(4)",
    "ART-72(1)", "ART-72(2)", "ART-73(1)", "ART-113-third(c)",
}


def _module(*, status: str = "supported_evidence") -> dict:
    evidence = [
        {
            "kind": "artifact_field",
            "baseline": "aegis_source",
            "path": "schemas/audit_artifact.schema.json",
            "locator": "/properties/checksum",
            "demonstrates": "The artifact records a content checksum.",
        },
        {
            "kind": "test",
            "baseline": "aegis_source",
            "path": "tests/test_audit_artifact_contract.py",
            "locator": "test_audit_artifact_schema_accepts_valid_artifact",
            "demonstrates": "A test validates the artifact contract.",
        },
    ]
    if status in {"external_control", "not_addressed"}:
        evidence = []
    mapping = {
        "aegis_evidence_status": status,
        "interpretation": "A bounded, non-authoritative interpretation.",
        "evidence": evidence,
        "host_controls": [
            {
                "owner": "adopter",
                "control": "The adopter evaluates applicability and sufficiency.",
            }
        ],
        "limitations": ["AEGIS does not determine control satisfaction."],
        "retention_assumptions": ["The host configures protected retention."],
    }
    if status == "partial_evidence":
        mapping["unsupported_portion"] = "Organizational effectiveness is outside AEGIS."
    if status == "external_control":
        mapping["external_owner"] = "adopter"
        mapping["external_control"] = "The adopter operates the organizational control."
    if status == "not_addressed":
        mapping["gap"] = "No AEGIS evidence contribution is identified."
        mapping["review_note"] = "Reassess when the AEGIS baseline changes."
    return {
        "schema_version": "1.0",
        "framework": {
            "id": "example-framework",
            "name": "Example Framework",
            "version": "1.0",
            "source_date": "2026-01-01",
            "authoritative_sources": [
                {
                    "source_id": "example-source",
                    "role": "control_source",
                    "title": "Example authoritative source",
                    "version": "1.0",
                    "publication_date": "2026-01-01",
                    "publication_id": "EXAMPLE-1",
                    "url": "https://example.invalid/source",
                    "accessed_on": "2026-08-01",
                }
            ],
        },
        "declared_scope": {
            "summary": "One identifier is included for contract testing.",
            "mapping_unit": "example identifier",
            "expected_mapping_count": 1,
            "exclusions": ["All other identifiers are excluded."],
        },
        "review": {
            "tier": "maintainer_verified",
            "decision": "approved",
            "contributor_github_ids": ["nealsolves"],
            "reviewer_github_ids": ["nealsolves"],
            "pr_url": "https://github.com/nealsolves/aegis/pull/100",
            "reviewed_commit_sha": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "reviewed_on": "2026-08-01",
            "next_review_due": "2027-01-28",
            "source_access_method": "public_authoritative_source",
        },
        "controls": [
            {
                "control_id": "EXAMPLE-1",
                "source_reference": {
                    "source_id": "example-source",
                    "locator": "Section 1",
                },
                "mapping": mapping,
            }
        ],
    }


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("key: one\nkey: two\n", "duplicate key"),
        ("first: &shared value\nsecond: *shared\n", "aliases and anchors"),
        ("value: !python/object value\n", "custom YAML tags"),
        ("base: &base\n  x: 1\nmerged:\n  <<: *base\n", "aliases and anchors"),
    ],
)
def test_strict_loader_rejects_yaml_features_that_obscure_catalog_data(
    tmp_path: Path, text: str, reason: str
):
    path = tmp_path / "catalog.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(CatalogInputError, match=reason):
        load_yaml(path)


def test_scope_validation_rejects_count_drift():
    module = _module()
    module["declared_scope"]["expected_mapping_count"] = 2

    findings = validate_framework_module(module, phase="scope", as_of=date(2026, 8, 10))

    assert [(item.code, item.location) for item in findings] == [
        ("SCOPE_COUNT_MISMATCH", "declared_scope.expected_mapping_count")
    ]


def test_mapping_validation_requires_pinned_source_and_executable_test_evidence():
    module = _module()
    module["controls"][0]["mapping"]["evidence"] = [
        {
            "kind": "documentation",
            "baseline": "catalog_asset",
            "path": "docs/reference/example.md",
            "locator": "#example",
            "demonstrates": "A catalog page describes the example.",
        }
    ]

    findings = validate_framework_module(module, phase="mapping", as_of=date(2026, 8, 10))

    assert {item.code for item in findings} == {
        "POSITIVE_SOURCE_EVIDENCE_REQUIRED",
        "EXECUTABLE_TEST_EVIDENCE_REQUIRED",
    }


@pytest.mark.parametrize("status", ["external_control", "not_addressed"])
def test_gap_statuses_reject_evidence(status: str):
    module = _module(status=status)
    module["controls"][0]["mapping"]["evidence"] = [
        {
            "kind": "test",
            "baseline": "aegis_source",
            "path": "tests/test_audit_artifact_contract.py",
            "locator": "test_audit_artifact_schema_accepts_valid_artifact",
            "demonstrates": "A test exists.",
        }
    ]

    findings = validate_framework_module(module, phase="mapping", as_of=date(2026, 8, 10))

    assert "GAP_STATUS_EVIDENCE_FORBIDDEN" in {item.code for item in findings}


def test_renderer_uses_exact_status_label_and_escapes_markdown_and_html():
    module = _module(status="partial_evidence")
    module["controls"][0]["mapping"]["interpretation"] = "Value | <script>unsafe</script>"
    manifest = {
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "disclaimer": "Non-authoritative evidence contribution; professional review is required.",
        "aegis_baseline": {
            "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "published_version": "0.9.0b1",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
        },
        "update_triggers": ["aegis_baseline_change"],
    }

    rendered = render_framework(manifest, module)

    assert "AEGIS evidence contribution: Partial evidence" in rendered
    assert "Value \\| &lt;script&gt;unsafe&lt;/script&gt;" in rendered
    assert "Unsupported portion:" in rendered
    assert "Organizational effectiveness is outside AEGIS." in rendered
    assert "Retention assumptions:" in rendered
    assert "The host configures protected retention." in rendered
    assert (
        "https://github.com/nealsolves/aegis/blob/"
        "a9d0e4967070a11474ab11b23b047a5cde4b0892/"
        "schemas/audit_artifact.schema.json" in rendered
    )
    assert "current source" in rendered
    assert "0.9.0b1" in rendered
    assert rendered == render_framework(manifest, module)


def test_closed_schema_rejects_unknown_public_prose_fields():
    module = _module()
    module["controls"][0]["mapping"]["marketing_claim"] = "AEGIS guarantees compliance."

    findings = validate_schema(
        module,
        Path(__file__).resolve().parents[1] / "schemas" / "compliance_mapping.schema.json",
    )

    assert any(
        item.code == "SCHEMA_VALIDATION_FAILURE"
        and "marketing_claim" in item.message
        for item in findings
    )


def test_scope_cli_accepts_inventory_before_mapping_review(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "schemas").mkdir(parents=True)
    schema_source = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json"
    )
    (root / "schemas" / "compliance_mapping.schema.json").write_text(
        schema_source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    module = _module()
    del module["controls"][0]["mapping"]
    del module["review"]
    module_path = root / "framework.yaml"
    import yaml

    module_path.write_text(yaml.safe_dump(module, sort_keys=False), encoding="utf-8")

    result = check_main(
        [
            "--root",
            str(root),
            "--module",
            "framework.yaml",
            "--phase",
            "scope",
            "--as-of",
            "2026-08-10",
        ]
    )

    assert result == 0


def test_repository_manifest_pins_current_source_and_human_review_policy():
    root = Path(__file__).resolve().parents[1]

    manifest = load_yaml(root / "compliance" / "catalog.yaml")

    assert manifest["catalog_version"] == "1.0.0"
    assert manifest["catalog_status"] == "current_source"
    assert manifest["aegis_baseline"] == {
        "git_commit": "c4f6add076f2c534ada089f90e5c52c38341783c",
        "distribution_name": "aegis-ai-governance",
        "published_version": "0.9.0b1",
        "mapped_channel": "current_source",
        "release_matrix": "docs/reference/RELEASE_MATRIX.md",
        "runtime_paths": [
            "aegis/**",
            "schemas/audit_artifact.schema.json",
            "schemas/workflow_artifact.schema.json",
            "policies/**",
            "pyproject.toml",
        ],
    }
    assert manifest["review_policy"] == {
        "default_interval_days": 180,
        "eu_ai_act_interval_days": 90,
    }
    assert manifest["framework_modules"] == [
        "compliance/frameworks/nist-ai-rmf-1.0.yaml",
        "compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml",
    ]


def test_scope_cli_does_not_require_a_completed_review_record(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "schemas").mkdir(parents=True)
    schema_source = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json"
    )
    (root / "schemas" / schema_source.name).write_text(
        schema_source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    module = _module()
    del module["controls"][0]["mapping"]
    del module["review"]
    import yaml

    (root / "framework.yaml").write_text(
        yaml.safe_dump(module, sort_keys=False), encoding="utf-8"
    )

    result = check_main(
        [
            "--root",
            str(root),
            "--module",
            "framework.yaml",
            "--phase",
            "scope",
            "--as-of",
            "2026-08-10",
        ]
    )

    assert result == 0


def test_claims_scan_covers_framework_names_labels_and_source_titles(tmp_path: Path):
    module = _module()
    module["framework"]["version"] = "AEGIS is certified"
    data = CatalogData(root=tmp_path, manifest={}, modules=(module,))

    findings = validate_claims(data)

    assert "CLAIMS_POLICY_FAILURE" in {item.code for item in findings}


def test_catalog_scripts_are_directly_invocable_from_repository_root():
    root = Path(__file__).resolve().parents[1]
    for script in (
        "scripts/check_compliance_catalog.py",
        "scripts/render_compliance_catalog.py",
    ):
        completed = subprocess.run(
            [sys.executable, script, "--help"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


def test_direct_checker_mapping_phase_loads_claims_adapter_without_package_crash():
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/check_compliance_catalog.py",
            "--module",
            "compliance/frameworks/nist-ai-rmf-1.0.yaml",
            "--phase",
            "mapping",
            "--as-of",
            "2026-08-12",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode in {0, 1}, completed.stderr
    assert "Traceback" not in completed.stderr
    assert "ModuleNotFoundError" not in completed.stderr


def test_renderer_rejects_framework_id_path_traversal(tmp_path: Path):
    import yaml

    root = tmp_path / "repo"
    (root / "compliance" / "frameworks").mkdir(parents=True)
    (root / "schemas").mkdir()
    schema_source = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json"
    )
    (root / "schemas" / schema_source.name).write_text(
        schema_source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    module = _module()
    module["framework"]["id"] = "../outside"
    module_paths = []
    for index in range(2):
        current = module if index == 0 else _module()
        if index:
            current["framework"]["id"] = f"example-{index}"
        relative = f"compliance/frameworks/module-{index}.yaml"
        module_paths.append(relative)
        (root / relative).write_text(
            yaml.safe_dump(current, sort_keys=False), encoding="utf-8"
        )
    manifest = {
        "schema_version": "1.0",
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "display_name": "Test catalog",
        "disclaimer": "Non-authoritative evidence contribution.",
        "aegis_baseline": {
            "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "distribution_name": "aegis-ai-governance",
            "published_version": "0.9.0b1",
            "mapped_channel": "current_source",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
            "runtime_paths": ["aegis/**"],
        },
        "framework_modules": module_paths,
        "review_policy": {
            "default_interval_days": 180,
            "eu_ai_act_interval_days": 90,
        },
        "update_triggers": ["aegis_baseline_change"],
    }
    (root / "compliance" / "catalog.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    output = root / "rendered"

    with pytest.raises(ValueError, match="framework id"):
        render_catalog(root, output)

    assert not (root / "outside.md").exists()


def test_publication_requires_completed_review_and_bounded_cadence():
    module = _module()
    module["review"]["tier"] = "unreviewed"
    module["review"]["decision"] = "pending"
    module["review"]["next_review_due"] = "2028-01-01"

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert {item.code for item in findings} >= {
        "COMPLETED_REVIEW_REQUIRED",
        "REVIEW_DECISION_REQUIRED",
        "REVIEW_CADENCE_EXCEEDED",
    }


def _tier_review(tier: str = "maintainer_verified") -> dict:
    return {
        "tier": tier,
        "decision": "approved",
        "contributor_github_ids": ["nealsolves"],
        "reviewer_github_ids": ["nealsolves"],
        "pr_url": "https://github.com/nealsolves/aegis/pull/100",
        "reviewed_commit_sha": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
        "reviewed_on": "2026-08-01",
        "next_review_due": "2027-01-28",
        "source_access_method": "public_authoritative_source",
    }


def test_publication_accepts_maintainer_verification_without_professional_review():
    module = _module()
    module["review"] = _tier_review()

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert findings == ()


def test_community_review_requires_a_distinct_reviewer_identity():
    module = _module()
    module["review"] = _tier_review("community_reviewed")

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "COMMUNITY_REVIEWER_NOT_DISTINCT" in {item.code for item in findings}


def test_qualified_review_requires_recorded_qualification_support():
    module = _module()
    module["review"] = _tier_review("qualified_reviewed")

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert {item.code for item in findings} >= {
        "QUALIFICATION_BASIS_REQUIRED",
        "QUALIFICATION_EVIDENCE_REQUIRED",
        "QUALIFICATION_VERIFICATION_REQUIRED",
        "QUALIFIED_REVIEW_SCOPE_REQUIRED",
    }


def test_independently_verified_qualification_names_its_verifier():
    module = _module()
    module["review"] = {
        **_tier_review("qualified_reviewed"),
        "qualification_basis": "Licensed attorney in the relevant jurisdiction.",
        "qualification_evidence_url": "https://example.invalid/credential",
        "qualification_verification": "independently_verified",
        "review_scope": "Identifier inventory and citation boundaries.",
    }

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "QUALIFICATION_VERIFIER_REQUIRED" in {item.code for item in findings}


def test_publication_rejects_a_review_completed_after_as_of():
    module = _module()
    module["review"]["reviewed_on"] = "2026-08-11"
    module["review"]["next_review_due"] = "2027-02-07"

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "REVIEW_DATE_IN_FUTURE" in {item.code for item in findings}


def test_publication_rejects_a_source_accessed_after_as_of():
    module = _module()
    module["framework"]["authoritative_sources"][0]["accessed_on"] = "2026-08-11"

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "SOURCE_ACCESS_DATE_IN_FUTURE" in {item.code for item in findings}


def test_completed_review_cannot_predate_its_latest_source_access():
    module = _module()
    module["framework"]["authoritative_sources"][0]["accessed_on"] = "2026-08-02"
    module["review"]["reviewed_on"] = "2026-08-01"

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "REVIEW_PRECEDES_SOURCE_ACCESS" in {item.code for item in findings}


def test_unreviewed_module_is_not_publishable():
    module = _module()
    module["review"] = {
        "tier": "unreviewed",
        "decision": "pending",
        "contributor_github_ids": [],
        "reviewer_github_ids": [],
        "source_access_method": "public_authoritative_source",
    }

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert "COMPLETED_REVIEW_REQUIRED" in {item.code for item in findings}


def test_eu_citation_rows_require_neutral_rationale_and_source_date():
    module = _module()
    module["framework"]["id"] = "eu-ai-act-2024-1689-amended-2026"
    module["review"] = _tier_review()

    findings = validate_framework_module(
        module,
        phase="mapping",
        as_of=date(2026, 8, 10),
    )

    assert {item.code for item in findings} >= {
        "EU_APPLICABILITY_STATEMENT_REQUIRED",
        "EU_EFFECTIVE_DATE_BASIS_REQUIRED",
        "EU_INCLUSION_RATIONALE_REQUIRED",
        "EU_SOURCE_DATE_REQUIRED",
    }


def test_renderer_derives_actual_review_tier_from_record():
    module = _module()
    module["review"] = _tier_review()
    manifest = {
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "disclaimer": "Non-authoritative evidence contribution.",
        "aegis_baseline": {
            "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "published_version": "0.9.0b1",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
        },
        "update_triggers": ["aegis_baseline_change"],
    }

    rendered = render_framework(manifest, module)

    assert "Review tier: `maintainer_verified`" in rendered
    assert "professional review" not in rendered.lower()


def test_renderer_displays_qualified_review_scope_and_evidence():
    module = _module()
    module["review"] = {
        **_tier_review("qualified_reviewed"),
        "qualification_basis": "Licensed attorney in the relevant jurisdiction.",
        "qualification_evidence_url": "https://example.invalid/credential",
        "qualification_verification": "independently_verified",
        "qualification_verified_by_github_id": "credential-checker",
        "review_scope": "Identifier inventory and citation boundaries.",
    }
    manifest = {
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "disclaimer": "Non-authoritative evidence contribution.",
        "aegis_baseline": {
            "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "published_version": "0.9.0b1",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
        },
        "update_triggers": ["aegis_baseline_change"],
    }

    rendered = render_framework(manifest, module)

    assert "Review scope: Identifier inventory and citation boundaries." in rendered
    assert "[qualification evidence](https://example.invalid/credential)" in rendered
    assert "Qualification verified by GitHub identity: `credential-checker`" in rendered


def test_closed_schema_forbids_an_overstated_public_review_label():
    module = _module()
    module["review"] = _tier_review()
    module["review"]["display_tier"] = "qualified_reviewed"

    findings = validate_schema(
        module,
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json",
    )

    assert "SCHEMA_VALIDATION_FAILURE" in {item.code for item in findings}


def test_manifest_schema_allows_an_explicit_two_module_subset():
    root = Path(__file__).resolve().parents[1]
    manifest = load_yaml(root / "compliance" / "catalog.yaml")
    manifest["framework_modules"] = [
        "compliance/frameworks/nist-ai-rmf-1.0.yaml",
        "compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml",
    ]

    assert validate_schema(
        manifest,
        root / "schemas" / "compliance_mapping.schema.json",
    ) == ()


def test_nist_module_has_the_complete_72_identifier_inventory_and_fixture_link():
    root = Path(__file__).resolve().parents[1]
    module = load_yaml(root / "compliance" / "frameworks" / "nist-ai-rmf-1.0.yaml")

    assert module["framework"]["version"] == "1.0"
    assert module["framework"]["source_date"] == "2023-01-26"
    assert {
        (source["publication_id"], source["url"])
        for source in module["framework"]["authoritative_sources"]
    } >= {
        ("NIST AI 100-1", "https://doi.org/10.6028/NIST.AI.100-1"),
        (
            "NIST AI RMF 1.0 Core, Tables 1-4",
            "https://airc.nist.gov/airmf-resources/airmf/5-sec-core/",
        ),
    }
    assert module["declared_scope"]["expected_mapping_count"] == 72
    assert {control["control_id"] for control in module["controls"]} == NIST_AI_RMF_CORE_IDS
    assert validate_schema(
        module,
        root / "schemas" / "compliance_mapping.schema.json",
    ) == ()
    assert validate_framework_module(
        module,
        phase="mapping",
        as_of=date(2026, 8, 12),
    ) == ()
    assert any(
        evidence["kind"] == "fixture"
        and evidence["path"] == "examples/compliance/regulated_workflow.py"
        for control in module["controls"]
        for evidence in control["mapping"]["evidence"]
    )


def test_nist_govern_4_2_does_not_overstate_lineage_as_risk_impact_evidence():
    root = Path(__file__).resolve().parents[1]
    module = load_yaml(root / "compliance" / "frameworks" / "nist-ai-rmf-1.0.yaml")
    row = next(control for control in module["controls"] if control["control_id"] == "GOVERN-4.2")

    assert row["mapping"]["aegis_evidence_status"] == "external_control"
    assert row["mapping"]["evidence"] == []
    assert "risks and potential impacts" in row["mapping"]["external_control"]


def test_eu_module_has_bounded_citation_scope_and_declines_applicability():
    root = Path(__file__).resolve().parents[1]
    module = load_yaml(
        root
        / "compliance"
        / "frameworks"
        / "eu-ai-act-2024-1689-amended-2026.yaml"
    )

    assert module["framework"]["source_date"] == "2026-07-24"
    assert {
        (source["publication_id"], source["url"])
        for source in module["framework"]["authoritative_sources"]
    } >= {
        (
            "CELEX:32024R1689",
            "https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng",
        ),
        (
            "CELEX:32026R1744",
            "https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng",
        ),
    }
    scope = module["declared_scope"]
    assert scope["expected_mapping_count"] == len(EU_AI_ACT_CITATION_IDS) == 32
    assert {control["control_id"] for control in module["controls"]} == EU_AI_ACT_CITATION_IDS
    assert scope["applicability_statement"] == (
        "This citation index does not determine whether any adopter, actor, "
        "system, or use case is within the scope of Regulation (EU) 2024/1689."
    )
    assert "2 December 2027" in scope["effective_date_basis"]
    assert "2 August 2028" in scope["effective_date_basis"]
    assert all(control["inclusion_rationale"] for control in module["controls"])
    assert {
        control["applicable_source_date"] for control in module["controls"]
    } == {"2026-07-24"}
    assert validate_schema(
        module,
        root / "schemas" / "compliance_mapping.schema.json",
    ) == ()
    assert validate_framework_module(
        module,
        phase="mapping",
        as_of=date(2026, 8, 12),
    ) == ()


def test_repository_generated_pages_match_the_two_active_modules():
    root = Path(__file__).resolve().parents[1]
    data = load_catalog(root)

    assert [module["framework"]["id"] for module in data.modules] == [
        "nist-ai-rmf-1.0",
        "eu-ai-act-2024-1689-amended-2026",
    ]
    for module in data.modules:
        framework_id = module["framework"]["id"]
        generated = (
            root / "docs" / "reference" / "compliance" / f"{framework_id}.md"
        )
        assert generated.read_text(encoding="utf-8") == render_framework(
            data.manifest,
            module,
        )


def test_publication_entrypoints_package_catalog_and_name_deferrals():
    root = Path(__file__).resolve().parents[1]
    command = 'python scripts/check_compliance_catalog.py --as-of "$(date -u +%F)"'

    for relative in (
        ".github/workflows/security-boundaries.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/deploy-demo-react.yml",
    ):
        assert command in (root / relative).read_text(encoding="utf-8")

    manifest = (root / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include compliance *.yaml" in manifest
    assert "recursive-include docs/reference/compliance *.md" in manifest

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "docs/reference/compliance/index.md" in readme
    runbook = (root / "docs" / "reference" / "OPERATIONS_RUNBOOK.md").read_text(
        encoding="utf-8"
    )
    assert command in runbook

    index = (
        root / "docs" / "reference" / "compliance" / "index.md"
    ).read_text(encoding="utf-8")
    assert "nist-ai-rmf-1.0.md" in index
    assert "eu-ai-act-2024-1689-amended-2026.md" in index
    assert "https://github.com/nealsolves/aegis/issues/76" in index
    assert "https://github.com/nealsolves/aegis/issues/77" in index
    assert "https://github.com/nealsolves/aegis/issues/78" in index


def test_baseline_git_failure_blocks_publication(tmp_path: Path):
    data = CatalogData(
        root=tmp_path,
        manifest={
            "aegis_baseline": {
                "git_commit": "a" * 40,
                "runtime_paths": ["aegis/**"],
            }
        },
        modules=(),
    )

    findings = baseline_drift(data)

    assert [item.code for item in findings] == ["BASELINE_GIT_FAILURE"]


def test_manifest_uses_the_same_closed_schema_as_framework_modules():
    root = Path(__file__).resolve().parents[1]
    manifest = load_yaml(root / "compliance" / "catalog.yaml")
    schema = root / "schemas" / "compliance_mapping.schema.json"

    assert validate_schema(manifest, schema) == ()
    manifest["unscanned_claim"] = "AEGIS is certified"

    findings = validate_schema(manifest, schema)
    assert {item.code for item in findings} == {"SCHEMA_VALIDATION_FAILURE"}


def test_mapping_cli_resolves_pinned_evidence_locators(tmp_path: Path):
    import yaml

    root = tmp_path / "repo"
    (root / "schemas").mkdir(parents=True)
    (root / "compliance").mkdir()
    schema_source = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json"
    )
    (root / "schemas" / schema_source.name).write_text(
        schema_source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (root / "artifact.json").write_text(
        '{"properties":{"checksum":{}}}', encoding="utf-8"
    )
    (root / "test_contract.py").write_text(
        "def test_contract():\n    pass\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest = {
        "schema_version": "1.0",
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "display_name": "Test catalog",
        "disclaimer": "Non-authoritative evidence contribution.",
        "aegis_baseline": {
            "git_commit": commit,
            "distribution_name": "aegis-ai-governance",
            "published_version": "0.9.0b1",
            "mapped_channel": "current_source",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
            "runtime_paths": ["artifact.json", "test_contract.py"],
        },
        "framework_modules": ["framework.yaml"],
        "review_policy": {"default_interval_days": 180, "eu_ai_act_interval_days": 90},
        "update_triggers": ["aegis_baseline_change"],
    }
    (root / "compliance" / "catalog.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    module = _module()
    module["controls"][0]["mapping"]["evidence"][0].update(
        path="artifact.json", locator="/properties/missing"
    )
    module["controls"][0]["mapping"]["evidence"][1].update(
        path="test_contract.py", locator="test_contract"
    )
    (root / "framework.yaml").write_text(
        yaml.safe_dump(module, sort_keys=False), encoding="utf-8"
    )

    result = check_main(
        [
            "--root",
            str(root),
            "--module",
            "framework.yaml",
            "--phase",
            "mapping",
            "--as-of",
            "2026-08-10",
        ]
    )

    assert result == 1


def test_catalog_asset_rejects_intent_to_add_index_entry(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / "asset.md"
    path.write_text("# Asset\n", encoding="utf-8")
    subprocess.run(["git", "add", "-N", "asset.md"], cwd=tmp_path, check=True)

    with pytest.raises(CatalogInputError, match="intent-to-add"):
        catalog_asset_text(tmp_path, "asset.md")


def test_manifest_is_validated_before_any_module_io(tmp_path: Path):
    import yaml

    (tmp_path / "compliance").mkdir()
    (tmp_path / "schemas").mkdir()
    schema_source = (
        Path(__file__).resolve().parents[1]
        / "schemas"
        / "compliance_mapping.schema.json"
    )
    (tmp_path / "schemas" / schema_source.name).write_text(
        schema_source.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "compliance" / "catalog.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "framework_modules": [f"missing-{index}.yaml" for index in range(100)],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CatalogInputError, match="manifest schema validation"):
        load_catalog(tmp_path)


def test_module_path_is_bound_to_expected_framework_id(tmp_path: Path):
    modules = tuple(_module() for _ in range(2))
    manifest = {
        "schema_version": "1.0",
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "framework_modules": [
            "compliance/frameworks/nist-ai-rmf-1.0.yaml",
            "compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml",
        ],
        "aegis_baseline": {
            "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
            "mapped_channel": "current_source",
        },
    }
    data = CatalogData(root=tmp_path, manifest=manifest, modules=modules)

    findings = _manifest_findings(data)

    assert "MODULE_FRAMEWORK_ID_MISMATCH" in {item.code for item in findings}


def test_reviewed_commit_must_contain_the_current_reviewable_module(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=tmp_path, check=True
    )
    (tmp_path / "README.md").write_text("historical commit\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-qm", "historical"],
        cwd=tmp_path,
        check=True,
    )
    historical_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    module = _module()
    module["review"]["reviewed_commit_sha"] = historical_commit

    findings = compliance_check.reviewed_module_findings(
        tmp_path,
        "compliance/frameworks/nist-ai-rmf-1.0.yaml",
        module,
    )

    assert [(item.code, item.location) for item in findings] == [
        (
            "REVIEWED_MODULE_CONTENT_MISMATCH",
            "compliance/frameworks/nist-ai-rmf-1.0.yaml.review.reviewed_commit_sha",
        )
    ]


def test_review_binding_allows_only_review_metadata_to_change(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=tmp_path, check=True
    )
    module_path = "compliance/frameworks/nist-ai-rmf-1.0.yaml"
    path = tmp_path / module_path
    path.parent.mkdir(parents=True)
    reviewed_module = _module()
    reviewed_module["review"] = {
        "tier": "unreviewed",
        "decision": "pending",
        "contributor_github_ids": [],
        "reviewer_github_ids": [],
        "source_access_method": "public_authoritative_source",
    }
    path.write_text(yaml.safe_dump(reviewed_module, sort_keys=False), encoding="utf-8")
    subprocess.run(["git", "add", module_path], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-qm", "reviewable snapshot"],
        cwd=tmp_path,
        check=True,
    )
    reviewed_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    published_module = _module()
    published_module["review"]["reviewed_commit_sha"] = reviewed_commit

    assert compliance_check.reviewed_module_findings(
        tmp_path, module_path, published_module
    ) == ()

    published_module["controls"][0]["mapping"]["interpretation"] = (
        "Mapping content changed after review."
    )
    findings = compliance_check.reviewed_module_findings(
        tmp_path, module_path, published_module
    )

    assert [item.code for item in findings] == ["REVIEWED_MODULE_CONTENT_MISMATCH"]


def test_reviewed_commit_must_be_an_ancestor_of_the_published_snapshot(
    tmp_path: Path,
):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=tmp_path, check=True
    )
    module_path = "compliance/frameworks/nist-ai-rmf-1.0.yaml"
    path = tmp_path / module_path
    subprocess.run(["git", "switch", "--orphan", "reviewed"], cwd=tmp_path, check=True)
    path.parent.mkdir(parents=True)
    reviewed_module = _module()
    reviewed_module["review"] = {
        "tier": "unreviewed",
        "decision": "pending",
        "contributor_github_ids": [],
        "reviewer_github_ids": [],
        "source_access_method": "public_authoritative_source",
    }
    path.write_text(yaml.safe_dump(reviewed_module, sort_keys=False), encoding="utf-8")
    subprocess.run(["git", "add", module_path], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-qm", "reviewed snapshot"],
        cwd=tmp_path,
        check=True,
    )
    reviewed_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "switch", "--orphan", "published"], cwd=tmp_path, check=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(reviewed_module, sort_keys=False), encoding="utf-8")
    subprocess.run(["git", "add", module_path], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-qm", "published snapshot"],
        cwd=tmp_path,
        check=True,
    )
    published_module = _module()
    published_module["review"]["reviewed_commit_sha"] = reviewed_commit

    findings = compliance_check.reviewed_module_findings(
        tmp_path, module_path, published_module
    )

    assert [item.code for item in findings] == ["REVIEW_COMMIT_NOT_ANCESTOR"]


def test_ignored_runtime_bytecode_is_baseline_drift(tmp_path: Path):
    (tmp_path / "aegis").mkdir()
    (tmp_path / "aegis" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--no-verify", "-qm", "baseline"],
        cwd=tmp_path,
        check=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    cache = tmp_path / "aegis" / "__pycache__"
    cache.mkdir()
    (cache / "module.pyc").write_bytes(b"ignored executable bytecode")
    data = CatalogData(
        root=tmp_path,
        manifest={
            "aegis_baseline": {
                "git_commit": commit,
                "runtime_paths": ["aegis/**"],
            }
        },
        modules=(),
    )

    findings = baseline_drift(data)

    assert [item.code for item in findings] == ["BASELINE_DRIFT"]
