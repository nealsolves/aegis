from __future__ import annotations

from datetime import date
from pathlib import Path
import subprocess
import sys

import pytest

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
            "reviewed_on": "2026-08-01",
            "next_review_due": "2027-01-28",
            "reviewer_roles": ["framework_scope", "evidence_mapping", "claims"],
            "scope_reviewed_in": "https://github.com/nealsolves/aegis/pull/100",
            "mapping_reviewed_in": "https://github.com/nealsolves/aegis/pull/100",
            "claims_reviewed_in": "https://github.com/nealsolves/aegis/pull/100",
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
    module["review"]["reviewer_roles"] = []
    module["review"]["scope_reviewed_in"] = ""
    module["review"]["mapping_reviewed_in"] = ""
    module["review"]["claims_reviewed_in"] = ""
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
        "git_commit": "a9d0e4967070a11474ab11b23b047a5cde4b0892",
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
        "compliance/frameworks/iso-iec-42001-2023.yaml",
        "compliance/frameworks/soc2-tsc-2017-revised-2022.yaml",
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
    for index in range(4):
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
        "disclaimer": "Professional review is required.",
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


def test_publication_requires_all_review_roles_and_bounded_cadence():
    module = _module()
    module["review"]["reviewer_roles"] = ["claims"]
    module["review"]["next_review_due"] = "2028-01-01"

    findings = validate_framework_module(
        module,
        phase="publication",
        as_of=date(2026, 8, 10),
        publication=True,
        review_interval_days=180,
    )

    assert {item.code for item in findings} >= {
        "REVIEW_ROLES_REQUIRED",
        "REVIEW_CADENCE_EXCEEDED",
    }


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
        "disclaimer": "Professional review is required.",
        "aegis_baseline": {
            "git_commit": commit,
            "distribution_name": "aegis-ai-governance",
            "published_version": "0.9.0b1",
            "mapped_channel": "current_source",
            "release_matrix": "docs/reference/RELEASE_MATRIX.md",
            "runtime_paths": ["artifact.json", "test_contract.py"],
        },
        "framework_modules": [
            "framework.yaml",
            "framework-2.yaml",
            "framework-3.yaml",
            "framework-4.yaml",
        ],
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
    modules = tuple(_module() for _ in range(4))
    manifest = {
        "schema_version": "1.0",
        "catalog_version": "1.0.0",
        "catalog_status": "current_source",
        "framework_modules": [
            "compliance/frameworks/nist-ai-rmf-1.0.yaml",
            "compliance/frameworks/iso-iec-42001-2023.yaml",
            "compliance/frameworks/soc2-tsc-2017-revised-2022.yaml",
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
