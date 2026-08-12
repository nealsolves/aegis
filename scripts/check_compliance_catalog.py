"""Fail-closed validation entry point for the evidence-oriented catalog."""

from __future__ import annotations

import argparse
from datetime import date
import importlib.util
from pathlib import Path
import subprocess
import sys
from typing import Iterable

if __package__:
    from scripts.compliance_catalog import (
        CatalogData,
        CatalogInputError,
        Finding,
        baseline_drift,
        git_blob,
        load_catalog,
        load_yaml,
        load_yaml_text,
        validate_claims,
        validate_evidence_references,
        validate_framework_module,
        validate_schema,
    )
    from scripts.render_compliance_catalog import render_framework
else:
    from compliance_catalog import (  # type: ignore
        CatalogData,
        CatalogInputError,
        Finding,
        baseline_drift,
        git_blob,
        load_catalog,
        load_yaml,
        load_yaml_text,
        validate_claims,
        validate_evidence_references,
        validate_framework_module,
        validate_schema,
    )
    from render_compliance_catalog import render_framework  # type: ignore


APPROVED_MODULES = (
    "compliance/frameworks/nist-ai-rmf-1.0.yaml",
    "compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml",
)
EXPECTED_FRAMEWORK_IDS = {
    "compliance/frameworks/nist-ai-rmf-1.0.yaml": "nist-ai-rmf-1.0",
    "compliance/frameworks/eu-ai-act-2024-1689-amended-2026.yaml": (
        "eu-ai-act-2024-1689-amended-2026"
    ),
}


def reviewable_module_content(module: dict) -> dict:
    """Return the module content whose exact snapshot receives review."""
    return {key: value for key, value in module.items() if key != "review"}


def reviewed_module_findings(
    root: Path,
    module_path: str,
    module: dict,
) -> tuple[Finding, ...]:
    """Bind a completed review to the exact non-review module content."""
    review = module.get("review")
    if not isinstance(review, dict) or review.get("tier") == "unreviewed":
        return ()
    reviewed_commit = review.get("reviewed_commit_sha")
    if not isinstance(reviewed_commit, str):
        return ()
    location = f"{module_path}.review.reviewed_commit_sha"
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", reviewed_commit, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if ancestry.returncode:
        return (
            Finding(
                "REVIEW_COMMIT_NOT_ANCESTOR",
                location,
                "reviewed commit must be an ancestor of the published snapshot",
            ),
        )
    try:
        reviewed_module = load_yaml_text(git_blob(root, reviewed_commit, module_path))
    except CatalogInputError:
        return (
            Finding(
                "REVIEWED_MODULE_CONTENT_MISMATCH",
                location,
                "reviewed commit does not contain the published module content",
            ),
        )
    if reviewable_module_content(reviewed_module) != reviewable_module_content(module):
        return (
            Finding(
                "REVIEWED_MODULE_CONTENT_MISMATCH",
                location,
                "reviewed commit does not contain the published module content",
            ),
        )
    return ()


def _parse_as_of(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--as-of must be YYYY-MM-DD") from exc


def _safe_module_path(root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise CatalogInputError("--module must be a repository-relative path")
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise CatalogInputError(f"module is missing or not a normal file: {value}")
    resolved_root = root.resolve()
    if resolved_root not in path.resolve().parents:
        raise CatalogInputError("module path escapes repository")
    return path


def _manifest_findings(data: CatalogData) -> list[Finding]:
    manifest = data.manifest
    findings: list[Finding] = []
    if manifest.get("schema_version") != "1.0":
        findings.append(Finding("MANIFEST_INVALID", "schema_version", "schema_version must be 1.0"))
    if manifest.get("catalog_version") != "1.0.0":
        findings.append(
            Finding(
                "MANIFEST_INVALID",
                "catalog_version",
                "initial catalog_version must be 1.0.0",
            )
        )
    if manifest.get("catalog_status") != "current_source":
        findings.append(
            Finding(
                "MANIFEST_INVALID",
                "catalog_status",
                "catalog_status must be current_source",
            )
        )
    listed = manifest.get("framework_modules")
    if not isinstance(listed, list) or tuple(listed) != APPROVED_MODULES:
        findings.append(
            Finding(
                "MODULE_INVENTORY_MISMATCH",
                "framework_modules",
                "publication requires the two active public-source modules in fixed order",
            )
        )
    expected_files = {Path(item).name for item in APPROVED_MODULES}
    framework_dir = data.root / "compliance" / "frameworks"
    actual_files = (
        {item.name for item in framework_dir.glob("*.yaml") if item.is_file()}
        if framework_dir.is_dir()
        else set()
    )
    extras = sorted(actual_files - expected_files)
    if extras:
        findings.append(
            Finding(
                "UNLISTED_FRAMEWORK_MODULE",
                "compliance/frameworks",
                "unlisted modules: " + ", ".join(extras),
            )
        )
    baseline = manifest.get("aegis_baseline")
    if not isinstance(baseline, dict):
        findings.append(
            Finding(
                "MANIFEST_INVALID",
                "aegis_baseline",
                "aegis_baseline must be an object",
            )
        )
    else:
        if baseline.get("git_commit") != "c4f6add076f2c534ada089f90e5c52c38341783c":
            findings.append(
                Finding(
                    "MANIFEST_INVALID",
                    "aegis_baseline.git_commit",
                    "unexpected initial source baseline",
                )
            )
        if baseline.get("mapped_channel") != "current_source":
            findings.append(
                Finding(
                    "MANIFEST_INVALID",
                    "aegis_baseline.mapped_channel",
                    "mapped channel must be current_source",
                )
            )
    framework_ids = [module.get("framework", {}).get("id") for module in data.modules]
    if len(framework_ids) != len(set(framework_ids)):
        findings.append(
            Finding(
                "DUPLICATE_FRAMEWORK_ID",
                "framework_modules",
                "framework ids must be unique",
            )
        )
    for path, module in zip(tuple(manifest.get("framework_modules", ())), data.modules):
        actual_id = module.get("framework", {}).get("id")
        expected_id = EXPECTED_FRAMEWORK_IDS.get(path)
        if actual_id != expected_id:
            findings.append(
                Finding(
                    "MODULE_FRAMEWORK_ID_MISMATCH",
                    path,
                    f"expected framework id {expected_id}, found {actual_id}",
                )
            )
        review = module.get("review")
        if not isinstance(review, dict) or review.get("tier") == "unreviewed":
            continue
        reviewed_commit = review.get("reviewed_commit_sha")
        if not isinstance(reviewed_commit, str):
            continue
        completed = subprocess.run(
            ["git", "cat-file", "-e", f"{reviewed_commit}^{{commit}}"],
            cwd=data.root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode:
            findings.append(
                Finding(
                    "REVIEW_COMMIT_NOT_FOUND",
                    f"{path}.review.reviewed_commit_sha",
                    "reviewed commit does not exist in the local Git object database",
                )
            )
            continue
        findings.extend(reviewed_module_findings(data.root, path, module))
    return findings


def _generated_findings(data: CatalogData) -> list[Finding]:
    findings: list[Finding] = []
    output_dir = data.root / "docs" / "reference" / "compliance"
    for module in data.modules:
        framework_id = module.get("framework", {}).get("id")
        if not isinstance(framework_id, str):
            continue
        path = output_dir / f"{framework_id}.md"
        expected = render_framework(data.manifest, module)
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            actual = ""
        if actual != expected:
            findings.append(
                Finding(
                    "GENERATED_OUTPUT_DRIFT",
                    path.relative_to(data.root).as_posix(),
                    "generated framework page is missing or stale",
                )
            )
    return findings


def _fixture_findings(data: CatalogData) -> list[Finding]:
    fixture_path = data.root / "examples" / "compliance" / "regulated_workflow.py"
    try:
        spec = importlib.util.spec_from_file_location(
            "_aegis_compliance_fixture_validation",
            fixture_path,
        )
        if spec is None or spec.loader is None:
            raise ImportError("fixture module spec is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        verify_fixture_contract = module.verify_fixture_contract
    except (ImportError, OSError, AttributeError):
        return [
            Finding(
                "FIXTURE_CONTRACT_FAILURE",
                "examples/compliance/regulated_workflow.py",
                "regulated fixture contract is unavailable",
            )
        ]
    try:
        verify_fixture_contract(root=data.root)
    except Exception as exc:  # the gate must convert fixture failures to bounded diagnostics
        return [
            Finding(
                "FIXTURE_CONTRACT_FAILURE",
                "examples/compliance/regulated_workflow.py",
                str(exc)[:500],
            )
        ]
    return []


def validate_publication(root: Path, as_of: date) -> tuple[Finding, ...]:
    data = load_catalog(root)
    schema_path = root / "schemas" / "compliance_mapping.schema.json"
    findings: list[Finding] = list(validate_schema(data.manifest, schema_path))
    findings.extend(_manifest_findings(data))
    for module in data.modules:
        framework_id = module.get("framework", {}).get("id")
        review_policy = data.manifest.get("review_policy", {})
        interval = (
            review_policy.get("eu_ai_act_interval_days")
            if framework_id == "eu-ai-act-2024-1689-amended-2026"
            else review_policy.get("default_interval_days")
        )
        findings.extend(validate_schema(module, schema_path))
        findings.extend(
            validate_framework_module(
                module,
                phase="publication",
                as_of=as_of,
                publication=True,
                review_interval_days=interval,
            )
        )
    findings.extend(validate_evidence_references(data))
    findings.extend(validate_claims(data))
    drift = baseline_drift(data)
    findings.extend(drift)
    findings.extend(_generated_findings(data))
    if not drift:
        findings.extend(_fixture_findings(data))
    return tuple(sorted(set(findings)))[:1000]


def _print_findings(findings: Iterable[Finding]) -> None:
    for finding in findings:
        print(f"{finding.code}: {finding.location}: {finding.message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--module")
    parser.add_argument("--phase", choices=("scope", "mapping"), default="mapping")
    parser.add_argument("--as-of", type=_parse_as_of, required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.module:
            module_path = _safe_module_path(root, args.module)
            module = load_yaml(module_path)
            schema_path = root / "schemas" / "compliance_mapping.schema.json"
            findings = list(validate_schema(module, schema_path))
            findings.extend(
                validate_framework_module(
                    module,
                    phase=args.phase,
                    as_of=args.as_of,
                )
            )
            if args.phase == "mapping":
                manifest = load_yaml(root / "compliance" / "catalog.yaml")
                findings.extend(validate_schema(manifest, schema_path))
                focused = CatalogData(
                    root=root,
                    manifest=manifest,
                    modules=(module,),
                )
                findings.extend(validate_evidence_references(focused))
                findings.extend(validate_claims(focused))
        else:
            findings = list(validate_publication(root, args.as_of))
    except (CatalogInputError, OSError, ValueError) as exc:
        print(f"CATALOG_INPUT_FAILURE: {str(exc)[:1000]}", file=sys.stderr)
        return 2
    if findings:
        _print_findings(findings)
        return 1
    print("Compliance catalog validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
