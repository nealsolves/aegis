"""Deterministically render compliance catalog YAML as escaped Markdown."""

from __future__ import annotations

import argparse
import html
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import quote

if __package__:
    from scripts.compliance_catalog import load_catalog
else:
    from compliance_catalog import load_catalog  # type: ignore


STATUS_LABELS = {
    "supported_evidence": "Supported evidence",
    "partial_evidence": "Partial evidence",
    "external_control": "External control",
    "not_addressed": "Not addressed",
}
FRAMEWORK_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[0-9]+)?\Z")


def _escape(value: object) -> str:
    text = html.escape(str(value), quote=True)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " <br> ")
    text = text.replace("\\", "\\\\")
    return re.sub(r"([|\[\]()`#*+!])", r"\\\1", text)


def _safe_url(value: object) -> str:
    text = str(value)
    if not re.fullmatch(r"https://[^\s<>]+", text):
        raise ValueError("only validated HTTPS source URLs may be rendered")
    return text.replace("(", "%28").replace(")", "%29")


def _evidence_url(manifest: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    path = quote(str(evidence["path"]), safe="/")
    if evidence["baseline"] == "aegis_source":
        commit = manifest["aegis_baseline"]["git_commit"]
        return f"https://github.com/nealsolves/aegis/blob/{commit}/{path}"
    return f"../../../{path}"


def render_framework(manifest: Mapping[str, Any], module: Mapping[str, Any]) -> str:
    framework = module["framework"]
    scope = module["declared_scope"]
    review = module["review"]
    baseline = manifest["aegis_baseline"]
    lines = [
        f"# {_escape(framework['name'])}",
        "",
        f"> {_escape(manifest['disclaimer'])}",
        "",
        "## Catalog and source baseline",
        "",
        f"- Catalog version: `{_escape(manifest['catalog_version'])}`",
        (
            f"- Framework version: `{_escape(framework['version'])}` "
            f"({_escape(framework['source_date'])})"
        ),
        (
            f"- AEGIS baseline: [`{_escape(baseline['git_commit'])}`]"
            f"(https://github.com/nealsolves/aegis/tree/"
            f"{_escape(baseline['git_commit'])})"
        ),
        (
            "- Availability: mapped to current source, not the published "
            f"`{_escape(baseline['published_version'])}` wheel; see "
            f"[{_escape(baseline['release_matrix'])}](../RELEASE_MATRIX.md)."
        ),
        f"- Review tier: `{_escape(review.get('tier', 'unreviewed'))}`",
        f"- Review decision: `{_escape(review.get('decision', 'pending'))}`",
        (
            f"- Reviewed: `{_escape(review.get('reviewed_on', 'not completed'))}`; "
            "next review due: "
            f"`{_escape(review.get('next_review_due', 'not scheduled'))}`"
        ),
        "",
        "## Declared scope",
        "",
        _escape(scope["summary"]),
        "",
        f"Mapping unit: {_escape(scope['mapping_unit'])}.",
        "",
        f"Expected mapping count: `{_escape(scope['expected_mapping_count'])}`.",
        "",
        "Exclusions:",
        "",
        *[f"- {_escape(item)}" for item in scope["exclusions"]],
        "",
    ]
    if scope.get("applicability_statement"):
        lines.extend(
            [
                "Applicability boundary:",
                "",
                _escape(scope["applicability_statement"]),
                "",
            ]
        )
    if scope.get("effective_date_basis"):
        lines.extend(
            [
                "Effective-date basis:",
                "",
                _escape(scope["effective_date_basis"]),
                "",
            ]
        )
    lines.extend(["## Authoritative sources", ""])
    for source in sorted(
        framework["authoritative_sources"], key=lambda item: item["source_id"]
    ):
        lines.append(
            f"- [{_escape(source['title'])}]({_safe_url(source['url'])}) — "
            f"`{_escape(source['publication_id'])}`, version {_escape(source['version'])}, "
            f"published {_escape(source['publication_date'])}, accessed "
            f"{_escape(source['accessed_on'])}."
        )
    lines.extend(["", "## Review record", ""])
    contributors = review.get("contributor_github_ids", [])
    reviewers = review.get("reviewer_github_ids", [])
    lines.extend(
        [
            "- Contributor GitHub identities: "
            + (", ".join(f"`{_escape(item)}`" for item in contributors) or "none recorded"),
            "- Reviewer GitHub identities: "
            + (", ".join(f"`{_escape(item)}`" for item in reviewers) or "none recorded"),
            f"- Pull request: {_escape(review.get('pr_url', 'not recorded'))}",
            (
                "- Reviewed commit: `"
                f"{_escape(review.get('reviewed_commit_sha', 'not recorded'))}`"
            ),
            (
                "- Qualification basis: "
                f"{_escape(review.get('qualification_basis', 'not claimed'))}"
            ),
            (
                "- Qualification verification: `"
                f"{_escape(review.get('qualification_verification', 'not applicable'))}`"
            ),
            "",
            (
                "Local CI checks record consistency only; it does not authenticate "
                "identity, credentials, legal correctness, or professional competence."
            ),
            "",
            "## Evidence mappings",
            "",
        ]
    )
    for control in sorted(module["controls"], key=lambda item: item["control_id"]):
        mapping = control["mapping"]
        status = STATUS_LABELS[mapping["aegis_evidence_status"]]
        lines.extend(
            [
                f"### {_escape(control['control_id'])}",
                "",
                f"Source locator: `{_escape(control['source_reference']['locator'])}`",
                "",
                *(
                    [
                        f"Inclusion rationale: {_escape(control['inclusion_rationale'])}",
                        "",
                    ]
                    if control.get("inclusion_rationale")
                    else []
                ),
                *(
                    [
                        f"Applicable source date: `{_escape(control['applicable_source_date'])}`",
                        "",
                    ]
                    if control.get("applicable_source_date")
                    else []
                ),
                f"AEGIS evidence contribution: {status}",
                "",
                _escape(mapping["interpretation"]),
                "",
                "Evidence references:",
                "",
            ]
        )
        evidence = mapping["evidence"]
        if evidence:
            for item in evidence:
                lines.append(
                    f"- {_escape(item['kind'])} — "
                    f"[{_escape(item['path'])}]({_evidence_url(manifest, item)}) "
                    f"({_escape(item['baseline'])}; locator: "
                    f"{_escape(item['locator'])}): {_escape(item['demonstrates'])}"
                )
                if item.get("invocation"):
                    lines.append(
                        f"  - Maintained invocation: {_escape(item['invocation'])}"
                    )
        else:
            lines.append("- None identified for this catalog row.")
        status_fields = (
            ("Unsupported portion", "unsupported_portion"),
            ("External owner", "external_owner"),
            ("External control", "external_control"),
            ("Gap", "gap"),
            ("Review note", "review_note"),
        )
        for label, field in status_fields:
            if mapping.get(field):
                lines.extend(["", f"{label}: {_escape(mapping[field])}"])
        lines.extend(["", "Host controls:", ""])
        for item in mapping["host_controls"]:
            if isinstance(item, dict):
                lines.append(f"- {_escape(item['owner'])}: {_escape(item['control'])}")
            else:
                lines.append(f"- {_escape(item)}")
        lines.extend(["", "Limitations:", ""])
        lines.extend(f"- {_escape(item)}" for item in mapping["limitations"])
        lines.extend(["", "Retention assumptions:", ""])
        lines.extend(
            f"- {_escape(item)}" for item in mapping["retention_assumptions"]
        )
        lines.append("")
    lines.extend(["## Update triggers", ""])
    lines.extend(f"- `{_escape(item)}`" for item in manifest["update_triggers"])
    return "\n".join(lines).rstrip() + "\n"


def render_catalog(root: Path, output_dir: Path) -> dict[Path, str]:
    data = load_catalog(root)
    rendered: dict[Path, str] = {}
    output_dir.mkdir(parents=True, exist_ok=True)
    for module in data.modules:
        framework_id = module.get("framework", {}).get("id")
        if not isinstance(framework_id, str) or not FRAMEWORK_ID.fullmatch(
            framework_id
        ):
            raise ValueError("framework id must be a filename-safe slug")
        relative = Path(f"{framework_id}.md")
        destination = (output_dir / relative).resolve()
        if destination.parent != output_dir.resolve():
            raise ValueError("framework id escapes the output directory")
        content = render_framework(data.manifest, module)
        destination.write_text(content, encoding="utf-8", newline="\n")
        rendered[relative] = content
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    output = args.output_dir or args.root / "docs" / "reference" / "compliance"
    render_catalog(args.root, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
