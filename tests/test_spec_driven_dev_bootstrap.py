"""Executable contract for the AEGIS spec-driven-dev bootstrap."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _yaml(relative_path: str) -> dict:
    return yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))


def test_project_control_plane_is_configured_for_aegis():
    project = _yaml(".claude/project.yaml")

    assert project["instruction_system"]["module_state"] == "complete"
    assert project["project"] == {
        "name": "AEGIS",
        "repository": "nealsolves/aegis",
        "lifecycle": "configured",
    }
    assert project["delivery"]["owner"] == "Neal Bhattacharya"
    assert project["remote_actions"]["enabled"] is False
    assert project["production_actions"]["enabled"] is False


def test_aegis_repository_guidance_is_preserved_and_always_routed():
    routing = _yaml(".claude/routing.yaml")

    assert "rules/aegis-project.md" in routing["always"]["rules"]
    guidance = (ROOT / ".claude/rules/aegis-project.md").read_text(encoding="utf-8")
    assert "AEGIS.open_session" in guidance
    assert "Pre-Push Code Review (Mandatory)" in guidance
    assert "origin/main" in guidance


def test_constitution_records_bootstrap_authority():
    constitution = (ROOT / ".specify/memory/constitution.md").read_text(
        encoding="utf-8"
    )

    assert "**Version:** 1.0.0" in constitution
    assert "**Ratified:** 2026-07-24" in constitution
    assert "**Owner:** Neal Bhattacharya" in constitution
    assert "BOOTSTRAP-2026-07-24-AEGIS-SDD" in constitution


def test_policy_engine_validates_instantiated_repository():
    result = subprocess.run(
        [
            sys.executable,
            "scripts/policy-engine.py",
            "validate",
            "--root",
            ".",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert '"valid": true' in result.stdout


def test_bootstrap_provenance_and_evidence_are_tracked():
    provenance = (
        ROOT / "docs/spec-driven-dev/BOOTSTRAP.md"
    ).read_text(encoding="utf-8")

    assert "f34bbcfc72a77e7cf24efe62001e2fd34eb5776c" in provenance
    assert "73f1bfc494dd5290a7e579069b3cad72e33457ed" in provenance
    assert "BOOTSTRAP-2026-07-24-AEGIS-SDD" in provenance


def test_bootstrap_has_a_hash_bound_authorized_policy_result():
    bootstrap_context = json.loads(
        (ROOT / "docs/spec-driven-dev/bootstrap-context.json").read_text(
            encoding="utf-8"
        )
    )
    expected_change_hash = bootstrap_context["change_hash"]
    result = json.loads(
        (ROOT / "docs/spec-driven-dev/bootstrap-response-result.json").read_text(
            encoding="utf-8"
        )
    )

    assert result["resolved_escalation"]["status"] == "resolved"
    assert result["response"]["decided_by"] == "Neal Bhattacharya"
    assert result["response"]["selected_option"] == "authorize_once"
    assert (
        result["decision"]["authority"]["outcome"]
        == "autonomous_with_enhanced_gates"
    )
    assert result["response"]["hashes"]["change_hash"] == expected_change_hash
    assert result["decision"]["hashes"]["change_hash"] == expected_change_hash
    assert result["decision"]["hashes"]["policy_hash"] == (
        "5d83cd5cc6626114dc06371750edc25b926cd278e19c45e2f3fdb6018c245f68"
    )
