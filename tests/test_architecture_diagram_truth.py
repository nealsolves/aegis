from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "architecture" / "diagrams"
DEMO_DIAGRAMS = ROOT / "demo-app-react" / "public" / "diagrams"
GENERATOR = DIAGRAMS / "render_v090_component_diagrams.py"


def test_beta_component_diagram_contains_only_current_candidate_surfaces():
    beta_svg = (DIAGRAMS / "aegis_architecture_component.svg").read_text(
        encoding="utf-8"
    )

    for anchor in (
        "Bedrock adapter",
        "A2A adapter",
        "OpenAI Agents adapter",
        "workflow trace",
        "workflow export",
    ):
        assert anchor in beta_svg
    for planned in ("AgentIdentity", "AgentCapabilityManifest", "ValidatorHook"):
        assert planned not in beta_svg


def test_docs_and_react_diagram_mirrors_are_byte_identical():
    for name in (
        "aegis_architecture_component.svg",
        "aegis_architecture_component_light.svg",
        "aegis_architecture_pipeline.svg",
        "aegis_architecture_pipeline_light.svg",
    ):
        assert (DIAGRAMS / name).read_bytes() == (DEMO_DIAGRAMS / name).read_bytes()


def test_generator_check_passes_without_creating_legacy_aigc_outputs():
    before = set(ROOT.rglob("aigc_*.svg"))
    try:
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert set(ROOT.rglob("aigc_*.svg")) == before
    finally:
        for path in set(ROOT.rglob("aigc_*.svg")) - before:
            path.unlink()


def test_generator_check_fails_when_a_canonical_output_is_stale():
    target = DIAGRAMS / "aegis_architecture_component.svg"
    original = target.read_text(encoding="utf-8")
    before = set(ROOT.rglob("aigc_*.svg"))
    try:
        target.write_text(original + "<!-- stale -->\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "aegis_architecture_component.svg" in result.stdout
    finally:
        target.write_text(original, encoding="utf-8")
        for path in set(ROOT.rglob("aigc_*.svg")) - before:
            path.unlink()

