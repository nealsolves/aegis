from __future__ import annotations

import subprocess
import sys
from html import unescape
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "architecture" / "diagrams"
DEMO_DIAGRAMS = ROOT / "demo-app-react" / "public" / "diagrams"
GENERATOR = DIAGRAMS / "render_v090_component_diagrams.py"

FONT_SIZES = {
    "box-title": 18,
    "box-title-compact": 15,
    "box-sub": 13,
    "box-sub-compact": 11,
    "body": 14,
    "body-plus": 15,
    "small": 12,
    "small-plus": 13,
}


def _estimated_text_width(text: str, font_size: int) -> float:
    units = 0.0
    for char in unescape(text):
        if char == " ":
            units += 0.32
        elif char in "il.,'|!":
            units += 0.28
        elif char in "MW@":
            units += 0.85
        else:
            units += 0.58
    return units * font_size


def _layout_failures(svg_path: Path) -> list[str]:
    root = ElementTree.parse(svg_path).getroot()
    active_box: tuple[str, float] | None = None
    failures: list[str] = []

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "rect":
            box_class = element.attrib.get("class", "")
            is_text_box = (
                box_class.startswith("node-")
                or box_class in {"host-box", "note-box"}
            )
            if is_text_box:
                active_box = (
                    f"{box_class}@({element.attrib.get('x')},{element.attrib.get('y')})",
                    float(element.attrib["width"]) - 24,
                )
            else:
                active_box = None
            continue
        if tag == "path":
            active_box = None
            continue
        if tag != "text" or active_box is None:
            continue

        classes = element.attrib.get("class", "").split()
        text_class = next((item for item in classes if item in FONT_SIZES), None)
        if text_class is None:
            continue
        text = "".join(element.itertext()).strip()
        estimated = _estimated_text_width(text, FONT_SIZES[text_class])
        box, usable_width = active_box
        if estimated > usable_width:
            failures.append(
                f"{svg_path.name}: {box}: {text!r} estimates to "
                f"{estimated:.1f}px > {usable_width:.1f}px"
            )
    return failures


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


def test_component_diagram_text_fits_its_layout_boxes():
    failures = []
    for name in (
        "aegis_architecture_component_light.svg",
        "aegis_architecture_component.svg",
    ):
        failures.extend(_layout_failures(DIAGRAMS / name))

    assert failures == []


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
