from __future__ import annotations

import subprocess
import sys
import re
from dataclasses import dataclass
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

GEOMETRY_DIAGRAMS = (
    "aegis_v090_beta_component_light.svg",
    "aegis_v090_full_component_light.svg",
    "aegis_architecture_pipeline_light.svg",
)
PATH_TOKEN = re.compile(r"[MLHV]|-?(?:\d+(?:\.\d*)?|\.\d+)")


@dataclass(frozen=True)
class Bounds:
    left: float
    top: float
    right: float
    bottom: float


@dataclass(frozen=True)
class Segment:
    start: tuple[float, float]
    end: tuple[float, float]


def _bounds(element: ElementTree.Element) -> Bounds:
    left = float(element.attrib["x"])
    top = float(element.attrib["y"])
    return Bounds(
        left=left,
        top=top,
        right=left + float(element.attrib["width"]),
        bottom=top + float(element.attrib["height"]),
    )


def _connector_segments(path_data: str) -> list[Segment]:
    tokens = PATH_TOKEN.findall(path_data.replace(",", " "))
    segments: list[Segment] = []
    current: tuple[float, float] | None = None
    index = 0

    while index < len(tokens):
        command = tokens[index]
        index += 1
        if command not in {"M", "L", "H", "V"}:
            raise AssertionError(f"unsupported or implicit SVG path command in {path_data!r}")
        if command in {"M", "L"}:
            if index + 1 >= len(tokens):
                raise AssertionError(f"incomplete {command} command in {path_data!r}")
            target = (float(tokens[index]), float(tokens[index + 1]))
            index += 2
        elif command == "H":
            if current is None or index >= len(tokens):
                raise AssertionError(f"invalid H command in {path_data!r}")
            target = (float(tokens[index]), current[1])
            index += 1
        else:
            if current is None or index >= len(tokens):
                raise AssertionError(f"invalid V command in {path_data!r}")
            target = (current[0], float(tokens[index]))
            index += 1

        if current is not None:
            if current[0] != target[0] and current[1] != target[1]:
                raise AssertionError(f"diagonal connector segment in {path_data!r}")
            if current != target:
                segments.append(Segment(current, target))
        current = target

    if not segments:
        raise AssertionError(f"connector has no segments: {path_data!r}")
    return segments


def _crosses_interior(segment: Segment, bounds: Bounds) -> bool:
    (x1, y1), (x2, y2) = segment.start, segment.end
    if y1 == y2:
        segment_left, segment_right = sorted((x1, x2))
        return (
            bounds.top < y1 < bounds.bottom
            and max(segment_left, bounds.left) < min(segment_right, bounds.right)
        )
    if x1 == x2:
        segment_top, segment_bottom = sorted((y1, y2))
        return (
            bounds.left < x1 < bounds.right
            and max(segment_top, bounds.top) < min(segment_bottom, bounds.bottom)
        )
    raise AssertionError(f"non-orthogonal segment: {segment!r}")


def _overlaps(first: Bounds, second: Bounds) -> bool:
    return (
        max(first.left, second.left) < min(first.right, second.right)
        and max(first.top, second.top) < min(first.bottom, second.bottom)
    )


def _touches_boundary_port(
    point: tuple[float, float],
    bounds: Bounds,
    port: str,
) -> bool:
    x, y = point
    if port == "top":
        return y == bounds.top and bounds.left <= x <= bounds.right
    if port == "right":
        return x == bounds.right and bounds.top <= y <= bounds.bottom
    if port == "bottom":
        return y == bounds.bottom and bounds.left <= x <= bounds.right
    if port == "left":
        return x == bounds.left and bounds.top <= y <= bounds.bottom
    return False


def _segments_intersect(first: Segment, second: Segment) -> bool:
    (ax1, ay1), (ax2, ay2) = first.start, first.end
    (bx1, by1), (bx2, by2) = second.start, second.end
    a_horizontal = ay1 == ay2
    b_horizontal = by1 == by2

    if a_horizontal and b_horizontal:
        if ay1 != by1:
            return False
        a_left, a_right = sorted((ax1, ax2))
        b_left, b_right = sorted((bx1, bx2))
        return max(a_left, b_left) <= min(a_right, b_right)
    if not a_horizontal and not b_horizontal:
        if ax1 != bx1:
            return False
        a_top, a_bottom = sorted((ay1, ay2))
        b_top, b_bottom = sorted((by1, by2))
        return max(a_top, b_top) <= min(a_bottom, b_bottom)

    horizontal, vertical = (first, second) if a_horizontal else (second, first)
    (hx1, hy), (hx2, _) = horizontal.start, horizontal.end
    (vx, vy1), (_, vy2) = vertical.start, vertical.end
    return (
        min(hx1, hx2) <= vx <= max(hx1, hx2)
        and min(vy1, vy2) <= hy <= max(vy1, vy2)
    )


def _geometry_failures(svg_path: Path) -> list[str]:
    root = ElementTree.parse(svg_path).getroot()
    nodes = {
        element.attrib["data-node-id"]: _bounds(element)
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == "rect"
        and "data-node-id" in element.attrib
    }
    labels = {
        element.attrib["data-connector-label"]: _bounds(element)
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == "rect"
        and "data-connector-label" in element.attrib
    }
    connectors = [
        element
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == "path"
        and element.attrib.get("class", "").startswith("connector")
    ]
    failures: list[str] = []

    if not nodes:
        failures.append(f"{svg_path.name}: no data-node-id rectangles")
    if len(labels) != len(connectors):
        failures.append(
            f"{svg_path.name}: expected one opaque label rectangle per connector "
            f"({len(connectors)} connectors, {len(labels)} labels)"
        )

    connector_segments: dict[str, list[Segment]] = {}
    for connector in connectors:
        connector_id = connector.attrib.get("data-connector-id")
        source = connector.attrib.get("data-from")
        destination = connector.attrib.get("data-to")
        source_port = connector.attrib.get("data-from-port")
        destination_port = connector.attrib.get("data-to-port")
        if (
            not connector_id
            or not source
            or not destination
            or not source_port
            or not destination_port
        ):
            failures.append(f"{svg_path.name}: connector missing routing metadata")
            continue
        if source not in nodes or destination not in nodes:
            failures.append(
                f"{svg_path.name}: {connector_id} names unknown endpoint "
                f"{source!r}->{destination!r}"
            )
            continue
        if connector_id not in labels:
            failures.append(f"{svg_path.name}: {connector_id} has no label rectangle")
        segments = _connector_segments(connector.attrib["d"])
        connector_segments[connector_id] = segments
        if not _touches_boundary_port(
            segments[0].start,
            nodes[source],
            source_port,
        ):
            failures.append(
                f"{svg_path.name}: {connector_id} endpoint "
                f"{segments[0].start} does not touch source {source} "
                f"{source_port} port"
            )
        if not _touches_boundary_port(
            segments[-1].end,
            nodes[destination],
            destination_port,
        ):
            failures.append(
                f"{svg_path.name}: {connector_id} endpoint "
                f"{segments[-1].end} does not touch destination {destination} "
                f"{destination_port} port"
            )
        for segment in segments:
            for node_id, node_bounds in nodes.items():
                if _crosses_interior(segment, node_bounds):
                    failures.append(
                        f"{svg_path.name}: {connector_id} crosses node {node_id}: "
                        f"{segment}"
                    )
            for label_id, label_bounds in labels.items():
                if _crosses_interior(segment, label_bounds):
                    failures.append(
                        f"{svg_path.name}: {connector_id} crosses label {label_id}: "
                        f"{segment}"
                    )

    for label_id, label_bounds in labels.items():
        for node_id, node_bounds in nodes.items():
            if _overlaps(label_bounds, node_bounds):
                failures.append(
                    f"{svg_path.name}: label {label_id} overlaps node {node_id}"
                )

    connector_items = list(connector_segments.items())
    for index, (first_id, first_segments) in enumerate(connector_items):
        for second_id, second_segments in connector_items[index + 1:]:
            for first_segment in first_segments:
                for second_segment in second_segments:
                    if _segments_intersect(first_segment, second_segment):
                        failures.append(
                            f"{svg_path.name}: connectors {first_id} and {second_id} "
                            f"intersect: {first_segment} / {second_segment}"
                        )
    return failures


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


def test_connector_path_parser_derives_axis_aligned_segments():
    assert _connector_segments("M 0 0 H 10 V 20 L 30 20") == [
        Segment((0.0, 0.0), (10.0, 0.0)),
        Segment((10.0, 0.0), (10.0, 20.0)),
        Segment((10.0, 20.0), (30.0, 20.0)),
    ]


def test_generated_diagram_routes_are_numerically_collision_free():
    failures = []
    for name in GEOMETRY_DIAGRAMS:
        failures.extend(_geometry_failures(DIAGRAMS / name))

    assert failures == []


def test_generated_connectors_declare_source_and_destination_boundary_ports():
    missing_ports = []
    for name in GEOMETRY_DIAGRAMS:
        root = ElementTree.parse(DIAGRAMS / name).getroot()
        for element in root.iter():
            if (
                element.tag.rsplit("}", 1)[-1] == "path"
                and element.attrib.get("class", "").startswith("connector")
            ):
                if not element.attrib.get("data-from-port"):
                    missing_ports.append(
                        f"{name}: {element.attrib.get('data-connector-id')} source"
                    )
                if not element.attrib.get("data-to-port"):
                    missing_ports.append(
                        f"{name}: {element.attrib.get('data-connector-id')} destination"
                    )

    assert missing_ports == []


def test_geometry_validator_rejects_floating_and_wrong_port_endpoints(tmp_path):
    cases = (
        ("floating", "right", "M 11 5 L 30 5", "source source right port"),
        ("wrong-port", "top", "M 10 5 L 30 5", "source source top port"),
    )

    for case_name, source_port, path_data, expected in cases:
        svg_path = tmp_path / f"{case_name}.svg"
        svg_path.write_text(
            (
                '<svg xmlns="http://www.w3.org/2000/svg">'
                '<rect x="0" y="0" width="10" height="10" data-node-id="source" />'
                '<rect x="30" y="0" width="10" height="10" data-node-id="destination" />'
                '<rect x="0" y="20" width="10" height="4" '
                'data-connector-label="route" />'
                f'<path class="connector" d="{path_data}" '
                'data-connector-id="route" data-from="source" '
                f'data-to="destination" data-from-port="{source_port}" '
                'data-to-port="left" />'
                "</svg>"
            ),
            encoding="utf-8",
        )

        failures = _geometry_failures(svg_path)

        assert any(expected in failure for failure in failures), failures


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
