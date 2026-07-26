from __future__ import annotations

import argparse
from dataclasses import dataclass
from html import escape
from pathlib import Path
from textwrap import dedent


SVG_NS = "http://www.w3.org/2000/svg"
WIDTH = 1600


@dataclass(frozen=True)
class Theme:
    name: str
    background: str
    page_border: str
    title: str
    subtitle: str
    section: str
    text: str
    subtext: str
    note: str
    small: str
    neutral_fill: str
    neutral_border: str
    policy_fill: str
    policy_border: str
    workflow_fill: str
    workflow_border: str
    kernel_fill: str
    kernel_border: str
    evidence_fill: str
    evidence_border: str
    ops_fill: str
    ops_border: str
    adapter_fill: str
    adapter_border: str
    note_fill: str
    note_border: str
    connector: str
    connector_muted: str


@dataclass(frozen=True)
class NodeSpec:
    node_id: str
    x: int
    y: int
    width: int
    height: int
    css_class: str
    title: tuple[str, ...]
    subtitle: tuple[str, ...] = ()
    compact: bool = False
    radius: int = 16


@dataclass(frozen=True)
class ConnectorSpec:
    connector_id: str
    source: str
    destination: str
    points: tuple[tuple[int, int], ...]
    label: str
    label_box: tuple[int, int, int, int]
    muted: bool = False
    soft: bool = False


LIGHT = Theme(
    name="light",
    background="#f5f7fb",
    page_border="#cad4e1",
    title="#0b5cc5",
    subtitle="#536276",
    section="#586476",
    text="#152235",
    subtext="#4f6073",
    note="#2f3b4c",
    small="#6e7c91",
    neutral_fill="#ffffff",
    neutral_border="#bcc7d6",
    policy_fill="#eef3f8",
    policy_border="#afbed4",
    workflow_fill="#edf5ff",
    workflow_border="#2f6feb",
    kernel_fill="#f4efff",
    kernel_border="#6f5ef5",
    evidence_fill="#edf8ef",
    evidence_border="#3aa35b",
    ops_fill="#f2f5f8",
    ops_border="#c0c9d6",
    adapter_fill="#f6f4ff",
    adapter_border="#7a71ea",
    note_fill="#ffffff",
    note_border="#c7d2df",
    connector="#587296",
    connector_muted="#8ea1ba",
)

DARK = Theme(
    name="dark",
    background="#0b1118",
    page_border="#334153",
    title="#8ab8ff",
    subtitle="#a3b2c8",
    section="#b4c2d8",
    text="#eef4ff",
    subtext="#c7d3e8",
    note="#e2ebf8",
    small="#95a6bd",
    neutral_fill="#131b24",
    neutral_border="#405064",
    policy_fill="#141d29",
    policy_border="#47576c",
    workflow_fill="#11253e",
    workflow_border="#68a3ff",
    kernel_fill="#22163a",
    kernel_border="#9a82ff",
    evidence_fill="#13281c",
    evidence_border="#57c372",
    ops_fill="#151d28",
    ops_border="#3b4758",
    adapter_fill="#111826",
    adapter_border="#7a8db3",
    note_fill="#101721",
    note_border="#334152",
    connector="#93acce",
    connector_muted="#6a7c94",
)


def xml(text: str) -> str:
    return escape(text, quote=False)


def attr(text: str) -> str:
    return escape(text, quote=True)


def css(theme: Theme) -> str:
    return dedent(
        f"""
        <style>
          svg {{ font-family: 'IBM Plex Sans', 'Avenir Next', 'Segoe UI', sans-serif; }}
          .mono {{ font-family: 'IBM Plex Mono', 'SFMono-Regular', 'Menlo', monospace; }}
          .page-title {{ fill: {theme.title}; font-size: 28px; font-weight: 700; letter-spacing: 0.04em; }}
          .page-subtitle {{ fill: {theme.subtitle}; font-size: 15px; }}
          .section-tag, .panel-title {{ fill: {theme.section}; font-size: 12px; font-weight: 700; letter-spacing: 0.14em; }}
          .box-title {{ fill: {theme.text}; font-size: 18px; font-weight: 600; }}
          .box-title-compact {{ fill: {theme.text}; font-size: 15px; font-weight: 600; }}
          .box-sub {{ fill: {theme.subtext}; font-size: 13px; font-weight: 500; }}
          .box-sub-compact {{ fill: {theme.subtext}; font-size: 11px; font-weight: 500; }}
          .body {{ fill: {theme.note}; font-size: 14px; font-weight: 500; }}
          .small {{ fill: {theme.small}; font-size: 12px; }}
          .footer-note {{ fill: {theme.note}; font-size: 15px; font-weight: 500; }}
          .footer-small {{ fill: {theme.small}; font-size: 13px; }}
          .connector-label {{ fill: {theme.text}; font-size: 11px; font-weight: 600; letter-spacing: 0.02em; }}
          .frame {{ fill: none; stroke: {theme.page_border}; stroke-width: 1.4; }}
          .band {{ fill: {theme.neutral_fill}; stroke: {theme.page_border}; stroke-width: 1.4; }}
          .host-box {{ fill: {theme.neutral_fill}; stroke: {theme.neutral_border}; stroke-width: 1.4; }}
          .policy-panel {{ fill: {theme.policy_fill}; stroke: {theme.policy_border}; stroke-width: 1.5; }}
          .workflow-panel {{ fill: {theme.workflow_fill}; stroke: {theme.workflow_border}; stroke-width: 1.7; }}
          .kernel-panel {{ fill: {theme.kernel_fill}; stroke: {theme.kernel_border}; stroke-width: 1.7; }}
          .evidence-panel {{ fill: {theme.evidence_fill}; stroke: {theme.evidence_border}; stroke-width: 1.6; }}
          .ops-panel {{ fill: {theme.ops_fill}; stroke: {theme.ops_border}; stroke-width: 1.4; }}
          .adapter-panel {{ fill: {theme.adapter_fill}; stroke: {theme.adapter_border}; stroke-width: 1.4; stroke-dasharray: 8 7; }}
          .note-box {{ fill: {theme.note_fill}; stroke: {theme.note_border}; stroke-width: 1.2; }}
          .node-neutral {{ fill: {theme.neutral_fill}; stroke: {theme.neutral_border}; stroke-width: 1.3; }}
          .node-policy {{ fill: {theme.neutral_fill}; stroke: {theme.policy_border}; stroke-width: 1.3; }}
          .node-workflow {{ fill: {theme.neutral_fill}; stroke: {theme.workflow_border}; stroke-width: 1.35; }}
          .node-kernel {{ fill: {theme.neutral_fill}; stroke: {theme.kernel_border}; stroke-width: 1.35; }}
          .node-evidence {{ fill: {theme.neutral_fill}; stroke: {theme.evidence_border}; stroke-width: 1.35; }}
          .node-ops {{ fill: {theme.note_fill}; stroke: {theme.ops_border}; stroke-width: 1.25; }}
          .node-adapter {{ fill: {theme.note_fill}; stroke: {theme.adapter_border}; stroke-width: 1.25; stroke-dasharray: 7 6; }}
          .connector {{ fill: none; stroke: {theme.connector}; stroke-width: 2.3; stroke-linecap: round; stroke-linejoin: round; }}
          .connector-muted {{ fill: none; stroke: {theme.connector_muted}; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; stroke-dasharray: 7 7; }}
          .connector-soft {{ fill: none; stroke: {theme.connector}; stroke-opacity: 0.72; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; }}
          .connector-label-fill {{ fill: {theme.background}; stroke: {theme.page_border}; stroke-width: 1; }}
        </style>
        <marker id="arrow" viewBox="0 0 12 10" refX="10" refY="5" markerWidth="10" markerHeight="8" orient="auto">
          <path d="M0 0 L12 5 L0 10 z" fill="{theme.connector}" />
        </marker>
        <marker id="arrow-muted" viewBox="0 0 12 10" refX="10" refY="5" markerWidth="10" markerHeight="8" orient="auto">
          <path d="M0 0 L12 5 L0 10 z" fill="{theme.connector_muted}" />
        </marker>
        <marker id="arrow-soft" viewBox="0 0 12 10" refX="10" refY="5" markerWidth="10" markerHeight="8" orient="auto">
          <path d="M0 0 L12 5 L0 10 z" fill="{theme.connector}" fill-opacity="0.72" />
        </marker>
        """
    ).strip()


def header(theme: Theme, title: str, subtitle: str, height: int) -> str:
    return (
        f'<svg xmlns="{SVG_NS}" viewBox="0 0 {WIDTH} {height}">'
        f"<defs>{css(theme)}</defs>"
        f'<rect width="{WIDTH}" height="{height}" fill="{theme.background}" rx="24" />'
        f'<rect x="36" y="36" width="{WIDTH - 72}" height="{height - 72}" class="frame" rx="24" />'
        f'<text class="page-title mono" x="60" y="44">{xml(title)}</text>'
        f'<text class="page-subtitle" x="60" y="68">{xml(subtitle)}</text>'
    )


def rect(
    x: int,
    y: int,
    width: int,
    height: int,
    css_class: str,
    radius: int = 20,
    extra: str = "",
) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
        f'rx="{radius}" class="{css_class}"{extra} />'
    )


def centered_lines(
    x: float,
    y_center: float,
    lines: tuple[tuple[str, str], ...],
) -> str:
    heights = {
        "box-title": 22,
        "box-title-compact": 18,
        "box-sub": 17,
        "box-sub-compact": 14,
        "body": 18,
        "small": 14,
    }
    gap = 5
    total = sum(heights[line_class] for line_class, _ in lines)
    total += gap * max(len(lines) - 1, 0)
    current = y_center - total / 2
    output: list[str] = []
    for line_class, text in lines:
        line_height = heights[line_class]
        baseline = current + line_height * 0.78
        output.append(
            f'<text class="{line_class}" x="{x}" y="{baseline:.1f}" '
            f'text-anchor="middle">{xml(text)}</text>'
        )
        current += line_height + gap
    return "".join(output)


def node(spec: NodeSpec) -> str:
    title_class = "box-title-compact" if spec.compact else "box-title"
    subtitle_class = "box-sub-compact" if spec.compact else "box-sub"
    lines = tuple((title_class, line) for line in spec.title)
    lines += tuple((subtitle_class, line) for line in spec.subtitle)
    metadata = f' data-node-id="{attr(spec.node_id)}"'
    return (
        rect(
            spec.x,
            spec.y,
            spec.width,
            spec.height,
            spec.css_class,
            spec.radius,
            metadata,
        )
        + centered_lines(
            spec.x + spec.width / 2,
            spec.y + spec.height / 2,
            lines,
        )
    )


def note_box(
    x: int,
    y: int,
    width: int,
    height: int,
    lines: tuple[str, ...],
    small_lines: tuple[str, ...] = (),
) -> str:
    text_lines = tuple(("body", line) for line in lines)
    text_lines += tuple(("small", line) for line in small_lines)
    return (
        rect(x, y, width, height, "note-box", 16)
        + centered_lines(x + width / 2, y + height / 2, text_lines)
    )


def section_label(x: int, y: int, text: str, panel: bool = False) -> str:
    css_class = "panel-title mono" if panel else "section-tag mono"
    return f'<text class="{css_class}" x="{x}" y="{y}">{xml(text)}</text>'


def connector(spec: ConnectorSpec) -> str:
    if len(spec.points) < 2:
        raise ValueError(f"{spec.connector_id} needs at least two points")
    for start, end in zip(spec.points, spec.points[1:]):
        if start[0] != end[0] and start[1] != end[1]:
            raise ValueError(f"{spec.connector_id} contains a diagonal segment")
    path_data = " ".join(
        f"{'M' if index == 0 else 'L'} {x} {y}"
        for index, (x, y) in enumerate(spec.points)
    )
    css_class = "connector-soft" if spec.soft else (
        "connector-muted" if spec.muted else "connector"
    )
    marker = "arrow-soft" if spec.soft else (
        "arrow-muted" if spec.muted else "arrow"
    )
    label_x, label_y, label_width, label_height = spec.label_box
    label_rect = rect(
        label_x,
        label_y,
        label_width,
        label_height,
        "connector-label-fill",
        7,
        f' data-connector-label="{attr(spec.connector_id)}"',
    )
    label_text = (
        f'<text class="connector-label mono" x="{label_x + label_width / 2:.1f}" '
        f'y="{label_y + label_height / 2 + 4:.1f}" text-anchor="middle">'
        f"{xml(spec.label)}</text>"
    )
    connector_path = (
        f'<path class="{css_class}" d="{path_data}" '
        f'data-connector-id="{attr(spec.connector_id)}" '
        f'data-from="{attr(spec.source)}" data-to="{attr(spec.destination)}" '
        f'marker-end="url(#{marker})" />'
    )
    return label_rect + label_text + connector_path


def footer_notes(
    notes: tuple[tuple[str, int], ...],
    small_notes: tuple[tuple[str, int], ...] = (),
) -> str:
    output = [
        f'<text class="footer-note" x="60" y="{y}">{xml(text)}</text>'
        for text, y in notes
    ]
    output.extend(
        f'<text class="footer-small" x="60" y="{y}">{xml(text)}</text>'
        for text, y in small_notes
    )
    return "".join(output)


def render_beta(theme: Theme) -> str:
    height = 1460
    parts = [
        header(
            theme,
            "AEGIS v0.9 BETA",
            "aegis-ai-governance==0.9.0b1 | public beta | released from main",
            height,
        ),
        rect(60, 90, 1480, 160, "band", 24),
        section_label(84, 118, "HOST APPLICATION"),
        node(NodeSpec("host-app", 90, 145, 300, 70, "host-box", ("App / Agent / Orchestrator",))),
        node(NodeSpec("host-runtime", 430, 145, 330, 70, "host-box", ("Provider / Tool / Transport",), ("host runtime",), True)),
        note_box(
            800,
            135,
            690,
            90,
            ("Host owns execution, retries, credentials, and business state.",),
            ("Provider and tool calls remain outside AEGIS after authorization.",),
        ),
        rect(60, 280, 1480, 720, "band", 24),
        section_label(84, 308, "AEGIS SDK v0.9.0 BETA SURFACE"),
        rect(90, 330, 300, 620, "policy-panel", 22),
        section_label(114, 358, "POLICY + LOADING", panel=True),
        rect(420, 330, 760, 620, "workflow-panel", 22),
        section_label(444, 358, "WORKFLOW + INVOCATION GOVERNANCE", panel=True),
        rect(1210, 330, 300, 620, "evidence-panel", 22),
        section_label(1234, 358, "EVIDENCE + SUPPORT", panel=True),
    ]

    parts.extend(
        node(spec)
        for spec in (
            NodeSpec("policy-yaml", 115, 390, 120, 70, "node-policy", ("Policy YAML",), compact=True),
            NodeSpec("policy-cache", 255, 390, 115, 70, "node-policy", ("PolicyCache",), compact=True),
            NodeSpec("file-policy-loader", 110, 500, 135, 86, "node-policy", ("FilePolicy", "Loader"), ("or PolicyLoader", "Base"), True),
            NodeSpec("json-schemas", 265, 500, 105, 86, "node-policy", ("JSON", "Schemas"), compact=True),
            NodeSpec("open-session", 450, 390, 160, 78, "node-workflow", ("AEGIS.", "open_session()"), compact=True),
            NodeSpec("governance-session", 640, 390, 170, 78, "node-workflow", ("GovernanceSession",), compact=True),
            NodeSpec("session-pre-call-result", 840, 390, 170, 78, "node-workflow", ("SessionPreCall", "Result"), ("workflow-bound token",), True),
            NodeSpec("workflow-dsl", 1030, 390, 125, 78, "node-workflow", ("Workflow", "DSL"), ("budgets +", "approvals"), True),
            NodeSpec("workflow-artifact", 820, 520, 335, 92, "node-evidence", ("Workflow artifact",), ("COMPLETED | FAILED", "CANCELED | INCOMPLETE"), True),
            NodeSpec("enforce-invocation", 450, 690, 170, 82, "node-kernel", ("enforce_", "invocation()"), compact=True),
            NodeSpec("aegis-enforce", 650, 690, 150, 82, "node-kernel", ("AEGIS.enforce()",), compact=True),
            NodeSpec("split-apis", 830, 690, 150, 82, "node-kernel", ("split APIs",), ("pre_call / post_call",), True),
            NodeSpec("ordered-gates", 1010, 690, 145, 82, "node-kernel", ("ordered gates",), ("auth -> output", "-> risk"), True),
            NodeSpec("invocation-artifact", 1240, 390, 240, 90, "node-evidence", ("Invocation artifact",), ("PASS or FAIL", "per attempt"), True),
            NodeSpec("audit-sink", 1240, 530, 240, 90, "node-evidence", ("AuditSink + signing",), ("JSONL / callback / custom", "optional signer"), True),
            NodeSpec("audit-lineage", 1240, 680, 240, 100, "node-ops", ("AuditLineage", "compliance export", "--lineage"), ("stored-trail analysis",), True),
        )
    )

    parts.extend(
        [
            note_box(
                115,
                630,
                250,
                110,
                ("Load, validate, cache, and", "compose policy contracts."),
                ("SDK-owned and deterministic.",),
            ),
            note_box(
                450,
                520,
                330,
                92,
                ("Tracks steps, checkpoints,", "participants, and budgets."),
            ),
            note_box(
                450,
                820,
                705,
                92,
                (
                    "Gate order: pre-authorization -> guards -> role -> preconditions -> tools",
                    "post-authorization -> pre-output -> schema -> postconditions -> post-output -> risk",
                ),
            ),
            note_box(
                1240,
                820,
                240,
                110,
                ("Workflow evidence", "stays separate", "from invocation artifacts."),
                ("Correlation is additive.",),
            ),
        ]
    )

    beta_connectors = (
        ConnectorSpec(
            "host-to-session",
            "host-app",
            "open-session",
            ((240, 215), (240, 260), (530, 260), (530, 390)),
            "governed workflow",
            (315, 232, 150, 22),
            soft=True,
        ),
        ConnectorSpec(
            "loader-to-entrypoint",
            "file-policy-loader",
            "enforce-invocation",
            ((177, 586), (177, 610), (400, 610), (400, 731), (450, 731)),
            "loads policy",
            (272, 750, 100, 22),
        ),
        ConnectorSpec(
            "open-to-session",
            "open-session",
            "governance-session",
            ((610, 429), (640, 429)),
            "opens",
            (592, 472, 65, 22),
        ),
        ConnectorSpec(
            "session-to-token",
            "governance-session",
            "session-pre-call-result",
            ((810, 429), (840, 429)),
            "authorizes",
            (800, 625, 92, 22),
        ),
        ConnectorSpec(
            "session-to-workflow-evidence",
            "governance-session",
            "workflow-artifact",
            ((725, 468), (725, 492), (987, 492), (987, 520)),
            "separate evidence",
            (660, 625, 130, 22),
            muted=True,
        ),
        ConnectorSpec(
            "token-to-split",
            "session-pre-call-result",
            "split-apis",
            ((925, 390), (925, 375), (1190, 375), (1190, 650), (905, 650), (905, 690)),
            "workflow-bound",
            (1035, 620, 120, 22),
        ),
        ConnectorSpec(
            "gates-to-invocation-evidence",
            "ordered-gates",
            "invocation-artifact",
            ((1155, 731), (1200, 731), (1200, 435), (1240, 435)),
            "per-attempt evidence",
            (1205, 638, 145, 22),
        ),
        ConnectorSpec(
            "artifact-to-sink",
            "invocation-artifact",
            "audit-sink",
            ((1360, 480), (1360, 530)),
            "emits",
            (1372, 494, 74, 22),
        ),
        ConnectorSpec(
            "sink-to-lineage",
            "audit-sink",
            "audit-lineage",
            ((1360, 620), (1360, 680)),
            "analyzes",
            (1372, 638, 82, 22),
            muted=True,
        ),
    )
    parts.extend(connector(spec) for spec in beta_connectors)

    parts.extend(
        [
            rect(60, 1030, 1480, 110, "adapter-panel", 24),
            section_label(84, 1058, "OPTIONAL NORMALIZATION ADAPTERS"),
            node(NodeSpec("bedrock-adapter", 90, 1080, 250, 44, "node-adapter", ("Bedrock adapter",), compact=True, radius=13)),
            node(NodeSpec("a2a-adapter", 365, 1080, 250, 44, "node-adapter", ("A2A adapter",), compact=True, radius=13)),
            node(NodeSpec("openai-agents-adapter", 640, 1080, 280, 44, "node-adapter", ("OpenAI Agents adapter",), compact=True, radius=13)),
            note_box(
                950,
                1070,
                550,
                64,
                ("Host owns clients, credentials, transport, retries, and execution.",),
            ),
            rect(60, 1170, 1480, 110, "ops-panel", 24),
            section_label(84, 1198, "ADOPTION + OPERATOR TOOLING"),
            node(NodeSpec("workflow-init", 90, 1220, 250, 44, "node-ops", ("aegis workflow init",), compact=True, radius=13)),
            node(NodeSpec("workflow-lint", 365, 1220, 250, 44, "node-ops", ("aegis workflow lint",), compact=True, radius=13)),
            node(NodeSpec("workflow-doctor", 640, 1220, 250, 44, "node-ops", ("aegis workflow doctor",), compact=True, radius=13)),
            node(NodeSpec("workflow-trace", 915, 1220, 250, 44, "node-ops", ("aegis workflow trace",), compact=True, radius=13)),
            node(NodeSpec("workflow-export", 1190, 1220, 280, 44, "node-ops", ("aegis workflow export",), compact=True, radius=13)),
            footer_notes(
                (
                    ("The host performs provider and tool calls after AEGIS authorizes a step or invocation.", 1335),
                    ("The beta adds workflow evidence. It does not turn AEGIS into a hosted orchestrator.", 1365),
                ),
                (
                    ("Public beta: workflow sessions and adapter submodules are packaged; internal implementation details", 1400),
                    ("and target-state identity / manifest types are intentionally absent from this current view.", 1422),
                ),
            ),
            "</svg>",
        ]
    )
    return "".join(parts)


def render_pipeline(theme: Theme) -> str:
    height = 1210
    parts = [
        header(
            theme,
            "AEGIS v0.9 BETA | ENFORCEMENT PIPELINE",
            "The host executes. AEGIS authorizes, validates, and emits separate invocation and workflow evidence.",
            height,
        ),
        rect(60, 90, 1480, 140, "band", 24),
        section_label(84, 118, "HOST OWNERSHIP"),
    ]
    parts.extend(
        node(spec)
        for spec in (
            NodeSpec("host-orchestration", 90, 145, 270, 54, "host-box", ("orchestration",), compact=True, radius=14),
            NodeSpec("host-provider-call", 390, 145, 270, 54, "host-box", ("provider / tool call",), compact=True, radius=14),
            NodeSpec("host-credentials", 690, 145, 270, 54, "host-box", ("credentials + retries",), compact=True, radius=14),
        )
    )
    parts.extend(
        [
            note_box(
                1000,
                135,
                500,
                76,
                ("Execution remains outside AEGIS.",),
                ("The host acts only after authorization.",),
            ),
            rect(60, 260, 1480, 160, "workflow-panel", 24),
            section_label(84, 288, "WORKFLOW COORDINATION"),
        ]
    )
    parts.extend(
        node(spec)
        for spec in (
            NodeSpec("pipeline-open-session", 90, 315, 230, 70, "node-workflow", ("AEGIS.open_session()",), compact=True),
            NodeSpec("pipeline-session", 350, 315, 230, 70, "node-workflow", ("GovernanceSession",), compact=True),
            NodeSpec("pipeline-token", 610, 315, 250, 70, "node-workflow", ("SessionPreCallResult",), ("single-use step token",), True),
            NodeSpec("pipeline-workflow-policy", 890, 315, 250, 70, "node-policy", ("Workflow policy",), ("sequence / budgets / approvals",), True),
            NodeSpec("pipeline-workflow-artifact", 1170, 315, 330, 70, "node-evidence", ("Workflow artifact",), ("separate session evidence",), True),
        )
    )
    workflow_connectors = (
        ConnectorSpec("workflow-open", "pipeline-open-session", "pipeline-session", ((320, 350), (350, 350)), "opens", (304, 292, 62, 20)),
        ConnectorSpec("workflow-authorize", "pipeline-session", "pipeline-token", ((580, 350), (610, 350)), "authorizes", (548, 392, 94, 20)),
        ConnectorSpec("token-checks-policy", "pipeline-token", "pipeline-workflow-policy", ((860, 350), (890, 350)), "checks", (844, 292, 62, 20)),
        ConnectorSpec("policy-to-workflow-artifact", "pipeline-workflow-policy", "pipeline-workflow-artifact", ((1140, 350), (1170, 350)), "records", (1122, 392, 68, 20), muted=True),
    )
    parts.extend(connector(spec) for spec in workflow_connectors)

    parts.extend(
        [
            rect(60, 450, 1480, 450, "kernel-panel", 24),
            section_label(84, 478, "DETERMINISTIC INVOCATION PIPELINE"),
            section_label(90, 510, "PHASE A | AUTHORIZE BEFORE HOST EXECUTION", panel=True),
        ]
    )
    phase_a_nodes = (
        NodeSpec("pipeline-policy-load", 90, 540, 160, 70, "node-kernel", ("Policy load", "+ validation"), compact=True),
        NodeSpec("pipeline-pre-auth", 280, 540, 160, 70, "node-kernel", ("pre_authorization",), compact=True),
        NodeSpec("pipeline-guards-role", 470, 540, 160, 70, "node-kernel", ("guards + role",), compact=True),
        NodeSpec("pipeline-preconditions", 660, 540, 190, 70, "node-kernel", ("preconditions + tools",), compact=True),
        NodeSpec("pipeline-post-auth", 880, 540, 180, 70, "node-kernel", ("post_authorization",), compact=True),
        NodeSpec("pipeline-host-execution", 1190, 520, 300, 90, "node-adapter", ("HOST EXECUTION",), ("one provider call, tool action,", "or workflow step"), True),
    )
    parts.extend(node(spec) for spec in phase_a_nodes)
    phase_a_connectors = (
        ConnectorSpec("load-to-pre-auth", "pipeline-policy-load", "pipeline-pre-auth", ((250, 575), (280, 575)), "then", (244, 616, 42, 20)),
        ConnectorSpec("pre-auth-to-guards", "pipeline-pre-auth", "pipeline-guards-role", ((440, 575), (470, 575)), "then", (434, 504, 42, 20)),
        ConnectorSpec("guards-to-preconditions", "pipeline-guards-role", "pipeline-preconditions", ((630, 575), (660, 575)), "then", (624, 616, 42, 20)),
        ConnectorSpec("preconditions-to-post-auth", "pipeline-preconditions", "pipeline-post-auth", ((850, 575), (880, 575)), "then", (844, 504, 42, 20)),
        ConnectorSpec("authorization-to-host", "pipeline-post-auth", "pipeline-host-execution", ((1060, 575), (1190, 575)), "authorized host action", (1068, 616, 142, 20)),
    )
    parts.extend(connector(spec) for spec in phase_a_connectors)

    parts.extend(
        [
            section_label(90, 745, "PHASE B | VALIDATE OUTPUT + EMIT EVIDENCE", panel=True),
        ]
    )
    phase_b_nodes = (
        NodeSpec("pipeline-pre-output", 90, 770, 160, 70, "node-kernel", ("pre_output",), compact=True),
        NodeSpec("pipeline-output-schema", 280, 770, 160, 70, "node-kernel", ("output schema",), compact=True),
        NodeSpec("pipeline-postconditions", 470, 770, 160, 70, "node-kernel", ("postconditions",), compact=True),
        NodeSpec("pipeline-post-output", 660, 770, 160, 70, "node-kernel", ("post_output",), compact=True),
        NodeSpec("pipeline-risk", 850, 770, 160, 70, "node-kernel", ("risk scoring",), compact=True),
        NodeSpec("pipeline-invocation-artifact", 1120, 760, 370, 80, "node-evidence", ("Invocation artifact",), ("PASS or FAIL per attempt",), True),
    )
    parts.extend(node(spec) for spec in phase_b_nodes)
    phase_b_connectors = (
        ConnectorSpec(
            "host-to-pre-output",
            "pipeline-host-execution",
            "pipeline-pre-output",
            ((1340, 610), (1340, 710), (170, 710), (170, 770)),
            "host supplies output",
            (1090, 678, 150, 22),
        ),
        ConnectorSpec("pre-output-to-schema", "pipeline-pre-output", "pipeline-output-schema", ((250, 805), (280, 805)), "then", (244, 846, 42, 20)),
        ConnectorSpec("schema-to-postconditions", "pipeline-output-schema", "pipeline-postconditions", ((440, 805), (470, 805)), "then", (434, 748, 42, 20)),
        ConnectorSpec("postconditions-to-post-output", "pipeline-postconditions", "pipeline-post-output", ((630, 805), (660, 805)), "then", (624, 846, 42, 20)),
        ConnectorSpec("post-output-to-risk", "pipeline-post-output", "pipeline-risk", ((820, 805), (850, 805)), "then", (814, 748, 42, 20)),
        ConnectorSpec("risk-to-invocation-artifact", "pipeline-risk", "pipeline-invocation-artifact", ((1010, 805), (1120, 805)), "emits", (1028, 846, 74, 20)),
    )
    parts.extend(connector(spec) for spec in phase_b_connectors)

    parts.extend(
        [
            rect(60, 940, 1480, 130, "evidence-panel", 24),
            section_label(84, 968, "EVIDENCE + OPERATOR TOOLING"),
        ]
    )
    evidence_nodes = (
        NodeSpec("pipeline-audit-sink", 90, 1000, 250, 50, "node-evidence", ("AuditSink + optional signing",), compact=True, radius=14),
        NodeSpec("pipeline-trace", 370, 1000, 240, 50, "node-ops", ("aegis workflow trace",), compact=True, radius=14),
        NodeSpec("pipeline-export", 640, 1000, 240, 50, "node-ops", ("aegis workflow export",), compact=True, radius=14),
        NodeSpec("pipeline-bedrock-a2a", 910, 1000, 240, 50, "node-adapter", ("Bedrock / A2A",), ("optional adapters",), True, 14),
        NodeSpec("pipeline-openai-adapter", 1180, 1000, 320, 50, "node-adapter", ("OpenAI Agents adapter",), ("optional extra",), True, 14),
    )
    parts.extend(node(spec) for spec in evidence_nodes)
    parts.append(
        connector(
            ConnectorSpec(
                "invocation-artifact-to-sink",
                "pipeline-invocation-artifact",
                "pipeline-audit-sink",
                ((1305, 840), (1305, 920), (215, 920), (215, 1000)),
                "sink emission",
                (570, 885, 112, 22),
            )
        )
    )
    parts.extend(
        [
            footer_notes(
                (
                    ("Split enforcement has been the @governed default since v0.3.3.", 1122),
                    ("Unified enforcement preserves the same ordered gates without moving execution into AEGIS.", 1152),
                )
            ),
            "</svg>",
        ]
    )
    return "".join(parts)


def render_full(theme: Theme) -> str:
    height = 1350
    parts = [
        header(
            theme,
            "AEGIS v0.9.0 FULL",
            "Intended full solution design surface. AEGIS remains an SDK, not a hosted runtime or orchestrator.",
            height,
        ),
        rect(60, 90, 1480, 140, "band", 24),
        section_label(84, 118, "HOST APPLICATION"),
    ]
    parts.extend(
        node(spec)
        for spec in (
            NodeSpec("full-host-app", 90, 145, 280, 65, "host-box", ("orchestration", "business logic"), compact=True),
            NodeSpec("full-model-tools", 400, 145, 250, 65, "host-box", ("model calls", "tool execution"), compact=True),
            NodeSpec("full-transport", 680, 145, 230, 65, "host-box", ("transport", "credentials"), compact=True),
        )
    )
    parts.extend(
        [
            note_box(
                940,
                135,
                560,
                80,
                ("Host-owned execution remains outside AEGIS governance surfaces.",),
                ("Adapters normalize visible evidence; they do not replace enforcement.",),
            ),
            rect(60, 260, 1480, 130, "adapter-panel", 24),
            section_label(84, 288, "OPTIONAL ADAPTERS"),
            node(NodeSpec("full-bedrock-adapter", 100, 315, 250, 54, "node-adapter", ("Bedrock adapter",), ("optional normalization",), True)),
            node(NodeSpec("full-a2a-adapter", 390, 315, 250, 54, "node-adapter", ("A2A adapter",), ("optional normalization",), True)),
            note_box(
                680,
                305,
                800,
                74,
                ("Governance normalization inlet for host-supplied trace, card, and task evidence.",),
                ("No HTTP clients, auth flows, retries, sockets, or remote sessions.",),
            ),
            connector(
                ConnectorSpec(
                    "full-host-to-adapter",
                    "full-host-app",
                    "full-bedrock-adapter",
                    ((230, 210), (230, 315)),
                    "host evidence",
                    (245, 232, 105, 22),
                    soft=True,
                )
            ),
            rect(60, 420, 1480, 850, "band", 24),
            section_label(84, 448, "AEGIS SDK v0.9.0 FULL SURFACE"),
            rect(90, 470, 1038, 150, "policy-panel", 22),
            section_label(114, 498, "POLICY + CONTRACTS", panel=True),
            rect(90, 650, 1038, 220, "workflow-panel", 22),
            section_label(114, 678, "WORKFLOW GOVERNANCE LAYER", panel=True),
            rect(90, 900, 1038, 190, "kernel-panel", 22),
            section_label(114, 928, "INVOCATION GOVERNANCE KERNEL", panel=True),
            rect(90, 1120, 1038, 120, "evidence-panel", 22),
            section_label(114, 1148, "EVIDENCE OUTPUTS", panel=True),
            rect(1158, 470, 352, 770, "ops-panel", 22),
            section_label(1182, 498, "VALIDATION + OPERATOR SURFACES", panel=True),
        ]
    )
    full_nodes = (
        NodeSpec("full-policy-yaml", 114, 530, 220, 60, "node-policy", ("Policy YAML /", "workflow DSL"), compact=True),
        NodeSpec("full-json-schemas", 360, 530, 170, 60, "node-policy", ("JSON Schemas",), compact=True),
        NodeSpec("full-manifests", 556, 530, 170, 60, "node-policy", ("manifests",), compact=True),
        NodeSpec("full-policy-loading", 752, 520, 350, 80, "node-policy", ("policy loading / validation",), ("composition / narrowing / fail closed",), True),
        NodeSpec("full-open-session", 114, 710, 206, 70, "node-workflow", ("AEGIS.open_session(...)",), compact=True),
        NodeSpec("full-session", 344, 710, 206, 70, "node-workflow", ("GovernanceSession",), compact=True),
        NodeSpec("full-session-token", 574, 710, 206, 70, "node-workflow", ("SessionPreCallResult",), compact=True),
        NodeSpec("full-agent-identity", 114, 800, 206, 50, "node-workflow", ("AgentIdentity",), compact=True),
        NodeSpec("full-capability-manifest", 344, 800, 206, 50, "node-workflow", ("AgentCapabilityManifest",), compact=True),
        NodeSpec("full-workflow-controls", 574, 800, 530, 50, "node-workflow", ("handoffs / budgets / escalation checkpoints",), ("session + evidence correlation",), True),
        NodeSpec("full-unified-split", 114, 960, 180, 62, "node-kernel", ("unified + split", "enforcement"), compact=True),
        NodeSpec("full-ordered-gates", 316, 960, 180, 62, "node-kernel", ("ordered gates",), compact=True),
        NodeSpec("full-pre-call", 518, 960, 180, 62, "node-kernel", ("pre-call", "authorization"), compact=True),
        NodeSpec("full-post-call", 720, 960, 180, 62, "node-kernel", ("post-call output", "validation"), compact=True),
        NodeSpec("full-risk", 922, 960, 180, 62, "node-kernel", ("risk",), compact=True),
        NodeSpec("full-invocation-artifacts", 114, 1170, 228, 50, "node-evidence", ("invocation artifacts",), compact=True),
        NodeSpec("full-workflow-artifacts", 364, 1170, 228, 50, "node-evidence", ("workflow artifacts",), compact=True),
        NodeSpec("full-audit-sink", 614, 1170, 228, 50, "node-evidence", ("AuditSink + signing",), compact=True),
        NodeSpec("full-operator-exports", 864, 1170, 238, 50, "node-evidence", ("operator exports",), compact=True),
        NodeSpec("full-validator-hook", 1182, 530, 302, 70, "node-ops", ("ValidatorHook",), ("typed extension contract",), True),
        NodeSpec("full-workflow-lint", 1182, 640, 302, 65, "node-ops", ("workflow lint",), ("schema / transitions / budgets",), True),
        NodeSpec("full-workflow-trace", 1182, 745, 302, 65, "node-ops", ("workflow trace",), ("timeline from emitted evidence",), True),
        NodeSpec("full-workflow-export", 1182, 850, 302, 65, "node-ops", ("workflow export",), ("operator-facing modes",), True),
    )
    parts.extend(node(spec) for spec in full_nodes)
    parts.extend(
        [
            note_box(
                114,
                1040,
                988,
                36,
                ("pre-auth -> guards -> role -> preconditions -> tools -> post-auth -> pre-output -> schema -> postconditions -> post-output -> risk",),
            ),
            note_box(
                1182,
                955,
                302,
                92,
                ("Operator tooling sits beside", "runtime semantics."),
                ("The host still executes.",),
            ),
            note_box(
                1182,
                1080,
                302,
                100,
                ("Trace and export consume", "emitted evidence."),
                ("Adapters remain optional.",),
            ),
        ]
    )
    full_connectors = (
        ConnectorSpec(
            "full-policy-to-workflow",
            "full-policy-loading",
            "full-open-session",
            ((927, 600), (927, 635), (217, 635), (217, 710)),
            "validated contracts",
            (535, 605, 140, 22),
        ),
        ConnectorSpec("full-session-opens", "full-open-session", "full-session", ((320, 745), (344, 745)), "opens", (300, 682, 64, 20)),
        ConnectorSpec("full-session-tokenizes", "full-session", "full-session-token", ((550, 745), (574, 745)), "authorizes", (512, 682, 100, 20)),
        ConnectorSpec(
            "full-token-to-kernel",
            "full-session-token",
            "full-unified-split",
            ((677, 780), (677, 790), (560, 790), (560, 885), (204, 885), (204, 960)),
            "workflow-bound call",
            (590, 852, 145, 22),
        ),
        ConnectorSpec("full-kernel-order", "full-unified-split", "full-ordered-gates", ((294, 991), (316, 991)), "then", (284, 930, 42, 20)),
        ConnectorSpec("full-gates-pre-call", "full-ordered-gates", "full-pre-call", ((496, 991), (518, 991)), "then", (486, 1028, 42, 20)),
        ConnectorSpec("full-pre-to-post", "full-pre-call", "full-post-call", ((698, 991), (720, 991)), "host acts", (680, 930, 62, 20)),
        ConnectorSpec("full-post-to-risk", "full-post-call", "full-risk", ((900, 991), (922, 991)), "then", (890, 1028, 42, 20)),
        ConnectorSpec(
            "full-risk-to-invocation-evidence",
            "full-risk",
            "full-invocation-artifacts",
            ((1012, 1022), (1012, 1100), (228, 1100), (228, 1170)),
            "per attempt",
            (620, 1068, 90, 22),
        ),
        ConnectorSpec(
            "full-workflow-to-workflow-evidence",
            "full-workflow-controls",
            "full-workflow-artifacts",
            ((1104, 825), (1138, 825), (1138, 1110), (478, 1110), (478, 1170)),
            "separate session evidence",
            (820, 1118, 165, 22),
            muted=True,
        ),
    )
    parts.extend(connector(spec) for spec in full_connectors)
    parts.extend(
        [
            footer_notes(
                (
                    ("AEGIS remains an SDK, not a hosted runtime or orchestrator.", 1300),
                    ("Provider, tool, transport, retry, credential, and business-state ownership remains with the host.", 1328),
                )
            ),
            "</svg>",
        ]
    )
    return "".join(parts)


def write_svg(path: Path, content: str) -> None:
    path.write_text(content + "\n", encoding="utf-8")


def architecture_outputs() -> dict[Path, str]:
    diagrams_dir = Path(__file__).resolve().parent
    repo_root = diagrams_dir.parents[2]
    demo_dir = repo_root / "demo-app-react" / "public" / "diagrams"

    beta_light = render_beta(LIGHT)
    beta_dark = render_beta(DARK)
    pipeline_light = render_pipeline(LIGHT)
    pipeline_dark = render_pipeline(DARK)
    full_light = render_full(LIGHT)
    full_dark = render_full(DARK)

    return {
        diagrams_dir / "aegis_v090_beta_component_light.svg": beta_light,
        diagrams_dir / "aegis_v090_beta_component_dark.svg": beta_dark,
        diagrams_dir / "aegis_v090_full_component_light.svg": full_light,
        diagrams_dir / "aegis_v090_full_component_dark.svg": full_dark,
        diagrams_dir / "aegis_architecture_component_light.svg": beta_light,
        diagrams_dir / "aegis_architecture_component.svg": beta_dark,
        diagrams_dir / "aegis_architecture_pipeline_light.svg": pipeline_light,
        diagrams_dir / "aegis_architecture_pipeline.svg": pipeline_dark,
        demo_dir / "aegis_architecture_component_light.svg": beta_light,
        demo_dir / "aegis_architecture_component.svg": beta_dark,
        demo_dir / "aegis_architecture_pipeline_light.svg": pipeline_light,
        demo_dir / "aegis_architecture_pipeline.svg": pipeline_dark,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic AEGIS architecture SVG assets."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Return non-zero when a checked-in output differs from generated content.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    outputs = architecture_outputs()
    if args.check:
        stale = [
            output_path
            for output_path, expected in outputs.items()
            if not output_path.exists()
            or output_path.read_text(encoding="utf-8") != expected + "\n"
        ]
        for output_path in stale:
            print(f"STALE: {output_path}")
        return 1 if stale else 0

    for output_path, content in outputs.items():
        write_svg(output_path, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
