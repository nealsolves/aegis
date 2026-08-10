"""CI contracts for the maintained evidence-claims guard."""

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
GUARD_COMMAND = "python scripts/check_evidence_claims.py"
CHECKOUT_ACTION = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd"
NODE_ACTION = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
PYTHON_ACTION = "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405"


def _workflow(relative_path: str) -> dict:
    """Load a workflow without YAML 1.1 coercing keys such as ``on``."""
    return yaml.load(
        (ROOT / relative_path).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def _step_index(steps: list[dict], predicate) -> int:
    for index, step in enumerate(steps):
        if predicate(step):
            return index
    raise AssertionError("Expected workflow step was not found")


def _run_step_index(steps: list[dict], command: str) -> int:
    return _step_index(steps, lambda step: command in step.get("run", ""))


def _setup_node_index(steps: list[dict]) -> int:
    return _step_index(steps, lambda step: step.get("uses") == NODE_ACTION)


def _setup_python_index(steps: list[dict]) -> int:
    return _step_index(steps, lambda step: step.get("uses") == PYTHON_ACTION)


def _markdown_link_targets(relative_path: str) -> set[str]:
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    return {
        bracketed or plain
        for bracketed, plain in re.findall(
            r"\[[^]]*\]\(<([^>]+)>\)|\[[^]]*\]\(([^ )]+)",
            text,
        )
    }


def _section(text: str, heading: str) -> str:
    start = text.index(f"## {heading}")
    following = text.find("\n## ", start + 1)
    return text[start:] if following < 0 else text[start:following]


def _table_row_labels(section: str) -> set[str]:
    labels = set()
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        label = line.split("|", 2)[1].strip()
        if label and not set(label) <= {"-", ":"}:
            labels.add(label)
    return labels


def test_canonical_guide_has_required_sections_and_contract_tables():
    """Fails if a required lifecycle section or assurance table row is removed."""
    guide = (
        ROOT / "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"
    ).read_text(encoding="utf-8")
    headings = {
        line[3:]
        for line in guide.splitlines()
        if line.startswith("## ")
    }
    assert {
        "Assurance model",
        "Provider-neutral reference architecture",
        "Ownership matrix",
        "Evidence set and data minimization",
        "Ingest verification",
        "Retention and object locking",
        "Least privilege",
        "Trusted checkpoint operations",
        "Monitoring",
        "Export verification",
        "Backup and disaster recovery",
        "Key rotation",
        "Revocation",
        "Suspected or confirmed compromise",
        "Provider outage",
        "Non-normative provider examples",
    } <= headings
    assert {
        "Tamper-evidence",
        "External anchoring",
        "Checkpoint-backed completeness",
        "Append-only/WORM retention",
        "Legal/compliance status",
    } <= _table_row_labels(_section(guide, "Assurance model"))
    assert {
        "Evidence creation",
        "Tamper-evidence",
        "External anchoring",
        "Checkpoints",
        "Retention",
        "Operations",
        "Assurance claims",
    } <= _table_row_labels(_section(guide, "Ownership matrix"))


def test_canonical_guide_links_its_contract_authorities():
    """Fails if the canonical guide is detached from a designated authority."""
    assert {
        "https://github.com/nealsolves/aegis/issues/44",
        "../decisions/ADR-0012-external-trust-anchor-signing.md",
        "https://github.com/nealsolves/aegis/issues/46",
        "../decisions/ADR-0015-trusted-checkpoints.md",
        "https://github.com/nealsolves/aegis/issues/58",
    } <= _markdown_link_targets(
        "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"
    )


def test_all_designated_entry_points_link_to_the_canonical_guide():
    """Fails if any maintained entry point drops its canonical destination."""
    destinations = {
        "README.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "SECURITY.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "CHANGELOG.md": "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/USAGE.md": "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/INTEGRATION_GUIDE.md": "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md",
        "docs/PUBLIC_INTEGRATION_CONTRACT.md": (
            "reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ),
        "docs/architecture/AEGIS_THREAT_MODEL.md": (
            "../reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ),
        "docs/reference/OPERATIONS_RUNBOOK.md": (
            "APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ),
        "docs/reference/external/AWS_KMS_SIGNING.md": (
            "../APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ),
        "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md": (
            "../APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ),
    }

    for relative, destination in destinations.items():
        assert destination in _markdown_link_targets(relative), relative
        resolved = ((ROOT / relative).parent / destination).resolve()
        assert resolved == (
            ROOT / "docs/reference/APPEND_ONLY_EVIDENCE_OPERATIONS.md"
        ).resolve()


def test_operations_runbook_core_validation_includes_claims_guard():
    """Fails if the mandated local guard command leaves core validation."""
    runbook = (ROOT / "docs/reference/OPERATIONS_RUNBOOK.md").read_text(
        encoding="utf-8"
    )
    core_validation = _section(runbook, "Core Validation Commands")
    fenced_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", core_validation, re.DOTALL)

    assert fenced_blocks
    commands = {
        line.strip()
        for line in fenced_blocks[0].splitlines()
        if line.strip()
    }
    assert GUARD_COMMAND in commands


def test_claims_guard_is_wired_into_all_required_workflows():
    security = _workflow(".github/workflows/security-boundaries.yml")
    publish = _workflow(".github/workflows/publish.yml")
    demo = _workflow(".github/workflows/deploy-demo-react.yml")

    evidence_claims = security["jobs"]["evidence-claims"]
    assert evidence_claims["runs-on"] == "ubuntu-latest"
    assert "strategy" not in evidence_claims
    security_steps = evidence_claims["steps"]
    assert security_steps[0]["uses"] == CHECKOUT_ACTION
    assert security_steps[0]["with"]["persist-credentials"] == "false"
    security_node = _setup_node_index(security_steps)
    assert security_steps[security_node]["with"]["node-version"] == "24"
    assert _setup_python_index(security_steps) < security_node
    assert _run_step_index(
        security_steps, 'python -m pip install -e ".[dev]"'
    ) < _run_step_index(security_steps, "npm ci") < _run_step_index(
        security_steps, GUARD_COMMAND
    )
    npm_step = security_steps[_run_step_index(security_steps, "npm ci")]
    assert npm_step["working-directory"] == "demo-app-react"

    release_steps = publish["jobs"]["build"]["steps"]
    release_node = _setup_node_index(release_steps)
    assert release_steps[release_node]["with"]["node-version"] == "24"
    assert _setup_python_index(release_steps) < release_node
    release_python_dependencies = _run_step_index(
        release_steps, '-e ".[dev,aws-kms,gcp-kms]"'
    )
    release_npm = _run_step_index(release_steps, "npm ci")
    release_validation = _run_step_index(release_steps, GUARD_COMMAND)
    assert release_python_dependencies < release_npm < release_validation
    assert release_steps[release_npm]["working-directory"] == "demo-app-react"
    assert release_steps[release_validation]["name"] == "Run release validation"

    demo_steps = demo["jobs"]["build"]["steps"]
    demo_node = _setup_node_index(demo_steps)
    assert demo_steps[demo_node]["with"]["node-version"] == "24"
    python_dependencies = _run_step_index(
        demo_steps, 'python -m pip install -e ".[dev]"'
    )
    demo_npm = _run_step_index(demo_steps, "npm ci")
    assert _setup_python_index(demo_steps) < python_dependencies < demo_npm
    assert demo_steps[demo_npm]["working-directory"] == "demo-app-react"
    demo_copy = _run_step_index(demo_steps, "python scripts/check_demo_copy.py")
    demo_guard = _run_step_index(demo_steps, GUARD_COMMAND)
    assert demo_guard == demo_copy + 1
