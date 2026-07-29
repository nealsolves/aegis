from __future__ import annotations

import ast
import builtins
from collections import Counter
import importlib
import importlib.util
import inspect
import re
import subprocess
import textwrap
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_doc_parity.py"


def _load_doc_parity_module():
    spec = importlib.util.spec_from_file_location("check_doc_parity_test", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_file(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def test_documentation_inventory_rejects_an_unclassified_tracked_doc(
    tmp_path, monkeypatch
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    _write_file(tmp_path, "docs/current.md", "# Current")
    _write_file(tmp_path, "docs/unclassified.md", "# Missing classification")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "add", "docs/current.md", "docs/unclassified.md"],
        cwd=tmp_path,
        check=True,
    )
    manifest = {
        "documentation_inventory": {
            "current": ["docs/current.md"],
            "target": [],
            "historical": [],
            "instruction_system": [],
        }
    }

    errors = module.check_documentation_inventory(manifest)

    assert errors == [
        "[documentation-inventory] unclassified tracked documentation: "
        "docs/unclassified.md"
    ]


def test_authoritative_policy_dsl_documents_the_workflow_schema():
    policy_dsl_spec = (
        SCRIPT_PATH.parents[1] / "policies" / "policy_dsl_spec.md"
    ).read_text(encoding="utf-8")

    for anchor in (
        "workflow",
        "participants",
        "sequence",
        "budgets",
        "approval_checkpoints",
        "protocol_constraints",
    ):
        assert anchor in policy_dsl_spec


def test_current_architecture_docs_describe_the_packaged_workflow_surface():
    root = SCRIPT_PATH.parents[1]
    for rel in (
        "docs/architecture/ARCHITECTURAL_INVARIANTS.md",
        "docs/architecture/ENFORCEMENT_PIPELINE.md",
    ):
        text = (root / rel).read_text(encoding="utf-8")
        for anchor in (
            "0.9.0b1",
            "GovernanceSession",
            "workflow trace",
            "workflow export",
        ):
            assert anchor in text, f"{rel} must include {anchor!r}"

    hld = (root / "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md").read_text(
        encoding="utf-8"
    )
    assert "Packaged beta public surface" in hld
    assert "Internal, not public" in hld
    assert "Not current public types" in hld
    assert "`ValidatorHook`" in hld
    assert "`AgentIdentity`" in hld
    assert "`AgentCapabilityManifest`" in hld


def test_released_quickstart_installs_the_pypi_distribution():
    root = SCRIPT_PATH.parents[1]
    quickstart = (root / "docs/reference/WORKFLOW_QUICKSTART.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(quickstart.lower().split())

    assert "git checkout v0.9.0b1" not in quickstart
    assert "pip install aegis-ai-governance==0.9.0b1" in quickstart
    assert "git switch develop" not in quickstart
    assert "after publication" not in normalized


def test_release_matrix_separates_package_and_current_docs_baselines():
    root = SCRIPT_PATH.parents[1]
    release_matrix = (root / "docs/reference/RELEASE_MATRIX.md").read_text(
        encoding="utf-8"
    )

    for anchor in (
        "8be5f54",
        "PR #17",
        "fdf3649",
        "PR #18",
        "merged",
        "Pending Trusted Publisher",
        "not on `main`",
        "not yet published to PyPI",
    ):
        assert anchor in release_matrix
    assert "under review in PR #17" not in release_matrix


def test_optional_adapter_reference_set_matches_the_packaged_submodules():
    root = SCRIPT_PATH.parents[1]
    external = root / "docs" / "reference" / "external"
    adapter_index = (external / "README.md").read_text(encoding="utf-8")

    assert (external / "BEDROCK_ADAPTER.md").exists()
    assert not (external / "what-is-bedrock.md").exists()
    for name in (
        "BEDROCK_ADAPTER.md",
        "A2A_ADAPTER.md",
        "OPENAI_AGENTS_ADAPTER.md",
    ):
        assert name in adapter_index

    bedrock = (external / "BEDROCK_ADAPTER.md").read_text(encoding="utf-8")
    for anchor in (
        "BedrockTraceAdapter",
        "BedrockParticipantBinding",
        "BedrockPreparedStep",
        "agent alias ARN",
        "require_trace",
        "require_alias_backed_identity",
        "host owns",
        "not re-exported",
    ):
        assert anchor in bedrock


def test_adapter_guides_use_packaged_candidate_status_and_exact_extra_install():
    root = SCRIPT_PATH.parents[1]
    external = root / "docs" / "reference" / "external"
    a2a = (external / "A2A_ADAPTER.md").read_text(encoding="utf-8")
    openai = (external / "OPENAI_AGENTS_ADAPTER.md").read_text(encoding="utf-8")

    for text in (a2a, openai):
        lower = text.lower()
        assert "aegis-ai-governance==0.9.0b1" in text
        assert "not re-exported" in lower
        assert "source-only" not in lower
        assert "local-only" not in lower

    assert 'pip install "aegis-ai-governance[openai-agents]"' in openai


def test_adapter_schema_and_release_gate_record_packaged_optional_status():
    root = SCRIPT_PATH.parents[1]
    for rel in (
        "schemas/policy_dsl.schema.json",
        "aegis/schemas/policy_dsl.schema.json",
    ):
        normalized = " ".join(
            (root / rel).read_text(encoding="utf-8").lower().split()
        )
        for adapter in ("bedrock", "a2a", "openai agents sdk"):
            assert f"{adapter} adapter constraints (packaged optional beta submodule)" in (
                normalized
            )
        assert "adapter constraints (source-only beta)" not in normalized

    release_gates = (root / "RELEASE_GATES.md").read_text(encoding="utf-8")
    assert "`A2AAdapter` is a packaged optional beta submodule" in release_gates
    assert "`A2AAdapter` is optional, source-only" not in release_gates


def test_instruction_guide_records_candidate_and_optional_adapter_status():
    root = SCRIPT_PATH.parents[1]
    guide = (root / ".claude" / "rules" / "aegis-project.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(guide.lower().split())

    assert "aegis-ai-governance==0.9.0b1" in guide
    assert "not published to pypi" in normalized
    for adapter in ("Bedrock", "A2A", "OpenAI Agents"):
        assert adapter in guide
    assert "published package version remains `0.3.3`" not in guide


AWS_KMS_ALGORITHMS = {
    "RSASSA_PSS_SHA_256",
    "ECDSA_SHA_256",
}

GOOGLE_KMS_ALGORITHMS = {
    "RSA_SIGN_PSS_2048_SHA256",
    "RSA_SIGN_PSS_3072_SHA256",
    "RSA_SIGN_PSS_4096_SHA256",
    "EC_SIGN_P256_SHA256",
}

AWS_GUIDE_IMPORTS = {
    ("aegis", "sign_artifact_with_metadata"),
    ("aegis", "verify_artifact_detailed"),
    ("aegis.integrations.aws_kms", "AwsKmsArtifactSigner"),
    ("aegis.integrations.aws_kms", "AwsKmsArtifactVerifier"),
    ("aegis.integrations.aws_kms", "AwsKmsVerificationTarget"),
    ("aegis.integrations.kms", "KmsKeyDisposition"),
}

GOOGLE_GUIDE_IMPORTS = {
    ("aegis", "sign_artifact_with_metadata"),
    ("aegis", "verify_artifact_detailed"),
    (
        "aegis.integrations.google_cloud_kms",
        "GoogleCloudKmsArtifactSigner",
    ),
    (
        "aegis.integrations.google_cloud_kms",
        "GoogleCloudKmsArtifactVerifier",
    ),
    (
        "aegis.integrations.google_cloud_kms",
        "GoogleCloudKmsVerificationTarget",
    ),
    ("aegis.integrations.kms", "KmsKeyDisposition"),
}

AWS_GUIDE_CALLS = {
    "AwsKmsArtifactSigner": 1,
    "sign_artifact_with_metadata": 1,
    "AwsKmsVerificationTarget": 1,
    "AwsKmsArtifactVerifier": 1,
    "verify_artifact_detailed": 1,
}

GOOGLE_GUIDE_CALLS = {
    "GoogleCloudKmsArtifactSigner": 1,
    "sign_artifact_with_metadata": 1,
    "GoogleCloudKmsVerificationTarget": 1,
    "GoogleCloudKmsArtifactVerifier": 1,
    "verify_artifact_detailed": 1,
}

KMS_PUBLIC_DOCS = (
    "README.md",
    "docs/INTEGRATION_GUIDE.md",
    "docs/PUBLIC_INTEGRATION_CONTRACT.md",
    "docs/reference/external/AWS_KMS_SIGNING.md",
    "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md",
)


def _python_fences(text: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", text, re.DOTALL)


def _markdown_section(text: str, heading: str) -> str:
    match = re.search(
        rf"(?ms)^{re.escape(heading)}[ \t]*\n(.*?)(?=^## |\Z)",
        text,
    )
    assert match is not None, f"missing Markdown section: {heading}"
    return match.group(1)


def _documented_algorithm_identifiers(text: str) -> set[str]:
    section = _markdown_section(text, "## Supported algorithms and identity")
    declaration = section.split("\n\n", 1)[0]
    inline_code = re.findall(r"(?<!`)`([^`\n]+)`(?!`)", declaration)
    return {
        identifier
        for identifier in inline_code
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", identifier)
    }


def _release_gate_kms_lanes(text: str) -> tuple[str, ...]:
    section = _markdown_section(
        text,
        "## Source-only KMS Adapter Release Gate",
    )
    bullet_items = re.findall(r"(?m)^- (.+?)[ \t]*$", section)
    lanes = []
    for item in bullet_items:
        match = re.fullmatch(r"`([a-z0-9]+(?:-[a-z0-9]+)*)`", item)
        assert match is not None, f"invalid KMS release lane item: {item}"
        lanes.append(match.group(1))
    return tuple(lanes)


def _assert_exact_kms_release_lanes(
    text: str,
    expected_lanes: set[str],
) -> None:
    lane_occurrences = _release_gate_kms_lanes(text)
    assert len(expected_lanes) == 7
    assert len(lane_occurrences) == 7
    assert len(set(lane_occurrences)) == len(lane_occurrences)
    assert set(lane_occurrences) == expected_lanes


def _is_aegis_module(module_name: str) -> bool:
    return module_name == "aegis" or module_name.startswith("aegis.")


def _assert_public_aegis_module(module_name: str) -> None:
    assert _is_aegis_module(module_name)
    assert all(
        not segment.startswith("_")
        for segment in module_name.split(".")[1:]
    )


_LOCAL_DIRECT_CALL = object()
_MISSING_DIRECT_CALL = object()
_BUILTIN_DIRECT_CALLS = frozenset(dir(builtins))
_KMS_EXAMPLE_COMPREHENSIONS = (
    ast.DictComp,
    ast.GeneratorExp,
    ast.ListComp,
    ast.SetComp,
)


class _KmsExampleScope:
    def __init__(
        self,
        kind: str,
        parent: _KmsExampleScope | None,
    ) -> None:
        self.kind = kind
        self.parent = parent
        self.bindings: dict[str, object] = {}


def _bind_kms_example_name(
    scope: _KmsExampleScope,
    name: str,
    binding: object = _LOCAL_DIRECT_CALL,
) -> None:
    existing = scope.bindings.get(name, _MISSING_DIRECT_CALL)
    if existing is _MISSING_DIRECT_CALL or existing == binding:
        scope.bindings[name] = binding
        return
    # Fail closed on source-order ambiguity: any local binding in this
    # lexical scope prevents the same name from counting as an AEGIS call.
    assert (
        existing is _LOCAL_DIRECT_CALL or binding is _LOCAL_DIRECT_CALL
    ), f"conflicting direct-call binding in KMS guide: {name}"
    scope.bindings[name] = _LOCAL_DIRECT_CALL


def _kms_example_enclosing_scope(scope: _KmsExampleScope) -> _KmsExampleScope:
    candidate = scope
    while candidate.kind == "class":
        assert candidate.parent is not None
        candidate = candidate.parent
    return candidate


def _bind_kms_parameters(
    scope: _KmsExampleScope,
    arguments: ast.arguments,
) -> None:
    for parameter in [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    ]:
        _bind_kms_example_name(scope, parameter.arg)
    for parameter in (arguments.vararg, arguments.kwarg):
        if parameter is not None:
            _bind_kms_example_name(scope, parameter.arg)


def _walk_kms_example(
    node: ast.AST,
    scope: _KmsExampleScope,
    scopes: dict[ast.AST, _KmsExampleScope],
    actual_imports: set[tuple[str, str]],
    actual_calls: Counter[str],
    *,
    collect: bool,
) -> None:
    def walk(
        child: ast.AST,
        child_scope: _KmsExampleScope = scope,
    ) -> None:
        _walk_kms_example(
            child,
            child_scope,
            scopes,
            actual_imports,
            actual_calls,
            collect=collect,
        )

    def nested_scope(kind: str) -> _KmsExampleScope:
        if not collect:
            return scopes[node]
        created = _KmsExampleScope(
            kind,
            _kms_example_enclosing_scope(scope),
        )
        scopes[node] = created
        return created

    assert not (
        isinstance(node, ast.NamedExpr)
        and scope.kind == "comprehension"
    ), "assignment expressions are unsupported in KMS guide comprehensions"

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        headers: list[ast.AST] = [*node.decorator_list, node.args]
        if node.returns is not None:
            headers.append(node.returns)
        headers.extend(getattr(node, "type_params", ()))
        if collect:
            _bind_kms_example_name(scope, node.name)
        body_scope = nested_scope("function")
        if collect:
            _bind_kms_parameters(body_scope, node.args)
        for child in headers:
            walk(child)
        for child in node.body:
            walk(child, body_scope)
        return

    if isinstance(node, ast.Lambda):
        body_scope = nested_scope("function")
        if collect:
            _bind_kms_parameters(body_scope, node.args)
        walk(node.args)
        walk(node.body, body_scope)
        return

    if isinstance(node, ast.ClassDef):
        headers = [
            *node.decorator_list,
            *node.bases,
            *node.keywords,
            *getattr(node, "type_params", ()),
        ]
        if collect:
            _bind_kms_example_name(scope, node.name)
        body_scope = nested_scope("class")
        for child in headers:
            walk(child)
        for child in node.body:
            walk(child, body_scope)
        return

    if isinstance(node, _KMS_EXAMPLE_COMPREHENSIONS):
        body_scope = nested_scope("comprehension")
        first_generator, *later_generators = node.generators
        assert not any(
            isinstance(candidate, ast.NamedExpr)
            for candidate in ast.walk(first_generator.iter)
        ), "assignment expressions are unsupported in KMS guide comprehensions"
        walk(first_generator.iter)
        for generator in [first_generator, *later_generators]:
            if generator is not first_generator:
                walk(generator.iter, body_scope)
            walk(generator.target, body_scope)
            for condition in generator.ifs:
                walk(condition, body_scope)
        values = (
            (node.key, node.value)
            if isinstance(node, ast.DictComp)
            else (node.elt,)
        )
        for value in values:
            walk(value, body_scope)
        return

    if collect and isinstance(node, ast.Import):
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".", 1)[0]
            if _is_aegis_module(alias.name):
                _assert_public_aegis_module(alias.name)
                actual_imports.add((alias.name, ""))
            _bind_kms_example_name(scope, local_name)
        return

    if collect and isinstance(node, ast.ImportFrom):
        assert node.level == 0
        module_name = node.module
        assert module_name is not None
        module = None
        if _is_aegis_module(module_name):
            _assert_public_aegis_module(module_name)
            module = importlib.import_module(module_name)
        for alias in node.names:
            assert alias.name != "*"
            local_name = alias.asname or alias.name
            if module is None:
                binding = _LOCAL_DIRECT_CALL
            else:
                assert not alias.name.startswith("_")
                actual_imports.add((module_name, alias.name))
                binding = (getattr(module, alias.name), alias.name)
            _bind_kms_example_name(scope, local_name, binding)
        return

    if (
        collect
        and isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
    ):
        _bind_kms_example_name(scope, node.id)
        return

    if (
        not collect
        and isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
    ):
        candidate: _KmsExampleScope | None = scope
        binding = _MISSING_DIRECT_CALL
        while candidate is not None:
            binding = candidate.bindings.get(
                node.func.id,
                _MISSING_DIRECT_CALL,
            )
            if binding is not _MISSING_DIRECT_CALL:
                break
            candidate = candidate.parent
        if (
            binding is _MISSING_DIRECT_CALL
            and node.func.id in _BUILTIN_DIRECT_CALLS
        ):
            binding = _LOCAL_DIRECT_CALL
        assert binding is not _MISSING_DIRECT_CALL, (
            f"unresolved direct call in KMS guide: {node.func.id}"
        )
        if binding is not _LOCAL_DIRECT_CALL:
            called, binding_name = binding
            actual_calls[binding_name] += 1
            assert not any(
                isinstance(argument, ast.Starred)
                for argument in node.args
            )
            assert all(keyword.arg is not None for keyword in node.keywords)
            positional = [object() for _argument in node.args]
            keywords = {
                keyword.arg: object()
                for keyword in node.keywords
                if keyword.arg is not None
            }
            inspect.signature(called).bind(*positional, **keywords)

    for child in ast.iter_child_nodes(node):
        walk(child)


def _assert_public_aegis_examples(
    text: str,
    expected_imports: set[tuple[str, str]],
    expected_calls: dict[str, int],
) -> None:
    actual_imports: set[tuple[str, str]] = set()
    actual_calls: Counter[str] = Counter()

    for index, sample in enumerate(_python_fences(text), start=1):
        tree = ast.parse(sample, filename=f"KMS guide Python fence {index}")
        module_scope = _KmsExampleScope("module", None)
        scopes = {tree: module_scope}
        _walk_kms_example(
            tree,
            module_scope,
            scopes,
            actual_imports,
            actual_calls,
            collect=True,
        )
        _walk_kms_example(
            tree,
            module_scope,
            scopes,
            actual_imports,
            actual_calls,
            collect=False,
        )

    assert actual_imports == expected_imports
    assert dict(actual_calls) == expected_calls


def test_kms_algorithm_parser_rejects_an_extra_backticked_identifier():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "The closed supported set is",
        "The closed supported set also includes `UNSUPPORTED_SHA_999`; "
        "originally it is",
        1,
    )

    assert _documented_algorithm_identifiers(mutated) == (
        AWS_KMS_ALGORITHMS | {"UNSUPPORTED_SHA_999"}
    )


def test_kms_algorithm_parser_ignores_identity_constants():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "`key_reference` is the host's configured selector",
        "`KEY_ID` is AWS terminology for a selector.\n\n"
        "`key_reference` is the host's configured selector",
        1,
    )
    assert mutated != aws

    assert _documented_algorithm_identifiers(mutated) == AWS_KMS_ALGORITHMS


def test_kms_lane_parser_rejects_an_eighth_release_lane():
    root = SCRIPT_PATH.parents[1]
    release_gates = (root / "RELEASE_GATES.md").read_text(encoding="utf-8")
    mutated = release_gates.replace(
        "- `combined-current-sdist`",
        "- `combined-current-sdist`\n- `eighth-kms-lane`",
        1,
    )

    assert _release_gate_kms_lanes(mutated) == (
        "base-wheel",
        "aws-min-wheel",
        "aws-current-wheel",
        "gcp-min-wheel",
        "gcp-current-wheel",
        "combined-current-wheel",
        "combined-current-sdist",
        "eighth-kms-lane",
    )


def test_kms_lane_validator_rejects_a_duplicate_release_lane():
    root = SCRIPT_PATH.parents[1]
    release_gates = (root / "RELEASE_GATES.md").read_text(encoding="utf-8")
    mutated = release_gates.replace(
        "- `combined-current-sdist`",
        "- `combined-current-sdist`\n- `combined-current-sdist`",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_exact_kms_release_lanes(
            mutated,
            {
                "base-wheel",
                "aws-min-wheel",
                "aws-current-wheel",
                "gcp-min-wheel",
                "gcp-current-wheel",
                "combined-current-wheel",
                "combined-current-sdist",
            },
        )


def test_kms_example_validator_rejects_a_plain_private_aegis_import():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "import boto3\n",
        "import boto3\nimport aegis._internal\n",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_a_moduleless_relative_import():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "import boto3\n",
        "import boto3\nfrom . import aegis\n",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_a_named_relative_import():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "import boto3\n",
        "import boto3\nfrom .host_helpers import helper\n",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_allows_a_defined_host_helper_call():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    extended = aws.replace(
        "import boto3\n",
        "import boto3\n\n"
        "def configure_host_client():\n"
        "    return None\n\n"
        "configure_host_client()\n",
        1,
    )

    _assert_public_aegis_examples(
        extended,
        AWS_GUIDE_IMPORTS,
        AWS_GUIDE_CALLS,
    )


def test_kms_example_validator_rejects_a_reassigned_aegis_import():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "sign_artifact_with_metadata(\n    artifact,",
        "sign_artifact_with_metadata = lambda *args, **kwargs: None\n"
        "sign_artifact_with_metadata(\n    artifact,",
        1,
    )
    assert mutated != aws

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_an_aegis_named_comprehension_target():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "sign_artifact_with_metadata(\n"
        "    artifact,\n"
        "    signer,\n"
        "    signed_at=int(time.time()),\n"
        ")",
        "[\n"
        "    sign_artifact_with_metadata(\n"
        "        artifact, signer, signed_at=int(time.time())\n"
        "    )\n"
        "    for sign_artifact_with_metadata in "
        "[lambda *args, **kwargs: None]\n"
        "]",
        1,
    )
    assert mutated != aws

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_a_comprehension_assignment_expression():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "from aegis import sign_artifact_with_metadata\n",
        "from aegis import sign_artifact_with_metadata\n"
        "[\n"
        "    None\n"
        "    for _ in (1,)\n"
        "    if (\n"
        "        sign_artifact_with_metadata := "
        "lambda *args, **kwargs: None\n"
        "    )\n"
        "]\n",
        1,
    )
    assert mutated != aws

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_a_first_iterable_assignment_expression():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(
        "from aegis import sign_artifact_with_metadata\n",
        "from aegis import sign_artifact_with_metadata\n"
        "[None for _ in (host_values := [1])]\n",
        1,
    )
    assert mutated != aws

    with pytest.raises(
        AssertionError,
        match="assignment expressions are unsupported",
    ):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


@pytest.mark.parametrize(
    ("anchor", "replacement", "unresolved_name"),
    [
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                def sibling_definer():
                    def sign_artifact_with_metadatum():
                        return None

                def sibling_caller():
                    sign_artifact_with_metadatum()

                sibling_caller()
                """
            ),
            "sign_artifact_with_metadatum",
            id="sibling-nested-helper",
        ),
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                def configure_host(enabled):
                    if enabled:
                        missing_host_setup()

                configure_host(True)
                """
            ),
            "missing_host_setup",
            id="unresolved-control-flow",
        ),
        pytest.param(
            "from aegis import sign_artifact_with_metadata\n",
            "def bind_sign_helper():\n"
            "    from aegis import sign_artifact_with_metadata\n",
            "sign_artifact_with_metadata",
            id="local-aegis-import",
        ),
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                def define_host_factory():
                    class HostFactory:
                        pass

                def create_host_client():
                    HostFactory()

                create_host_client()
                """
            ),
            "HostFactory",
            id="sibling-local-class",
        ),
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                def keep_callback(callback):
                    return callback

                def run_host_callback():
                    callback()

                run_host_callback()
                """
            ),
            "callback",
            id="sibling-parameter",
        ),
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                class HostConfiguration:
                    class HostFactory:
                        pass

                    def create_host_client(self):
                        HostFactory()

                HostConfiguration()
                """
            ),
            "HostFactory",
            id="class-binding-from-method",
        ),
        pytest.param(
            "import boto3\n",
            textwrap.dedent(
                """\
                import boto3

                class HostConfiguration:
                    def configure_host_client():
                        return None

                    clients = [
                        configure_host_client()
                        for _ in range(1)
                    ]

                HostConfiguration()
                """
            ),
            "configure_host_client",
            id="class-binding-from-comprehension",
        ),
    ],
)
def test_kms_example_validator_rejects_out_of_scope_direct_call(
    anchor,
    replacement,
    unresolved_name,
):
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = aws.replace(anchor, replacement, 1)
    assert mutated != aws

    with pytest.raises(
        AssertionError,
        match=rf"unresolved direct call.*{unresolved_name}",
    ):
        _assert_public_aegis_examples(
            mutated,
            AWS_GUIDE_IMPORTS,
            AWS_GUIDE_CALLS,
        )


@pytest.mark.parametrize(
    "extension",
    [
        pytest.param(
            textwrap.dedent(
                """\
                def configure_host():
                    def configure_host_client():
                        return None

                    configure_host_client()

                configure_host()
                """
            ),
            id="enclosing-nested-helper",
        ),
        pytest.param(
            textwrap.dedent(
                """\
                def configure_host_client():
                    return None

                def configure_host():
                    configure_host_client()

                configure_host()
                """
            ),
            id="module-helper-in-function",
        ),
        pytest.param(
            textwrap.dedent(
                """\
                def run_host_callback(callback):
                    callback()

                run_host_callback(lambda: None)
                """
            ),
            id="callable-function-parameter",
        ),
        pytest.param(
            textwrap.dedent(
                """\
                configure_host_client = lambda: None
                configure_host_client()
                """
            ),
            id="lambda-assigned-host-helper",
        ),
    ],
)
def test_kms_example_validator_allows_lexically_available_direct_call(
    extension,
):
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    extended = aws.replace(
        "import boto3\n",
        f"import boto3\n\n{extension}",
        1,
    )
    assert extended != aws

    _assert_public_aegis_examples(
        extended,
        AWS_GUIDE_IMPORTS,
        AWS_GUIDE_CALLS,
    )


def test_kms_example_validator_rejects_a_typoed_intended_helper_call():
    root = SCRIPT_PATH.parents[1]
    google = (
        root / "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = google.replace(
        "sign_artifact_with_metadata(",
        "sign_artifact_with_metadatum(",
        1,
    )

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            GOOGLE_GUIDE_IMPORTS,
            GOOGLE_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_an_extra_unresolved_call():
    root = SCRIPT_PATH.parents[1]
    google = (
        root / "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = google.replace(
        "    signed_at=int(time.time()),\n)\n```",
        "    signed_at=int(time.time()),\n)\n"
        "sign_artifact_with_metadatum()\n```",
        1,
    )
    assert mutated != google

    with pytest.raises(AssertionError):
        _assert_public_aegis_examples(
            mutated,
            GOOGLE_GUIDE_IMPORTS,
            GOOGLE_GUIDE_CALLS,
        )


def test_kms_example_validator_rejects_a_wrong_public_keyword():
    root = SCRIPT_PATH.parents[1]
    google = (
        root / "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    mutated = google.replace(
        "signed_at=int(time.time()),",
        "signed_when=int(time.time()),",
        1,
    )

    with pytest.raises(TypeError):
        _assert_public_aegis_examples(
            mutated,
            GOOGLE_GUIDE_IMPORTS,
            GOOGLE_GUIDE_CALLS,
        )


def test_kms_guides_publish_exact_extras_algorithms_and_compilable_examples():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    google = (
        root / "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")

    assert 'pip install "aegis-ai-governance[aws-kms]"' in aws
    assert 'pip install "aegis-ai-governance[gcp-kms]"' in google

    assert _documented_algorithm_identifiers(aws) == AWS_KMS_ALGORITHMS
    assert (
        _documented_algorithm_identifiers(google)
        == GOOGLE_KMS_ALGORITHMS
    )
    _assert_public_aegis_examples(
        aws,
        AWS_GUIDE_IMPORTS,
        AWS_GUIDE_CALLS,
    )
    _assert_public_aegis_examples(
        google,
        GOOGLE_GUIDE_IMPORTS,
        GOOGLE_GUIDE_CALLS,
    )


def test_kms_guides_preserve_provider_identity_and_verification_boundaries():
    root = SCRIPT_PATH.parents[1]
    aws = (
        root / "docs/reference/external/AWS_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    google = (
        root / "docs/reference/external/GOOGLE_CLOUD_KMS_SIGNING.md"
    ).read_text(encoding="utf-8")
    combined = f"{aws}\n{google}".lower()

    assert "logical-key identity" in aws.lower()
    assert "backing-material version" in aws.lower()
    for partition in (
        "aws",
        "aws-cn",
        "aws-us-gov",
        "aws-iso",
        "aws-iso-b",
        "aws-iso-e",
        "aws-iso-f",
        "aws-eusc",
    ):
        assert f"`{partition}`" in aws

    for anchor in (
        "public_key.data",
        "crc32c",
        "retained pem",
        "exact cryptokeyversion",
    ):
        assert anchor in google.lower()

    assert "artifact metadata does not select provider resources" in combined
    for responsibility in (
        "clients",
        "credentials",
        "retry",
        "timeout",
        "endpoints",
        "regional",
        "project configuration",
        "iam",
        "trust policy",
        "retained evidence",
    ):
        assert responsibility in combined


def test_kms_docs_make_only_bounded_operational_and_compliance_claims():
    root = SCRIPT_PATH.parents[1]
    adr = (
        root / "docs/decisions/ADR-0013-aws-google-kms-adapters.md"
    ).read_text(encoding="utf-8")
    public_text = "\n".join(
        (root / rel).read_text(encoding="utf-8") for rel in KMS_PUBLIC_DOCS
    )
    combined = " ".join(f"{adr}\n{public_text}".lower().split())

    for non_claim in (
        "immutable logging",
        "trusted time",
        "complete history",
        "hsm/fips status",
        "certification",
    ):
        assert f"does not claim {non_claim}" in combined

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    source_only = changelog.split("## [0.9.0b1]", 1)[0]
    assert "AWS KMS" in source_only
    assert "Google Cloud KMS" in source_only


def test_release_gates_publish_the_exact_optional_extra_artifact_lanes():
    root = SCRIPT_PATH.parents[1]
    release_gates = (root / "RELEASE_GATES.md").read_text(encoding="utf-8")
    expected_lanes = {
        "base-wheel",
        "aws-min-wheel",
        "aws-current-wheel",
        "gcp-min-wheel",
        "gcp-current-wheel",
        "combined-current-wheel",
        "combined-current-sdist",
    }

    _assert_exact_kms_release_lanes(release_gates, expected_lanes)


REFERENCE_TABLE = """
| PR | Branch | Goal |
|----|--------|------|
| PR-01 | `feat/v0.9-01-source-of-truth` | Canonical plan, release packet, and CI truth checks |
| PR-07 | `feat/v0.9-07-beta-proof` | Mandatory stop-ship checkpoint |
| PR-11 | `feat/v0.9-11-beta-freeze` -> `release/v0.9.0` | Final beta freeze and release cut |
"""

FREEZE_GO_RULE = """
Do NOT open or merge a PR from `origin/develop` -> `origin/main` until
`v0.9.0` is formally declared a GO.
"""

STOP_SHIP_RULE = """
PR-07 is the mandatory stop-ship checkpoint. If the golden path fails there,
no further public-surface work proceeds until the default path is repaired.
"""


def _make_release_doc(
    *,
    table: str = REFERENCE_TABLE,
    freeze_rule: str = FREEZE_GO_RULE,
    stop_ship_rule: str = STOP_SHIP_RULE,
    extra: str = "",
) -> str:
    table = textwrap.dedent(table).strip()
    freeze_rule = textwrap.dedent(freeze_rule).strip()
    stop_ship_rule = textwrap.dedent(stop_ship_rule).strip()
    extra = textwrap.dedent(extra).strip()
    return f"""
    # Release Truth

    {freeze_rule}

    ## PR Table

    {table}

    {stop_ship_rule}

    {extra}
    """


def _seed_release_truth_repo(root: Path, *, pr_context: str, release_gates: str,
                             implementation_status: str) -> None:
    _write_file(
        root,
        "CLAUDE.md",
        _make_release_doc(extra="Active branch: `feat/v0.9-01-source-of-truth`"),
    )
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "RELEASE_GATES.md", release_gates)
    _write_file(root, "implementation_status.md", implementation_status)


def test_v090_release_truth_accepts_exact_row_mapping_and_coupled_freeze(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    good_doc = _make_release_doc(extra="Active branch: `feat/v0.9-01-source-of-truth`")
    _seed_release_truth_repo(
        tmp_path,
        pr_context=good_doc,
        release_gates=good_doc,
        implementation_status=good_doc,
    )

    assert module.check_v090_release_truth() == []


def test_v090_release_truth_rejects_row_level_pr_branch_mismatch(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    mismatched_table = """
    | PR | Branch | Goal |
    |----|--------|------|
    | PR-01 | `feat/v0.9-07-beta-proof` | Wrong branch mapping |
    | PR-07 | `feat/v0.9-07-beta-proof` | Mandatory stop-ship checkpoint |
    | PR-11 | `feat/v0.9-11-beta-freeze` -> `release/v0.9.0` | Final beta freeze and release cut |
    """
    mismatched_doc = _make_release_doc(
        table=mismatched_table,
        extra="Active branch: `feat/v0.9-01-source-of-truth`",
    )
    good_doc = _make_release_doc(extra="Active branch: `feat/v0.9-01-source-of-truth`")

    _seed_release_truth_repo(
        tmp_path,
        pr_context=mismatched_doc,
        release_gates=good_doc,
        implementation_status=good_doc,
    )

    errors = module.check_v090_release_truth()
    joined = "\n".join(errors)

    assert "docs/dev/pr_context.md: PR-01 row maps to" in joined, errors


_CANONICAL_PLAN_REL = "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md"
_HISTORICAL_PLAN_RELS = [
    "docs/plans/0.9.0 plan backup.md",
    "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN_DRAFT.md",
    "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN_DRAFT_ORIG.md",
    "docs/plans/AEGIS_v0.9.0_IMPLEMENTATION_PLAN_UPDATED.md",
]

_CANONICAL_PLAN_CONTENT = """\
# AEGIS v0.9.0 Implementation Plan

This document is the canonical implementation plan for the v0.9.0 beta.
"""

_HISTORICAL_PLAN_CONTENT = (
    "> Superseded on 2026-04-15.\n"
    f"> Active file: `{_CANONICAL_PLAN_REL}`.\n"
    "> Status: historical input only for PR-01 source-of-truth review.\n"
)


def _seed_plan_truth_repo(
    root: Path, *, canonical_content: str, stale_content: str
) -> None:
    _write_file(root, _CANONICAL_PLAN_REL, canonical_content)
    for rel in _HISTORICAL_PLAN_RELS:
        _write_file(root, rel, stale_content)


def test_v090_plan_truth_accepts_one_canonical_and_marked_stale_variants(
    tmp_path, monkeypatch
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_plan_truth_repo(
        tmp_path,
        canonical_content=_CANONICAL_PLAN_CONTENT,
        stale_content=_HISTORICAL_PLAN_CONTENT,
    )

    assert module.check_v090_plan_truth() == []


def test_v090_plan_truth_rejects_stale_plan_missing_supersession_banner(
    tmp_path, monkeypatch
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    no_banner = "# AEGIS v0.9.0 Draft\n\nNo supersession notice.\n"

    _seed_plan_truth_repo(
        tmp_path,
        canonical_content=_CANONICAL_PLAN_CONTENT,
        stale_content=no_banner,
    )

    errors = module.check_v090_plan_truth()
    joined = "\n".join(errors)
    assert "stale plan is not marked superseded" in joined, errors


def test_v090_release_truth_rejects_uncoupled_freeze_and_go_statements(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    uncoupled_freeze = """
    Do NOT open or merge a PR from `origin/develop` -> `origin/main`.

    `v0.9.0` is formally declared a GO by the release review.
    """
    uncoupled_doc = _make_release_doc(freeze_rule=uncoupled_freeze)
    good_doc = _make_release_doc(extra="Active branch: `feat/v0.9-01-source-of-truth`")

    _seed_release_truth_repo(
        tmp_path,
        pr_context=good_doc,
        release_gates=uncoupled_doc,
        implementation_status=good_doc,
    )

    errors = module.check_v090_release_truth()

    assert any(
        "RELEASE_GATES.md: missing explicit origin/main freeze language tied to formal GO"
        in error
        for error in errors
    )


_PR02_PLAN_CONTENT = """\
# AEGIS v0.9.0 Implementation Plan

### Public surface and migration posture

- `v0.9.0` does not introduce a new module-level `open_session(...)` public API.
- `GovernanceSession`, `SessionPreCallResult`, and `AEGIS.open_session(...)`
  are frozen as planned-only contract surfaces before runtime work lands.
  PR-02 documents and tests them; it does not ship placeholder runtime stubs.

### Session and artifact semantics

Canonical session lifecycle states:

- `OPEN`
- `PAUSED`
- `FAILED`
- `COMPLETED`
- `CANCELED`
- `FINALIZED`

Canonical workflow artifact `status` values:

- `COMPLETED`
- `FAILED`
- `CANCELED`
- `INCOMPLETE`

Rules:

- `FINALIZED` is a lifecycle state only and is never serialized as an artifact status.
- `finalize()` from `OPEN` or `PAUSED` is allowed and emits `INCOMPLETE`.

### `SessionPreCallResult` semantics

- `SessionPreCallResult` wraps a valid invocation `PreCallResult` plus immutable `session_id`, `step_id`, `participant_id`, and workflow-bound replay protection.
- The wrapper is single-use.
- A wrapped token cannot be completed through module-level `enforce_post_call(...)`; it must be completed through the owning `GovernanceSession`.
- Session completion validates both underlying invocation integrity and workflow-step binding before post-call enforcement proceeds.

### Bedrock contract lock

- Governed Bedrock handoffs require alias-backed participant identity.
- Descriptive names such as `collaboratorName` are descriptive evidence only and cannot be the sole binding key for governed authorization.

### A2A contract lock

- gRPC is out of scope for `v0.9.0` normalization and must fail with a typed protocol violation.
- Compatibility is validated from `supportedInterfaces[].protocolVersion`, not descriptive Agent Card version text.
- Wire task states must validate as normative ProtoJSON `TASK_STATE_*` values.
- Informal or shorthand task-state names are rejected at the boundary.
"""

_PR02_HLD_CONTENT = """\
# AEGIS High-Level Design

Availability boundary: this document describes the intended `1.0.0` public
surface. The shipped `0.3.3` package and CLI do not yet export
`GovernanceSession`, `SessionPreCallResult`, `AgentIdentity`,
`AgentCapabilityManifest`, `ValidatorHook`, `BedrockTraceAdapter`,
`A2AAdapter`, or `aegis workflow ...` commands, and `AEGIS.open_session(...)`
is not part of the installable runtime yet.

### 7.1 Session Lifecycle

Canonical lifecycle states:

- `OPEN`
- `PAUSED`
- `FAILED`
- `COMPLETED`
- `CANCELED`
- `FINALIZED`

Canonical serialized workflow artifact `status` values:

- `COMPLETED`
- `FAILED`
- `CANCELED`
- `INCOMPLETE`

| Lifecycle condition when the workflow artifact is emitted | Serialized `status` |
| --------------------------------------------------------- | ------------------- |
| `OPEN` or `PAUSED` finalized without terminal completion | `INCOMPLETE` |

Rules:

- `FINALIZED` is a lifecycle state only. It is never serialized as a workflow artifact `status`.

Workflow adoption remains instance-scoped through `AEGIS.open_session(...)`.
The target design does not add a module-level `open_session(...)` convenience.

### 10.1 Bedrock Adapter

- when policy requires trace, Bedrock trace is mandatory and missing trace fails closed
- alias-backed collaborator identity is required for governed participant binding; `collaboratorName` alone is descriptive evidence only

### 10.2 A2A Adapter

- `GRPC`

- compatibility is validated from `supportedInterfaces[].protocolVersion`, not descriptive Agent Card version text
- non-normative or shorthand task-state names are rejected at the boundary
"""

_PR02_README_CONTENT = """\
# README

The target-state `1.0.0` architecture expands this invocation-first model with
planned workflow governance built around `AEGIS.open_session(...)`,
`GovernanceSession`, `SessionPreCallResult`, and optional Bedrock/A2A
normalization adapters. These remain planned-only surfaces today and are not
part of the shipped `v0.3.3` runtime or CLI.
"""

_PR02_PUBLIC_CONTRACT_CONTENT = """\
# Public Contract

Planned-only surfaces described in that target-state document — including
`AEGIS.open_session(...)`, `GovernanceSession`, `SessionPreCallResult`,
`AgentIdentity`, `AgentCapabilityManifest`, `ValidatorHook`,
`BedrockTraceAdapter`, `A2AAdapter`, and `aegis workflow ...` commands — are
not part of the installable `v0.3.3` artifact today. There is no current
module-level `open_session()` convenience in the shipped package.
"""

_PR02_PR_CONTEXT_CONTENT = """\
# PR Context

Active branch: `feat/v0.9-02-contract-freeze`

PR type:

- docs, CI, and sentinel tests only

Contract Notes

- PR-02 is docs, CI, and sentinel tests only. Workflow runtime implementation
  starts in PR-04.
"""

_PR02_RELEASE_GATES_CONTENT = """\
# Release Gates

## PR-02 — Contract Freeze Gate

- [ ] public-surface sentinel tests confirm no workflow runtime or workflow CLI
      surface shipped early
- [ ] protocol-boundary contract tests freeze Bedrock and A2A fail-closed
      rules without runtime adapters
"""

_PR02_IMPLEMENTATION_STATUS_CONTENT = """\
# Implementation Status

**Active Branch:** `feat/v0.9-02-contract-freeze`

- PR-02 is contract freeze only. It updates docs, CI, and sentinel tests only.
- Workflow runtime implementation begins in PR-04.

## PR-02 Deliverables
"""


def _seed_pr02_contract_repo(
    root: Path,
    *,
    plan: str = _PR02_PLAN_CONTENT,
    hld: str = _PR02_HLD_CONTENT,
    readme: str = _PR02_README_CONTENT,
    public_contract: str = _PR02_PUBLIC_CONTRACT_CONTENT,
    pr_context: str = _PR02_PR_CONTEXT_CONTENT,
    release_gates: str = _PR02_RELEASE_GATES_CONTENT,
    implementation_status: str = _PR02_IMPLEMENTATION_STATUS_CONTENT,
) -> None:
    _write_file(root, "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md", plan)
    _write_file(root, "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md", hld)
    _write_file(root, "README.md", readme)
    _write_file(root, "docs/PUBLIC_INTEGRATION_CONTRACT.md", public_contract)
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "RELEASE_GATES.md", release_gates)
    _write_file(root, "implementation_status.md", implementation_status)


def test_v090_pr02_contract_accepts_frozen_contract_docs(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr02_contract_repo(tmp_path)

    assert module.check_v090_pr02_contract() == []


def test_v090_pr02_contract_rejects_lifecycle_state_drift(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_plan = _PR02_PLAN_CONTENT.replace("- `FINALIZED`\n", "")
    _seed_pr02_contract_repo(tmp_path, plan=bad_plan)

    errors = module.check_v090_pr02_contract()
    joined = "\n".join(errors)

    assert "session lifecycle states list" in joined, errors


def test_v090_pr02_contract_rejects_missing_planned_only_boundary(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_public_contract = _PR02_PUBLIC_CONTRACT_CONTENT.replace(
        "There is no current\nmodule-level `open_session()` convenience in the shipped package.\n",
        "",
    )
    _seed_pr02_contract_repo(tmp_path, public_contract=bad_public_contract)

    errors = module.check_v090_pr02_contract()

    assert any(
        "missing planned-only public integration boundary" in error
        for error in errors
    ), errors


def test_v090_pr02_contract_rejects_missing_a2a_protocol_version_rule(
    tmp_path, monkeypatch
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_hld = _PR02_HLD_CONTENT.replace(
        "- compatibility is validated from `supportedInterfaces[].protocolVersion`, not descriptive Agent Card version text\n",
        "",
    )
    _seed_pr02_contract_repo(tmp_path, hld=bad_hld)

    errors = module.check_v090_pr02_contract()

    assert any(
        "missing frozen HLD contract" in error and "supportedInterfaces[].protocolVersion" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("override_key", "bad_content", "expected_label", "expected_needle"),
    [
        (
            "plan",
            _PR02_PLAN_CONTENT.replace(
                "- gRPC is out of scope for `v0.9.0` normalization and must fail with a typed protocol violation.\n",
                "",
            ),
            "missing frozen plan contract",
            "gRPC is out of scope",
        ),
        (
            "readme",
            _PR02_README_CONTENT.replace("`SessionPreCallResult`, and optional Bedrock/A2A\n", ""),
            "missing planned-only README boundary",
            "`SessionPreCallResult`",
        ),
        (
            "pr_context",
            _PR02_PR_CONTEXT_CONTENT.replace(
                "Active branch: `feat/v0.9-02-contract-freeze`\n\n",
                "",
            ),
            "missing PR-02 branch and scope",
            "feat/v0.9-02-contract-freeze",
        ),
        (
            "release_gates",
            _PR02_RELEASE_GATES_CONTENT.replace(
                "## PR-02 — Contract Freeze Gate\n\n",
                "",
            ),
            "missing PR-02 release gate",
            "## PR-02 — Contract Freeze Gate",
        ),
        (
            "implementation_status",
            _PR02_IMPLEMENTATION_STATUS_CONTENT.replace("## PR-02 Deliverables\n", ""),
            "missing PR-02 implementation status",
            "## PR-02 Deliverables",
        ),
        (
            "hld",
            _PR02_HLD_CONTENT.replace("- `GRPC`\n\n", ""),
            "missing frozen HLD contract",
            "`GRPC`",
        ),
    ],
)
def test_v090_pr02_contract_rejects_missing_required_rules(
    tmp_path, monkeypatch, override_key, bad_content, expected_label, expected_needle
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr02_contract_repo(tmp_path, **{override_key: bad_content})

    errors = module.check_v090_pr02_contract()

    assert any(
        expected_label in error and expected_needle in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    ("override_key", "bad_content", "expected_rel", "expected_list_name"),
    [
        (
            "hld",
            _PR02_HLD_CONTENT.replace("- `FINALIZED`\n", ""),
            "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md",
            "session lifecycle states list",
        ),
        (
            "plan",
            _PR02_PLAN_CONTENT.replace("- `INCOMPLETE`\n", ""),
            "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md",
            "workflow artifact statuses list",
        ),
        (
            "hld",
            _PR02_HLD_CONTENT.replace("- `INCOMPLETE`\n", ""),
            "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md",
            "workflow artifact statuses list",
        ),
    ],
)
def test_v090_pr02_contract_rejects_other_exact_list_drifts(
    tmp_path, monkeypatch, override_key, bad_content, expected_rel, expected_list_name
):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr02_contract_repo(tmp_path, **{override_key: bad_content})

    errors = module.check_v090_pr02_contract()

    assert any(
        expected_rel in error and expected_list_name in error
        for error in errors
    ), errors


_PR03_PLAN_CONTENT = """\
# AEGIS v0.9.0 Implementation Plan

### Public surface and migration posture

- The frozen golden-path CLI inventory is `aegis policy init`, `aegis workflow init`, `aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`, and `aegis workflow export`.
- Public examples, quickstarts, starter assets, presets, recipes, and demo code must use only public APIs and must never import from `aegis._internal`.
- Hand-authored workflow DSL remains supported but is advanced mode.

### Golden-path contract freeze

Frozen CLI command inventory:

- `aegis policy init`
- `aegis workflow init`
- `aegis workflow lint`
- `aegis workflow doctor`
- `aegis workflow trace`
- `aegis workflow export`

Frozen scaffold profiles:

- `minimal`
- `standard`
- `regulated-high-assurance`

Required starter coverage:

- local multi-step review
- approval checkpoint
- source required
- tool budget

Frozen first-user diagnostic reason codes:

- `WORKFLOW_INVALID_TRANSITION`
- `WORKFLOW_APPROVAL_REQUIRED`
- `WORKFLOW_SOURCE_REQUIRED`
- `WORKFLOW_TOOL_BUDGET_EXCEEDED`
- `WORKFLOW_UNSUPPORTED_BINDING`
- `WORKFLOW_SESSION_TOKEN_INVALID`
- `WORKFLOW_STARTER_INTEGRITY_ERROR`

Frozen first-adopter docs order:

1. workflow quickstart
2. migration from invocation-only to workflow
3. troubleshooting and `workflow doctor` / `workflow lint` guide
4. starter recipes and starter index
5. workflow CLI guide
6. public API boundary and integration contract
7. supported environments
8. operations runbook
9. adapter docs as advanced follow-on material
"""

_PR03_HLD_CONTENT = """\
# AEGIS High-Level Design

Availability boundary: this document describes the intended `1.0.0` public
surface. The shipped `0.3.3` package and CLI do not yet export
`GovernanceSession`, `SessionPreCallResult`, `AgentIdentity`,
`AgentCapabilityManifest`, `ValidatorHook`, `BedrockTraceAdapter`,
`A2AAdapter`, `aegis policy init`, or `aegis workflow ...` commands, and
`AEGIS.open_session(...)` is not part of the installable runtime yet.

### 13.4 Frozen First-Adopter Contract

Frozen CLI command inventory:

- `aegis policy init`
- `aegis workflow init`
- `aegis workflow lint`
- `aegis workflow doctor`
- `aegis workflow trace`
- `aegis workflow export`

Frozen scaffold profiles:

- `minimal`
- `standard`
- `regulated-high-assurance`

Required starter coverage:

- local multi-step review
- approval checkpoint
- source required
- tool budget

Rules:

- hand-authored workflow DSL remains supported as advanced mode and is not required for the default path
- public quickstarts, starter packs, presets, demo code, and docs snippets must use public `aegis` imports only and must not depend on `aegis._internal`

Frozen first-user diagnostic reason codes:

- `WORKFLOW_INVALID_TRANSITION`
- `WORKFLOW_APPROVAL_REQUIRED`
- `WORKFLOW_SOURCE_REQUIRED`
- `WORKFLOW_TOOL_BUDGET_EXCEEDED`
- `WORKFLOW_UNSUPPORTED_BINDING`
- `WORKFLOW_SESSION_TOKEN_INVALID`
- `WORKFLOW_STARTER_INTEGRITY_ERROR`

Frozen first-adopter docs order:

1. workflow quickstart
2. migration from invocation-only to workflow
3. troubleshooting and `workflow doctor` / `workflow lint` guide
4. starter recipes and starter index
5. workflow CLI guide
6. public API boundary and integration contract
7. supported environments
8. operations runbook
9. adapter docs as advanced follow-on material
"""

_PR03_README_CONTENT = """\
# README

The planned golden-path CLI names — `aegis policy init`, `aegis workflow init`,
`aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`, and
`aegis workflow export` — are also frozen in the repo docs, but none of those
workflow surfaces are part of the shipped `v0.3.3` runtime or CLI.
"""

_PR03_PUBLIC_CONTRACT_CONTENT = """\
# Public Contract

Planned-only surfaces described in that target-state document — including
`aegis policy init` and `aegis workflow ...` commands — are not part of the
installable `v0.3.3` artifact today.

All public examples, starter packs, presets, demo code, and docs snippets
must use public `aegis` imports only and must not depend on `aegis._internal`.
"""

_PR03_PR_CONTEXT_CONTENT = """\
# PR Context

Active branch: `feat/v0.9-03-golden-path-contract`

PR type:

- docs, CI, sentinel tests, and public-import hygiene only

Contract Notes

- The frozen golden-path CLI inventory is `aegis policy init`, `aegis workflow init`, `aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`, and `aegis workflow export`, but those commands are still absent from the shipped `v0.3.3` CLI in PR-03.
- PR-03 is docs, CI, sentinel tests, and public-import hygiene only. Workflow runtime implementation still starts in PR-04.
"""

_PR03_RELEASE_GATES_CONTENT = """\
# Release Gates

## PR-03 — Golden-Path Contract Freeze Gate

- [ ] staged CLI sentinel tests prove the current shipped CLI still exposes no `workflow` or `policy init` commands while freezing the future command names in docs
- [ ] public-import boundary tests confirm maintained onboarding examples and demo code use public `aegis` imports only
"""

_PR03_IMPLEMENTATION_STATUS_CONTENT = """\
# Implementation Status

**Active Branch:** `feat/v0.9-03-golden-path-contract`

- PR-03 is golden-path contract freeze only. It updates docs, CI, sentinel tests, and public-import hygiene only.

## PR-03 Deliverables
"""


def _seed_pr03_contract_repo(
    root: Path,
    *,
    plan: str = _PR03_PLAN_CONTENT,
    hld: str = _PR03_HLD_CONTENT,
    readme: str = _PR03_README_CONTENT,
    public_contract: str = _PR03_PUBLIC_CONTRACT_CONTENT,
    pr_context: str = _PR03_PR_CONTEXT_CONTENT,
    release_gates: str = _PR03_RELEASE_GATES_CONTENT,
    implementation_status: str = _PR03_IMPLEMENTATION_STATUS_CONTENT,
) -> None:
    _write_file(root, "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md", plan)
    _write_file(root, "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md", hld)
    _write_file(root, "README.md", readme)
    _write_file(root, "docs/PUBLIC_INTEGRATION_CONTRACT.md", public_contract)
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "RELEASE_GATES.md", release_gates)
    _write_file(root, "implementation_status.md", implementation_status)


def test_v090_pr03_contract_accepts_frozen_golden_path_docs(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr03_contract_repo(tmp_path)

    assert module.check_v090_pr03_contract() == []


def test_v090_pr03_contract_rejects_cli_inventory_drift(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_plan = _PR03_PLAN_CONTENT.replace("- `aegis policy init`\n", "")
    _seed_pr03_contract_repo(tmp_path, plan=bad_plan)

    errors = module.check_v090_pr03_contract()

    assert any(
        "CLI command inventory list" in error
        and "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md" in error
        for error in errors
    ), errors


def test_v090_pr03_contract_rejects_docs_order_drift(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_hld = _PR03_HLD_CONTENT.replace(
        "5. workflow CLI guide\n6. public API boundary and integration contract\n",
        "5. public API boundary and integration contract\n6. workflow CLI guide\n",
    )
    _seed_pr03_contract_repo(tmp_path, hld=bad_hld)

    errors = module.check_v090_pr03_contract()

    assert any(
        "first-adopter docs order list" in error
        and "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md" in error
        for error in errors
    ), errors


def test_v090_pr03_contract_rejects_missing_readme_cli_boundary(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_readme = _PR03_README_CONTENT.replace("`aegis policy init`, ", "")
    _seed_pr03_contract_repo(tmp_path, readme=bad_readme)

    errors = module.check_v090_pr03_contract()

    assert any(
        "missing planned-only README CLI boundary" in error
        and "`aegis policy init`" in error
        for error in errors
    ), errors


def test_v090_pr03_contract_rejects_missing_release_gate(tmp_path, monkeypatch):
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_release_gates = _PR03_RELEASE_GATES_CONTENT.replace(
        "## PR-03 — Golden-Path Contract Freeze Gate\n\n",
        "",
    )
    _seed_pr03_contract_repo(tmp_path, release_gates=bad_release_gates)

    errors = module.check_v090_pr03_contract()

    assert any(
        "missing PR-03 release gate" in error
        and "## PR-03 — Golden-Path Contract Freeze Gate" in error
        for error in errors
    ), errors


# ---------------------------------------------------------------------------
# PR-04 Seeded Contract Tests
# ---------------------------------------------------------------------------

_PR04_PLAN_CONTENT = """\
# AEGIS v0.9.0 Implementation Plan

PR-04 implements GovernanceSession, AEGIS.open_session(...), and SessionPreCallResult.
"""

_PR04_HLD_CONTENT = """\
# AEGIS High Level Design

Availability boundary: The currently shipped package remains v0.3.3.
The upcoming unreleased v0.9.0-beta line will add GovernanceSession, SessionPreCallResult,
and AEGIS.open_session(...).

## Planned for v0.9.0-beta (not yet released)

| Surface | Intended role |
| ------- | ------------- |
| `GovernanceSession` | workflow governance primitive |
| `SessionPreCallResult` | workflow-scoped split handoff |
| `AEGIS.open_session(...)` | instance-scoped workflow entrypoint |

## Planned for 1.0.0 (not in v0.9.0-beta)

| Planned surface | Intended role in `1.0.0` |
| --------------- | ------------------------ |
| `AgentIdentity` | participant identity contract |
"""

_PR04_README_CONTENT = """\
# AEGIS README

The upcoming unreleased v0.9.0-beta line will add workflow governance built
around `AEGIS.open_session(...)`, `GovernanceSession`, and `SessionPreCallResult`.
The currently shipped package remains `v0.3.3`.
"""

_PR04_PUBLIC_CONTRACT_CONTENT = """\
# AEGIS Public Integration Contract

The following surfaces are planned for the upcoming unreleased v0.9.0-beta line
and are not part of the installable `v0.3.3` artifact: `AEGIS.open_session(...)`,
`GovernanceSession`, `SessionPreCallResult`.

The following surfaces remain planned-only: `AgentIdentity`, `AgentCapabilityManifest`,
`aegis policy init`, and `aegis workflow ...` commands.
"""

_PR04_PR_CONTEXT_CONTENT = """\
# PR Context - v0.9.0 PR-04 Minimal Session Flow

Active branch: `feat/v0.9-04-minimal-session-flow`

PR-04 lands GovernanceSession, AEGIS.open_session, and SessionPreCallResult.
"""

_PR04_RELEASE_GATES_CONTENT = """\
# Release Gates

## PR-03 — Golden-Path Contract Freeze Gate

- [ ] staged CLI sentinel tests pass
"""

_PR04_IMPLEMENTATION_STATUS_CONTENT = """\
# Implementation Status

**Active Branch:** `feat/v0.9-04-minimal-session-flow`

- PR-04 is in progress
"""

_PR04_PROJECT_MD_CONTENT = """\
# PROJECT.md

The currently shipped package remains `v0.3.3`. The upcoming unreleased v0.9.0-beta
line will add `GovernanceSession`, `SessionPreCallResult`, and `AEGIS.open_session(...)`.
"""

_PR04_ENFORCEMENT_PIPELINE_CONTENT = """\
# Enforcement Pipeline

The shipped `0.3.3` runtime remains invocation-scoped. Its provenance, lineage,
and risk-history additions are groundwork for the upcoming unreleased v0.9.0-beta
line, which will ship the initial `GovernanceSession` primitive. The currently
shipped package remains `v0.3.3`.
"""


def _seed_pr04_contract_repo(
    root: Path,
    *,
    plan: str = _PR04_PLAN_CONTENT,
    hld: str = _PR04_HLD_CONTENT,
    readme: str = _PR04_README_CONTENT,
    public_contract: str = _PR04_PUBLIC_CONTRACT_CONTENT,
    pr_context: str = _PR04_PR_CONTEXT_CONTENT,
    release_gates: str = _PR04_RELEASE_GATES_CONTENT,
    implementation_status: str = _PR04_IMPLEMENTATION_STATUS_CONTENT,
    project_md: str = _PR04_PROJECT_MD_CONTENT,
    enforcement_pipeline: str = _PR04_ENFORCEMENT_PIPELINE_CONTENT,
) -> None:
    _write_file(root, "docs/plans/AEGIS V0.9.0 IMPLEMENTATION_PLAN.md", plan)
    _write_file(root, "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md", hld)
    _write_file(root, "README.md", readme)
    _write_file(root, "docs/PUBLIC_INTEGRATION_CONTRACT.md", public_contract)
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "RELEASE_GATES.md", release_gates)
    _write_file(root, "implementation_status.md", implementation_status)
    _write_file(root, "PROJECT.md", project_md)
    _write_file(root, "docs/architecture/ENFORCEMENT_PIPELINE.md", enforcement_pipeline)


def test_v090_pr04_contract_accepts_valid_pr04_docs(tmp_path, monkeypatch):
    """Seeded valid PR-04 docs pass check_v090_pr04_contract()."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr04_contract_repo(tmp_path)

    errors = module.check_v090_pr04_contract()
    assert errors == [], f"Unexpected errors: {errors}"


def test_v090_pr04_contract_rejects_surface_availability_drift(tmp_path, monkeypatch):
    """README/public contract still have old planned-only language → errors returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_readme = """\
# AEGIS README

The target-state 1.0.0 architecture expands this invocation-first model with
planned workflow governance. None of those workflow surfaces are part of the
shipped `v0.3.3` runtime or CLI.
"""
    _seed_pr04_contract_repo(tmp_path, readme=bad_readme)

    errors = module.check_v090_pr04_contract()

    assert any("README.md" in e for e in errors), (
        f"Expected README error for missing v0.9.0-beta wording, got: {errors}"
    )


def test_v090_pr04_contract_rejects_hld_project_enforcement_old_wording(tmp_path, monkeypatch):
    """HLD/PROJECT/ENFORCEMENT docs with old unqualified language → errors returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_enforcement = """\
# Enforcement Pipeline

The shipped 0.3.3 runtime remains invocation-scoped. Its additions are groundwork
for this future session model, not a shipped `GovernanceSession` workflow runtime.
"""
    _seed_pr04_contract_repo(tmp_path, enforcement_pipeline=bad_enforcement)

    errors = module.check_v090_pr04_contract()

    assert any("ENFORCEMENT_PIPELINE" in e for e in errors), (
        f"Expected ENFORCEMENT_PIPELINE error for old unqualified language, got: {errors}"
    )


def test_v090_pr04_contract_rejects_missing_positive_beta_wording(tmp_path, monkeypatch):
    """Old wording removed but no positive v0.9.0-beta replacement added → errors returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    # PROJECT.md with old wording removed but no positive replacement
    bad_project_md = """\
# PROJECT.md

0.3.3 extends AEGIS's invocation-governance runtime with provenance, lineage,
and risk-trend primitives that future workflow governance will build on.
"""
    _seed_pr04_contract_repo(tmp_path, project_md=bad_project_md)

    errors = module.check_v090_pr04_contract()

    assert any("PROJECT.md" in e for e in errors), (
        f"Expected PROJECT.md error for missing positive v0.9.0-beta wording, got: {errors}"
    )


def test_v090_pr04_contract_rejects_active_branch_drift(tmp_path, monkeypatch):
    """Wrong branch in pr_context/implementation_status → errors returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_pr_context = _PR04_PR_CONTEXT_CONTENT.replace(
        "Active branch: `feat/v0.9-04-minimal-session-flow`",
        "Active branch: `feat/v0.9-03-golden-path-contract`",
    )
    _seed_pr04_contract_repo(tmp_path, pr_context=bad_pr_context)

    errors = module.check_v090_pr04_contract()

    assert any(
        "PR-04 active branch" in e and "pr_context.md" in e
        for e in errors
    ), f"Expected active branch drift error, got: {errors}"


# ---------------------------------------------------------------------------
# PR-05 contract seeded tests
# ---------------------------------------------------------------------------

_PR05_PR_CONTEXT_CONTENT = """\
# PR Context

Active branch: `feat/v0.9-05-starters-and-migration`

PR-05 ships `aegis workflow init`, `aegis policy init`, starter scaffolds, and migration helpers.
"""

_PR05_IMPLEMENTATION_STATUS_CONTENT = """\
# Implementation Status

**Target Version:** `0.9.0` Beta
**Active Branch:** `feat/v0.9-05-starters-and-migration`

PR-01 through PR-08 are complete.
Starters and migration: in progress.
"""

_PR05_PUBLIC_CONTRACT_CONTENT = """\
# Public Integration Contract

Also planned for the upcoming unreleased v0.9.0-beta: `aegis workflow init`,
`aegis policy init`, `aegis.presets.MinimalPreset`, starter scaffolds.
"""

_PR05_README_CONTENT = """\
## Shipped in v0.9.0-beta

`aegis workflow init` and `aegis policy init` are now available.
Use `aegis workflow lint`, `aegis workflow doctor`, `aegis workflow trace`,
and `aegis workflow export` (planned for future releases).
"""

_PR05_HLD_CONTENT = """\
v0.9.0-beta adds `GovernanceSession`, `SessionPreCallResult`,
`aegis workflow init`, and `aegis policy init`.
`ValidatorHook`, `BedrockTraceAdapter`, `A2AAdapter`, `aegis workflow lint`,
`aegis workflow doctor`, `aegis workflow trace`, and `aegis workflow export`
remain planned-only and are not part of any currently released artifact.
"""


def _seed_pr05_contract_repo(
    root: Path,
    *,
    pr_context: str = _PR05_PR_CONTEXT_CONTENT,
    implementation_status: str = _PR05_IMPLEMENTATION_STATUS_CONTENT,
    public_contract: str = _PR05_PUBLIC_CONTRACT_CONTENT,
    readme: str = _PR05_README_CONTENT,
    hld: str = _PR05_HLD_CONTENT,
) -> None:
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "implementation_status.md", implementation_status)
    _write_file(root, "docs/PUBLIC_INTEGRATION_CONTRACT.md", public_contract)
    _write_file(root, "README.md", readme)
    _write_file(root, "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md", hld)


def test_pr05_contract_accepts_valid_docs(tmp_path, monkeypatch):
    """Seeded valid PR-05 docs pass check_v090_pr05_contract()."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr05_contract_repo(tmp_path)

    errors = module.check_v090_pr05_contract()
    assert errors == [], f"Unexpected errors: {errors}"


def test_pr05_contract_rejects_wrong_active_branch(tmp_path, monkeypatch):
    """implementation_status.md missing PR-06 complete row → error returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_impl_status = _PR05_IMPLEMENTATION_STATUS_CONTENT.replace(
        "PR-01 through PR-08 are complete.",
        "PR-04 is complete.",
    )
    _seed_pr05_contract_repo(tmp_path, implementation_status=bad_impl_status)

    errors = module.check_v090_pr05_contract()

    assert any("PR-01 through PR-08 complete" in e for e in errors), (
        f"Expected PR-08 complete row error, got: {errors}"
    )


def test_pr05_contract_rejects_missing_pr05_surfaces(tmp_path, monkeypatch):
    """README missing aegis policy init → error returned."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_readme = "# README\n\nOnly `aegis workflow init` is mentioned here.\n"
    _seed_pr05_contract_repo(tmp_path, readme=bad_readme)

    errors = module.check_v090_pr05_contract()

    assert any("aegis policy init" in e and "README.md" in e for e in errors), (
        f"Expected README error for missing aegis policy init, got: {errors}"
    )


# ---------------------------------------------------------------------------
# PR-09 parity tests — check_v090_pr09_contract()
# ---------------------------------------------------------------------------

_PR09_PR_CONTEXT_CONTENT = """\
# PR Context — `v0.9.0` PR-09 exports-and-ops

Date: 2026-04-19
Status: `feat/v0.9-09-exports-and-ops` contains PR-01 through PR-09
Active branch: `feat/v0.9-09-exports-and-ops`

## PR-09 Outcomes

- `aegis workflow trace` — timeline reconstruction from workflow and invocation artifacts
- `aegis workflow export` — operator and audit export modes
"""

_PR09_HLD_CONTENT = """\
Available in the source-only `v0.9.0` beta line — not part of the `v0.3.3` artifact:

| Surface | Intended role |
| ------- | ------------- |
| `aegis workflow lint` / `aegis workflow doctor` | beta diagnostic surface |
| `aegis workflow trace` / `aegis workflow export` | operator inspection and audit export surface (shipped in PR-09) |

Planned for 1.0.0 or later (not in the current beta public surface):

| Planned surface | Intended role in `1.0.0` |
| --------------- | ------------------------ |
| `AgentIdentity` | participant identity contract |
| `BedrockTraceAdapter` | optional Bedrock normalization adapter |

### 13.2 Stability Contract
"""

_PR09_CLI_REF_CONTENT = """\
## workflow trace

`aegis workflow trace --input <file> [--output <file>]`

## workflow export

`aegis workflow export --input <file> --mode operator|audit [--output <file>]`

Options: `--mode operator`, `--mode audit`
"""

_PR09_OPS_RUNBOOK_CONTENT = """\
## Observability

Use `aegis workflow trace` and `aegis workflow export` for evidence inspection.
"""

_PR09_GENERIC_DOC_CONTENT = """\
# Generic v0.9.0 document

No stale pre-PR-09 language here.
"""


def _seed_pr09_contract_repo(
    root: Path,
    *,
    pr_context: str = _PR09_PR_CONTEXT_CONTENT,
    hld: str = _PR09_HLD_CONTENT,
    cli_ref: str = _PR09_CLI_REF_CONTENT,
    ops_runbook: str = _PR09_OPS_RUNBOOK_CONTENT,
    generic: str = _PR09_GENERIC_DOC_CONTENT,
) -> None:
    _write_file(root, "docs/dev/pr_context.md", pr_context)
    _write_file(root, "docs/architecture/AEGIS_HIGH_LEVEL_DESIGN.md", hld)
    _write_file(root, "docs/reference/WORKFLOW_CLI.md", cli_ref)
    _write_file(root, "docs/reference/OPERATIONS_RUNBOOK.md", ops_runbook)
    for rel in ["CLAUDE.md", "RELEASE_GATES.md", "implementation_status.md",
                "README.md", "docs/PUBLIC_INTEGRATION_CONTRACT.md"]:
        _write_file(root, rel, generic)


def test_pr09_contract_accepts_valid_docs(tmp_path, monkeypatch):
    """Seeded valid PR-09 docs pass check_v090_pr09_contract() with no errors."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    _seed_pr09_contract_repo(tmp_path)

    errors = module.check_v090_pr09_contract()
    assert errors == [], f"Unexpected errors: {errors}"


def test_pr09_contract_rejects_stale_between_pr08_and_pr09_header(tmp_path, monkeypatch):
    """pr_context.md with old 'Between PR-08 And PR-09' header → error."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    stale_ctx = "# PR Context — `v0.9.0` Between PR-08 And PR-09\n\nDate: 2026-04-18\n"
    _seed_pr09_contract_repo(tmp_path, pr_context=stale_ctx)

    errors = module.check_v090_pr09_contract()
    assert any("Between PR-08 And PR-09" in e for e in errors), (
        f"Expected stale-header error, got: {errors}"
    )


def test_pr09_contract_rejects_pr09_has_not_started(tmp_path, monkeypatch):
    """pr_context.md with 'PR-09 has not started' status line → error."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    stale_ctx = "# PR Context\n\nStatus: PR-09 has not started\nActive branch: develop\n"
    _seed_pr09_contract_repo(tmp_path, pr_context=stale_ctx)

    errors = module.check_v090_pr09_contract()
    assert any("PR-09 has not started" in e for e in errors), (
        f"Expected 'PR-09 has not started' error, got: {errors}"
    )


def test_pr09_contract_rejects_hld_trace_export_in_planned_section(tmp_path, monkeypatch):
    """HLD listing trace/export under 'Planned for 1.0.0 or later' → error."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    stale_hld = """\
Available in the source-only `v0.9.0` beta line:

| Surface | Intended role |
| ------- | ------------- |
| `aegis workflow lint` / `aegis workflow doctor` | beta diagnostic surface |

Planned for 1.0.0 or later (not in the current beta public surface):

| Planned surface | Intended role in `1.0.0` |
| --------------- | ------------------------ |
| `aegis workflow trace` and `aegis workflow export` | operator inspection and export surface |

### 13.2 Stability Contract
"""
    _seed_pr09_contract_repo(tmp_path, hld=stale_hld)

    errors = module.check_v090_pr09_contract()
    assert any("workflow trace" in e and "Planned for 1.0.0" in e for e in errors), (
        f"Expected HLD planned-section drift error, got: {errors}"
    )


def test_pr09_contract_rejects_missing_cli_ref_anchor(tmp_path, monkeypatch):
    """WORKFLOW_CLI.md missing '--mode operator' → error."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_cli_ref = "## workflow trace\n\n`aegis workflow trace --input <file>`\n\n## workflow export\n\nOptions: --mode audit\n"
    _seed_pr09_contract_repo(tmp_path, cli_ref=bad_cli_ref)

    errors = module.check_v090_pr09_contract()
    assert any("--mode operator" in e and "WORKFLOW_CLI.md" in e for e in errors), (
        f"Expected missing anchor error, got: {errors}"
    )


def test_pr09_contract_rejects_missing_ops_runbook_command(tmp_path, monkeypatch):
    """OPERATIONS_RUNBOOK.md missing 'aegis workflow export' → error."""
    module = _load_doc_parity_module()
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)

    bad_runbook = "## Observability\n\nUse `aegis workflow trace` for evidence inspection.\n"
    _seed_pr09_contract_repo(tmp_path, ops_runbook=bad_runbook)

    errors = module.check_v090_pr09_contract()
    assert any("aegis workflow export" in e and "OPERATIONS_RUNBOOK.md" in e for e in errors), (
        f"Expected missing ops runbook command error, got: {errors}"
    )
