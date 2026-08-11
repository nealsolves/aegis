from __future__ import annotations

import pytest

from bounded_yaml import ensure_bounded_json_response, load_bounded_yaml
from demo_errors import DemoPublicError
from demo_limits import YAML_MAX_ENCODED_BYTES


def _issue_59_reproduction() -> str:
    width = 6
    lines: list[str] = []
    previous: str | None = None
    for name in "abcdefg":
        values = ["x"] * width if previous is None else [f"*{previous}"] * width
        lines.append(f"{name}: &{name} [" + ", ".join(values) + "]")
        previous = name
    body = "\n".join(lines) + "\n"
    assert len(body.encode("utf-8")) == 211
    return body


def _assert_yaml_error(body: str, code: str) -> None:
    with pytest.raises(DemoPublicError) as caught:
        load_bounded_yaml(body)
    assert caught.value.status_code == 422
    assert caught.value.code == code


def test_loads_json_compatible_mapping_with_bounded_alias_reuse() -> None:
    body = "root: &root [alpha, 2, true, null]\ncopy: *root\n"

    loaded = load_bounded_yaml(body)

    assert loaded == {
        "root": ["alpha", 2, True, None],
        "copy": ["alpha", 2, True, None],
    }


def test_rejects_exact_issue_59_expansion_before_response_amplification() -> None:
    _assert_yaml_error(_issue_59_reproduction(), "YAML_LIMIT_EXCEEDED")


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("x: [unterminated", "YAML_INVALID"),
        ("---\nx: 1\n---\ny: 2\n", "YAML_INVALID"),
        ("x: !custom value\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: !!python/object/apply:os.system ['id']\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: 2026-08-11\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: !!binary SGVsbG8=\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: !!set {a: null}\n", "YAML_UNSUPPORTED_VALUE"),
        ("{1: value}\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: .nan\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: .inf\n", "YAML_UNSUPPORTED_VALUE"),
        ("base: &base {x: 1}\nmerged: {<<: *base}\n", "YAML_UNSUPPORTED_VALUE"),
        ("x: 1\nx: 2\n", "YAML_UNSUPPORTED_VALUE"),
    ],
)
def test_rejects_invalid_ambiguous_or_non_json_yaml(body: str, code: str) -> None:
    _assert_yaml_error(body, code)


def test_rejects_encoded_input_over_limit_using_utf8_bytes() -> None:
    body = "value: " + ("é" * (YAML_MAX_ENCODED_BYTES // 2))
    assert len(body) < YAML_MAX_ENCODED_BYTES
    assert len(body.encode("utf-8")) > YAML_MAX_ENCODED_BYTES

    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_more_than_24_anchor_definitions() -> None:
    body = "\n".join(f"k{index}: &a{index} value" for index in range(25))
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_more_than_24_alias_events() -> None:
    body = "anchor: &a value\nvalues: [" + ", ".join(["*a"] * 25) + "]\n"
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_nesting_deeper_than_20_collections() -> None:
    body = "value: " + ("[" * 21) + "x" + ("]" * 21) + "\n"
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_more_than_2048_scalar_events() -> None:
    body = "values: [" + ", ".join(["x"] * 2_048) + "]\n"
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_more_than_512_collection_events() -> None:
    body = "values: [" + ", ".join(["[]"] * 512) + "]\n"
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_repeated_expanded_scalar_bytes() -> None:
    scalar = "x" * 20_000
    body = f'anchor: &a "{scalar}"\nvalues: [*a, *a, *a, *a, *a, *a]\n'
    assert len(body.encode("utf-8")) < YAML_MAX_ENCODED_BYTES
    _assert_yaml_error(body, "YAML_LIMIT_EXCEEDED")


def test_rejects_recursive_alias_cycle_with_specific_code() -> None:
    _assert_yaml_error("value: &value [*value]\n", "YAML_CYCLE_REJECTED")


def test_requires_mapping_by_default_but_can_load_a_list_explicitly() -> None:
    _assert_yaml_error("[one, two]\n", "YAML_UNSUPPORTED_VALUE")
    assert load_bounded_yaml("[one, two]\n", require_mapping=False) == ["one", "two"]


def test_response_preflight_counts_incremental_utf8_bytes() -> None:
    ensure_bounded_json_response({"value": "é" * 10}, max_bytes=40)

    with pytest.raises(DemoPublicError) as caught:
        ensure_bounded_json_response({"value": "é" * 40}, max_bytes=40)

    assert caught.value.status_code == 422
    assert caught.value.code == "RESPONSE_TOO_LARGE"
