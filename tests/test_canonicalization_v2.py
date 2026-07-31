import json
from itertools import combinations

import pytest

from aegis._internal.canonicalization import (
    CANONICALIZATION_PROFILE_V2,
    SAFE_INTEGER_MAX,
    CanonicalizationError,
    canonicalize_v2,
    normalize_json_v2,
)


@pytest.mark.parametrize(
    "value",
    [
        {1: "a"},
        {True: "a"},
        {"x": {2: "b"}},
        (1, 2),
        {1, 2},
        b"bytes",
        {"n": float("nan")},
        {"n": float("inf")},
        {"n": float("-inf")},
    ],
)
def test_v2_rejects_values_outside_closed_json_domain(value):
    with pytest.raises(CanonicalizationError):
        canonicalize_v2(value)


@pytest.mark.parametrize(
    ("value", "code", "path"),
    [
        ({1: "integer", "1": "string"}, "NON_STRING_KEY", "$"),
        ({True: "boolean", "true": "string"}, "NON_STRING_KEY", "$"),
        ({None: "null", "null": "string"}, "NON_STRING_KEY", "$"),
        ({"nested": {1.0: "number"}}, "NON_STRING_KEY", "$.nested"),
        ({"s": "\ud800"}, "LONE_SURROGATE", "$.s"),
        ({"s": "\udfff"}, "LONE_SURROGATE", "$.s"),
        (SAFE_INTEGER_MAX + 1, "INTEGER_OUT_OF_RANGE", "$"),
        (-SAFE_INTEGER_MAX - 1, "INTEGER_OUT_OF_RANGE", "$"),
    ],
)
def test_v2_rejection_reports_stable_code_and_path(value, code, path):
    with pytest.raises(CanonicalizationError) as exc:
        canonicalize_v2(value)
    assert exc.value.code == code
    assert exc.value.details == {"path": path}


def test_round_trip_keeps_bytes_and_value_identical():
    first = canonicalize_v2({"n": 1.0, "s": "é", "z": -0.0})
    second = canonicalize_v2(json.loads(first.data))
    assert first.data == second.data
    assert first.value == second.value
    assert first.profile == CANONICALIZATION_PROFILE_V2


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
        ([333333333.33333329, 1e30, 4.50, 2e-3, 1e-27], b"[333333333.3333333,1e+30,4.5,0.002,1e-27]"),
        ({"control": "\b\t\n\f\r\"\\"}, b'{"control":"\\b\\t\\n\\f\\r\\\"\\\\"}'),
        ({"unicode": "é€"}, '{"unicode":"é€"}'.encode()),
        ({"zero": -0.0}, b'{"zero":0}'),
    ],
)
def test_rfc8785_serialization_vectors(value, expected):
    assert canonicalize_v2(value).data == expected


@pytest.mark.parametrize("value", [-SAFE_INTEGER_MAX, SAFE_INTEGER_MAX])
def test_safe_integer_edges_are_accepted(value):
    assert normalize_json_v2(value) == value


def test_strings_are_not_unicode_normalized():
    composed = canonicalize_v2("é")
    decomposed = canonicalize_v2("e\u0301")
    assert composed.value != decomposed.value
    assert composed.data != decomposed.data


def test_distinct_accepted_normalized_values_have_distinct_bytes():
    values = [
        None,
        False,
        True,
        0,
        1,
        -1,
        1.5,
        "",
        "0",
        [],
        [0],
        {},
        {"0": 0},
        {"a": 1},
        {"b": 1},
    ]
    canonicalized = [canonicalize_v2(value) for value in values]
    for left, right in combinations(canonicalized, 2):
        assert left.data != right.data
