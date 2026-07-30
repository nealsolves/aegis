"""Tests for the bounded google-re2 pattern compiler."""

import pytest

from aegis._internal.errors import PolicyValidationError
from aegis._internal.patterns import (
    PatternInputTooLargeError,
    compile_pattern,
)


PATTERN_PATH = "$.pre_conditions.required.code.pattern"


def test_re2_supported_alternation_and_repetition_fullmatch():
    pattern = compile_pattern(
        "^(APPROVED|REJECTED)-[0-9]{2,4}$",
        path=PATTERN_PATH,
    )
    assert pattern.fullmatch("APPROVED-123")
    assert pattern.fullmatch("REJECTED-42")
    assert not pattern.fullmatch("PENDING-42")


@pytest.mark.parametrize("source", [r"(?=APPROVED)APPROVED", r"(APPROVED)\1"])
def test_unsupported_re2_construct_is_compile_error(source):
    with pytest.raises(PolicyValidationError) as exc:
        compile_pattern(source, path=PATTERN_PATH)
    assert exc.value.code == "PATTERN_UNSUPPORTED"


def test_non_string_pattern_source_is_invalid():
    with pytest.raises(PolicyValidationError) as exc:
        compile_pattern(42, path=PATTERN_PATH)
    assert exc.value.code == "PATTERN_INVALID"


def test_non_string_pattern_candidate_fails_closed():
    pattern = compile_pattern("^x+$", path=PATTERN_PATH)
    assert pattern.fullmatch(42) is False


def test_exact_256_byte_pattern_source_is_accepted():
    source = "x" * 256
    pattern = compile_pattern(source, path=PATTERN_PATH)
    assert pattern.fullmatch(source)


def test_257_byte_pattern_source_is_rejected():
    with pytest.raises(PolicyValidationError) as exc:
        compile_pattern("x" * 257, path=PATTERN_PATH)
    assert exc.value.code == "PATTERN_INVALID"


def test_source_limit_counts_utf8_bytes_not_code_points():
    compile_pattern("é" * 128, path=PATTERN_PATH)
    with pytest.raises(PolicyValidationError) as exc:
        compile_pattern("é" * 129, path=PATTERN_PATH)
    assert exc.value.code == "PATTERN_INVALID"


def test_unencodable_pattern_source_is_invalid():
    with pytest.raises(PolicyValidationError) as exc:
        compile_pattern("\ud800", path=PATTERN_PATH)
    assert exc.value.code == "PATTERN_INVALID"


def test_exact_16384_byte_candidate_is_accepted():
    pattern = compile_pattern("^x+$", path=PATTERN_PATH)
    assert pattern.fullmatch("x" * 16_384)


def test_candidate_over_16384_bytes_fails_closed():
    pattern = compile_pattern("^x+$", path=PATTERN_PATH)
    with pytest.raises(PatternInputTooLargeError) as exc:
        pattern.fullmatch("x" * 16_385)
    assert exc.value.code == "PATTERN_INPUT_TOO_LARGE"


def test_candidate_limit_counts_utf8_bytes_not_code_points():
    pattern = compile_pattern("^é+$", path=PATTERN_PATH)
    assert pattern.fullmatch("é" * 8_192)
    with pytest.raises(PatternInputTooLargeError):
        pattern.fullmatch("é" * 8_193)


def test_unencodable_pattern_candidate_fails_closed():
    pattern = compile_pattern("^x+$", path=PATTERN_PATH)
    with pytest.raises(PatternInputTooLargeError):
        pattern.fullmatch("\ud800")
