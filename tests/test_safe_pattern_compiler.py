"""Tests for the bounded google-re2 pattern compiler."""

from threading import Event, Thread

import pytest
import re2

import aegis._internal.patterns as pattern_module
from aegis._internal.errors import PolicyValidationError
from aegis._internal.patterns import (
    PatternInputTooLargeError,
    PatternProgramIntegrityError,
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


@pytest.mark.parametrize("tamper", ["program_bytes", "compiled"])
def test_private_runtime_cache_tamper_is_safely_rebuilt(tamper):
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    stale_runtime = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    if tamper == "program_bytes":
        object.__setattr__(stale_runtime, "program_bytes", b"tampered")
    else:
        object.__setattr__(stale_runtime, "compiled", re2.compile(".*"))

    assert pattern.fullmatch("not-ok") is False
    assert pattern.fullmatch("ok") is True
    assert pattern_module._RUNTIME_CACHE[pattern.program_digest] is not (
        stale_runtime
    )


def test_authenticated_pattern_metadata_tamper_fails_closed():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    object.__setattr__(pattern, "source", ".*")

    with pytest.raises(PatternProgramIntegrityError) as exc:
        pattern.fullmatch("not-ok")

    assert exc.value.code == "PATTERN_PROGRAM_INTEGRITY_ERROR"


class _ForgedPatternHandle:
    pattern = "^ok$"

    def fullmatch(self, candidate):
        return object()

    def search(self, candidate):
        return object()


def test_forged_cached_pattern_handle_is_rejected_and_rebuilt():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    stale_runtime = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    object.__setattr__(
        stale_runtime,
        "compiled",
        _ForgedPatternHandle(),
    )

    assert pattern.fullmatch("not-ok") is False
    assert pattern_module._RUNTIME_CACHE[pattern.program_digest] is not (
        stale_runtime
    )


def test_concurrent_cache_corruption_cannot_weaken_evaluation():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    stale_runtime = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    corrupted = Event()
    release_cache_lock = Event()
    decisions = []

    def corrupt_cache():
        with pattern_module._RUNTIME_CACHE_LOCK:
            object.__setattr__(
                stale_runtime,
                "compiled",
                _ForgedPatternHandle(),
            )
            corrupted.set()
            release_cache_lock.wait(timeout=2)

    def evaluate_pattern():
        decisions.append(pattern.fullmatch("not-ok"))

    corruptor = Thread(target=corrupt_cache)
    corruptor.start()
    assert corrupted.wait(timeout=2)
    evaluator = Thread(target=evaluate_pattern)
    evaluator.start()
    release_cache_lock.set()
    corruptor.join(timeout=2)
    evaluator.join(timeout=2)

    assert not corruptor.is_alive()
    assert not evaluator.is_alive()
    assert decisions == [False]


def _case_insensitive_handle():
    options = re2.Options()
    options.case_sensitive = False
    return re2.compile("^ok$", options=options)


def test_same_source_altered_options_handle_is_replaced_before_use():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    stale_runtime = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    altered = _case_insensitive_handle()
    assert type(altered) is type(stale_runtime.compiled)
    assert altered.pattern == stale_runtime.compiled.pattern
    object.__setattr__(stale_runtime, "compiled", altered)

    assert pattern.fullmatch("OK") is False
    assert pattern_module._RUNTIME_CACHE[pattern.program_digest] is not (
        stale_runtime
    )


def test_whole_cache_entry_replacement_cannot_replace_attested_handle():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    original = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    re2.purge()
    replacement_handle = re2.compile("^ok$")
    assert replacement_handle is not original.compiled
    replacement = pattern_module._PatternRuntime(
        program_bytes=original.program_bytes,
        compiled=replacement_handle,
    )
    pattern_module._RUNTIME_CACHE[pattern.program_digest] = replacement

    assert pattern.fullmatch("ok") is True
    assert pattern_module._RUNTIME_CACHE[pattern.program_digest] is not (
        replacement
    )


def test_concurrent_same_source_handle_replacement_cannot_change_decision():
    pattern = compile_pattern("^ok$", path=PATTERN_PATH)
    original = pattern_module._RUNTIME_CACHE[pattern.program_digest]
    corrupted = Event()
    release_cache_lock = Event()
    decisions = []

    def replace_cache_entry():
        with pattern_module._RUNTIME_CACHE_LOCK:
            pattern_module._RUNTIME_CACHE[pattern.program_digest] = (
                pattern_module._PatternRuntime(
                    program_bytes=original.program_bytes,
                    compiled=_case_insensitive_handle(),
                )
            )
            corrupted.set()
            release_cache_lock.wait(timeout=2)

    def evaluate_pattern():
        decisions.append(pattern.fullmatch("OK"))

    corruptor = Thread(target=replace_cache_entry)
    corruptor.start()
    assert corrupted.wait(timeout=2)
    evaluator = Thread(target=evaluate_pattern)
    evaluator.start()
    release_cache_lock.set()
    corruptor.join(timeout=2)
    evaluator.join(timeout=2)

    assert not corruptor.is_alive()
    assert not evaluator.is_alive()
    assert decisions == [False]
