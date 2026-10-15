import pytest
from scanner.core.evaluator import evaluate
from scanner.core.exceptions import EvaluationError


class TestEquals:
    def test_bool_true(self):
        assert evaluate("equals", True, True) is True

    def test_bool_false(self):
        assert evaluate("equals", False, False) is True

    def test_int(self):
        assert evaluate("equals", 14, 14) is True

    def test_string_int(self):
        assert evaluate("equals", 14, "14") is True

    def test_mismatch(self):
        assert evaluate("equals", True, False) is False


class TestNotEquals:
    def test_bool(self):
        assert evaluate("not_equals", True, False) is True
        assert evaluate("not_equals", False, True) is True


class TestGt:
    def test_int(self):
        assert evaluate("gt", 10, 15) is True

    def test_float(self):
        assert evaluate("gt", 10.5, 11.0) is True

    def test_false(self):
        assert evaluate("gt", 10, 10) is False


class TestGte:
    def test_equal(self):
        assert evaluate("gte", 10, 10) is True

    def test_greater(self):
        assert evaluate("gte", 10, 15) is True


class TestLt:
    def test_int(self):
        assert evaluate("lt", 10, 5) is True


class TestLte:
    def test_equal(self):
        assert evaluate("lte", 10, 10) is True


class TestIn:
    def test_in_list(self):
        assert evaluate("in", [1, 2, 3], 2) is True

    def test_not_in(self):
        assert evaluate("in", [1, 2, 3], 5) is False


class TestNotIn:
    def test_not_in(self):
        assert evaluate("not_in", [1, 2, 3], 5) is True


class TestOneOf:
    def test_one_of(self):
        assert evaluate("one_of", [1, 2, 3], 2) is True


class TestMatches:
    def test_regex_match(self):
        assert evaluate("matches", r"^[a-z]+$", "hello") is True

    def test_regex_no_match(self):
        assert evaluate("matches", r"^[a-z]+$", "Hello") is False


class TestContains:
    def test_substring(self):
        assert evaluate("contains", "hello", "hello world") is True


class TestExists:
    def test_exists(self):
        assert evaluate("exists", None, "value") is True

    def test_not_exists(self):
        assert evaluate("exists", None, None) is False


class TestNotExists:
    def test_not_exists(self):
        assert evaluate("not_exists", None, None) is True


class TestInvalidOperator:
    def test_raises(self):
        with pytest.raises(EvaluationError, match="Unknown operator"):
            evaluate("fuzzy_match", 1, 1)


class TestTypeCoercion:
    def test_string_to_int(self):
        assert evaluate("gt", 10, "15") is True

    def test_string_to_float(self):
        assert evaluate("gt", 10.5, "11") is True


# ── Strict coercion edge cases ────────────────────────────────

class TestStrictCoercion:
    def test_underscore_string_not_coerced(self):
        # BUG LAMA: int("1_000") → 1000
        assert evaluate("equals", 1000, "1_000") is False

    def test_nan_never_passes(self):
        assert evaluate("equals", 14.0, float("nan")) is False
        assert evaluate("gte",   14.0, float("nan")) is False
        assert evaluate("lt",    14.0, float("nan")) is False

    def test_inf_rejected(self):
        assert evaluate("equals", 14.0, float("inf")) is False
        assert evaluate("gt", 14.0, float("inf")) is False

    def test_bool_only_01(self):
        # True hanya dari 1/true/yes/enabled/on
        assert evaluate("equals", True, 1)      is True
        assert evaluate("equals", True, 0)      is False
        assert evaluate("equals", True, 2)      is False  # ← bukan True!
        assert evaluate("equals", True, "yes")  is True
        assert evaluate("equals", True, "on")   is True

    def test_float_int_strict(self):
        assert evaluate("equals", 14,    "14.0") is False
        assert evaluate("equals", 14.0,  14)     is True
        assert evaluate("equals", 14,    " 14 ") is True  # whitespace strip

    def test_type_mismatch_is_fail_not_error(self):
        # Sebelumnya gte(14, "abc") raise error, equals(14, "abc") return False.
        # Sekarang dua-duanya FAIL konsisten.
        assert evaluate("equals", 14, "abc")  is False
        assert evaluate("gte",    14, "abc")  is False
        assert evaluate("gte",    14, None)   is False

    def test_case_sensitive_string(self):
        assert evaluate("equals", "no", "NO") is False

    def test_in_coerces(self):
        assert evaluate("in", [1, 2, 3], "2")   is True
        assert evaluate("in", ["a", "b"], "A")  is False  # case-sensitive


# ── Error cases (yang memang harus raise) ────────────────────

class TestErrorCases:
    def test_invalid_regex_raises(self):
        with pytest.raises(EvaluationError):
            evaluate("matches", "[invalid", "x")

    def test_in_with_non_list_raises(self):
        with pytest.raises(EvaluationError):
            evaluate("in", 5, "abc")

    def test_unknown_operator_raises(self):
        with pytest.raises(EvaluationError):
            evaluate("fuzzy_match", 1, 1)

    def test_not_in_with_non_list_raises(self):
        with pytest.raises(EvaluationError):
            evaluate("not_in", 5, "abc")

    def test_matches_requires_string_expected(self):
        with pytest.raises(EvaluationError):
            evaluate("matches", 123, "abc")


# ── Boolean variants ────────────────────────────────────────

class TestBooleanVariants:
    def test_true_variants(self):
        for val in ["true", "yes", "enabled", "on", "1"]:
            assert evaluate("equals", True, val) is True, f"Failed for {val}"

    def test_false_variants(self):
        for val in ["false", "no", "disabled", "off", "0"]:
            assert evaluate("equals", False, val) is True, f"Failed for {val}"

    def test_case_insensitive(self):
        assert evaluate("equals", True, "TRUE") is True
        assert evaluate("equals", True, "Yes") is True
        assert evaluate("equals", False, "FALSE") is True
        assert evaluate("equals", False, "NO") is True


# ── Probe raw string handling ─────────────────────────────────

class TestProbeRawString:
    """Probe returns raw string; evaluator handles coercion based on expected type."""

    def test_probe_returns_raw_string_int(self):
        # Probe returns "1_000" (raw), expected int 1000
        # Regex-based coercion rejects "1_000" → FAIL (correct)
        assert evaluate("equals", 1000, "1_000") is False

    def test_probe_returns_raw_string_nan(self):
        # Probe returns "NaN", expected float
        # Evaluator rejects NaN → FAIL (correct)
        assert evaluate("equals", 14.0, "NaN") is False

    def test_probe_returns_raw_string_bool_true(self):
        # Probe returns "True", expected bool True
        assert evaluate("equals", True, "True") is True

    def test_probe_returns_raw_string_bool_false(self):
        # Probe returns "False", expected bool False
        assert evaluate("equals", False, "False") is True

    def test_probe_returns_raw_string_numeric(self):
        # Probe returns "14", expected int 14
        assert evaluate("equals", 14, "14") is True
        assert evaluate("gte", 10, "14") is True