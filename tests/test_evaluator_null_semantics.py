"""P1-1: pin the ACTUAL null/empty/wrong-type semantics of every operator.

These tests exist to freeze the current evaluator contract so a future
"normalize() type-blind" refactor cannot silently change it. If any of these
starts failing, the change is a SEMANTIC change and must be justified in
docs/METHODOLOGY.md before it lands.

Run with: python -m pytest tests/test_evaluator_null_semantics.py -v
"""
import pytest
from scanner.core.evaluator import evaluate


# ── null (None) ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("op,exp", [
    ("equals",     14),
    ("not_equals", 14),
    ("gt",         10),
    ("gte",        10),
    ("lt",         10),
    ("lte",        10),
    ("in",         [1, 2, 3]),
    ("one_of",     [1, 2, 3]),
    ("matches",    r"^\d+$"),
    ("contains",   "abc"),
])
def test_null_is_not_a_match(op, exp):
    """None never satisfies a value comparison -- it means 'not present'."""
    assert evaluate(op, exp, None) is False


def test_not_in_null_is_pass():
    """not_in + None = PASS (designed: WIN-LMHASH-DISABLED relies on this)."""
    assert evaluate("not_in", [0, "0"], None) is True


def test_not_equals_null_is_fail():
    """not_equals + None = FAIL (differs from not_in -- documented deviation)."""
    assert evaluate("not_equals", 14, None) is False


def test_exists_null_is_false():
    assert evaluate("exists", False, None) is False


def test_not_exists_null_is_true():
    assert evaluate("not_exists", True, None) is True


# ── empty string ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("op,exp", [
    ("equals",     14),
    ("not_equals", 14),
    ("gt",         10),
    ("gte",        10),
    ("lt",         10),
    ("lte",        10),
    ("in",         [1, 2, 3]),
    ("one_of",     [1, 2, 3]),
    ("matches",    r"^\d+$"),
])
def test_empty_string_is_not_a_match(op, exp):
    assert evaluate(op, exp, "") is False


def test_not_in_empty_string_is_pass():
    assert evaluate("not_in", [0, "0"], "") is True


def test_contains_empty_string_is_fail():
    """contains('abc', '') -> 'abc' not in '' -> False."""
    assert evaluate("contains", "abc", "") is False


def test_exists_empty_string_is_true():
    """An empty string IS present (key exists, value is empty)."""
    assert evaluate("exists", False, "") is True


def test_not_exists_empty_string_is_false():
    assert evaluate("not_exists", True, "") is False


# ── wrong type (str where int expected, etc.) ──────────────────────────────────

def test_equals_wrong_type_is_fail():
    assert evaluate("equals", 14, "abc") is False
    assert evaluate("equals", 14, True) is False


def test_not_equals_wrong_type_is_fail():
    """not_equals coerces actual to expected's type, same as equals.

    Verified actual behavior:
      not_equals(14, 'abc') -> False  (string fails int coercion)
      not_equals(14, True)  -> True   (bool coerces to int 1, 1 != 14)
    """
    assert evaluate("not_equals", 14, "abc") is False
    assert evaluate("not_equals", 14, True) is True


def test_numeric_wrong_type_str_passes():
    """'42' coerces to int 42 -> gt(10, '42') is True."""
    assert evaluate("gt", 10, "42") is True


def test_bool_coerces_to_int_in_numeric_ops():
    """True coerces to 1 -> lt(10, True) is True. Known True==1 behavior."""
    assert evaluate("lt", 10, True) is True
    assert evaluate("lte", 10, True) is True


def test_matches_coerces_int_to_str():
    r"""matches(r'^\d+$', 42) -> str(42)='42' -> True."""
    assert evaluate("matches", r"^\d+$", 42) is True


def test_contains_coerces_expected_to_str():
    """contains('abc', 'abc') -> 'abc' in 'abc' -> True."""
    assert evaluate("contains", "abc", "abc") is True


def test_in_coerces_actual():
    assert evaluate("in", [1, 2, 3], "2") is True
    assert evaluate("in", [1, 2, 3], True) is True   # True coerces to 1


def test_not_in_coerces_actual():
    assert evaluate("not_in", [0, "0"], "0") is False
    assert evaluate("not_in", [0, "0"], 0) is False


def test_exists_wrong_type_is_true():
    assert evaluate("exists", False, "abc") is True
    assert evaluate("exists", False, 0) is True


def test_not_exists_wrong_type_is_false():
    assert evaluate("not_exists", True, "abc") is False
    assert evaluate("not_exists", True, 0) is False