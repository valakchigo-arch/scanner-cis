import math
import re
from typing import Any
from .exceptions import EvaluationError


_INT_RE   = re.compile(r'^-?\d+$')
_FLOAT_RE = re.compile(r'^-?\d+\.\d+$')

_TRUE_STRINGS  = {"true", "yes", "enabled", "on", "1"}
_FALSE_STRINGS = {"false", "no", "disabled", "off", "0"}


def _coerce(actual: Any, target_type: type) -> tuple[Any, bool]:
    """
    Coerce actual ke target_type. Return (value, ok).
    ok=False → caller harus anggap FAIL (bukan ERROR).
    """
    # Exact type match
    if type(actual) is target_type:
        return actual, True

    if actual is None:
        return None, False

    # ── target: bool ─────────────────────────────────
    if target_type is bool:
        if isinstance(actual, str):
            low = actual.strip().lower()
            if low in _TRUE_STRINGS:  return True,  True
            if low in _FALSE_STRINGS: return False, True
            return None, False
        if isinstance(actual, int):
            if actual == 0: return False, True
            if actual == 1: return True,  True
            return None, False
        return None, False

    # ── target: int ──────────────────────────────────
    if target_type is int:
        if isinstance(actual, bool):
            return int(actual), True
        if isinstance(actual, float):
            if math.isfinite(actual) and actual.is_integer():
                return int(actual), True
            return None, False
        if isinstance(actual, str):
            s = actual.strip()
            if _INT_RE.match(s):
                return int(s), True
            return None, False
        return None, False

    # ── target: float ────────────────────────────────
    if target_type is float:
        if isinstance(actual, bool):
            return float(actual), True
        if isinstance(actual, int):
            return float(actual), True
        if isinstance(actual, str):
            s = actual.strip()
            if _INT_RE.match(s) or _FLOAT_RE.match(s):
                f = float(s)
                if math.isnan(f) or math.isinf(f):
                    return None, False
                return f, True
            return None, False
        return None, False

    # ── target: str ──────────────────────────────────
    if target_type is str:
        if isinstance(actual, (int, float, bool)):
            return str(actual), True
        return None, False

    return None, False


def _compare_numeric(actual, expected, op) -> bool:
    a, ok_a = _coerce(actual, type(expected))
    if not ok_a:
        return False
    e, ok_e = _coerce(expected, type(expected))
    if not ok_e:
        return False
    # Reject NaN/Inf after coercion
    if isinstance(a, float) and (math.isnan(a) or math.isinf(a)):
        return False
    if isinstance(e, float) and (math.isnan(e) or math.isinf(e)):
        return False
    if op == "gt":  return a >  e
    if op == "gte": return a >= e
    if op == "lt":  return a <  e
    if op == "lte": return a <= e
    return False


def evaluate(operator: str, expected: Any, actual: Any) -> bool:
    """Evaluate condition. Return True kalau PASS."""
    try:
        if operator == "equals":
            a, ok = _coerce(actual, type(expected))
            return ok and a == expected

        if operator == "not_equals":
            a, ok = _coerce(actual, type(expected))
            return ok and a != expected

        if operator in ("gt", "gte", "lt", "lte"):
            return _compare_numeric(actual, expected, operator)

        if operator == "in":
            if not isinstance(expected, (list, tuple, set)):
                raise EvaluationError(
                    f"'in' requires list/tuple/set expected, got {type(expected).__name__}"
                )
            for exp in expected:
                a, ok = _coerce(actual, type(exp))
                if ok and a == exp:
                    return True
            return False

        if operator == "not_in":
            if not isinstance(expected, (list, tuple, set)):
                raise EvaluationError(
                    f"'not_in' requires list/tuple/set expected, got {type(expected).__name__}"
                )
            for exp in expected:
                a, ok = _coerce(actual, type(exp))
                if ok and a == exp:
                    return False
            return True

        if operator == "one_of":
            return evaluate("in", expected, actual)

        if operator == "matches":
            if not isinstance(expected, str):
                raise EvaluationError("'matches' requires string expected")
            if actual is None:          # nilai tidak ada != string "None"
                return False
            try:
                return re.search(expected, str(actual)) is not None
            except re.error as e:
                raise EvaluationError(f"Invalid regex {expected!r}: {e}")

        if operator == "contains":
            if actual is None:          # BUG FIX: sebelumnya "Non" in "None" -> True
                return False
            return str(expected) in str(actual)

        if operator == "exists":
            return actual is not None

        if operator == "not_exists":
            return actual is None

    except EvaluationError:
        raise
    except Exception as e:
        raise EvaluationError(f"Unexpected error: {e}")

    raise EvaluationError(f"Unknown operator: {operator}")