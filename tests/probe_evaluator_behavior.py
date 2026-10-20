"""Snapshot the ACTUAL current behavior of every operator x null/empty/wrong-type.

Run: python -m tests.probe_evaluator_behavior  (or just import from a test)
Output is a markdown table consumed by docs/METHODOLOGY.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core.evaluator import evaluate, EvaluationError

OPS = ["equals", "not_equals", "gt", "gte", "lt", "lte", "in", "not_in",
       "one_of", "matches", "contains", "exists", "not_exists"]

# (label, actual_value)
SAMPLES = [
    ("None",        None),
    ("empty_str",   ""),
    ("str_wrong",   "abc"),
    ("int_wrong",   42),
    ("bool_wrong",  True),
    ("list_wrong",  [1, 2]),
]

# expected values chosen to be meaningful per operator
EXPECTED = {
    "equals":      14,
    "not_equals":  14,
    "gt":          10,
    "gte":         10,
    "lt":          10,
    "lte":         10,
    "in":          [1, 2, 3],
    "not_in":      [0, "0"],
    "one_of":      [1, 2, 3],
    "matches":     r"^\d+$",
    "contains":    "abc",
    "exists":      False,
    "not_exists":  True,
}


def cell(op, sample_label, actual):
    exp = EXPECTED[op]
    try:
        result = evaluate(op, exp, actual)
        return "PASS" if result is True else "FAIL"
    except EvaluationError as e:
        return f"RAISE({e})"


def main():
    print("| Operator | expected | " + " | ".join(S[0] for S in SAMPLES) + " |")
    print("|---|---|" + "---|" * len(SAMPLES))
    for op in OPS:
        row = [cell(op, label, val) for label, val in SAMPLES]
        print(f"| `{op}` | `{EXPECTED[op]!r}` | " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()