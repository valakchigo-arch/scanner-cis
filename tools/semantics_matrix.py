"""Matriks semantik evaluator: operator x {None, '', tipe salah, ...} -> PASS/FAIL/ERROR.
Dihitung dari KODE (sumber kebenaran tabel di docs/METHODOLOGY.md); dikunci terpisah di
tests/regression/test_evaluator_semantics.py dengan tabel yang ditulis manual."""
from scanner.core.evaluator import evaluate
from scanner.core.exceptions import EvaluationError

OPS = [("equals", 1), ("equals", "x"), ("equals", True), ("not_equals", 0), ("not_equals", "x"),
       ("gt", 5), ("gte", 5), ("lt", 5), ("lte", 5), ("in", [1, 2, 3]), ("not_in", [0, "0"]),
       ("not_in", [1, 2]), ("one_of", [1, 2, 3]), ("matches", "^[0-9]+$"), ("contains", "ab"),
       ("exists", None), ("not_exists", None)]
INPUTS = [("None", None), ("''", ""), ("'abc'", "abc"), ("'5'", "5"), ("'  '", "  ")]


def outcome(op, expected, actual):
    try:
        return "PASS" if evaluate(op, expected, actual) else "FAIL"
    except EvaluationError:
        return "ERROR"


def compute():
    return {(op, repr(exp)): [outcome(op, exp, a) for _, a in INPUTS] for op, exp in OPS}


def render_markdown() -> str:
    head = "| operator `expected` | " + " | ".join(f"actual={n}" for n, _ in INPUTS) + " |"
    rows = [head, "|---|" + "---|" * len(INPUTS)]
    for (op, exp), res in compute().items():
        rows.append(f"| `{op} {exp}` | " + " | ".join(res) + " |")
    return "\n".join(rows)
