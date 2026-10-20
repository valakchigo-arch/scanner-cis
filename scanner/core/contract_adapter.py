"""
core/contract_adapter.py
------------------------
Menjembatani rule engine (finding SCHEMA.md: PASS/FAIL/ERROR/NOT_APPLICABLE)
ke kontrak beacon v2 (hanya temuan yang GAGAL + blok meta).

Aturan pemetaan (disengaja, dijelaskan di docs/METHODOLOGY.md):
  FAIL            -> finding kontrak
  PASS            -> tidak dikirim (dihitung di tests_executed)
  ERROR           -> TIDAK dikirim sebagai temuan; dihitung di tests_skipped/tests_errored.
                     Probe yang gagal bukan bukti kontrol dilanggar.
  NOT_APPLICABLE  -> tidak dikirim; dihitung di tests_skipped
hardening_index = PASS / (PASS + FAIL) * 100 dari kontrol yang benar-benar dinilai;
None bila tidak ada satu pun yang dinilai (bukan 0 dan bukan 100).
"""
from __future__ import annotations

from typing import Any, Optional

_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
             "LOW": "Low", "INFO": "Low", "UNCLASSIFIED": "Low"}

_OP_TEXT = {"equals": "=", "not_equals": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=",
            "in": "in", "not_in": "not in", "one_of": "one of", "matches": "matches",
            "contains": "contains", "exists": "exists", "not_exists": "not exists"}


def _fmt_expected(cmp: dict) -> str:
    if cmp.get("display"):          # rule menyediakan teks yang layak dibaca (mis. untuk regex)
        return str(cmp["display"])
    op, exp = cmp.get("operator"), cmp.get("expected")
    if op in ("exists", "not_exists"):
        return _OP_TEXT[op]
    return f"{_OP_TEXT.get(op, op)} {exp}"


def findings_to_contract(findings: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return (meta_counts, contract_findings)."""
    contract: list[dict[str, Any]] = []
    passed = failed = errored = skipped_na = 0
    errored_ids: list[str] = []

    for f in findings:
        status = f.get("status")
        if status == "PASS":
            passed += 1
        elif status == "FAIL":
            failed += 1
            actual = f.get("comparison", {}).get("actual")
            contract.append({
                "check_id": f["control_id"],
                "category": f.get("category"),
                "finding_type": "cis_check",
                "severity": _SEVERITY.get(f.get("severity"), "Low"),
                "description": f.get("title") or f.get("description"),
                "detail_field": f["control_id"],
                "current_value": (str(actual)[:150] if actual not in (None, "") else "(kosong/tidak terdeteksi)"),
                "recommended_value": _fmt_expected(f.get("comparison", {})),
            })
        elif status == "NOT_APPLICABLE":
            skipped_na += 1
        else:  # ERROR / UNKNOWN / lainnya: tidak boleh dianggap pelanggaran
            errored += 1
            errored_ids.append(f.get("control_id", "?"))

    assessed = passed + failed
    meta = {
        "hardening_index": round(100 * passed / assessed) if assessed else None,
        "tests_executed": assessed,
        "tests_skipped": errored + skipped_na,
        "tests_errored": errored,
        # % kontrol yang BERHASIL dinilai (di luar N/A). <100 = hasil parsial -> indeks
        # dihitung dari sebagian kontrol saja; jangan dibaca setara scan lengkap.
        "coverage_percent": round(100 * assessed / (assessed + errored)) if (assessed + errored) else 0,
        "errored_check_ids": errored_ids,
    }
    return meta, contract
