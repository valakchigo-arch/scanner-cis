"""B3: verifikasi exact-match standard.reference tiap rule vs tabel CIS v4.0.0."""
from pathlib import Path
import pytest
from scanner.core.rule_loader import load_rules_from_dir

EXPECTED = {
    "WIN-PASS-MINLEN":        "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.1.4 (L1)",
    "WIN-PASS-COMPLEX":       "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.1.5 (L1)",
    "WIN-ACCT-LOCKOUT":       "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.2.2 (L1)",
    "WIN-GUEST-DISABLED":     "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.1.2 (L1)",
    "WIN-SCREENLOCK-TIMEOUT": "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.7.4 (L1)",
    "WIN-LMHASH-DISABLED":    "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.11.5 (L1)",
    "WIN-UAC-ENABLED":        "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.17.6 (L1)",
    "WIN-REMOTEREG-DISABLED": "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 5.26 (L2)",
    "WIN-FW-DOMAIN":          "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.1.1 (L1)",
    "WIN-FW-PRIVATE":         "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.2.1 (L1)",
    "WIN-FW-PUBLIC":          "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.3.1 (L1)",
    "WIN-SMB1-DISABLED":      "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.4.2 + 18.4.3 (L1)",
    "WIN-DEFENDER-ENABLED":   "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.10.43.10.3 (L1)",
    "WIN-RDP-NLA":            "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.10.57.3.9.4 (L1)",
}

def test_all_14_rules_have_expected_reference():
    rules = load_rules_from_dir("rules/windows")
    assert len(rules) == 14, f"Expected 14 rules, got {len(rules)}"
    actual = {r.rule_id: r.standard["reference"] for r in rules}
    mismatches = {rid: (actual.get(rid), EXPECTED[rid])
                  for rid in EXPECTED if actual.get(rid) != EXPECTED[rid]}
    assert not mismatches, "Reference mismatches:\n" + "\n".join(
        f"  {rid}\n    expected: {exp!r}\n    actual:   {act!r}"
        for rid, (act, exp) in mismatches.items()
    )

def test_reference_format():
    rules = load_rules_from_dir("rules/windows")
    for r in rules:
        ref = r.standard["reference"]
        assert ref.startswith("CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, "), \
            f"{r.rule_id}: bad prefix"
        assert "(L1)" in ref or "(L2)" in ref, f"{r.rule_id}: missing level marker"

def test_rule_count_and_levels():
    rules = load_rules_from_dir("rules/windows")
    l2_count = sum(1 for r in rules if "(L2)" in r.standard["reference"])
    l1_count = sum(1 for r in rules if "(L1)" in r.standard["reference"])
    assert l2_count == 1, f"Expected exactly 1 L2 rule (WIN-REMOTEREG), got {l2_count}"
    assert l1_count == 13, f"Expected 13 L1 rules, got {l1_count}"
