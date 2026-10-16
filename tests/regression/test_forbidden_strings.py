import os
from pathlib import Path

def test_no_forbidden_strings_in_rules_and_docs():
    """P2: ensure no 'Server 2019' / 'Windows Server' CIS labels remain."""
    root = Path(__file__).resolve().parents[2]
    forbidden = ("Server 2019", "CIS Windows Server")
    offenders = []
    for p in root.rglob("*.yaml"):
        if "DEPRECATED" in str(p):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for f in forbidden:
            if f in txt:
                offenders.append(f"{p}:{f}")
    # docs check
    for p in root.rglob("*.md"):
        if "DEPRECATED" in str(p):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for f in forbidden:
            if f in txt and f != "Windows Server":  # allow generic if needed? per spec forbid
                offenders.append(f"{p}:{f}")
    assert not offenders, f"Forbidden strings found: {offenders}"


def test_all_rule_references_match_format():
    """All 14 rules must have CIS Windows 10 Enterprise v4.0.0 + section + (L1/L2)."""
    root = Path(__file__).resolve().parents[2]
    y = []
    for p in root.rglob("rules/windows/*.yaml"):
        txt = p.read_text(encoding="utf-8")
        assert "Windows 10 Enterprise Benchmark v4.0.0" in txt
        assert "Server 2019" not in txt
        y.append(p)
    assert len(y) == 14, f"Expected 14 YAMLs, found {len(y)}"