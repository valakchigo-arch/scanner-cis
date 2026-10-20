"""condition.display: teks ramah-manusia untuk recommended_value (regex tidak boleh bocor ke dashboard/AI)."""
import pytest

from scanner.core import load_rule, load_rules_from_dir, execute_rule, registry
from scanner.core.contract_adapter import findings_to_contract
from scanner.core.probes.base import ProbeResult


@pytest.fixture(autouse=True)
def restore():
    orig = registry._providers.get("windows.registry")
    yield
    if orig:
        registry._providers["windows.registry"] = orig


def test_matches_rule_exposes_readable_recommended_value_not_regex():
    registry._providers["windows.registry"] = lambda p: ProbeResult(value="901", evidence={}, raw_output="901")
    f = execute_rule(load_rule("rules/windows/win-screenlock-timeout.yaml"), "s", 1)
    assert f["status"] == "FAIL"
    _, contract = findings_to_contract([f])
    rv = contract[0]["recommended_value"]
    assert "matches" not in rv and "\\d" not in rv and "900" in rv


def test_every_shipped_matches_rule_declares_display():
    for r in load_rules_from_dir("rules/windows"):
        if r.condition.operator == "matches":
            assert r.condition.display, r.rule_id


def test_rules_without_display_keep_the_old_format():
    f = {"status": "FAIL", "control_id": "X", "category": "c", "severity": "HIGH", "title": "t",
         "comparison": {"operator": "gte", "expected": 14, "actual": "0"}}
    assert findings_to_contract([f])[1][0]["recommended_value"] == ">= 14"
    # kunci 'display' tidak muncul di finding bila rule tidak mengisinya (skema lama utuh)
    assert "display" not in execute_rule(load_rule("rules/windows/win-uac-enabled.yaml"), "s", 1).get("comparison", {})


# ---- non-vacuous: tidak bergantung pada ada/tidaknya rule `matches` di rules/ (gagal pada kode tanpa fitur display) ----
def test_adapter_prefers_display_over_raw_expected_value():
    f = {"status": "FAIL", "control_id": "X", "category": "c", "severity": "HIGH", "title": "t",
         "comparison": {"operator": "matches", "expected": r"^\d+$", "actual": "x", "display": "a whole number"}}
    assert findings_to_contract([f])[1][0]["recommended_value"] == "a whole number"


def test_loader_reads_condition_display(tmp_path):
    import textwrap
    base = textwrap.dedent("""\
        rule_id: T-1
        title: t
        category: authentication
        os: windows
        standard: {name: CIS, reference: r}
        severity: LOW
        confidence: DIRECT
        condition: {operator: matches, expected_value: '^1$'%s}
        probe: {provider: windows.registry, params: {path: 'HKLM\\X', key: K}}
        remediation: {action: a}
        description: d
        """)
    (tmp_path / "with.yaml").write_text(base % ", display: 'exactly one'")
    (tmp_path / "without.yaml").write_text(base % "")
    assert load_rule(str(tmp_path / "with.yaml")).condition.display == "exactly one"
    assert load_rule(str(tmp_path / "without.yaml")).condition.display == ""


def test_emitter_includes_display_only_when_set():
    from scanner.core.finding_emitter import emit_finding
    r = load_rule("rules/windows/win-screenlock-timeout.yaml")
    f = emit_finding(r, "s", 1, "FAIL", "901", None)
    assert f["comparison"]["display"] == r.condition.display and r.condition.display
    g = emit_finding(load_rule("rules/windows/win-uac-enabled.yaml"), "s", 1, "FAIL", "0", None)
    assert "display" not in g["comparison"]
