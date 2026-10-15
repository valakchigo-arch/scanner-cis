import pytest
from scanner.core import load_rule, evaluate, emit_finding
from scanner.core.probes.base import ProbeResult


RULE_PATH = "rules/windows/win-fw-domain.yaml"


def test_emit_finding_schema_compliance():
    rule = load_rule(RULE_PATH)
    probe = ProbeResult(
        value=False,
        evidence={"source": "powershell", "observed": False, "command": "..."},
    )
    status = "PASS" if evaluate(
        rule.condition.operator, rule.condition.expected_value, probe.value
    ) else "FAIL"

    finding = emit_finding(
        rule=rule, scan_id="scan-test-001", index=1,
        status=status, actual_value=probe.value, probe_result=probe,
    )

    # Required fields per SCHEMA.md Section 4
    assert "finding_id" in finding
    assert "control_id" in finding
    assert "title" in finding
    assert "category" in finding
    assert "status" in finding
    assert "severity" in finding
    assert "confidence" in finding
    assert "timestamp" in finding
    assert "standard" in finding
    assert "description" in finding
    assert "comparison" in finding
    assert "evidence" in finding
    assert "remediation" in finding

    # Values
    assert finding["finding_id"] == "scan-test-001-001"
    assert finding["control_id"] == "WIN-FW-DOMAIN"
    assert finding["title"] == "Windows Firewall Domain Profile Enabled"
    assert finding["category"] == "network_security"
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "CRITICAL"
    assert finding["confidence"] == "DIRECT"
    assert finding["standard"]["name"] == "CIS"
    assert finding["comparison"]["operator"] == "equals"
    assert finding["comparison"]["expected"] is True
    assert finding["comparison"]["actual"] is False
    assert finding["evidence"]["source"] == "powershell"
    assert finding["remediation"]["action"] is not None


def test_emit_finding_pass_status():
    rule = load_rule(RULE_PATH)
    probe = ProbeResult(
        value=True,
        evidence={"source": "powershell", "observed": True},
    )
    status = "PASS" if evaluate(
        rule.condition.operator, rule.condition.expected_value, probe.value
    ) else "FAIL"

    finding = emit_finding(
        rule=rule, scan_id="scan-test-002", index=1,
        status=status, actual_value=probe.value, probe_result=probe,
    )

    assert finding["status"] == "PASS"
    assert finding["comparison"]["actual"] is True


def test_emit_finding_without_probe_result():
    rule = load_rule(RULE_PATH)
    finding = emit_finding(
        rule=rule, scan_id="scan-test-003", index=1,
        status="ERROR", actual_value=None, probe_result=None,
    )

    assert finding["evidence"] == {}
    assert finding["comparison"]["actual"] is None