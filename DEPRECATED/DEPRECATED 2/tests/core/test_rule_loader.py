import os
import sys
import pytest

# Ensure scanner is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scanner.core import (
    load_rule, evaluate, emit_finding, registry,
)
from scanner.core.probes.base import ProbeResult
from scanner.core.exceptions import RuleValidationError


RULE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "rules", "windows", "win-fw-domain.yaml")


def test_load_rule():
    rule = load_rule(RULE_PATH)
    assert rule.rule_id == "WIN-FW-DOMAIN"
    assert rule.category == "network_security"
    assert rule.severity == "CRITICAL"
    assert rule.condition.operator == "equals"
    assert rule.condition.expected_value is True
    assert rule.probe.provider == "windows.powershell"


def test_evaluate_pass():
    assert evaluate("equals", True, True) is True
    assert evaluate("equals", True, "true") is True


def test_evaluate_fail():
    assert evaluate("equals", True, False) is False


def test_emit_finding_schema():
    rule = load_rule(RULE_PATH)
    probe = ProbeResult(
        value=False,
        evidence={"source": "powershell", "observed": False},
    )
    status = "PASS" if evaluate(
        rule.condition.operator, rule.condition.expected_value, probe.value
    ) else "FAIL"

    finding = emit_finding(
        rule=rule, scan_id="scan-test-001", index=1,
        status=status, actual_value=probe.value, probe_result=probe,
    )

    # Schema compliance check
    assert finding["finding_id"] == "scan-test-001-001"
    assert finding["control_id"] == "WIN-FW-DOMAIN"
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "CRITICAL"
    assert finding["comparison"]["expected"] is True
    assert finding["comparison"]["actual"] is False
    assert "timestamp" in finding
    assert "evidence" in finding
    assert "remediation" in finding


def test_probe_registry_has_windows_powershell():
    assert "windows.powershell" in registry.list_providers()


def test_invalid_operator_raises():
    from scanner.core.evaluator import EvaluationError
    with pytest.raises(EvaluationError):
        evaluate("invalid_op", True, True)


def test_load_invalid_rule_missing_field(tmp_path):
    bad_rule = tmp_path / "bad.yaml"
    bad_rule.write_text("rule_id: TEST\n")  # missing required fields
    with pytest.raises(RuleValidationError):
        load_rule(str(bad_rule))


def test_duplicate_rule_id_detection(tmp_path):
    rule1 = tmp_path / "rule1.yaml"
    rule2 = tmp_path / "rule2.yaml"
    content = """rule_id: DUPLICATE
title: Test
category: authentication
os: windows
standard:
  name: CIS
  reference: "1.0"
severity: HIGH
confidence: DIRECT
condition:
  operator: equals
  expected_value: true
probe:
  provider: windows.powershell
  params:
    command: "echo test"
remediation:
  action: "fix"
"""
    rule1.write_text(content)
    rule2.write_text(content)
    from scanner.core import load_rules_from_dir
    with pytest.raises(RuleValidationError, match="Duplicate rule_id"):
        load_rules_from_dir(str(tmp_path))