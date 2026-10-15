import os
import sys
import pytest

# Ensure scanner is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scanner.core import (
    load_rule, evaluate, emit_finding, registry,
)
from scanner.core.probes.base import ProbeResult
from scanner.core.probes import windows_powershell
from scanner.core.exceptions import ProbeExecutionError


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


# This test requires Windows + PowerShell
# Run with: pytest tests/core/test_win_fw_domain_e2e.py::test_probe_execution -v
@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows PowerShell")
def test_probe_execution():
    """Test actual PowerShell probe execution on Windows.

    Probe returns RAW STRING (by design). Type coercion happens in evaluator.
    """
    rule = load_rule(RULE_PATH)
    probe_fn = registry.get("windows.powershell")

    probe_result = probe_fn(rule.probe.params)

    # Probe returns raw string — NOT bool/int/float
    assert isinstance(probe_result.value, str), \
        f"Expected str, got {type(probe_result.value).__name__}: {probe_result.value!r}"

    # Get-NetFirewallProfile returns "True" or "False"
    assert probe_result.value in ("True", "False"), \
        f"Unexpected PowerShell output: {probe_result.value!r}"

    # Evidence should contain the observed value
    assert probe_result.evidence["observed"] == probe_result.value
    assert probe_result.evidence["source"] == "powershell"


@pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows PowerShell")
def test_full_e2e_flow():
    """Complete rule → probe → evaluate → emit flow."""
    rule = load_rule(RULE_PATH)

    # 1. Load rule
    assert rule.rule_id == "WIN-FW-DOMAIN"

    # 2. Get probe
    probe_fn = registry.get(rule.probe.provider)

    # 3. Execute probe
    probe_result = probe_fn(rule.probe.params)

    # 4. Evaluate
    passed = evaluate(rule.condition.operator, rule.condition.expected_value, probe_result.value)

    # 5. Emit finding
    finding = emit_finding(
        rule=rule, scan_id="scan-e2e-002", index=1,
        status="PASS" if passed else "FAIL",
        actual_value=probe_result.value,
        probe_result=probe_result,
    )

    # Verify complete finding
    assert finding["finding_id"] == "scan-e2e-002-001"
    assert finding["control_id"] == "WIN-FW-DOMAIN"
    assert finding["status"] in ("PASS", "FAIL")
    assert finding["comparison"]["operator"] == "equals"
    assert finding["comparison"]["expected"] is True
    assert finding["comparison"]["actual"] == probe_result.value
    assert finding["evidence"]["source"] == "powershell"
    assert "timestamp" in finding

    print(f"\nE2E Test Result:")
    print(f"  Rule: {rule.rule_id}")
    print(f"  Probe value: {probe_result.value}")
    print(f"  Status: {finding['status']}")
    print(f"  Finding ID: {finding['finding_id']}")