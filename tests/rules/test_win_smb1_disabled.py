import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-smb1-disabled.yaml"


@pytest.fixture(autouse=True)
def mock_powershell():
    original = registry._providers.get("windows.powershell")
    yield
    if original:
        registry._providers["windows.powershell"] = original


def _set_mock(value):
    def mock(params):
        return ProbeResult(value=value, evidence={"source": "powershell"}, raw_output=str(value))
    registry._providers["windows.powershell"] = mock


def test_smb1_disabled_pass():
    _set_mock("Disabled")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "PASS"


def test_smb1_enabled_fail():
    """Host-B baseline: SMBv1 Enabled -> FAIL (CRITICAL)."""
    _set_mock("Enabled")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_smb1_offline_state_fail():
    _set_mock("Offline")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_smb1_missing_value_fail():
    """Probe returns None (feature not enumerated) -> cannot confirm disabled -> FAIL."""
    _set_mock(None)
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_smb1_rule_is_inferred_confidence():
    """P0-3: confidence must be INFERRED (mechanism differs from CIS 18.4.2/18.4.3)."""
    r = load_rule(RULE_PATH)
    assert r.confidence == "INFERRED"
    assert "18.4.2" in r.description and "18.4.3" in r.description


def test_smb1_rule_cis_reference_is_win10_enterprise_v4():
    """P0-1: reference must name Windows 10 Enterprise v4.0.0, sections 18.4.2+18.4.3, L1."""
    r = load_rule(RULE_PATH)
    ref = r.standard["reference"]
    assert "Windows 10 Enterprise Benchmark v4.0.0" in ref
    assert "18.4.2" in ref and "18.4.3" in ref
    assert "(L1)" in ref
    assert "Server 2019" not in ref


def test_smb1_rule_probe_is_powershell_optional_feature():
    """P0-3 decision (a): probe stays on Get-WindowsOptionalFeature, not registry."""
    r = load_rule(RULE_PATH)
    assert r.probe.provider == "windows.powershell"
    assert "Get-WindowsOptionalFeature" in r.probe.params["command"]
    assert "SMB1Protocol" in r.probe.params["command"]