import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-acct-lockout.yaml"


@pytest.fixture(autouse=True)
def mock_registry():
    original = registry._providers.get("windows.powershell")
    yield
    if original:
        registry._providers["windows.powershell"] = original


def _set_mock(value):
    def mock(params):
        return ProbeResult(value=value, evidence={"source": "secedit"}, raw_output=str(value))
    registry._providers["windows.powershell"] = mock


@pytest.mark.parametrize("threshold", ["1", "3", "5"])
def test_lockout_valid_thresholds_pass(threshold):
    _set_mock(threshold)
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "PASS", f"Threshold {threshold} should PASS"


def test_lockout_zero_fail():
    """0 = never lock = endpoint never protects against brute force."""
    _set_mock("0")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL", "Threshold 0 (never lock) must FAIL"


def test_lockout_10_fail():
    """10 > 5 = too permissive."""
    _set_mock("10")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_lockout_100_fail():
    _set_mock("100")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"