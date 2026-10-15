import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-pass-complex.yaml"


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


def test_complex_enabled_pass():
    _set_mock("1")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "PASS"


def test_complex_disabled_fail():
    _set_mock("0")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"