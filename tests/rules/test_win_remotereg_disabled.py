import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-remotereg-disabled.yaml"


@pytest.fixture(autouse=True)
def mock_registry():
    original = registry._providers.get("windows.registry")
    yield
    if original:
        registry._providers["windows.registry"] = original


def _set_mock(value):
    def mock(params):
        return ProbeResult(value=value, evidence={"source": "registry"}, raw_output=str(value))
    registry._providers["windows.registry"] = mock


def test_remotereg_disabled_pass():
    _set_mock("4")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "PASS"


def test_remotereg_manual_fail():
    _set_mock("3")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL", "Manual start = FAIL per CIS"


def test_remotereg_auto_fail():
    _set_mock("2")
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"