import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-uac-enabled.yaml"


@pytest.fixture(autouse=True)
def mock_registry():
    """Temporarily replace windows.registry provider."""
    original = registry._providers.get("windows.registry")
    yield
    if original:
        registry._providers["windows.registry"] = original


def _set_mock(value):
    def mock(params):
        return ProbeResult(value=value, evidence={"source": "registry"}, raw_output=str(value))
    registry._providers["windows.registry"] = mock


def test_uac_enabled_pass():
    _set_mock("1")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "PASS"
    assert finding["comparison"]["actual"] == "1"
    assert finding["comparison"]["expected"] == 1


def test_uac_disabled_fail():
    _set_mock("0")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_uac_missing_key_fail():
    _set_mock(None)
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL"