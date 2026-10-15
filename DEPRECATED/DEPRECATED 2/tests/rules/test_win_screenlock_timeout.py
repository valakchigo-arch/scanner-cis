import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-screenlock-timeout.yaml"


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


def test_screenlock_900_pass():
    """900 detik = tepat di threshold = PASS."""
    _set_mock("900")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "PASS"


def test_screenlock_600_pass():
    """600 detik < 900 = lebih ketat = PASS."""
    _set_mock("600")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "PASS"


def test_screenlock_1800_fail():
    """1800 detik > 900 = FAIL."""
    _set_mock("1800")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL"


def test_screenlock_missing_fail():
    """Key absen = tidak ada screen lock = FAIL."""
    _set_mock(None)
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL"