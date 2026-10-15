import pytest
from scanner.core import load_rule, execute_rule, registry
from scanner.core.probes.base import ProbeResult

RULE_PATH = "rules/windows/win-lmhash-disabled.yaml"


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


def test_lmhash_missing_key_pass():
    """Key absen = default modern Windows = LM hash disabled = PASS."""
    _set_mock(None)
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "PASS", \
        "Missing NoLMHash key should PASS (modern default)"


def test_lmhash_explicit_one_pass():
    """NoLMHash=1 = eksplisit disabled = PASS."""
    _set_mock("1")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "PASS"


def test_lmhash_zero_fail():
    """NoLMHash=0 = LM hash enabled = FAIL."""
    _set_mock("0")
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL", \
        "NoLMHash=0 means LM hash enabled — must FAIL"


def test_lmhash_int_zero_fail():
    """Kalau provider return int 0 (bukan string), harus tetap FAIL."""
    _set_mock(0)
    rule = load_rule(RULE_PATH)
    finding = execute_rule(rule, "scan-test", 1)
    assert finding["status"] == "FAIL"