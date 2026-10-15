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


# ── P0-2 boundary matrix (machine inactivity limit, seconds) ──────────────────

@pytest.mark.parametrize("value,expected", [
    ("0",    "FAIL"),   # 0 = no limit -> must be rejected (was accepted by lte 900)
    ("1",    "PASS"),   # minimum valid
    ("600",  "PASS"),   # 10 minutes
    ("900",  "PASS"),   # exactly 15 minutes (boundary)
    ("901",  "FAIL"),   # one second over
    ("1800", "FAIL"),   # 30 minutes
    (None,   "FAIL"),   # key absent = unconfigured
])
def test_screenlock_boundary(value, expected):
    _set_mock(value)
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == expected, \
        f"value={value!r} expected {expected}, got {finding['status']}"


def test_screenlock_rule_uses_machine_wide_policy_path():
    """P0-2: probe must read HKLM InactivityTimeoutSecs, NOT HKCU ScreenSaveTimeOut."""
    r = load_rule(RULE_PATH)
    assert r.probe.params["path"] == \
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    assert r.probe.params["key"] == "InactivityTimeoutSecs"
    assert r.condition.operator == "matches"
    # regex must reject the standalone value "0" (no-limit) even though the
    # literal "900" legitimately contains the digit 0.
    import re as _re
    assert _re.search(r.condition.expected_value, "0") is None
    assert _re.search(r.condition.expected_value, "900") is not None


def test_screenlock_rule_cis_reference_is_win10_enterprise_v4():
    """P0-1: reference must name Windows 10 Enterprise v4.0.0, section 2.3.7.4, L1."""
    r = load_rule(RULE_PATH)
    ref = r.standard["reference"]
    assert "Windows 10 Enterprise Benchmark v4.0.0" in ref
    assert "2.3.7.4" in ref
    assert "(L1)" in ref
    assert "Server 2019" not in ref


def test_screenlock_int_zero_still_fails():
    """Provider returning int 0 (not string) must also FAIL."""
    _set_mock(0)
    finding = execute_rule(load_rule(RULE_PATH), "scan-test", 1)
    assert finding["status"] == "FAIL"