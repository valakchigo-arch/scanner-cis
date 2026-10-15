import pytest
from scanner.core import (
    load_rule, execute_rule, execute_rules, execute_probe, evaluate_condition,
    registry, Rule, Condition, Probe
)
from scanner.core.probes.base import ProbeResult
from scanner.core.exceptions import ProbeNotFoundError, ProbeExecutionError, EvaluationError


RULE_PATH = "rules/windows/win-fw-domain.yaml"


def create_mock_rule(provider: str, params: dict, expected_value, operator: str = "equals") -> Rule:
    """Create a test rule with mock provider."""
    return Rule(
        rule_id="TEST-MOCK",
        title="Test Mock Rule",
        category="authentication",
        os="windows",
        standard={"name": "CIS", "reference": "1.0"},
        severity="HIGH",
        confidence="DIRECT",
        condition=Condition(operator=operator, expected_value=expected_value),
        probe=Probe(provider=provider, params=params),
        remediation={"action": "Enable setting"},
        description="Test rule for mock provider",
    )


class TestExecutor:
    def test_evaluate_condition_pass(self):
        rule = load_rule(RULE_PATH)
        assert evaluate_condition(rule, True) is True

    def test_evaluate_condition_fail(self):
        rule = load_rule(RULE_PATH)
        assert evaluate_condition(rule, False) is False

    def test_execute_rules_multiple(self):
        rule = load_rule(RULE_PATH)
        findings = execute_rules([rule, rule], "scan-multi-001")
        assert len(findings) == 2
        assert findings[0]["finding_id"] == "scan-multi-001-001"
        assert findings[1]["finding_id"] == "scan-multi-001-002"
        assert findings[0]["control_id"] == "WIN-FW-DOMAIN"
        assert findings[1]["control_id"] == "WIN-FW-DOMAIN"


class TestExecutorWithMockProbe:
    """Test executor with a mock probe provider."""

    @classmethod
    def setup_class(cls):
        # Register a mock provider once
        def mock_probe(params):
            return ProbeResult(
                value=params.get("return_value", True),
                evidence={"source": "mock", "params": params},
            )
        registry.register("mock.provider", mock_probe)

    def test_execute_rule_with_mock_pass(self):
        rule = create_mock_rule("mock.provider", {"return_value": True}, True)
        finding = execute_rule(rule, "scan-mock-001", 1)
        assert finding["status"] == "PASS"
        assert finding["comparison"]["actual"] is True
        assert finding["evidence"]["source"] == "mock"

    def test_execute_rule_with_mock_fail(self):
        rule = create_mock_rule("mock.provider", {"return_value": False}, True)
        finding = execute_rule(rule, "scan-mock-002", 1)
        assert finding["status"] == "FAIL"
        assert finding["comparison"]["actual"] is False

    def test_execute_rule_with_mock_numeric_gt(self):
        rule = create_mock_rule("mock.provider", {"return_value": 15}, 10, "gt")
        finding = execute_rule(rule, "scan-mock-003", 1)
        assert finding["status"] == "PASS"
        assert finding["comparison"]["actual"] == 15

    def test_execute_rule_with_mock_numeric_fail(self):
        rule = create_mock_rule("mock.provider", {"return_value": 5}, 10, "gt")
        finding = execute_rule(rule, "scan-mock-004", 1)
        assert finding["status"] == "FAIL"
        assert finding["comparison"]["actual"] == 5

    def test_execute_rule_unknown_provider_returns_error(self):
        rule = create_mock_rule("unknown.provider", {}, True)
        finding = execute_rule(rule, "scan-mock-006", 1)
        assert finding["status"] == "ERROR"
        assert finding["comparison"]["actual"] is None

    def test_execute_probe_with_mock(self):
        rule = create_mock_rule("mock.provider", {"return_value": "test-value"}, True)
        result = execute_probe(rule)
        assert isinstance(result, ProbeResult)
        assert result.value == "test-value"
        assert result.evidence["source"] == "mock"

    def test_execute_probe_unknown_provider_raises(self):
        rule = create_mock_rule("unknown.provider", {}, True)
        with pytest.raises(ProbeNotFoundError):
            execute_probe(rule)


class TestExecutorE2EFiringRule:
    """Test the actual Windows firewall rule loads and executes (without PowerShell)."""

    def test_load_windows_firewall_rule(self):
        rule = load_rule(RULE_PATH)
        assert rule.rule_id == "WIN-FW-DOMAIN"
        assert rule.probe.provider == "windows.powershell"
        assert rule.condition.operator == "equals"
        assert rule.condition.expected_value is True

    def test_execute_rule_returns_error_when_probe_fails(self):
        """When probe execution fails, execute_rule returns ERROR (not crash)."""
        from scanner.core.exceptions import ProbeExecutionError
        from scanner.core.rule_model import Rule, Condition, Probe

        # Provider yang sengaja fail
        def failing_probe(params):
            raise ProbeExecutionError("simulated probe failure")

        if "test.failing.probe" not in registry.list_providers():
            registry.register("test.failing.probe", failing_probe)

        rule = Rule(
            rule_id="TEST-FAILING-PROBE",
            title="Failing probe test rule",
            category="network_security",
            os="any",
            standard={"name": "TEST", "reference": "1.0"},
            severity="HIGH",
            confidence="DIRECT",
            condition=Condition(operator="equals", expected_value=True),
            probe=Probe(provider="test.failing.probe", params={}),
            remediation={"action": "N/A"},
        )

        finding = execute_rule(rule, "scan-test-001", 1)

        assert finding["status"] == "ERROR"
        assert finding["control_id"] == "TEST-FAILING-PROBE"
        assert finding["comparison"]["actual"] is None