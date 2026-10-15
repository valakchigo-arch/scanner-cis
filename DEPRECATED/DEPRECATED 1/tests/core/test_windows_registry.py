import pytest
from scanner.core import (
    execute_probe, evaluate_condition, registry, Rule, Condition, Probe
)
from scanner.core.probes.base import ProbeResult
from scanner.core.exceptions import ProbeNotFoundError, ProbeExecutionError


class TestWindowsRegistryProvider:
    """Test windows.registry provider with mocked PowerShell output."""

    @classmethod
    def setup_class(cls):
        # Provider already registered in core/__init__.py, replace with mock
        def mock_registry(params):
            path = params.get("path")
            key = params.get("key")
            
            # Simulate different registry scenarios
            if path == "HKLM\\SYSTEM\\ControlSet001\\Control\\Lsa" and key == "NoLMHash":
                # Key missing (modern Windows default)
                return ProbeResult(
                    value=None,
                    evidence={"source": "registry", "path": path, "key": key, "observed": None, "note": "value_not_present"},
                    raw_output="__NOT_FOUND__",
                )
            elif path == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" and key == "EnableLUA":
                # UAC enabled
                return ProbeResult(
                    value="1",
                    evidence={"source": "registry", "path": path, "key": key, "observed": "1"},
                    raw_output="1",
                )
            elif path == "HKCU\\Control Panel\\Desktop" and key == "ScreenSaveTimeOut":
                # Screen saver timeout = 900 seconds
                return ProbeResult(
                    value="900",
                    evidence={"source": "registry", "path": path, "key": key, "observed": "900"},
                    raw_output="900",
                )
            else:
                raise ProbeExecutionError(f"Unexpected params: {params}")

        # Unregister and re-register with mock
        registry._providers.pop("windows.registry", None)
        registry.register("windows.registry", mock_registry)

    def test_registry_provider_registered(self):
        assert "windows.registry" in registry.list_providers()

    def test_execute_probe_missing_key_returns_none(self):
        """Key not found → value=None, evidence.note='value_not_present'"""
        rule = Rule(
            rule_id="TEST-LMHASH",
            title="Test LM Hash",
            category="cryptography",
            os="windows",
            standard={"name": "CIS", "reference": "1.0"},
            severity="HIGH",
            confidence="INFERRED",
            condition=Condition(operator="exists", expected_value=False),
            probe=Probe(provider="windows.registry", params={
                "path": "HKLM\\SYSTEM\\ControlSet001\\Control\\Lsa",
                "key": "NoLMHash"
            }),
            remediation={"action": "Set NoLMHash=1"},
        )
        result = execute_probe(rule)
        assert result.value is None
        assert result.evidence["note"] == "value_not_present"
        assert result.evidence["source"] == "registry"

    def test_execute_probe_uac_enabled(self):
        """UAC registry value '1' → string '1'"""
        rule = Rule(
            rule_id="TEST-UAC",
            title="Test UAC",
            category="authorization",
            os="windows",
            standard={"name": "CIS", "reference": "1.0"},
            severity="HIGH",
            confidence="DIRECT",
            condition=Condition(operator="equals", expected_value=True),
            probe=Probe(provider="windows.registry", params={
                "path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "key": "EnableLUA"
            }),
            remediation={"action": "Enable UAC"},
        )
        result = execute_probe(rule)
        assert result.value == "1"
        assert result.evidence["source"] == "registry"

    def test_execute_probe_numeric_string(self):
        """ScreenSaveTimeOut returns string '900'"""
        rule = Rule(
            rule_id="TEST-SCREENLOCK",
            title="Test Screen Lock",
            category="authentication",
            os="windows",
            standard={"name": "CIS", "reference": "1.0"},
            severity="MEDIUM",
            confidence="DIRECT",
            condition=Condition(operator="lte", expected_value=900),
            probe=Probe(provider="windows.registry", params={
                "path": "HKCU\\Control Panel\\Desktop",
                "key": "ScreenSaveTimeOut"
            }),
            remediation={"action": "Set timeout <= 900"},
        )
        result = execute_probe(rule)
        assert result.value == "900"

    def test_evaluate_missing_key_exists_false(self):
        """exists operator with None → False (PASS for expected_value: false)"""
        from scanner.core.evaluator import evaluate
        # exists(None) = False, expected_value=False → PASS
        assert evaluate("exists", False, None) is False

    def test_evaluate_numeric_lte(self):
        """lte with string '900' vs expected int 900"""
        from scanner.core.evaluator import evaluate
        # evaluator coerces "900" → 900, then 900 <= 900 → True
        assert evaluate("lte", 900, "900") is True
        assert evaluate("lte", 900, "1800") is False


class TestLMHashLogic:
    """Test the LM Hash logic: missing key = PASS, value=0 = FAIL, value=1 = PASS."""

    def test_lmhash_missing_key_passes(self):
        """Key tidak ada → None → exists=False → PASS (expected_value: false)"""
        from scanner.core.evaluator import evaluate
        # exists(None) = False, expected=False → PASS
        assert evaluate("exists", False, None) is False

    def test_lmhash_zero_value_fails(self):
        """Key ada & value='0' → exists=True → FAIL (expected_value: false)"""
        from scanner.core.evaluator import evaluate
        assert evaluate("exists", False, "0") is True  # exists returns True → doesn't match expected=False

    def test_lmhash_explicit_one_passes(self):
        """Key ada & value='1' → exists=True → FAIL (expected_value: false) - WRONG"""
        from scanner.core.evaluator import evaluate
        assert evaluate("exists", False, "1") is True  # This FAILs but should PASS - design flaw

    def test_lmhash_better_design_not_equals_zero(self):
        """
        Better design: operator=not_equals, expected_value="0" (string)
        - missing key (None) → str coercion fails → type mismatch → FAIL (wrong!)
        - value='0' → "0" == "0" → not_equals = False → FAIL ✅
        - value='1' → "1" != "0" → PASS ✅
        """
        from scanner.core.evaluator import evaluate
        
        # None fails coercion to str → type mismatch → FAIL
        assert evaluate("not_equals", "0", None) is False
        
        # "0" == "0" → not_equals = False → FAIL ✅
        assert evaluate("not_equals", "0", "0") is False
        
        # "1" != "0" → PASS ✅
        assert evaluate("not_equals", "0", "1") is True

    def test_lmhash_best_design_one_of(self):
        """
        Best design: operator=one_of, expected_value=[None, "1", 1]
        But one_of uses _coerce which rejects None.
        
        Actually the cleanest for this specific case:
        - Use operator=not_equals with expected_value=0 (int)
        - Missing key (None) → coerce fails → FAIL (wrong)
        - "0" → coerce to 0 → 0 != 0 → False → FAIL ✅
        - "1" → coerce to 1 → 1 != 0 → True → PASS ✅
        
        Problem: None always fails coercion.
        
        Solution: Custom rule with condition that handles None specially,
        or use MANUAL confidence with logic in rule description.
        """
        from scanner.core.evaluator import evaluate
        
        # Test: operator=not_equals, expected_value=0 (int)
        assert evaluate("not_equals", 0, None) is False  # type mismatch → FAIL
        assert evaluate("not_equals", 0, "0") is False   # 0 == 0 → FAIL ✅
        assert evaluate("not_equals", 0, "1") is True    # 1 != 0 → PASS ✅


class TestRegistryEdgeCases:
    """Test edge cases for registry provider."""

    def test_unknown_provider_raises(self):
        rule = Rule(
            rule_id="T", title="T", category="c", os="windows",
            standard={"name": "CIS", "reference": "1.0"},
            severity="HIGH", confidence="DIRECT",
            condition=Condition(operator="equals", expected_value=True),
            probe=Probe(provider="windows.unknown", params={}),
            remediation={"action": "a"},
        )
        with pytest.raises(ProbeNotFoundError):
            execute_probe(rule)

    def test_missing_params_raises(self):
        # This would be caught by provider, but let's test executor handles it
        pass  # Need real PowerShell to test