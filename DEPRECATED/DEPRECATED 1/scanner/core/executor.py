from typing import List
from .rule_model import Rule
from .probe_registry import registry
from .evaluator import evaluate
from .finding_emitter import emit_finding
from .exceptions import ProbeNotFoundError, ProbeExecutionError, EvaluationError
from .probes.base import ProbeResult


def execute_probe(rule: Rule) -> ProbeResult:
    """Execute probe for a rule. Returns ProbeResult or raises exception."""
    try:
        probe_fn = registry.get(rule.probe.provider)
        return probe_fn(rule.probe.params)
    except ProbeNotFoundError:
        raise
    except EvaluationError:
        raise
    except Exception as e:
        raise ProbeExecutionError(f"Probe '{rule.probe.provider}' failed: {e}")


def evaluate_condition(rule: Rule, actual_value) -> bool:
    """Evaluate rule condition against actual value. Returns True if PASS."""
    try:
        return evaluate(
            rule.condition.operator,
            rule.condition.expected_value,
            actual_value,
        )
    except EvaluationError:
        raise
    except Exception as e:
        raise EvaluationError(f"Evaluation failed: {e}")


def execute_rule(rule: Rule, scan_id: str, index: int) -> dict:
    """Full pipeline: probe → evaluate → emit finding."""
    try:
        probe_result = execute_probe(rule)
        passed = evaluate_condition(rule, probe_result.value)
        return emit_finding(
            rule=rule,
            scan_id=scan_id,
            index=index,
            status="PASS" if passed else "FAIL",
            actual_value=probe_result.value,
            probe_result=probe_result,
        )
    except (ProbeNotFoundError, ProbeExecutionError) as e:
        return emit_finding(
            rule=rule,
            scan_id=scan_id,
            index=index,
            status="ERROR",
            actual_value=None,
            probe_result=None,
        )
    except EvaluationError as e:
        return emit_finding(
            rule=rule,
            scan_id=scan_id,
            index=index,
            status="ERROR",
            actual_value=None,
            probe_result=None,
        )


def execute_rules(rules: List[Rule], scan_id: str) -> List[dict]:
    """Execute multiple rules sequentially. Returns list of findings."""
    findings = []
    for i, rule in enumerate(rules):
        finding = execute_rule(rule, scan_id, i + 1)
        findings.append(finding)
    return findings