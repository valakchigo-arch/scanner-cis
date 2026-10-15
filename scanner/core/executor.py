import logging
import time
from typing import List, Optional

from .rule_model import Rule
from .probe_registry import registry
from .evaluator import evaluate
from .finding_emitter import emit_finding
from .exceptions import ProbeNotFoundError, ProbeExecutionError, EvaluationError
from .probes.base import ProbeResult

logger = logging.getLogger("scanner.executor")


def execute_probe(rule: Rule) -> ProbeResult:
    """Execute probe for a rule. Returns ProbeResult or raises exception."""
    try:
        probe_fn = registry.get(rule.probe.provider)
        result = probe_fn(rule.probe.params)
    except (ProbeNotFoundError, EvaluationError, ProbeExecutionError):
        raise
    except Exception as e:
        raise ProbeExecutionError(f"Probe '{rule.probe.provider}' failed: {e}")
    if not isinstance(result, ProbeResult):
        raise ProbeExecutionError(
            f"Probe '{rule.probe.provider}' returned {type(result).__name__}, expected ProbeResult"
        )
    return result


def evaluate_condition(rule: Rule, actual_value) -> bool:
    """Evaluate rule condition against actual value. Returns True if PASS."""
    try:
        return evaluate(rule.condition.operator, rule.condition.expected_value, actual_value)
    except EvaluationError:
        raise
    except Exception as e:
        raise EvaluationError(f"Evaluation failed: {e}")


def execute_rule(rule: Rule, scan_id: str, index: int, host_os: Optional[str] = None) -> dict:
    """Full pipeline: (OS gate) -> probe -> evaluate -> emit finding.

    Status:
      PASS / FAIL     kondisi dievaluasi
      ERROR           probe/evaluasi gagal; alasan di finding["error_detail"]
      NOT_APPLICABLE  rule.os tidak cocok dengan host_os (hanya bila host_os diberikan)

    TIDAK PERNAH melempar exception ke pemanggil -- satu rule rusak tidak boleh
    menggagalkan seluruh scan.
    """
    t0 = time.perf_counter()
    if host_os and rule.os not in ("any", host_os):
        return emit_finding(rule, scan_id, index, "NOT_APPLICABLE", None, None,
                            error_detail=f"rule os={rule.os}, host os={host_os}")
    try:
        probe_result = execute_probe(rule)
        passed = evaluate_condition(rule, probe_result.value)
        finding = emit_finding(
            rule=rule, scan_id=scan_id, index=index,
            status="PASS" if passed else "FAIL",
            actual_value=probe_result.value, probe_result=probe_result,
        )
        finding["duration_ms"] = round((time.perf_counter() - t0) * 1000)
        return finding
    except Exception as e:  # noqa: BLE001  (ProbeNotFound/ProbeExecution/Evaluation/lainnya)
        detail = f"{type(e).__name__}: {e}"
        logger.warning("rule %s -> ERROR (%s)", rule.rule_id, detail)
        finding = emit_finding(rule=rule, scan_id=scan_id, index=index, status="ERROR",
                               actual_value=None, probe_result=None, error_detail=detail)
        finding["duration_ms"] = round((time.perf_counter() - t0) * 1000)
        return finding


def execute_rules(rules: List[Rule], scan_id: str, host_os: Optional[str] = None) -> List[dict]:
    """Execute multiple rules sequentially. Returns list of findings."""
    return [execute_rule(rule, scan_id, i + 1, host_os) for i, rule in enumerate(rules)]
