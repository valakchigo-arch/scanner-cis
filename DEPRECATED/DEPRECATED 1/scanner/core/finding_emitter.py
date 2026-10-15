from datetime import datetime, timezone
from .rule_model import Rule
from .probes.base import ProbeResult


def emit_finding(
    rule: Rule,
    scan_id: str,
    index: int,
    status: str,                   # PASS | FAIL | ERROR | MANUAL | ...
    actual_value,
    probe_result: ProbeResult = None,
) -> dict:
    """
    Emit finding dict per docs/assessment/SCHEMA.md Section 4.
    """
    finding_id = f"{scan_id}-{index:03d}"

    evidence = {}
    if probe_result is not None:
        evidence = probe_result.evidence

    finding = {
        "finding_id": finding_id,
        "control_id": rule.rule_id,
        "title": rule.title,
        "category": rule.category,
        "status": status,
        "severity": rule.severity,
        "confidence": rule.confidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "standard": rule.standard,
        "description": rule.description or rule.title,
        "comparison": {
            "operator": rule.condition.operator,
            "expected": rule.condition.expected_value,
            "actual": actual_value,
        },
        "evidence": evidence,
        "remediation": rule.remediation,
    }
    return finding