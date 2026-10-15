"""
Scoring Engine — Hitung Hardening Index & Risk Score per SCHEMA.md Section 7.

Configurable weights via JSON/YAML config file.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path
import json


# Default severity weights per SCHEMA.md
DEFAULT_SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
    "UNCLASSIFIED": 0,
}

# Risk level thresholds per SCHEMA.md Section 10
# These are the LOWER bounds for each risk level
# LOW: [0, 25), MEDIUM: [25, 50), HIGH: [50, 75), CRITICAL: [75, 100]
RISK_LEVEL_THRESHOLDS = {
    "MEDIUM": 25,
    "HIGH": 50,
    "CRITICAL": 75,
}

# Finding status constants
FINDING_STATUS = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "NOT_APPLICABLE": "NOT_APPLICABLE",
    "MANUAL": "MANUAL",
    "ERROR": "ERROR",
    "UNKNOWN": "UNKNOWN",
}

# Statuses that count toward applicable controls
APPLICABLE_STATUSES = {FINDING_STATUS["PASS"], FINDING_STATUS["FAIL"], FINDING_STATUS["MANUAL"]}

# Statuses that count as assessed (for coverage)
ASSESSED_STATUSES = {FINDING_STATUS["PASS"], FINDING_STATUS["FAIL"], FINDING_STATUS["NOT_APPLICABLE"], FINDING_STATUS["MANUAL"]}


@dataclass
class ScoringConfig:
    """Konfigurasi scoring yang bisa di-override via config file."""
    severity_weights: dict[str, int] = field(default_factory=lambda: DEFAULT_SEVERITY_WEIGHTS.copy())
    risk_thresholds: dict[str, int] = field(default_factory=lambda: RISK_LEVEL_THRESHOLDS.copy())

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ScoringConfig":
        """Load config from JSON file. Returns defaults if file not found."""
        config = cls()
        if path:
            p = Path(path)
            if p.exists():
                with p.open(encoding="utf-8") as f:
                    data = json.load(f)
                config.severity_weights.update(data.get("severity_weights", {}))
                config.risk_thresholds.update(data.get("risk_thresholds", {}))
        return config

    def save(self, path: str | Path):
        """Save current config to JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump({
                "severity_weights": self.severity_weights,
                "risk_thresholds": self.risk_thresholds,
            }, f, indent=2)


@dataclass
class AssessmentScore:
    """Hasil perhitungan scoring untuk satu assessment."""
    total_controls: int
    applicable_controls: int
    passed: int
    failed: int
    not_applicable: int
    manual: int
    error: int
    unknown: int
    hardening_index: float
    risk_score: float
    risk_level: str
    coverage_percent: float
    # Additive (tidak mengubah angka spec): hasil dengan ERROR/UNKNOWN atau tanpa
    # control yang bisa dinilai tidak boleh dibaca sebagai "100% hardened" murni.
    complete: bool = True          # True jika tidak ada ERROR/UNKNOWN
    indeterminate: bool = False    # True jika tidak ada satu pun control yang dinilai

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_controls": self.total_controls,
            "applicable_controls": self.applicable_controls,
            "passed": self.passed,
            "failed": self.failed,
            "not_applicable": self.not_applicable,
            "manual": self.manual,
            "error": self.error,
            "unknown": self.unknown,
            "hardening_index": round(self.hardening_index, 2),
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level,
            "coverage_percent": round(self.coverage_percent, 2),
            "complete": self.complete,
            "indeterminate": self.indeterminate,
        }


def compute_score(findings: list[dict], config: ScoringConfig | None = None) -> AssessmentScore:
    """
    Hitung Hardening Index & Risk Score dari list findings.

    Args:
        findings: List of finding dicts dengan keys: status, severity
        config: ScoringConfig (optional, uses defaults if None)

    Returns:
        AssessmentScore object
    """
    if config is None:
        config = ScoringConfig()

    total = len(findings)

    # Count by status
    passed = sum(1 for f in findings if f.get("status") == FINDING_STATUS["PASS"])
    failed = sum(1 for f in findings if f.get("status") == FINDING_STATUS["FAIL"])
    not_applicable = sum(1 for f in findings if f.get("status") == FINDING_STATUS["NOT_APPLICABLE"])
    manual = sum(1 for f in findings if f.get("status") == FINDING_STATUS["MANUAL"])
    error = sum(1 for f in findings if f.get("status") == FINDING_STATUS["ERROR"])
    unknown = sum(1 for f in findings if f.get("status") == FINDING_STATUS["UNKNOWN"])

    # Applicable = PASS + FAIL + MANUAL
    applicable = passed + failed + manual

    # Hardening Index = PASS / applicable * 100
    if applicable > 0:
        hardening_index = (passed / applicable) * 100
    else:
        hardening_index = 100.0  # No applicable controls = fully hardened

    # Risk Score (Normalized per SCHEMA.md Section 7)
    # raw = sum(severity_weight[severity] for each FAIL)
    # max_possible = sum(severity_weight[severity] for each applicable control)
    # risk_score = (raw / max_possible) * 100

    raw = 0
    max_possible = 0

    for f in findings:
        status = f.get("status")
        severity = f.get("severity", "UNCLASSIFIED")
        weight = config.severity_weights.get(severity, 0)

        if status in APPLICABLE_STATUSES:
            max_possible += weight
            if status == FINDING_STATUS["FAIL"]:
                raw += weight

    if max_possible > 0:
        risk_score = (raw / max_possible) * 100
    else:
        risk_score = 0.0  # No applicable controls = no risk

    # Risk Level
    risk_level = "LOW"
    if risk_score >= config.risk_thresholds.get("CRITICAL", 75):
        risk_level = "CRITICAL"
    elif risk_score >= config.risk_thresholds.get("HIGH", 50):
        risk_level = "HIGH"
    elif risk_score >= config.risk_thresholds.get("MEDIUM", 25):
        risk_level = "MEDIUM"

    # Coverage = assessed / total * 100
    assessed = sum(1 for f in findings if f.get("status") in ASSESSED_STATUSES)
    coverage_percent = (assessed / total * 100) if total > 0 else 0.0

    return AssessmentScore(
        total_controls=total,
        applicable_controls=applicable,
        passed=passed,
        failed=failed,
        not_applicable=not_applicable,
        manual=manual,
        error=error,
        unknown=unknown,
        hardening_index=hardening_index,
        risk_score=risk_score,
        risk_level=risk_level,
        coverage_percent=coverage_percent,
        complete=(error == 0 and unknown == 0),
        indeterminate=(total > 0 and applicable == 0),
    )


def score_assessment(findings: list[dict], config_path: str | Path | None = None) -> dict[str, Any]:
    """
    Convenience function: load config, compute score, return dict.

    Usage:
        score = score_assessment(findings)
        # or with custom config:
        score = score_assessment(findings, "config/scoring.json")
    """
    config = ScoringConfig.load(config_path)
    score = compute_score(findings, config)
    return score.to_dict()


# Example config file content:
# {
#   "severity_weights": {
#     "CRITICAL": 10,
#     "HIGH": 7,
#     "MEDIUM": 4,
#     "LOW": 1,
#     "INFO": 0,
#     "UNCLASSIFIED": 0
#   },
#   "risk_thresholds": {      # LOWER bound tiap level (lihat RISK_LEVEL_THRESHOLDS)
#     "MEDIUM": 25,
#     "HIGH": 50,
#     "CRITICAL": 75
#   }
# }