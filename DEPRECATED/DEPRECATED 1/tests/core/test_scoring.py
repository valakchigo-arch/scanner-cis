import pytest
from scanner.core.scoring import (
    compute_score, score_assessment, ScoringConfig, DEFAULT_SEVERITY_WEIGHTS, RISK_LEVEL_THRESHOLDS,
    FINDING_STATUS, APPLICABLE_STATUSES, ASSESSED_STATUSES,
)


# ─── Test Fixtures ──────────────────────────────────────────────

def make_finding(status: str, severity: str = "HIGH") -> dict:
    return {"status": status, "severity": severity}


def all_pass_findings(n: int = 5) -> list[dict]:
    return [make_finding("PASS") for _ in range(n)]


def mixed_findings() -> list[dict]:
    return [
        make_finding("PASS", "CRITICAL"),
        make_finding("PASS", "HIGH"),
        make_finding("FAIL", "CRITICAL"),
        make_finding("FAIL", "HIGH"),
        make_finding("FAIL", "MEDIUM"),
        make_finding("NOT_APPLICABLE", "LOW"),
        make_finding("MANUAL", "HIGH"),
        make_finding("ERROR", "MEDIUM"),
        make_finding("UNKNOWN", "INFO"),
    ]


# ─── Config Tests ───────────────────────────────────────────────

def test_default_config():
    cfg = ScoringConfig()
    assert cfg.severity_weights == DEFAULT_SEVERITY_WEIGHTS
    assert cfg.risk_thresholds == RISK_LEVEL_THRESHOLDS


def test_config_load_from_file(tmp_path):
    config_file = tmp_path / "scoring.json"
    config_file.write_text('{"severity_weights": {"CRITICAL": 20}}')
    cfg = ScoringConfig.load(config_file)
    assert cfg.severity_weights["CRITICAL"] == 20
    assert cfg.severity_weights["HIGH"] == 7  # default preserved


def test_config_save(tmp_path):
    cfg = ScoringConfig()
    cfg.severity_weights["CRITICAL"] = 15
    out = tmp_path / "out.json"
    cfg.save(out)
    import json
    data = json.loads(out.read_text())
    assert data["severity_weights"]["CRITICAL"] == 15


# ─── Scoring Core Tests ─────────────────────────────────────────

def test_all_pass():
    findings = all_pass_findings(10)
    score = compute_score(findings)

    assert score.total_controls == 10
    assert score.applicable_controls == 10
    assert score.passed == 10
    assert score.failed == 0
    assert score.not_applicable == 0
    assert score.manual == 0
    assert score.error == 0
    assert score.unknown == 0
    assert score.hardening_index == 100.0
    assert score.risk_score == 0.0
    assert score.risk_level == "LOW"
    assert score.coverage_percent == 100.0


def test_all_fail():
    findings = [make_finding("FAIL", "HIGH") for _ in range(5)]
    score = compute_score(findings)

    assert score.applicable_controls == 5
    assert score.passed == 0
    assert score.failed == 5
    assert score.hardening_index == 0.0
    # raw = 5 * 7 = 35, max = 5 * 7 = 35 → risk_score = 100
    assert score.risk_score == 100.0
    assert score.risk_level == "CRITICAL"


def test_mixed_severities():
    findings = mixed_findings()
    score = compute_score(findings)

    assert score.total_controls == 9
    # Applicable: PASS(2) + FAIL(3) + MANUAL(1) = 6
    assert score.applicable_controls == 6
    assert score.passed == 2
    assert score.failed == 3
    assert score.manual == 1
    assert score.not_applicable == 1
    assert score.error == 1
    assert score.unknown == 1

    # Hardening Index = 2 / 6 * 100 = 33.33
    assert abs(score.hardening_index - 33.33) < 0.01

    # Risk Score:
    # FAIL: CRITICAL(10) + HIGH(7) + MEDIUM(4) = 21
    # Applicable weights: PASS: CRITICAL(10) + HIGH(7) = 17
    #                     FAIL: CRITICAL(10) + HIGH(7) + MEDIUM(4) = 21
    #                     MANUAL: HIGH(7) = 7
    # max_possible = 17 + 21 + 7 = 45
    # risk = 21/45 * 100 = 46.67
    assert abs(score.risk_score - 46.67) < 0.01
    assert score.risk_level == "MEDIUM"


def test_not_applicable_excluded_from_applicable():
    findings = [
        make_finding("PASS"),
        make_finding("FAIL"),
        make_finding("NOT_APPLICABLE"),
        make_finding("NOT_APPLICABLE"),
    ]
    score = compute_score(findings)

    assert score.applicable_controls == 2  # only PASS + FAIL
    assert score.not_applicable == 2
    assert score.hardening_index == 50.0  # 1/2


def test_manual_included_in_applicable():
    findings = [
        make_finding("PASS"),
        make_finding("MANUAL"),
    ]
    score = compute_score(findings)

    assert score.applicable_controls == 2
    assert score.manual == 1
    assert score.hardening_index == 50.0  # 1/2


def test_error_unknown_excluded():
    findings = [
        make_finding("PASS"),
        make_finding("ERROR"),
        make_finding("UNKNOWN"),
    ]
    score = compute_score(findings)

    assert score.applicable_controls == 1
    assert score.error == 1
    assert score.unknown == 1
    assert score.hardening_index == 100.0


def test_zero_applicable_controls():
    """Edge case: all NOT_APPLICABLE/ERROR/UNKNOWN"""
    findings = [
        make_finding("NOT_APPLICABLE"),
        make_finding("ERROR"),
        make_finding("UNKNOWN"),
    ]
    score = compute_score(findings)

    assert score.applicable_controls == 0
    assert score.hardening_index == 100.0  # per spec
    assert score.risk_score == 0.0
    assert score.risk_level == "LOW"


def test_risk_level_thresholds():
    # Test each threshold boundary
    cfg = ScoringConfig()

    # LOW < 25
    findings = [make_finding("FAIL", "LOW")] * 2  # weight 1 each
    findings += [make_finding("PASS", "LOW")] * 8
    score = compute_score(findings, cfg)
    assert score.risk_level == "LOW"

    # MEDIUM >= 25, < 50
    findings = [make_finding("FAIL", "MEDIUM")] * 2  # weight 4 each = 8
    findings += [make_finding("PASS", "MEDIUM")] * 8  # weight 4 each = 32
    # raw = 8, max = 40 → 20% → LOW... need more fails
    findings = [make_finding("FAIL", "MEDIUM")] * 5  # 20
    findings += [make_finding("PASS", "MEDIUM")] * 5  # 20
    # raw = 20, max = 40 → 50% → HIGH boundary
    score = compute_score(findings, cfg)
    assert score.risk_level in ("MEDIUM", "HIGH")  # boundary

    # HIGH >= 50, < 75
    findings = [make_finding("FAIL", "HIGH")] * 3  # 21
    findings += [make_finding("PASS", "HIGH")] * 2  # 14
    # raw = 21, max = 35 → 60% → HIGH
    score = compute_score(findings, cfg)
    assert score.risk_level == "HIGH"

    # CRITICAL >= 75
    findings = [make_finding("FAIL", "CRITICAL")] * 3  # 30
    findings += [make_finding("PASS", "CRITICAL")] * 1  # 10
    # raw = 30, max = 40 → 75% → CRITICAL
    score = compute_score(findings, cfg)
    assert score.risk_level == "CRITICAL"


def test_custom_weights():
    cfg = ScoringConfig()
    cfg.severity_weights["CRITICAL"] = 100
    cfg.severity_weights["HIGH"] = 1

    findings = [
        make_finding("FAIL", "CRITICAL"),
        make_finding("PASS", "HIGH"),
    ]
    score = compute_score(findings, cfg)

    # raw = 100, max = 101 → ~99%
    assert score.risk_score > 99
    assert score.risk_level == "CRITICAL"


def test_coverage_percent():
    findings = [
        make_finding("PASS"),
        make_finding("FAIL"),
        make_finding("NOT_APPLICABLE"),
        make_finding("ERROR"),
        make_finding("UNKNOWN"),
    ]
    score = compute_score(findings)

    # Assessed = PASS + FAIL + NOT_APPLICABLE = 3
    # Total = 5
    # Coverage = 60%
    assert score.coverage_percent == 60.0


def test_to_dict():
    findings = all_pass_findings(3)
    score = compute_score(findings)
    d = score.to_dict()

    assert d["total_controls"] == 3
    assert d["hardening_index"] == 100.0
    assert d["risk_score"] == 0.0
    assert d["risk_level"] == "LOW"
    assert d["coverage_percent"] == 100.0


# ─── Convenience Function Tests ─────────────────────────────────

def test_score_assessment():
    findings = all_pass_findings(2)
    result = score_assessment(findings)

    assert result["total_controls"] == 2
    assert result["hardening_index"] == 100.0


# ─── Constants Tests ────────────────────────────────────────────

def test_status_constants():
    assert FINDING_STATUS["PASS"] == "PASS"
    assert FINDING_STATUS["FAIL"] == "FAIL"
    assert FINDING_STATUS["NOT_APPLICABLE"] == "NOT_APPLICABLE"
    assert FINDING_STATUS["MANUAL"] == "MANUAL"
    assert FINDING_STATUS["ERROR"] == "ERROR"
    assert FINDING_STATUS["UNKNOWN"] == "UNKNOWN"


def test_applicable_statuses():
    assert "PASS" in APPLICABLE_STATUSES
    assert "FAIL" in APPLICABLE_STATUSES
    assert "MANUAL" in APPLICABLE_STATUSES
    assert "NOT_APPLICABLE" not in APPLICABLE_STATUSES
    assert "ERROR" not in APPLICABLE_STATUSES
    assert "UNKNOWN" not in APPLICABLE_STATUSES


def test_assessed_statuses():
    assert "PASS" in ASSESSED_STATUSES
    assert "FAIL" in ASSESSED_STATUSES
    assert "NOT_APPLICABLE" in ASSESSED_STATUSES
    assert "MANUAL" in ASSESSED_STATUSES
    assert "ERROR" not in ASSESSED_STATUSES
    assert "UNKNOWN" not in ASSESSED_STATUSES


# ─── Real-world Scenario Tests ──────────────────────────────────

def test_typical_windows_assessment():
    """Simulate a typical Windows assessment with 14 controls."""
    findings = [
        # Firewall (3 CRITICAL)
        make_finding("PASS", "CRITICAL"),  # WIN-FW-DOMAIN
        make_finding("PASS", "CRITICAL"),  # WIN-FW-PRIVATE
        make_finding("FAIL", "CRITICAL"),  # WIN-FW-PUBLIC
        # SMB1 (1 CRITICAL)
        make_finding("PASS", "CRITICAL"),  # WIN-SMB1-DISABLED
        # Defender (1 CRITICAL)
        make_finding("PASS", "CRITICAL"),  # WIN-DEFENDER-ENABLED
        # Guest (1 HIGH)
        make_finding("PASS", "HIGH"),      # WIN-GUEST-DISABLED
        # UAC (1 HIGH)
        make_finding("FAIL", "HIGH"),      # WIN-UAC-ENABLED
        # LM Hash (1 HIGH) - INFERRED but treated same
        make_finding("PASS", "HIGH"),      # WIN-LMHASH-DISABLED
        # Screen Lock (1 MEDIUM)
        make_finding("FAIL", "MEDIUM"),    # WIN-SCREENLOCK-TIMEOUT
        # Password MinLen (1 HIGH)
        make_finding("FAIL", "HIGH"),      # WIN-PASS-MINLEN
        # Account Lockout (1 HIGH)
        make_finding("PASS", "HIGH"),      # WIN-ACCT-LOCKOUT
        # RDP NLA (1 CRITICAL)
        make_finding("PASS", "CRITICAL"),  # WIN-RDP-NLA
        # Remote Registry (1 MEDIUM)
        make_finding("FAIL", "MEDIUM"),    # WIN-REMOTEREG-DISABLED
        # Password Complexity (1 HIGH)
        make_finding("PASS", "HIGH"),      # WIN-PASS-COMPLEX
    ]

    score = compute_score(findings)

    assert score.total_controls == 14
    assert score.applicable_controls == 14
    assert score.passed == 9
    assert score.failed == 5
    assert abs(score.hardening_index - 64.29) < 0.01
    # Risk: 5 fails weighted
    # FAIL: FW-PUBLIC(CRITICAL=10) + UAC(HIGH=7) + SCREENLOCK(MEDIUM=4)
    #       + PASS-MINLEN(HIGH=7) + REMOTEREG(MEDIUM=4) = 32
    # max_possible: semua 14 controls weighted
    #   6 CRITICAL * 10 = 60  (FW-DOMAIN, FW-PRIVATE, FW-PUBLIC, SMB1, DEFENDER, RDP-NLA)
    #   6 HIGH * 7 = 42       (GUEST, UAC, LMHASH, PASS-MINLEN, ACCT-LOCKOUT, PASS-COMPLEX)
    #   2 MEDIUM * 4 = 8      (SCREENLOCK, REMOTEREG)
    #   max = 60 + 42 + 8 = 110
    #   risk = 32 / 110 * 100 = 29.09%
    assert abs(score.risk_score - 29.09) < 0.5
    assert score.risk_level == "MEDIUM"
    assert score.coverage_percent == 100.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])