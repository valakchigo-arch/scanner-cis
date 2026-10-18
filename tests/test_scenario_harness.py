"""Linux-safe tests for the scenario harness (P1-2/P1-3).

Uses DictTarget + mock providers, so the full rule engine path
(load_rule -> probe -> evaluate -> emit) runs on Linux without spawning
PowerShell.
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.scenario_harness import (
    DictTarget, Scenario, ScenarioRunner,
    default_scenarios,
)


def _baseline() -> dict[str, object]:
    """Baseline state: all controls in their default (unconfigured) state."""
    return {}


def test_runner_detects_pass_and_fail():
    target = DictTarget({"WIN-SCREENLOCK-TIMEOUT": 1800})
    runner = ScenarioRunner(target)
    scenarios = default_scenarios()
    results = runner.run(scenarios)
    assert results, "no scenarios ran"
    # screenlock_900_pass must be detected
    r900 = next(r for r in results if r.name == "screenlock_900_pass")
    assert r900.detected is True, r900
    assert r900.rollback_ok is True, r900


def test_runner_rejects_no_op():
    target = DictTarget({"WIN-SCREENLOCK-TIMEOUT": 900})
    runner = ScenarioRunner(target)
    results = runner.run(default_scenarios())
    noop = [r for r in results if r.no_op]
    assert noop, "expected at least one no-op scenario (900_pass vs baseline 900)"
    assert all("NO-OP" in (r.errors[0] if r.errors else "") for r in noop)


def test_runner_verifies_rollback():
    target = DictTarget({"WIN-SCREENLOCK-TIMEOUT": 1800})
    runner = ScenarioRunner(target)
    results = runner.run(default_scenarios())
    for r in results:
        if r.no_op:
            continue
        # rollback_ok means the state returned to the BASELINE value, which
        # is the harness contract. rollback_observed is the raw value after
        # the restore step.
        assert r.rollback_observed == target.baseline["WIN-SCREENLOCK-TIMEOUT"], (
            r.name, r.rollback_observed, target.baseline
        )


def test_summarize_and_writers(tmp_path: Path):
    target = DictTarget({"WIN-SCREENLOCK-TIMEOUT": 1800})
    runner = ScenarioRunner(target, out_dir=tmp_path)
    results = runner.run(default_scenarios())
    s = runner.summary()
    assert s["total"] == len(default_scenarios())
    assert s["ran"] >= 1

    path = runner.write_report("test-run")
    assert path.exists()
    payload = json.loads(path.read_text())
    assert payload["label"] == "test-run"
    md = runner.markdown(label="test-run")
    assert "test-run" in md


def test_default_scenarios_cover_p1_3_matrix():
    """P1-3: sensitivity matrix must include boundary + no-limit cases."""
    names = {s.name for s in default_scenarios()}
    assert "screenlock_900_pass" in names
    assert "screenlock_901_fail" in names
    assert "screenlock_0_fail" in names
    assert "screenlock_600_pass" in names
    assert "screenlock_1800_fail" in names