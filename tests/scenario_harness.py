"""P1-2/P1-3: data-driven scenario harness.

Prinsip:
- Satu skenario = {name, control_id, spec, set_to, rollback_to,
  expect_after, expect_observed}.
- Harness MENOLAK skenario no-op (set_to == baseline value).
- Harness memverifikasi rollback mengembalikan nilai baseline PERSIS.
- Tiap run punya label unik; output JSON + markdown.
- Core (ScenarioRunner) target-agnostic -> bisa diuji di Linux via DictTarget.
  WindowsRegistryTarget hanya dieksekusi di Windows.

Scenarios use MOCK providers that delegate to a Target, so the harness runs
on Linux without spawning PowerShell. On Windows, swap in WindowsRegistryTarget
and the real providers for live validation.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Protocol

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core import load_rules_from_dir, execute_rules, registry  # noqa: E402

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "windows"


class Target(Protocol):
    def read(self, spec: dict) -> Any: ...
    def write(self, spec: dict, value: Any) -> None: ...
    def delete(self, spec: dict) -> None: ...
    def describe(self) -> str: ...


# --- SECTION 2: DictTarget (in-memory, testable on Linux) ----------------------

class DictTarget:
    """In-memory target keyed by control_id. Fully testable on Linux.

    Resolves control_id from the rule whose probe params match the spec,
    so callers pass a {control_id: value} baseline.
    """

    def __init__(self, baseline: dict[str, Any]):
        self._baseline: dict[str, Any] = dict(baseline)
        self._state: dict[str, Any] = dict(baseline)
        self._spec_to_cid: dict[str, str] = self._build_spec_index()

    @staticmethod
    def _build_spec_index() -> dict[str, str]:
        rules = load_rules_from_dir(str(RULES_DIR))
        out: dict[str, str] = {}
        for r in rules:
            out[json.dumps(r.probe.params, sort_keys=True, default=str)] = r.rule_id
        return out

    def _cid(self, spec: dict) -> str:
        return self._spec_to_cid.get(json.dumps(spec, sort_keys=True, default=str), "")

    def read(self, spec: dict) -> Any:
        return self._state.get(self._cid(spec))

    def write(self, spec: dict, value: Any) -> None:
        self._state[self._cid(spec)] = value

    def delete(self, spec: dict) -> None:
        self._state[self._cid(spec)] = None

    def describe(self) -> str:
        return f"DictTarget(baseline={self._baseline})"

    @property
    def baseline(self) -> dict[str, Any]:
        return self._baseline

    @property
    def state(self) -> dict[str, Any]:
        return self._state


# --- SECTION 3: Scenario + ScenarioResult --------------------------------------

@dataclass
class Scenario:
    name: str
    control_id: str
    spec: dict[str, Any]          # probe params (path/key/command)
    set_to: Any                   # value to apply
    rollback_to: Any              # value to restore; None = auto-restore baseline
    expect_after: str             # PASS | FAIL
    expect_observed: Any          # raw value expected after set
    description: str = ""
    skip: bool = False
    skip_reason: str = ""


@dataclass
class ScenarioResult:
    name: str
    control_id: str
    baseline_status: str
    baseline_observed: Any
    after_status: str
    after_observed: Any
    rollback_status: str
    rollback_observed: Any
    expected_after: str
    expected_observed: Any
    detected: bool
    rollback_ok: bool
    no_op: bool
    spurious_flips: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _make_probes(target: Target):
    """Install mock providers that delegate to target. Idempotent."""
    def _mock_registry(params):
        from scanner.core.probes.base import ProbeResult
        value = target.read(params)
        return ProbeResult(
            value=value,
            evidence={"source": "mock-registry", "observed": value},
            raw_output=str(value),
        )

    def _mock_powershell(params):
        from scanner.core.probes.base import ProbeResult
        value = target.read(params)
        return ProbeResult(
            value=value,
            evidence={"source": "mock-powershell", "observed": value},
            raw_output=str(value),
        )

    registry._providers["windows.registry"] = _mock_registry
    registry._providers["windows.powershell"] = _mock_powershell


def _scan(target) -> dict[str, dict]:
    """Run all rules against target. Returns {control_id: {status, actual}}."""
    _make_probes(target)
    rules = load_rules_from_dir(str(RULES_DIR))
    findings = execute_rules(rules, scan_id="harness", host_os="windows")
    out: dict[str, dict] = {}
    for f in findings:
        out[f["control_id"]] = {
            "status": f["status"],
            "actual": f["comparison"]["actual"],
        }
    return out


# --- SECTION 4: ScenarioRunner -------------------------------------------------

class ScenarioRunner:
    """Execute scenarios against a Target. Rejects no-ops, verifies rollback."""

    def __init__(self, target, out_dir: Optional[Path] = None):
        self.target = target
        self.out_dir = Path(out_dir) if out_dir else Path("results/scenarios")
        self.results: list[ScenarioResult] = []
        self._baseline: Optional[dict[str, dict]] = None

    def _ensure_baseline(self) -> dict[str, dict]:
        if self._baseline is None:
            self._baseline = _scan(self.target)
        return self._baseline

    def run(self, scenario) -> list[ScenarioResult]:
        """Run one Scenario or a list of Scenarios. Always returns a list."""
        if isinstance(scenario, list):
            out: list[ScenarioResult] = []
            for s in scenario:
                out.extend(self.run(s))
            return out
        cid = scenario.control_id
        base = self._ensure_baseline()
        r = ScenarioResult(
            name=scenario.name, control_id=cid,
            baseline_status=base[cid]["status"],
            baseline_observed=base[cid]["actual"],
            after_status="UNKNOWN", after_observed=None,
            rollback_status="UNKNOWN", rollback_observed=None,
            expected_after=scenario.expect_after,
            expected_observed=scenario.expect_observed,
            detected=False, rollback_ok=False, no_op=False,
        )

        if scenario.skip:
            r.errors.append(f"SKIP: {scenario.skip_reason}")
            self.results.append(r)
            return [r]

        # No-op guard: set_to must differ from current baseline value.
        cur = base[cid]["actual"]
        if scenario.set_to == cur:
            r.no_op = True
            r.errors.append(
                f"NO-OP: set_to={scenario.set_to!r} == baseline {cur!r}; "
                "scenario would not change anything"
            )
            self.results.append(r)
            return [r]

        # Apply perturbation.
        try:
            self.target.write(scenario.spec, scenario.set_to)
        except Exception as exc:  # noqa: BLE001
            r.errors.append(f"SET FAILED: {exc!r}")
            r.no_op = True
            self.results.append(r)
            return [r]

        after = _scan(self.target)
        r.after_status = after[cid]["status"]
        r.after_observed = after[cid]["actual"]

        # Detection: status_after == expected_after.
        r.detected = (r.after_status == scenario.expect_after)

        # Rollback: None means "restore baseline value".
        rollback_value = scenario.rollback_to
        if rollback_value is None:
            rollback_value = base[cid]["actual"]
        try:
            self.target.write(scenario.spec, rollback_value)
        except Exception as exc:  # noqa: BLE001
            r.errors.append(f"ROLLBACK FAILED: {exc!r}")
            r.rollback_ok = False
            self.results.append(r)
            return [r]

        rb = _scan(self.target)
        r.rollback_status = rb[cid]["status"]
        r.rollback_observed = rb[cid]["actual"]
        r.rollback_ok = (
            r.rollback_status == r.baseline_status
            and r.rollback_observed == r.baseline_observed
        )

        # Spurious flips: any control that changed status between baseline and
        # after, other than the target control_id.
        for other_cid, other_after in after.items():
            if other_cid == cid:
                continue
            if other_after["status"] != base[other_cid]["status"]:
                r.spurious_flips.append(other_cid)

        self.results.append(r)
        return [r]

    def summary(self) -> dict[str, Any]:
        valid = [r for r in self.results if not r.no_op and not r.errors]
        detected = sum(1 for r in valid if r.detected)
        rollback_ok = sum(1 for r in valid if r.rollback_ok)
        spurious = sum(len(r.spurious_flips) for r in valid)
        return {
            "total": len(self.results),
            "valid": len(valid),
            "ran": len(valid),
            "no_op": sum(1 for r in self.results if r.no_op),
            "no_op_skipped": sum(1 for r in self.results if r.no_op),
            "detected": detected,
            "rollback_ok": rollback_ok,
            "spurious_flips": spurious,
            "detection_rate": round(detected / len(valid) * 100, 1) if valid else None,
            "rollback_rate": round(rollback_ok / len(valid) * 100, 1) if valid else None,
            "rollback_ok_rate": round(rollback_ok / len(valid) * 100, 1) if valid else None,
            "spurious_flip_rate": spurious,
        }

    def write_report(self, label: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / f"{label}_{ts}.json"
        payload = {
            "label": label,
            "target": self.target.describe(),
            "summary": self.summary(),
            "results": [asdict(r) for r in self.results],
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def markdown(self, label: str = "") -> str:
        lines = [
            f"# Scenario Harness Report — {label}".rstrip(),
            "",
            f"Target: {self.target.describe()}",
            "",
            "## Results",
            "",
            "| Scenario | Control | Baseline | After | Expected | Detected | Rollback | Spurious |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in self.results:
            lines.append(
                f"| {r.name} | {r.control_id} | {r.baseline_status} | "
                f"{r.after_status} | {r.expected_after} | {r.detected} | "
                f"{r.rollback_ok} | {','.join(r.spurious_flips) or '-'} |"
            )
        lines += ["", "## Summary", ""]
        s = self.summary()
        for k, v in s.items():
            lines.append(f"- {k}: {v}")
        return "\n".join(lines)


# --- SECTION 5: default scenarios (P1-3 sensitivity matrix) -------------------

def default_scenarios() -> list[Scenario]:
    """P1-3 sensitivity matrix. Each scenario perturbs one control.

    All set/rollback use the real probe spec from the rule YAML, so the
    harness exercises the actual evaluator path (not a hand-rolled replica).
    rollback_to=None means "auto-restore the baseline value", which is the
    harness contract: every scenario must return the target to baseline.
    """
    SL = {"path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "key": "InactivityTimeoutSecs"}
    return [
        # --- ScreenLock (CIS 2.3.7.4) ---
        Scenario("screenlock_900_pass", "WIN-SCREENLOCK-TIMEOUT", SL,
                 900, None, "PASS", "900",
                 "boundary: exactly 15 minutes = PASS"),
        Scenario("screenlock_901_fail", "WIN-SCREENLOCK-TIMEOUT", SL,
                 901, None, "FAIL", "901",
                 "boundary+1: 15m1s = FAIL"),
        Scenario("screenlock_0_fail", "WIN-SCREENLOCK-TIMEOUT", SL,
                 0, None, "FAIL", "0",
                 "0 = no limit = must FAIL (was accepted by lte 900)"),
        Scenario("screenlock_600_pass", "WIN-SCREENLOCK-TIMEOUT", SL,
                 600, None, "PASS", "600",
                 "10 minutes = PASS"),
        Scenario("screenlock_1800_fail", "WIN-SCREENLOCK-TIMEOUT", SL,
                 1800, None, "FAIL", "1800",
                 "30 minutes = FAIL"),
    ]