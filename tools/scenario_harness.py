"""
tools/scenario_harness.py -- harness skenario sensitivitas (perturbation testing) yang data-driven.

Satu skenario = {set, rollback, expected_observed, expected_status_after} (scenarios/windows_scenarios.yaml).
Harness MENOLAK skenario yang tidak valid SEBELUM menyentuh sistem, menjalankan rollback di `finally`,
lalu memverifikasi bahwa mesin kembali ke baseline.

Contoh (PowerShell **Administrator**, di VM yang SUDAH di-snapshot):
    python tools/scenario_harness.py --host-kind vm --host-alias Host-B --confirm-snapshot
    python tools/scenario_harness.py --dry-run --baseline-json results/baseline_X.json     # aman, tidak mengubah apa pun
    python tools/scenario_harness.py --aggregate results/                                  # gabungkan banyak run

Klasifikasi hasil per skenario (outcome):
    DETECTED              nilai berubah sesuai harapan DAN status rule = expected_status_after
    DETECTION_FAILURE     nilai berubah sesuai harapan TETAPI status rule salah  -> temuan nyata tentang scanner
    SET_INEFFECTIVE       setelan tidak berubah (mis. Tamper Protection, pending-reboot)  -> BUKAN kesalahan scanner
    ERROR_AFTER           probe ERROR setelah perubahan (mis. timeout)
    REJECTED_NOOP         nilai harapan == nilai baseline: tidak membuktikan apa-apa, tidak dijalankan
    REJECTED_NO_ROLLBACK  tidak ada cara pemulihan yang aman, tidak dijalankan
    SKIPPED_*             prasyarat tidak terpenuhi, tidak dijalankan

Exit code: 0 bersih | 1 ditolak/penggunaan salah | 2 selesai tetapi ada anomali | 3 rollback GAGAL (mesin mungkin kotor!)
Status verifikasi: logika harness [VERIFIED oleh pytest dengan sistem palsu]; perintah Windows [NOT RUN: butuh Windows].
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import socket
import statistics
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DEFAULT_SCENARIOS = ROOT / "scenarios" / "windows_scenarios.yaml"
SAFE_BASELINE = re.compile(r"^-?\d+$")          # satu-satunya bentuk nilai baseline yang boleh disubstitusi ke perintah
OUTCOMES_RAN = {"DETECTED", "DETECTION_FAILURE", "SET_INEFFECTIVE", "ERROR_AFTER"}

_MISSING = object()


class ScenarioError(Exception):
    pass


# ----------------------------------------------------------------------------- model
def norm(v: Any) -> Optional[str]:
    """Normalisasi nilai terbaca untuk perbandingan: None tetap None, lainnya str.strip()."""
    return None if v is None else str(v).strip()


def _as_list(v: Any) -> list:
    return list(v) if isinstance(v, (list, tuple)) else [v]


class Scenario:
    def __init__(self, raw: dict):
        for k in ("id", "control", "title", "set", "rollback", "expected_status_after"):
            if k not in raw:
                raise ScenarioError(f"skenario {raw.get('id', '?')}: field '{k}' wajib")
        if "expected_observed" not in raw:
            raise ScenarioError(f"skenario {raw['id']}: field 'expected_observed' wajib (null = key tidak ada)")
        if raw["expected_status_after"] not in ("PASS", "FAIL"):
            raise ScenarioError(f"skenario {raw['id']}: expected_status_after harus PASS/FAIL")
        self.id = str(raw["id"])
        self.control = raw["control"]
        self.title = raw["title"]
        self.set = [str(c) for c in _as_list(raw["set"])]
        self.rollback = [str(c) for c in _as_list(raw["rollback"])]
        self.rollback_when_absent = [str(c) for c in _as_list(raw.get("rollback_when_absent") or [])]
        self.expected_observed = [norm(x) for x in _as_list(raw["expected_observed"])]
        self.expected_status_after = raw["expected_status_after"]
        bm = raw.get("baseline_must_be")
        self.baseline_must_be = None if bm is None else [norm(x) for x in _as_list(bm)]
        self.rollback_accept = [norm(x) for x in _as_list(raw.get("rollback_accept") or [])]
        # rollback_accept terisi = pemulihan penuh baru terjadi setelah restart -> mesin 'tercemar' (pending) untuk skenario berikutnya
        self.leaves_pending_state = bool(self.rollback_accept)
        self.also_affects = set(raw.get("also_affects") or [])
        self.kind = raw.get("kind", "flip")
        self.vm_only = bool(raw.get("vm_only", False))
        self.needs_reboot = bool(raw.get("needs_reboot", False))
        self.prior_evidence = raw.get("prior_evidence", "")
        if not self.set or not self.rollback:
            raise ScenarioError(f"skenario {self.id}: set dan rollback tidak boleh kosong")

    def uses_baseline_placeholder(self) -> bool:
        return any("{baseline}" in c for c in self.rollback)


def load_scenarios(path: Path = DEFAULT_SCENARIOS, known_controls: Optional[set] = None) -> list[Scenario]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    out, seen = [], set()
    for raw in data.get("scenarios", []):
        sc = Scenario(raw)
        if sc.id in seen:
            raise ScenarioError(f"id skenario ganda: {sc.id}")
        seen.add(sc.id)
        if known_controls is not None and sc.control not in known_controls:
            raise ScenarioError(f"skenario {sc.id}: kontrol tidak dikenal {sc.control}")
        out.append(sc)
    return out


# ----------------------------------------------------------------------------- validasi pra-eksekusi
def index_findings(findings: list[dict]) -> dict[str, dict]:
    return {f["control_id"]: f for f in findings}


def observed_of(f: dict) -> Optional[str]:
    return norm((f.get("comparison") or {}).get("actual"))


def pre_check(sc: Scenario, base: dict[str, dict], host_kind: str) -> Optional[tuple[str, str]]:
    """Kembalikan (outcome, alasan) bila skenario TIDAK boleh dijalankan; None bila boleh."""
    f = base.get(sc.control)
    if f is None:
        return "SKIPPED_UNKNOWN_CONTROL", f"{sc.control} tidak ada di hasil baseline"
    if sc.vm_only and host_kind != "vm":
        return "SKIPPED_VM_ONLY", "skenario hanya boleh dijalankan dengan --host-kind vm"
    if f["status"] not in ("PASS", "FAIL"):
        return "SKIPPED_BASELINE_UNASSESSED", f"baseline {sc.control} berstatus {f['status']}"
    b_obs = observed_of(f)
    if b_obs in sc.expected_observed:
        return "REJECTED_NOOP", f"nilai harapan {sc.expected_observed} sama dengan baseline {b_obs!r}: tidak membuktikan apa pun"
    if sc.baseline_must_be is not None and b_obs not in sc.baseline_must_be:
        return "SKIPPED_PRECONDITION", f"baseline {b_obs!r} bukan salah satu dari {sc.baseline_must_be}"
    cmds = rollback_commands(sc, b_obs)
    if cmds is None:
        return "REJECTED_NO_ROLLBACK", "tidak ada rollback yang aman untuk nilai baseline ini"
    return None


def rollback_commands(sc: Scenario, b_obs: Optional[str]) -> Optional[list[str]]:
    """Daftar perintah rollback final, atau None bila tidak aman/tidak mungkin."""
    if b_obs is None:
        if sc.rollback_when_absent:
            return list(sc.rollback_when_absent)
        return None if sc.uses_baseline_placeholder() else list(sc.rollback)
    if sc.uses_baseline_placeholder():
        if not SAFE_BASELINE.match(b_obs):         # cegah injeksi perintah lewat nilai baseline
            return None
        return [c.replace("{baseline}", b_obs) for c in sc.rollback]
    return list(sc.rollback)


# ----------------------------------------------------------------------------- eksekusi satu skenario
def _scan(scan_fn, label: str, sc: Scenario, fast: bool) -> list[dict]:
    """Mode fast: hanya kontrol yang diuji (jauh lebih cepat di VM lambat). Mode penuh: semua kontrol."""
    return scan_fn(label, only=[sc.control]) if fast else scan_fn(label)


def run_scenario(sc: Scenario, base: dict[str, dict], scan_fn: Callable[..., list[dict]],
                 run_cmd: Callable[[str], int], run_id: str, host_kind: str, fast: bool = False) -> dict:
    res: dict[str, Any] = {"id": sc.id, "control": sc.control, "title": sc.title, "kind": sc.kind,
                           "needs_reboot": sc.needs_reboot, "prior_evidence": sc.prior_evidence,
                           "mode": "fast" if fast else "full", "spurious_checked": not fast}
    refuse = pre_check(sc, base, host_kind)
    b = base.get(sc.control)
    if b is not None:
        res.update(baseline_status=b["status"], baseline_observed=observed_of(b))
    if refuse:
        res.update(outcome=refuse[0], reason=refuse[1], applied=False)
        return res

    b_obs = observed_of(b)
    rb_cmds = rollback_commands(sc, b_obs)
    res.update(applied=True, expected_observed=sc.expected_observed, expected_status_after=sc.expected_status_after)
    after: dict[str, dict] = {}
    rb: dict[str, dict] = {}
    set_rcs: list[int] = []
    try:
        for c in sc.set:
            set_rcs.append(run_cmd(c))
        after = index_findings(_scan(scan_fn, f"{run_id}/{sc.id}/after", sc, fast))
    finally:                                   # rollback SELALU, walau scan/ set gagal atau dibatalkan (Ctrl+C)
        rb_rcs = [run_cmd(c) for c in rb_cmds]
        res["rollback_rcs"] = rb_rcs
        res["rollback_command_failed"] = any(rc != 0 for rc in rb_rcs)
    rb = index_findings(_scan(scan_fn, f"{run_id}/{sc.id}/rollback", sc, fast))
    res["set_rcs"] = set_rcs

    a = after.get(sc.control)
    a_status, a_obs = (a["status"], observed_of(a)) if a else ("MISSING", None)
    res.update(status_after=a_status, observed_after=a_obs, flip=f"{b['status']}_to_{a_status}")
    if a_status == "ERROR":
        res["outcome"], res["reason"] = "ERROR_AFTER", (a.get("error_detail") or "")[:200]
    elif a_obs not in sc.expected_observed:
        res["outcome"] = "SET_INEFFECTIVE"
        res["reason"] = f"nilai terbaca {a_obs!r}, diharapkan {sc.expected_observed} (perubahan tidak berlaku / pending / diblokir)"
    elif a_status == sc.expected_status_after:
        res["outcome"] = "DETECTED"
    else:
        res["outcome"] = "DETECTION_FAILURE"
        res["reason"] = f"nilai {a_obs!r} benar, status {a_status}, diharapkan {sc.expected_status_after}"
    res["detected"] = res["outcome"] == "DETECTED"
    res["boundary_ok"] = res["detected"] if sc.kind == "boundary" else None

    # kontrol yang TIDAK disentuh tidak boleh berubah
    others = [cid for cid in base if cid != sc.control and cid not in sc.also_affects]
    res["spurious_flips"] = sorted(c for c in others if c in after and after[c]["status"] != base[c]["status"])
    res["spurious_value_changes"] = sorted(c for c in others if c in after and c not in res["spurious_flips"]
                                           and observed_of(after[c]) != observed_of(base[c]))

    # rollback: seluruh scan harus kembali ke baseline
    r = rb.get(sc.control)
    r_obs = observed_of(r) if r else None
    accepted = {b_obs, *sc.rollback_accept}
    control_ok = r is not None and r_obs in accepted and (sc.rollback_accept or r["status"] == b["status"])
    drift = sorted(c for c in base if c != sc.control and (c in rb or not fast) and (
        c not in rb or rb[c]["status"] != base[c]["status"] or observed_of(rb[c]) != observed_of(base[c])))
    res.update(rollback_observed=r_obs, rollback_drift=drift,
               rollback_ok=bool(control_ok and not drift and not res["rollback_command_failed"]),
               rollback_pending_reboot=bool(sc.rollback_accept and r_obs != b_obs))
    return res


# ----------------------------------------------------------------------------- metrik
def percentile(values: list[float], p: float) -> Optional[float]:
    """Nearest-rank. None bila tidak ada data. (Dengan n kecil p95 = nilai maksimum; laporkan n.)"""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(p / 100 * len(s)) - 1)]


def compute_metrics(results: list[dict], scan_seconds: list[float], baseline: dict[str, dict],
                    truth: Optional[dict[str, str]] = None) -> dict:
    ran = [r for r in results if r.get("applied")]
    denom = [r for r in ran if r["outcome"] in ("DETECTED", "DETECTION_FAILURE")]
    det = [r for r in denom if r["outcome"] == "DETECTED"]
    counts: dict[str, int] = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    assessed = sum(1 for f in baseline.values() if f["status"] in ("PASS", "FAIL"))
    errors = sum(1 for f in baseline.values() if f["status"] == "ERROR")
    m: dict[str, Any] = {
        "scenarios_total": len(results), "scenarios_executed": len(ran), "outcomes": counts,
        "detection_rate": (len(det) / len(denom)) if denom else None,
        "detection_denominator": len(denom),
        "flip_PASS_to_FAIL": sum(1 for r in det if r.get("flip") == "PASS_to_FAIL"),
        "flip_FAIL_to_PASS": sum(1 for r in det if r.get("flip") == "FAIL_to_PASS"),
        "boundary_ok": sum(1 for r in ran if r.get("boundary_ok") is True),
        "boundary_total": sum(1 for r in ran if r.get("boundary_ok") is not None),
        "rollback_ok_rate": (sum(1 for r in ran if r["rollback_ok"]) / len(ran)) if ran else None,
        # None = tidak dinilai (mode fast tidak memindai kontrol lain, jadi "0" akan menyesatkan)
        "spurious_flips_total": (None if any(not r.get("spurious_checked", True) for r in ran)
                                 else sum(len(r["spurious_flips"]) for r in ran)),
        "spurious_value_changes_total": (None if any(not r.get("spurious_checked", True) for r in ran)
                                         else sum(len(r["spurious_value_changes"]) for r in ran)),
        "baseline_error_rate": (errors / len(baseline)) if baseline else None,
        "baseline_coverage_percent": (100 * assessed / (assessed + errors)) if (assessed + errors) else None,
        "scan_seconds_n": len(scan_seconds),
        "scan_seconds_median": statistics.median(scan_seconds) if scan_seconds else None,
        "scan_seconds_p95": percentile(scan_seconds, 95),
        "false_positive_rate_baseline": None, "false_negative_rate_baseline": None,
    }
    if truth:
        tp_pass = [c for c, t in truth.items() if t == "PASS" and c in baseline]
        tp_fail = [c for c, t in truth.items() if t == "FAIL" and c in baseline]
        fp = [c for c in tp_pass if baseline[c]["status"] == "FAIL"]
        fn = [c for c in tp_fail if baseline[c]["status"] == "PASS"]
        m["false_positive_rate_baseline"] = (len(fp) / len(tp_pass)) if tp_pass else None
        m["false_negative_rate_baseline"] = (len(fn) / len(tp_fail)) if tp_fail else None
        m["truth_controls"] = len(tp_pass) + len(tp_fail)
        m["false_positives"], m["false_negatives"] = sorted(fp), sorted(fn)
    return m


def anomalies(results: list[dict], metrics: dict) -> list[str]:
    out = []
    for r in results:
        if r["outcome"] == "DETECTION_FAILURE":
            out.append(f"{r['id']}: DETECTION_FAILURE ({r.get('reason')})")
        if r.get("applied") and not r["rollback_ok"]:
            out.append(f"{r['id']}: rollback TIDAK kembali ke baseline (control={r.get('rollback_observed')!r}, drift={r.get('rollback_drift')})")
        if r.get("spurious_flips"):
            out.append(f"{r['id']}: spurious flip pada {r['spurious_flips']}")
    return out


# ----------------------------------------------------------------------------- laporan
def render_markdown(meta: dict, results: list[dict], metrics: dict, notes: list[str]) -> str:
    def pct(x):
        return "n/a" if x is None else f"{100 * x:.1f}%"
    L = [f"# Hasil skenario `{meta['run_id']}`", "",
         f"- host: **{meta['host_alias']}** ({meta['host_kind']}) | OS: {meta['os']} | admin: {meta['is_admin']}",
         f"- rules: {meta['rules_dir']} | skenario: {meta['scenarios_file']}", "",
         "## Metrik", "",
         f"- detection_rate: **{pct(metrics['detection_rate'])}** (n={metrics['detection_denominator']})",
         f"- rollback_ok_rate: **{pct(metrics['rollback_ok_rate'])}** | spurious_flips: **"
         f"{'n/a (mode fast: tidak diukur)' if metrics['spurious_flips_total'] is None else metrics['spurious_flips_total']}** "
         f"(perubahan nilai tanpa flip status: "
         f"{'n/a' if metrics['spurious_value_changes_total'] is None else metrics['spurious_value_changes_total']})",
         f"- flip PASS->FAIL: {metrics['flip_PASS_to_FAIL']} | FAIL->PASS: {metrics['flip_FAIL_to_PASS']} | "
         f"boundary_ok: {metrics['boundary_ok']}/{metrics['boundary_total']}",
         f"- baseline: ERROR_rate {pct(metrics['baseline_error_rate'])}, coverage "
         f"{'n/a' if metrics['baseline_coverage_percent'] is None else format(metrics['baseline_coverage_percent'], '.0f') + '%'}",
         f"- durasi scan (n={metrics['scan_seconds_n']}): median {metrics['scan_seconds_median']} s, p95 {metrics['scan_seconds_p95']} s "
         f"[{meta['host_kind']}]",
         f"- FPR baseline: {pct(metrics['false_positive_rate_baseline'])} | FNR baseline: {pct(metrics['false_negative_rate_baseline'])} "
         "(hanya dihitung bila --baseline-truth diberikan; truth harus dari perintah independen)", "",
         "## Per skenario", "",
         "| id | kontrol | baseline | after (nilai/status) | flip | outcome | rollback_ok | spurious |",
         "|---|---|---|---|---|---|---|---|"]
    for r in results:
        L.append("| {id} | {control} | {b} | {a} | {flip} | **{outcome}** | {rb} | {sp} |".format(
            id=r["id"], control=r["control"], b=f"{r.get('baseline_observed')!r}/{r.get('baseline_status')}",
            a=f"{r.get('observed_after')!r}/{r.get('status_after')}" if r.get("applied") else "-",
            flip=r.get("flip", "-"), outcome=r["outcome"], rb=r.get("rollback_ok", "-"),
            sp=len(r.get("spurious_flips", [])) if r.get("applied") else "-"))
    skipped = [r for r in results if not r.get("applied")]
    if skipped:
        L += ["", "## Tidak dijalankan", ""] + [f"- `{r['id']}` {r['outcome']}: {r.get('reason')}" for r in skipped]
    if notes:
        L += ["", "## Anomali", ""] + [f"- {n}" for n in notes]
    pend = [r["id"] for r in results if r.get("needs_reboot") and r.get("applied")]
    if pend:
        L += ["", f"> Skenario butuh restart ({', '.join(pend)}): kembalikan snapshot VM setelah selesai."]
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------- orkestrasi
def run_all(scenarios: list[Scenario], scan_fn, run_cmd, *, host_kind: str, host_alias: str, meta_extra: dict,
            truth: Optional[dict] = None, run_id: Optional[str] = None,
            baseline_findings: Optional[list[dict]] = None, fast: bool = False) -> dict:
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    seconds: list[float] = []

    def timed_scan(label: str, **kw) -> list[dict]:
        t0 = time.perf_counter()
        out = scan_fn(label, **kw)
        seconds.append(round(time.perf_counter() - t0, 3))
        return out

    base = index_findings(baseline_findings if baseline_findings is not None else timed_scan(f"{run_id}/baseline"))
    results, aborted, pending_by = [], None, None
    # skenario yang meninggalkan state pending-reboot dijalankan PALING AKHIR (stabil terhadap urutan file)
    for sc in sorted(scenarios, key=lambda s: s.leaves_pending_state):
        if aborted:
            results.append({"id": sc.id, "control": sc.control, "title": sc.title, "outcome": "SKIPPED_ABORTED",
                            "reason": aborted, "applied": False})
            continue
        if pending_by:
            results.append({"id": sc.id, "control": sc.control, "title": sc.title, "outcome": "SKIPPED_PENDING_REBOOT",
                            "reason": f"{pending_by} meninggalkan state pending-reboot; restart/restore snapshot lalu jalankan ulang",
                            "applied": False})
            continue
        try:
            r = run_scenario(sc, base, timed_scan, run_cmd, run_id, host_kind, fast=fast)
        except Exception as exc:                # noqa: BLE001  rollback sudah dijalankan di `finally`; hasilnya TIDAK terverifikasi
            r = {"id": sc.id, "control": sc.control, "title": sc.title, "outcome": "ERROR_HARNESS", "applied": True,
                 "reason": f"{type(exc).__name__}: {exc}", "rollback_ok": False, "spurious_flips": [],
                 "spurious_value_changes": [], "boundary_ok": None, "rollback_command_failed": False}
            aborted = f"error harness pada {sc.id}: rollback dijalankan tetapi tidak diverifikasi; periksa mesin"
        results.append(r)
        if r.get("rollback_pending_reboot"):
            pending_by = sc.id
        if r.get("rollback_command_failed"):
            aborted = f"rollback {sc.id} GAGAL: hentikan, periksa mesin / kembalikan snapshot"
    metrics = compute_metrics(results, seconds, base, truth)
    notes = anomalies(results, metrics) + ([aborted] if aborted else [])
    meta = {"run_id": run_id, "host_alias": host_alias, "host_kind": host_kind,
            "rules_dir": "rules/windows", "scenarios_file": "scenarios/windows_scenarios.yaml",
            "mode": "fast" if fast else "full", **meta_extra}
    return {"meta": meta, "metrics": metrics, "results": results, "anomalies": notes,
            "baseline": {cid: {"status": f["status"], "observed": observed_of(f), "duration_ms": f.get("duration_ms")}
                         for cid, f in base.items()},
            "aborted": aborted, "exit_code": 3 if aborted else (2 if notes else 0)}


def default_alias() -> str:
    return "host-" + hashlib.sha256(socket.gethostname().encode()).hexdigest()[:6]   # hostname asli tidak ditulis ke artefak


def aggregate(paths: list[Path]) -> dict:
    """Gabungkan banyak summary JSON: durasi & detection per host_kind (VM vs fisik dipisah)."""
    groups: dict[str, dict] = {}
    for p in paths:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        g = groups.setdefault(d["meta"]["host_kind"], {"runs": 0, "seconds": [], "det": 0, "den": 0, "spurious": 0,
                                                      "rb_ok": 0, "rb_n": 0, "errors": []})
        m = d["metrics"]
        g["runs"] += 1
        g["seconds"] += [] if m["scan_seconds_median"] is None else [m["scan_seconds_median"]]
        g["det"] += sum(1 for r in d["results"] if r["outcome"] == "DETECTED")
        g["den"] += m["detection_denominator"]
        g["spurious"] += m["spurious_flips_total"] or 0
        g["rb_n"] += m["scenarios_executed"]
        g["rb_ok"] += sum(1 for r in d["results"] if r.get("applied") and r.get("rollback_ok"))
        if m["baseline_error_rate"] is not None:
            g["errors"].append(m["baseline_error_rate"])
    return {k: {"runs": v["runs"], "detection_rate": (v["det"] / v["den"]) if v["den"] else None,
                "rollback_ok_rate": (v["rb_ok"] / v["rb_n"]) if v["rb_n"] else None,
                "spurious_flips_total": v["spurious"], "run_median_seconds_median": statistics.median(v["seconds"]) if v["seconds"] else None,
                "run_median_seconds_p95": percentile(v["seconds"], 95), "mean_baseline_error_rate":
                (sum(v["errors"]) / len(v["errors"])) if v["errors"] else None} for k, v in groups.items()}


# ----------------------------------------------------------------------------- CLI (Windows nyata)
def _real_runners(rules_dir: Path):
    from scanner.core import load_rules_from_dir, execute_rules            # import lambat: hanya saat benar-benar jalan
    from scanner.core.probes._powershell import run_powershell
    rules = load_rules_from_dir(str(rules_dir))

    def scan_fn(label: str, only=None) -> list[dict]:
        chosen = rules if only is None else [r for r in rules if r.rule_id in set(only)]
        return execute_rules(chosen, "scn-" + re.sub(r"[^A-Za-z0-9]+", "-", label), host_os="windows")

    def run_cmd(cmd: str) -> int:
        try:
            r = run_powershell(cmd + "\nif ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                               timeout=180, strict=True)
        except Exception as exc:                                         # noqa: BLE001
            print(f"  ! perintah gagal dijalankan: {exc}", file=sys.stderr)
            return 1
        if r.returncode != 0:
            print(f"  ! rc={r.returncode}: {(r.stderr or r.stdout)[:200]}", file=sys.stderr)
        return r.returncode
    return rules, scan_fn, run_cmd


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())               # type: ignore[attr-defined]
    except Exception:                                                    # noqa: BLE001
        return False


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Harness skenario sensitivitas (data-driven).")
    ap.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    ap.add_argument("--rules", default=str(ROOT / "rules" / "windows"))
    ap.add_argument("--only", help="id skenario dipisah koma")
    ap.add_argument("--host-kind", choices=["vm", "physical"], default="physical")
    ap.add_argument("--host-alias", default=None, help="nama anonim untuk laporan (default: hash hostname)")
    ap.add_argument("--confirm-snapshot", action="store_true", help="WAJIB untuk eksekusi nyata: saya sudah snapshot VM / paham risikonya")
    ap.add_argument("--fast", action="store_true",
                    help="after/rollback hanya memindai kontrol yang diuji (cepat di VM lambat). spurious_flips TIDAK diukur")
    ap.add_argument("--dry-run", action="store_true", help="validasi saja; tidak ada perintah yang dijalankan")
    ap.add_argument("--baseline-json", help="hasil run_rules_live.py (dipakai --dry-run untuk menilai validitas skenario)")
    ap.add_argument("--baseline-truth", help="YAML {control_id: PASS|FAIL} dari perintah INDEPENDEN, untuk FPR/FNR")
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--aggregate", metavar="DIR", help="gabungkan semua scenario_*.json di DIR lalu keluar")
    a = ap.parse_args(argv)

    if a.aggregate:
        files = sorted(Path(a.aggregate).glob("scenario_*.json"))
        print(json.dumps(aggregate(files), indent=2))
        return 0

    from scanner.core import load_rules_from_dir
    rules = load_rules_from_dir(a.rules)
    try:
        scenarios = load_scenarios(Path(a.scenarios), {r.rule_id for r in rules})
    except ScenarioError as exc:
        print(f"SKENARIO TIDAK VALID: {exc}", file=sys.stderr)
        return 1
    if a.only:
        want = set(a.only.split(","))
        scenarios = [s for s in scenarios if s.id in want]

    if a.dry_run:
        base = index_findings(json.loads(Path(a.baseline_json).read_text(encoding="utf-8"))["findings"]) if a.baseline_json else None
        for sc in scenarios:
            verdict = "tanpa --baseline-json: validitas tidak dinilai"
            if base is not None:
                refuse = pre_check(sc, base, a.host_kind)
                verdict = f"{refuse[0]}: {refuse[1]}" if refuse else "AKAN DIJALANKAN"
            print(f"[{sc.id}] {sc.control}: {verdict}")
            for c in sc.set:
                print("    set     :", c.strip().splitlines()[0][:110])
            for c in (sc.rollback_when_absent or sc.rollback)[:1]:
                print("    rollback:", c.strip().splitlines()[0][:110])
        return 0

    if sys.platform != "win32":
        print("DITOLAK: eksekusi nyata hanya di Windows (gunakan --dry-run di OS lain).", file=sys.stderr)
        return 1
    if not _is_admin():
        print("DITOLAK: jalankan dari PowerShell sebagai Administrator.", file=sys.stderr)
        return 1
    if not a.confirm_snapshot:
        print("DITOLAK: skenario MENGUBAH setelan keamanan. Buat snapshot VM lalu tambahkan --confirm-snapshot.", file=sys.stderr)
        return 1

    truth = yaml.safe_load(Path(a.baseline_truth).read_text(encoding="utf-8")) if a.baseline_truth else None
    _, scan_fn, run_cmd = _real_runners(Path(a.rules))
    import platform
    alias = a.host_alias or default_alias()
    summary = run_all(scenarios, scan_fn, run_cmd, host_kind=a.host_kind, host_alias=alias,
                      meta_extra={"os": platform.platform(), "is_admin": True}, truth=truth, fast=a.fast)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"scenario_{summary['meta']['run_id']}_{alias}"
    (out / f"{stem}.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    md = render_markdown(summary["meta"], summary["results"], summary["metrics"], summary["anomalies"])
    (out / f"{stem}.md").write_text(md, encoding="utf-8")
    print(md)
    if summary["aborted"]:
        print("\n!!! ROLLBACK GAGAL: mesin mungkin berada pada kondisi tidak aman. Kembalikan snapshot VM.", file=sys.stderr)
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
