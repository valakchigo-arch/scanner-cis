"""Harness skenario (P1-2/P1-3). Semua memakai Windows PALSU yang mengevaluasi rule YAML ASLI.
Yang dibuktikan di sini: logika harness + konsistensi internal data skenario (perintah vs nilai harapan, menurut MODEL kami
tentang Windows). Yang TIDAK dibuktikan: perintah benar-benar bekerja di Windows [NOT RUN]."""
import copy
import json
import re

import pytest

from scanner.core import evaluate, load_rules_from_dir
from tools import scenario_harness as H

RULES = load_rules_from_dir("rules/windows")
DEFAULT_STATE = {
    "WIN-PASS-MINLEN": "0", "WIN-PASS-COMPLEX": "0", "WIN-ACCT-LOCKOUT": "10", "WIN-SCREENLOCK-TIMEOUT": None,
    "WIN-GUEST-DISABLED": "False", "WIN-DEFENDER-ENABLED": "False", "WIN-FW-DOMAIN": "True", "WIN-FW-PRIVATE": "True",
    "WIN-FW-PUBLIC": "True", "WIN-SMB1-DISABLED": "Disabled", "WIN-UAC-ENABLED": "1", "WIN-REMOTEREG-DISABLED": "4",
    "WIN-LMHASH-DISABLED": "1", "WIN-RDP-NLA": "1",
}
SYS = r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"


class FakeWin:
    """Model Windows minimal. Perintah tak dikenal => AssertionError (typo di YAML ketahuan)."""
    def __init__(self, state=None, tamper=False, ignore=None, fail_rc=None, side_effect=None, buggy=None, scan_boom=None):
        self.state = dict(state or DEFAULT_STATE)
        self.tamper, self.ignore, self.fail_rc = tamper, ignore, fail_rc
        self.side_effect, self.buggy, self.scan_boom = side_effect or {}, buggy or {}, scan_boom
        self.cmds, self.labels, self.only_calls = [], [], []

    def scan(self, label, only=None):
        self.labels.append(label)
        self.only_calls.append(only)
        if self.scan_boom and self.scan_boom in label:
            raise RuntimeError("boom")
        out = []
        for r in RULES:
            if only is not None and r.rule_id not in only:
                continue
            obs = self.state[r.rule_id]
            ok = evaluate(r.condition.operator, r.condition.expected_value, obs)
            if r.rule_id in self.buggy:
                ok = True                                    # scanner "rusak": selalu PASS
            out.append({"control_id": r.rule_id, "status": "PASS" if ok else "FAIL", "duration_ms": 1,
                        "comparison": {"actual": obs}})
        return out

    def run(self, cmd):
        self.cmds.append(cmd)
        if self.fail_rc and re.search(self.fail_rc, cmd):
            return 1
        if self.ignore and re.search(self.ignore, cmd):
            return 0
        for k, (cid, val) in self.side_effect.items():
            if k in cmd:
                self.state[cid] = val
        s = self.state
        def m(p):
            return re.search(p, cmd, re.S)
        if x := m(r"net accounts /minpwlen:(\d+)"): s["WIN-PASS-MINLEN"] = x.group(1)
        elif x := m(r"net accounts /lockoutthreshold:(\d+)"): s["WIN-ACCT-LOCKOUT"] = x.group(1)
        elif "InactivityTimeoutSecs" in cmd and cmd.startswith("reg delete"): s["WIN-SCREENLOCK-TIMEOUT"] = None
        elif "InactivityTimeoutSecs" in cmd and (x := m(r"/d (\d+)")): s["WIN-SCREENLOCK-TIMEOUT"] = x.group(1)
        elif "PasswordComplexity" in cmd and (x := m(r"PasswordComplexity = (\d)")): s["WIN-PASS-COMPLEX"] = x.group(1)
        elif x := m(r"Set-MpPreference -DisableRealtimeMonitoring \$(true|false)"):
            if not self.tamper: s["WIN-DEFENDER-ENABLED"] = "True" if x.group(1) == "true" else "False"
        elif x := m(r"Set-NetFirewallProfile -Name (\w+) -Enabled (True|False)"): s[f"WIN-FW-{x.group(1).upper()}"] = x.group(2)
        elif "Enable-WindowsOptionalFeature" in cmd: s["WIN-SMB1-DISABLED"] = "EnablePending"
        elif "Disable-WindowsOptionalFeature" in cmd: s["WIN-SMB1-DISABLED"] = "DisablePending"
        elif "NoLMHash" in cmd and cmd.startswith("reg delete"): s["WIN-LMHASH-DISABLED"] = None
        elif "NoLMHash" in cmd and (x := m(r"/d (\d)")): s["WIN-LMHASH-DISABLED"] = x.group(1)
        elif "Enable-LocalUser" in cmd: s["WIN-GUEST-DISABLED"] = "True"
        elif "Disable-LocalUser" in cmd: s["WIN-GUEST-DISABLED"] = "False"
        elif x := m(r"Set-Service -Name RemoteRegistry -StartupType (Automatic|Disabled)"): s["WIN-REMOTEREG-DISABLED"] = "2" if x.group(1) == "Automatic" else "4"
        elif "UserAuthentication" in cmd and (x := m(r"/d (\d)")): s["WIN-RDP-NLA"] = x.group(1)
        elif "EnableLUA" in cmd and (x := m(r"/d (\d)")): s["WIN-UAC-ENABLED"] = x.group(1)
        else:
            raise AssertionError(f"perintah tidak dikenal oleh model: {cmd[:90]!r}")
        return 0


def sc(**kw):
    base = dict(id="t", control="WIN-PASS-MINLEN", title="t", set=["net accounts /minpwlen:14"],
                rollback=["net accounts /minpwlen:{baseline}"], expected_observed="14", expected_status_after="PASS")
    base.update(kw)
    return H.Scenario(base)


def go(scs, fake=None, kind="vm", **kw):
    fake = fake or FakeWin()
    out = H.run_all(scs, fake.scan, fake.run, host_kind=kind, host_alias="Host-X", meta_extra={"os": "fake", "is_admin": True}, **kw)
    return out, fake


# ------------------------------------------------------------------ data skenario
def test_shipped_scenarios_load_and_reference_known_rules():
    scs = H.load_scenarios(H.DEFAULT_SCENARIOS, {r.rule_id for r in RULES})
    assert len(scs) == 19 and len({s.id for s in scs}) == 19


def test_every_shipped_scenario_is_internally_consistent_with_the_model():
    scs = H.load_scenarios(H.DEFAULT_SCENARIOS, {r.rule_id for r in RULES})
    out, fake = go(scs)
    assert [r["outcome"] for r in out["results"]] == ["DETECTED"] * 19, [(r["id"], r["outcome"], r.get("reason")) for r in out["results"] if r["outcome"] != "DETECTED"]
    assert all(r["rollback_ok"] for r in out["results"])
    assert out["results"][-1]["id"] == "smb1_enable"                           # state pending dijalankan paling akhir
    assert out["metrics"]["detection_rate"] == 1.0 and out["metrics"]["spurious_flips_total"] == 0
    assert out["exit_code"] == 0
    assert fake.state["WIN-SMB1-DISABLED"] == "DisablePending"            # pending-reboot: diterima lewat rollback_accept
    assert {k: v for k, v in fake.state.items() if k != "WIN-SMB1-DISABLED"} == {k: v for k, v in DEFAULT_STATE.items() if k != "WIN-SMB1-DISABLED"}


def test_shipped_data_covers_the_required_p1_3_matrix():
    ids = {s.id for s in H.load_scenarios(H.DEFAULT_SCENARIOS)}
    need = {"complexity_on", "minlen_13", "minlen_14", "lockout_5", "lockout_6", "screenlock_900", "screenlock_901",
            "screenlock_0", "defender_off", "fw_domain_off", "smb1_enable", "lmhash_absent"}
    assert need <= ids
    assert "complexity_off" not in ids                      # no-op pada baseline 0: tidak boleh ada


@pytest.mark.parametrize("bad,msg", [
    ({"expected_observed": None, "drop": "expected_observed"}, "expected_observed"),
    ({"expected_status_after": "MAYBE"}, "PASS/FAIL"),
    ({"set": []}, "tidak boleh kosong"),
])
def test_scenario_validation(bad, msg):
    raw = dict(id="t", control="X", title="t", set=["a"], rollback=["b"], expected_observed="1", expected_status_after="PASS")
    drop = bad.pop("drop", None)
    raw.update(bad)
    if drop:
        raw.pop(drop)
    with pytest.raises(H.ScenarioError, match=msg):
        H.Scenario(raw)


# ------------------------------------------------------------------ penolakan sebelum menyentuh sistem
def test_noop_scenario_is_rejected_and_nothing_runs():
    s = sc(id="complexity_off", control="WIN-PASS-COMPLEX", set=["x"], rollback=["y"], expected_observed="0", expected_status_after="FAIL")
    out, fake = go([s])
    assert out["results"][0]["outcome"] == "REJECTED_NOOP" and fake.cmds == []
    assert out["metrics"]["scenarios_executed"] == 0 and out["metrics"]["detection_rate"] is None


def test_precondition_mismatch_skips_without_running():
    s = sc(control="WIN-REMOTEREG-DISABLED", set=["Set-Service -Name RemoteRegistry -StartupType Automatic"],
           rollback=["Set-Service -Name RemoteRegistry -StartupType Disabled"], expected_observed="2",
           expected_status_after="FAIL", baseline_must_be=["4"])
    st = dict(DEFAULT_STATE, **{"WIN-REMOTEREG-DISABLED": "3"})             # Manual: bukan 4 dan bukan no-op -> rollback statis tidak aman
    out, fake = go([s], FakeWin(st))
    assert out["results"][0]["outcome"] == "SKIPPED_PRECONDITION" and fake.cmds == []


def test_baseline_placeholder_rejects_unsafe_value_no_command_injection():
    st = dict(DEFAULT_STATE, **{"WIN-PASS-MINLEN": "1; Remove-Item C:\\ -Recurse"})
    out, fake = go([sc()], FakeWin(st))
    assert out["results"][0]["outcome"] == "REJECTED_NO_ROLLBACK" and fake.cmds == []


def test_absent_baseline_without_rollback_when_absent_is_rejected():
    s = sc(control="WIN-SCREENLOCK-TIMEOUT", set=['reg add "' + SYS + '" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f'],
           rollback=['reg add "' + SYS + '" /v InactivityTimeoutSecs /t REG_DWORD /d {baseline} /f'], expected_observed="900")
    out, fake = go([s])
    assert out["results"][0]["outcome"] == "REJECTED_NO_ROLLBACK" and fake.cmds == []


def test_vm_only_scenario_skipped_on_physical_host():
    s = sc(vm_only=True)
    out, fake = go([s], kind="physical")
    assert out["results"][0]["outcome"] == "SKIPPED_VM_ONLY" and fake.cmds == []


# ------------------------------------------------------------------ klasifikasi hasil
def test_detected_and_rollback_restores_baseline():
    out, fake = go([sc()])
    r = out["results"][0]
    assert r["outcome"] == "DETECTED" and r["flip"] == "FAIL_to_PASS" and r["boundary_ok"] is None
    assert r["rollback_ok"] and fake.state == DEFAULT_STATE
    assert fake.cmds == ["net accounts /minpwlen:14", "net accounts /minpwlen:0"]


def test_ineffective_set_is_not_a_scanner_failure_and_not_in_denominator():
    s = sc(control="WIN-DEFENDER-ENABLED", set=["Set-MpPreference -DisableRealtimeMonitoring $true"],
           rollback=["Set-MpPreference -DisableRealtimeMonitoring $false"], expected_observed="True", expected_status_after="FAIL")
    out, _ = go([s], FakeWin(tamper=True))
    assert out["results"][0]["outcome"] == "SET_INEFFECTIVE"
    assert out["metrics"]["detection_denominator"] == 0 and out["metrics"]["detection_rate"] is None


def test_detection_failure_is_reported_and_sets_exit_code_2():
    s = sc(set=["net accounts /minpwlen:13"], expected_observed="13", expected_status_after="FAIL")
    out, _ = go([s], FakeWin(buggy={"WIN-PASS-MINLEN": True}))
    assert out["results"][0]["outcome"] == "DETECTION_FAILURE" and out["metrics"]["detection_rate"] == 0.0
    assert out["exit_code"] == 2 and any("DETECTION_FAILURE" in a for a in out["anomalies"])


def test_boundary_kind_reports_boundary_ok():
    out, _ = go([sc(kind="boundary")])
    assert out["results"][0]["boundary_ok"] is True and out["metrics"]["boundary_ok"] == 1 == out["metrics"]["boundary_total"]


def test_unverified_rollback_is_flagged_as_anomaly():
    out, fake = go([sc()], FakeWin(ignore=r"/minpwlen:0"))          # rollback tidak berlaku
    r = out["results"][0]
    assert r["rollback_ok"] is False and fake.state["WIN-PASS-MINLEN"] == "14"
    assert out["exit_code"] == 2 and any("rollback" in a for a in out["anomalies"])


def test_failed_rollback_command_aborts_remaining_and_exit_3():
    s1, s2 = sc(id="a"), sc(id="b")
    out, fake = go([s1, s2], FakeWin(fail_rc=r"/minpwlen:0"))
    assert out["results"][0]["rollback_command_failed"] and out["results"][1]["outcome"] == "SKIPPED_ABORTED"
    assert out["exit_code"] == 3 and out["aborted"]


def test_rollback_runs_even_when_scan_after_set_blows_up():
    fake = FakeWin(scan_boom="/after")
    out, _ = go([sc()], fake)
    assert out["results"][0]["outcome"] == "ERROR_HARNESS" and out["exit_code"] == 3
    assert fake.state == DEFAULT_STATE and fake.cmds[-1] == "net accounts /minpwlen:0"


def test_spurious_flip_is_detected_and_also_affects_exempts_it():
    se = {"/minpwlen:14": ("WIN-ACCT-LOCKOUT", "3")}                # efek samping: lockout FAIL -> PASS
    out, _ = go([sc()], FakeWin(side_effect=se))
    assert out["results"][0]["spurious_flips"] == ["WIN-ACCT-LOCKOUT"] and out["metrics"]["spurious_flips_total"] == 1
    out2, _ = go([sc(also_affects=["WIN-ACCT-LOCKOUT"])], FakeWin(side_effect=se))
    assert out2["results"][0]["spurious_flips"] == []


def test_value_change_without_status_flip_is_tracked_separately():
    se = {"/minpwlen:14": ("WIN-ACCT-LOCKOUT", "11")}              # 10 -> 11: tetap FAIL
    out, _ = go([sc()], FakeWin(side_effect=se))
    r = out["results"][0]
    assert r["spurious_flips"] == [] and r["spurious_value_changes"] == ["WIN-ACCT-LOCKOUT"]


# ------------------------------------------------------------------ label, metrik, laporan
def test_labels_are_unique_per_run_and_carry_run_id():
    o1, f1 = go([sc()])
    o2, f2 = go([sc()])
    assert o1["meta"]["run_id"] != o2["meta"]["run_id"]
    assert all(l.startswith(o1["meta"]["run_id"]) for l in f1.labels) and len(set(f1.labels)) == len(f1.labels)


def test_percentile_nearest_rank():
    assert H.percentile([], 95) is None
    assert H.percentile([5], 95) == 5
    assert H.percentile(list(range(1, 21)), 95) == 19 and H.percentile(list(range(1, 21)), 50) == 10


def test_false_positive_and_negative_rates_use_independent_truth():
    out, _ = go([], truth={"WIN-PASS-MINLEN": "FAIL", "WIN-FW-DOMAIN": "PASS", "WIN-GUEST-DISABLED": "FAIL"})
    m = out["metrics"]
    # scanner: MINLEN=FAIL (benar), FW-DOMAIN=PASS (benar), GUEST=PASS tetapi truth FAIL -> 1 FN
    assert m["false_positive_rate_baseline"] == 0.0 and m["false_negative_rate_baseline"] == 0.5
    assert m["false_negatives"] == ["WIN-GUEST-DISABLED"]


def test_markdown_and_json_summary_contain_no_raw_hostname(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostname", lambda: "SECRET-PC-4711")      # nilai unik: tidak bisa bentrok dengan kata lain
    out, _ = go([sc()])
    text = json.dumps(out, default=str) + H.render_markdown(out["meta"], out["results"], out["metrics"], out["anomalies"])
    assert "SECRET-PC-4711" not in text and "Host-X" in text
    assert "SECRET-PC-4711" not in H.default_alias() and H.default_alias().startswith("host-")


def test_aggregate_groups_vm_and_physical_separately(tmp_path):
    for i, kind in enumerate(["vm", "vm", "physical"]):
        out, _ = go([sc()], kind=kind, run_id=f"r{i}")
        out["metrics"]["scan_seconds_median"] = 100.0 + i if kind == "vm" else 10.0
        (tmp_path / f"scenario_r{i}.json").write_text(json.dumps(out, default=str))
    agg = H.aggregate(sorted(tmp_path.glob("scenario_*.json")))
    assert set(agg) == {"vm", "physical"} and agg["vm"]["runs"] == 2 and agg["physical"]["run_median_seconds_median"] == 10.0


# ------------------------------------------------------------------ CLI
def test_cli_refuses_real_execution_off_windows(capsys):
    rc = H.main([])
    assert rc == 1 and "DITOLAK" in capsys.readouterr().err


def test_cli_dry_run_judges_validity_without_running(tmp_path, capsys):
    base = {"findings": [{"control_id": r.rule_id, "status": "PASS", "comparison": {"actual": DEFAULT_STATE[r.rule_id]}} for r in RULES]}
    # tandai baseline realistis: complexity=0 -> FAIL
    for f in base["findings"]:
        if f["control_id"] == "WIN-PASS-COMPLEX":
            f["status"] = "FAIL"
    p = tmp_path / "b.json"
    p.write_text(json.dumps(base))
    rc = H.main(["--dry-run", "--baseline-json", str(p), "--host-kind", "physical"])
    out = capsys.readouterr().out
    assert rc == 0 and "[minlen_14]" in out and "AKAN DIJALANKAN" in out and "SKIPPED_VM_ONLY" in out


def test_scenario_leaving_pending_state_runs_last_and_blocks_the_rest():
    pend = sc(id="pend", control="WIN-SMB1-DISABLED", set=["Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"],
              rollback=["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"], expected_observed=["Enabled", "EnablePending"],
              expected_status_after="FAIL", rollback_accept=["Disabled", "DisablePending"])
    other = sc(id="other")
    out, _ = go([pend, other])                                                  # urutan input: pend dulu
    assert [r["id"] for r in out["results"]] == ["other", "pend"]               # tetapi pend dijalankan terakhir
    assert out["results"][1]["rollback_pending_reboot"] is True and out["exit_code"] == 0
    third = sc(id="third")
    out2, _ = go([pend, third, sc(id="x2", leaves=1)] if False else [pend, third])
    assert [r["outcome"] for r in out2["results"]] == ["DETECTED", "DETECTED"]
    # dua skenario pending: yang kedua dilewati
    pend2 = sc(id="pend2", control="WIN-SMB1-DISABLED", set=["Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"],
               rollback=["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"], expected_observed=["Enabled", "EnablePending"],
               expected_status_after="FAIL", rollback_accept=["Disabled", "DisablePending"])
    out3, _ = go([pend, pend2])
    assert [r["outcome"] for r in out3["results"]] == ["DETECTED", "SKIPPED_PENDING_REBOOT"]


# ------------------------------------------------------------------ mode fast
def test_fast_mode_scans_only_the_tested_control_after_baseline():
    out, fake = go([sc()], fast=True)
    assert fake.only_calls[0] is None                                 # baseline: selalu penuh
    assert fake.only_calls[1:] == [["WIN-PASS-MINLEN"], ["WIN-PASS-MINLEN"]]   # after + rollback: hanya kontrol yang diuji
    r = out["results"][0]
    assert r["outcome"] == "DETECTED" and r["rollback_ok"] and r["mode"] == "fast" and out["meta"]["mode"] == "fast"


def test_fast_mode_does_not_claim_zero_spurious_flips_it_never_measured():
    se = {"/minpwlen:14": ("WIN-ACCT-LOCKOUT", "3")}                  # ada efek samping nyata, tetapi tidak terlihat di mode fast
    out, _ = go([sc()], FakeWin(side_effect=se), fast=True)
    assert out["metrics"]["spurious_flips_total"] is None and out["metrics"]["spurious_value_changes_total"] is None
    md = H.render_markdown(out["meta"], out["results"], out["metrics"], out["anomalies"])
    assert "n/a (mode fast" in md
    full, _ = go([sc()], FakeWin(side_effect=se))                     # mode penuh tetap menangkapnya
    assert full["metrics"]["spurious_flips_total"] == 1


def test_fast_mode_still_flags_unrestored_control():
    out, fake = go([sc()], FakeWin(ignore=r"/minpwlen:0"), fast=True)
    assert out["results"][0]["rollback_ok"] is False and out["exit_code"] == 2


def test_full_mode_requires_every_control_to_be_present_in_rollback_scan():
    class Lossy(FakeWin):
        def scan(self, label, only=None):
            out = super().scan(label, only)
            return [f for f in out if not (label.endswith("/rollback") and f["control_id"] == "WIN-FW-PUBLIC")]
    out, _ = go([sc()], Lossy())
    assert out["results"][0]["rollback_ok"] is False and "WIN-FW-PUBLIC" in out["results"][0]["rollback_drift"]
