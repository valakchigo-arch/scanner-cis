"""Regression test: satu test per bug yang ditemukan pada audit (lihat docs/AUDIT_FINDINGS.md)."""
import json, os, re, subprocess
from pathlib import Path
import pytest

from scanner.core import Rule, Condition, Probe, execute_rule, execute_rules, evaluate, registry
from scanner.core.rule_loader import load_rule, load_rules_from_dir
from scanner.core.exceptions import RuleValidationError
from scanner.core.probes import windows_powershell, windows_registry
from scanner.core.probes import _powershell as ps
from scanner.core.scoring import compute_score
from scanner.core.contract_adapter import findings_to_contract
from scanner.common import beacon_contract as bc
from scanner.common.spool import spool_payload, flush_spool
from scanner.windows import cis_scanner_windows as win
from scanner.linux.cis_scanner_linux import parse_lynis_report


def _rule(op="equals", exp=1, provider="windows.powershell", params=None, os_="windows", sev="HIGH"):
    return Rule("R-1", "t", "authentication", os_, {"name": "CIS"}, sev, "DIRECT",
                Condition(op, exp), Probe(provider, params or {"command": "x"}), {"action": "fix"})


# ---------- evaluator ----------
@pytest.mark.parametrize("op,exp", [("contains", "Non"), ("contains", "one"), ("matches", "^None$"), ("matches", "Non")])
def test_missing_value_never_matches_string_None(op, exp):
    assert evaluate(op, exp, None) is False        # sebelumnya True ("None" di-str())


# ---------- legacy windows: regex ----------
def _ok(cid, out):
    c = next(c for c in win.CHECKS if c["check_id"] == cid)
    return bool(re.search(c["expected_pattern"], out))

@pytest.mark.parametrize("val,expect", [(1, True), (5, True), (0, False), (6, False), (10, False), (15, False), (25, False), (55, False)])
def test_lockout_only_1_to_5(val, expect):
    assert _ok("WIN-ACCT-LOCKOUT", f"Lockout threshold:    {val}") is expect   # 15/25/55 dulu lolos

@pytest.mark.parametrize("val,expect", [(0, False), (1, True), (900, True), (901, False), (950, False), (999, False)])
def test_screenlock_max_900(val, expect):
    assert _ok("WIN-SCREENLOCK-TIMEOUT", str(val)) is expect

@pytest.mark.parametrize("val,expect", [(8, False), (13, False), (14, True), (64, True), (100, True), (128, True)])
def test_minlen_14_and_above(val, expect):
    assert _ok("WIN-PASS-MINLEN", f"Minimum password length   {val}") is expect  # 100 dulu FAIL

def test_remote_registry_not_installed_is_safe():
    assert _ok("WIN-REMOTEREG-DISABLED", "NotInstalled") and _ok("WIN-REMOTEREG-DISABLED", "Disabled")
    assert not _ok("WIN-REMOTEREG-DISABLED", "Automatic")


# ---------- legacy windows: error != fail ----------
def test_runner_error_is_not_reported_as_failure():
    meta, findings = win.run_checks_local(runner=lambda c: (_ for _ in ()).throw(RuntimeError("x")))
    assert findings == [] and meta["tests_errored"] == len(win.CHECKS) and meta["hardening_index"] is None

def test_partial_error_does_not_lower_index():
    outs = {c["check_id"]: "" for c in win.CHECKS}
    outs["WIN-FW-DOMAIN"] = "True"
    outs["WIN-FW-PRIVATE"] = "__ERROR__: timeout"
    meta, _ = win.score_checks_from_outputs(outs)
    assert "WIN-FW-PRIVATE" in meta["errored_check_ids"]
    assert meta["tests_executed"] + meta["tests_errored"] == len(win.CHECKS)


# ---------- probes (subprocess dipalsukan: tidak butuh PowerShell) ----------
class _Proc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out.encode(), err.encode()

@pytest.fixture
def fake_ps(monkeypatch):
    calls = []
    monkeypatch.setattr(windows_registry, "_native_available", lambda: False)
    def install(proc):
        monkeypatch.setattr(ps.shutil, "which", lambda n: "/usr/bin/pwsh")
        def run(cmd, **kw):
            calls.append(cmd); return proc
        monkeypatch.setattr(ps.subprocess, "run", run)
        return calls
    return install

def test_powershell_probe_nonzero_rc_is_error(fake_ps):
    fake_ps(_Proc(1, "", "Access is denied"))
    with pytest.raises(Exception, match="Access is denied"):
        windows_powershell.run({"command": "secedit"})

def test_powershell_probe_is_strict_by_default(fake_ps):
    import base64
    calls = fake_ps(_Proc(0, "14"))
    windows_powershell.run({"command": "echo 14"})
    script = base64.b64decode(calls[0][-1]).decode("utf-16-le")
    assert "$ErrorActionPreference='Stop'" in script

def test_registry_probe_not_found_and_value(fake_ps):
    fake_ps(_Proc(0, "__NOT_FOUND__"))
    assert windows_registry.run({"path": "HKLM\\X", "key": "K"}).value is None
    fake_ps(_Proc(0, "900"))
    assert windows_registry.run({"path": "HKLM\\X", "key": "K"}).value == "900"

def test_registry_probe_failure_is_error_not_empty_fail(fake_ps):
    fake_ps(_Proc(1, "", "boom"))        # dulu: rc diabaikan -> value "" -> FAIL palsu
    with pytest.raises(Exception, match="boom"):
        windows_registry.run({"path": "HKLM\\X", "key": "K"})

def test_registry_probe_escapes_single_quotes(fake_ps):
    import base64
    calls = fake_ps(_Proc(0, "1"))
    windows_registry.run({"path": "HKLM\\X", "key": "a'; Remove-Item C:\\ #"})
    script = base64.b64decode(calls[0][-1]).decode("utf-16-le")
    assert "a''; Remove-Item" in script          # kutip digandakan -> tetap literal, bukan injeksi


# ---------- executor ----------
def test_error_reason_is_preserved():
    f = execute_rule(_rule(provider="nope.provider"), "s", 1)
    assert f["status"] == "ERROR" and "ProbeNotFoundError" in f["error_detail"]

def test_bad_probe_return_type_does_not_crash_scan():
    registry._providers["t.bad"] = lambda p: {"not": "ProbeResult"}
    try:
        f = execute_rule(_rule(provider="t.bad"), "s", 1)
    finally:
        registry._providers.pop("t.bad")
    assert f["status"] == "ERROR"

def test_host_os_gate_marks_not_applicable():
    fs = execute_rules([_rule(os_="linux"), _rule(os_="any", provider="nope")], "s", host_os="windows")
    assert fs[0]["status"] == "NOT_APPLICABLE" and fs[1]["status"] == "ERROR"


# ---------- loader ----------
def test_loader_rejects_non_mapping_probe(tmp_path):
    y = Path("rules/windows/win-fw-domain.yaml").read_text(encoding="utf-8").replace("probe:\n", "probe: oops\n_x:\n", 1)
    f = tmp_path / "r.yaml"; f.write_text(y, encoding="utf-8")
    with pytest.raises(RuleValidationError):
        load_rule(str(f))

def test_loader_missing_directory():
    with pytest.raises(RuleValidationError):
        load_rules_from_dir("/no/such/dir")

def test_all_shipped_rules_load_and_are_unique():
    rules = load_rules_from_dir("rules/windows")
    assert len(rules) == 14 and len({r.rule_id for r in rules}) == 14

def test_screenlock_rule_uses_machine_wide_policy_path():
    """P0-2: probe reads HKLM InactivityTimeoutSecs (CIS 2.3.7.4 machine inactivity limit).

    Catatan historis: path HKCU\\Control Panel\\Desktop\\ScreenSaveTimeOut pernah
    diverifikasi LIVE (nilai 1800 terbaca; docs/VALIDATION_RESULTS.md) dan kemudian
    diganti ke HKLM\\SOFTWARE\\Policies\\...\\Control Panel\\Desktop oleh scanner legacy
    -- langkah itu KELIRU (path HKLM itu tidak pernah terverifikasi sebagai lokasi
    policy screen-lock; versi awal audit F-07 sudah ditarik kembali ke HKCU).
    Keputusan akhir (P0-2): beralih ke HKLM\\...\\Policies\\System\\InactivityTimeoutSecs
    karena (a) CIS 2.3.7.4 secara eksplisit merujuk *machine inactivity limit*, (b) HKCU
    hanya mencerminkan akun yang menjalankan scanner, bukan kebijakan mesin.
    """
    r = load_rule("rules/windows/win-screenlock-timeout.yaml")
    assert r.probe.params["path"] == \
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    assert r.probe.params["key"] == "InactivityTimeoutSecs"
    assert r.condition.operator == "matches"


# ---------- scoring ----------
def test_all_error_assessment_is_flagged_not_silently_perfect():
    s = compute_score([{"status": "ERROR", "severity": "HIGH"}] * 3).to_dict()
    assert s["indeterminate"] is True and s["complete"] is False

def test_clean_assessment_is_complete():
    s = compute_score([{"status": "PASS", "severity": "HIGH"}]).to_dict()
    assert s["complete"] is True and s["indeterminate"] is False


# ---------- adapter ----------
def test_adapter_error_is_not_a_finding():
    fs = [
        {"status": "PASS", "control_id": "A"},
        {"status": "FAIL", "control_id": "B", "category": "authentication", "severity": "CRITICAL", "title": "t",
         "comparison": {"operator": "gte", "expected": 14, "actual": "0"}},
        {"status": "ERROR", "control_id": "C"},
    ]
    meta, out = findings_to_contract(fs)
    assert [o["check_id"] for o in out] == ["B"] and out[0]["severity"] == "Critical"
    assert out[0]["recommended_value"] == ">= 14"
    assert meta["hardening_index"] == 50 and meta["tests_errored"] == 1 and meta["tests_executed"] == 2

def test_adapter_all_error_gives_none_index():
    meta, out = findings_to_contract([{"status": "ERROR", "control_id": "X"}])
    assert meta["hardening_index"] is None and meta["tests_executed"] == 0 and out == []


# ---------- beacon ----------
def test_linux_scan_severity_is_max_not_first():
    r = bc.findings_from_linux_scan({}, [{"check_id": "a", "severity": "Low"}, {"check_id": "b", "severity": "High"}],
                                    "10.0.0.1", "h", "d")
    assert r.severity == "High"

def test_bad_env_numbers_do_not_crash_import(monkeypatch):
    monkeypatch.setenv("SCANNER_MAX_RETRIES", "abc")
    assert bc._env_num("SCANNER_MAX_RETRIES", 3, int, 1) == 3
    monkeypatch.setenv("SCANNER_MAX_RETRIES", "0")
    assert bc._env_num("SCANNER_MAX_RETRIES", 3, int, 1) == 3

def _resp(status):
    import requests
    r = requests.Response(); r.status_code = status; r._content = b"{}"; return r

@pytest.mark.parametrize("status,expected_calls", [(404, 1), (422, 1), (401, 1), (503, 3), (429, 3)])
def test_retry_only_transient(monkeypatch, status, expected_calls):
    monkeypatch.setattr(bc, "N8N_WEBHOOK_URL", "http://x/y"); monkeypatch.setattr(bc, "N8N_WEBHOOK_SECRET", "s")
    monkeypatch.setattr(bc, "MAX_RETRIES", 3); monkeypatch.setattr(bc.time, "sleep", lambda s: None)
    n = {"c": 0}
    def post(*a, **k):
        n["c"] += 1; return _resp(status)
    monkeypatch.setattr(bc.requests, "post", post)
    with pytest.raises(RuntimeError):
        bc.send_payload({"scan_id": "s1"})
    assert n["c"] == expected_calls

def test_backoff_is_exponential_and_capped(monkeypatch):
    sleeps = []
    monkeypatch.setattr(bc.time, "sleep", sleeps.append)
    monkeypatch.setattr(bc, "MAX_RETRIES", 5); monkeypatch.setattr(bc, "RETRY_DELAY_SEC", 2.0)
    for a in range(1, 6): bc._backoff(a)
    assert sleeps == [2.0, 4.0, 8.0, 16.0]          # tidak tidur setelah percobaan terakhir


# ---------- spool ----------
def test_spool_blocks_path_traversal(tmp_path):
    p = spool_payload({"scan_id": "../../etc/evil"}, tmp_path / "spool")
    assert p.parent == (tmp_path / "spool") and ".." not in p.name

def test_spool_is_atomic_no_tmp_left(tmp_path):
    spool_payload({"scan_id": "ok"}, tmp_path)
    assert [f.name for f in tmp_path.iterdir()] == ["ok.json"]

def test_spool_quarantines_corrupt_and_continues(tmp_path):
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    spool_payload({"scan_id": "good"}, tmp_path)
    sent = []
    ok, failed = flush_spool(tmp_path, sent.append)
    assert ok == 1 and failed == 1 and sent[0]["scan_id"] == "good"
    assert (tmp_path / "bad.json.corrupt").exists() and not (tmp_path / "bad.json").exists()

def test_spool_failed_send_keeps_file(tmp_path):
    spool_payload({"scan_id": "keep"}, tmp_path)
    def boom(p): raise RuntimeError("down")
    assert flush_spool(tmp_path, boom) == (0, 1) and (tmp_path / "keep.json").exists()


# ---------- linux ----------
def test_lynis_severity_heuristic_and_bad_index():
    rpt = "hardening_index=N/A\nwarning[]=AUTH-1|bad|\nsuggestion[]=SSH-1|meh|\nmanual[]=check this\n"
    meta, f = parse_lynis_report(rpt)
    assert meta["hardening_index"] == 0                       # tidak crash
    assert [x["severity"] for x in f] == ["High", "Low", "Low"]
    assert bc.findings_from_linux_scan(meta, f, "1.1.1.1", "h", "d").severity == "High"


# ---------- rule secedit: tidak boleh memakai file temp bernama tetap ----------
@pytest.mark.parametrize("rid", ["win-pass-minlen", "win-acct-lockout", "win-pass-complex"])
def test_secedit_rules_use_unique_temp_and_cleanup(rid):
    cmd = load_rule(f"rules/windows/{rid}.yaml").probe.params["command"]
    assert "NewGuid" in cmd and "Remove-Item" in cmd and "$LASTEXITCODE" in cmd
    assert "secpol_" in cmd and ".inf\"" not in cmd.replace("'.inf'", "")   # bukan path tetap



# ======================================================================
# Perbaikan dari hasil uji live (VM Win10 lambat; docs/VALIDATION_RESULTS.md)
# ======================================================================
import sys, types, subprocess as _sp


def _fake_winreg(values=None, raise_on_open=None):
    """winreg palsu: values = {(hive_const, subkey, name): value}."""
    m = types.ModuleType("winreg")
    m.HKEY_LOCAL_MACHINE, m.HKEY_CURRENT_USER, m.HKEY_USERS, m.HKEY_CLASSES_ROOT = "HKLM", "HKCU", "HKU", "HKCR"
    m.KEY_READ, m.KEY_WOW64_64KEY = 1, 256
    m.seen = {}
    class _H:
        def __init__(self, k): self.k = k
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def OpenKey(hive, sub, res, access):
        m.seen["access"] = access
        if raise_on_open: raise raise_on_open
        return _H((hive, sub))
    def QueryValueEx(h, name):
        key = (*h.k, name)
        if key not in (values or {}): raise FileNotFoundError(name)
        return values[key], 4
    m.OpenKey, m.QueryValueEx = OpenKey, QueryValueEx
    return m


@pytest.fixture
def native(monkeypatch):
    def install(values=None, raise_on_open=None):
        fake = _fake_winreg(values, raise_on_open)
        monkeypatch.setitem(sys.modules, "winreg", fake)
        return fake
    return install


def test_native_registry_reads_dword_as_string(native):
    native({("HKLM", "SYSTEM\\X", "Start"): 4})
    r = windows_registry.run({"path": "HKLM\\SYSTEM\\X", "key": "Start"})
    assert r.value == "4" and r.evidence["method"] == "winreg"

def test_native_registry_missing_value_is_none_not_error(native):
    native({})
    r = windows_registry.run({"path": "HKCU\\Control Panel\\Desktop", "key": "ScreenSaveTimeOut"})
    assert r.value is None and r.evidence["note"] == "value_not_present"

def test_native_registry_uses_64bit_view(native):
    fake = native({("HKLM", "S", "K"): 1})
    windows_registry.run({"path": "HKLM\\S", "key": "K"})
    assert fake.seen["access"] & 256

def test_native_registry_permission_error_is_probe_error(native):
    native(raise_on_open=PermissionError("denied"))
    with pytest.raises(Exception, match="denied"):
        windows_registry.run({"path": "HKLM\\S", "key": "K"})

def test_native_registry_unsupported_hive(native):
    native({})
    with pytest.raises(Exception, match="unsupported registry hive"):
        windows_registry.run({"path": "HKXX\\S", "key": "K"})

def test_native_registry_does_not_spawn_powershell(native, monkeypatch):
    native({("HKLM", "S", "K"): 1})
    monkeypatch.setattr(ps.subprocess, "run", lambda *a, **k: pytest.fail("PowerShell tidak boleh dipakai"))
    assert windows_registry.run({"path": "HKLM\\S", "key": "K"}).value == "1"


# ---- timeout / retry PowerShell ----
def _install_ps(monkeypatch, behaviors, seen=None):
    monkeypatch.setattr(ps.shutil, "which", lambda n: "/usr/bin/pwsh")
    it = iter(behaviors)
    def run(cmd, **kw):
        if seen is not None: seen.append(kw.get("timeout"))
        b = next(it)
        if b == "timeout": raise _sp.TimeoutExpired(cmd, kw.get("timeout"))
        return _Proc(0, b)
    monkeypatch.setattr(ps.subprocess, "run", run)

def test_powershell_retries_once_after_timeout(monkeypatch):
    _install_ps(monkeypatch, ["timeout", "ok"])
    assert ps.run_powershell("x").stdout == "ok"

def test_powershell_gives_up_after_retries(monkeypatch):
    _install_ps(monkeypatch, ["timeout", "timeout"])
    with pytest.raises(Exception, match="timed out after 30s \\(2 percobaan\\)"):
        ps.run_powershell("x", timeout=30)

def test_timeout_scale_and_retries_from_env(monkeypatch):
    seen = []
    monkeypatch.setenv("SCANNER_PROBE_TIMEOUT_SCALE", "3"); monkeypatch.setenv("SCANNER_PS_RETRIES", "0")
    _install_ps(monkeypatch, ["timeout"], seen)
    with pytest.raises(Exception, match="timed out after 90s \\(1 percobaan\\)"):
        ps.run_powershell("x", timeout=30)
    assert seen == [90.0]

def test_bad_timeout_env_falls_back(monkeypatch):
    monkeypatch.setenv("SCANNER_PROBE_TIMEOUT_SCALE", "abc"); monkeypatch.setenv("SCANNER_PS_RETRIES", "-5")
    seen = []; _install_ps(monkeypatch, ["ok"], seen)
    ps.run_powershell("x", timeout=30)
    assert seen == [30.0]


# ---- durasi & coverage ----
def test_findings_carry_duration_ms():
    f = execute_rule(_rule(provider="nope"), "s", 1)
    assert isinstance(f["duration_ms"], int) and f["duration_ms"] >= 0

def test_adapter_reports_partial_coverage():
    fs = [{"status": "PASS", "control_id": "A"}, {"status": "FAIL", "control_id": "B", "category": "x",
          "severity": "LOW", "title": "t", "comparison": {"operator": "exists", "expected": None, "actual": None}}] \
         + [{"status": "ERROR", "control_id": f"E{i}"} for i in range(6)]
    meta, _ = findings_to_contract(fs)
    assert meta["coverage_percent"] == 25 and meta["tests_errored"] == 6      # data VM: 8 dinilai dari 14 -> 57%

def test_adapter_na_does_not_reduce_coverage():
    meta, _ = findings_to_contract([{"status": "PASS", "control_id": "A"}, {"status": "NOT_APPLICABLE", "control_id": "B"}])
    assert meta["coverage_percent"] == 100

def test_low_coverage_scan_is_refused_not_sent(monkeypatch):
    from scanner.windows import rule_scanner_windows as rsw
    def fake_scan(rules_dir, host_os="windows"):
        fs = [{"status": "PASS", "control_id": "A"}] + [{"status": "ERROR", "control_id": f"E{i}"} for i in range(3)]
        meta, cf = findings_to_contract(fs)
        return fs, meta, cf, compute_score(fs)
    monkeypatch.setattr(rsw, "run_scan", fake_scan)
    sent = []
    monkeypatch.setattr(rsw, "beacon_send", lambda r: sent.append(r))
    assert rsw.main(["--allow-non-admin", "--dry-run", "--min-coverage", "70"]) == 1
    assert rsw.main(["--allow-non-admin", "--dry-run", "--min-coverage", "0"]) == 0
    assert sent == []

def test_scan_payload_carries_coverage_meta():
    r = bc.findings_from_windows_scan({"coverage_percent": 57, "tests_errored": 6}, [], "1.1.1.1", "h", "d")
    assert r.to_dict()["meta"]["coverage_percent"] == 57
