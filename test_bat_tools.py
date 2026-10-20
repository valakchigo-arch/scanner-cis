"""run_scenarios.bat + bat_baseline_guard.py + summarize_scenarios.py (jalur validasi kedua).
Hanya logika Python dan struktur statis bat yang dibuktikan di sini; eksekusi bat di Windows = [NOT RUN]."""
import json
import re
from pathlib import Path

import pytest

import summarize_scenarios as S
from tools import bat_baseline_guard as G

ROOT = Path(__file__).resolve().parents[1]
BAT = (ROOT / "run_scenarios.bat").read_bytes().decode("utf-8")

DEFAULT = {"WIN-SCREENLOCK-TIMEOUT": None, "WIN-PASS-MINLEN": "0", "WIN-ACCT-LOCKOUT": "10", "WIN-GUEST-DISABLED": "False",
           "WIN-REMOTEREG-DISABLED": "4", "WIN-FW-PRIVATE": "True", "WIN-FW-PUBLIC": "True", "WIN-LMHASH-DISABLED": "1",
           "WIN-RDP-NLA": "1", "WIN-UAC-ENABLED": "1", "WIN-PASS-COMPLEX": "0", "WIN-DEFENDER-ENABLED": "False",
           "WIN-FW-DOMAIN": "True", "WIN-SMB1-DISABLED": "Disabled"}
FAILING = {"WIN-SCREENLOCK-TIMEOUT", "WIN-PASS-MINLEN", "WIN-ACCT-LOCKOUT", "WIN-PASS-COMPLEX"}


def scan_json(path, overrides=None, status_over=None):
    vals = dict(DEFAULT, **(overrides or {}))
    st = {c: ("FAIL" if c in FAILING else "PASS") for c in vals}
    st.update(status_over or {})
    path.write_text(json.dumps({"findings": [{"control_id": c, "status": st[c], "comparison": {"actual": v}} for c, v in vals.items()]}))


# ------------------------------------------------------------------ label
@pytest.mark.parametrize("name,label", [
    ("baseline.json", "baseline"),
    ("after_screenlock_1800.json", "after_screenlock_1800"),             # keluaran bat; versi lama memotongnya jadi 'after'
    ("rollback_fw_private.json", "rollback_fw_private"),                # versi lama: 'rollback' -> cek rollback dilewati diam-diam
    ("baseline_DESKTOP-83VKRIT_20261012T154745Z.json", "baseline"),
    ("rollback_fw_private_HOST-A_20261012T154745Z.json", "rollback_fw_private"),
    ("after_rdp_nla_off_Host-B_20261012T160258Z.json", "after_rdp_nla_off"),
])
def test_extract_label_both_naming_patterns(name, label):
    assert S.extract_label(name) == label


# ------------------------------------------------------------------ summarizer
def make_dir(tmp_path):
    scan_json(tmp_path / "baseline.json")
    scan_json(tmp_path / "after_screenlock_1800.json", {"WIN-SCREENLOCK-TIMEOUT": "1800"})                     # FAIL tetap FAIL, nilai berubah
    scan_json(tmp_path / "after_screenlock_900.json", {"WIN-SCREENLOCK-TIMEOUT": "900"}, {"WIN-SCREENLOCK-TIMEOUT": "PASS"})   # FAIL -> PASS
    scan_json(tmp_path / "after_fw_private_off.json", {"WIN-FW-PRIVATE": "False"}, {"WIN-FW-PRIVATE": "FAIL"})
    scan_json(tmp_path / "rollback_fw_private.json")
    scan_json(tmp_path / "rollback_screenlock.json")
    return tmp_path


def test_summarizer_keeps_every_scenario_distinct_and_checks_all_rollbacks(tmp_path):
    lines, anomalies = S.summarize(str(make_dir(tmp_path)))
    text = "\n".join(lines)
    for label in ("after_screenlock_1800", "after_screenlock_900", "after_fw_private_off", "rollback_fw_private", "rollback_screenlock"):
        assert label in text                                             # tidak ada yang runtuh/tertimpa
    assert "[OK]   rollback_fw_private" in text and "[OK]   rollback_screenlock" in text
    assert "'900'/PASS" in text and "None/FAIL -> '900'/PASS" in text      # arah FAIL->PASS terlihat
    assert anomalies == 0


def test_rollback_drift_is_detected_even_when_status_is_unchanged(tmp_path):
    d = make_dir(tmp_path)
    scan_json(d / "rollback_screenlock.json", {"WIN-SCREENLOCK-TIMEOUT": "1"})     # masih FAIL, tetapi nilai tidak kembali (hanya cek FAIL-set lama lolos)
    lines, anomalies = S.summarize(str(d))
    assert anomalies == 1 and any("rollback_screenlock: TIDAK kembali" in l for l in lines)


def test_rollback_drift_on_a_different_control_is_detected(tmp_path):
    d = make_dir(tmp_path)
    scan_json(d / "rollback_fw_private.json", {"WIN-GUEST-DISABLED": "True"}, {"WIN-GUEST-DISABLED": "FAIL"})
    assert S.summarize(str(d))[1] == 1


def test_after_scenario_without_any_change_is_flagged_as_suspected_noop(tmp_path):
    d = make_dir(tmp_path)
    scan_json(d / "after_fw_private_off.json")                          # tidak ada perubahan sama sekali
    lines, anomalies = S.summarize(str(d))
    assert anomalies == 1 and any("after_fw_private_off: tidak ada perubahan" in l for l in lines)


def test_main_exit_codes(tmp_path, capsys):
    d = make_dir(tmp_path)
    assert S.main([str(d)]) == 0
    scan_json(d / "rollback_screenlock.json", {"WIN-SCREENLOCK-TIMEOUT": "1"})
    assert S.main([str(d)]) == 2
    assert S.main([str(tmp_path / "kosong")]) == 1


# ------------------------------------------------------------------ guard baseline
def test_guard_accepts_default_baseline(tmp_path):
    p = tmp_path / "b.json"
    scan_json(p)
    assert G.main([str(p)]) == 0


@pytest.mark.parametrize("override,needle", [
    ({"WIN-ACCT-LOCKOUT": "5"}, "WIN-ACCT-LOCKOUT"),                    # hardened: rollback hard-coded (10) akan MENGUBAH mesin
    ({"WIN-SCREENLOCK-TIMEOUT": "600"}, "WIN-SCREENLOCK-TIMEOUT"),      # rollback = reg delete akan MENGHAPUS nilai yang sudah ada
    ({"WIN-PASS-MINLEN": "14"}, "WIN-PASS-MINLEN"),
    ({"WIN-FW-PUBLIC": "False"}, "WIN-FW-PUBLIC"),
])
def test_guard_refuses_non_default_baseline(tmp_path, override, needle, capsys):
    p = tmp_path / "b.json"
    scan_json(p, override)
    assert G.main([str(p)]) == 1 and needle in capsys.readouterr().out


def test_guard_refuses_error_missing_and_unreadable(tmp_path):
    p = tmp_path / "b.json"
    scan_json(p, status_over={"WIN-GUEST-DISABLED": "ERROR"})
    assert G.main([str(p)]) == 1
    data = json.loads(p.read_text())
    data["findings"] = [f for f in data["findings"] if f["control_id"] != "WIN-UAC-ENABLED"]
    p.write_text(json.dumps(data))
    assert G.main([str(p)]) == 1
    assert G.main([str(tmp_path / "tidak-ada.json")]) == 1
    assert G.main([]) == 2


# ------------------------------------------------------------------ struktur statis bat
MUTATING = ("reg add", "reg delete", "net accounts", "net user", "sc.exe config", "netsh advfirewall set", "secedit /configure", "net stop", "net start")


def test_bat_runs_guard_after_baseline_and_before_any_setting_change():
    lines = [l.strip().lower() for l in BAT.splitlines()]
    first_mut = next(i for i, l in enumerate(lines) if l.startswith(MUTATING))
    guard = next(i for i, l in enumerate(lines) if "bat_baseline_guard.py" in l)
    base = next(i for i, l in enumerate(lines) if l == "call :run_scan baseline")
    assert base < guard < first_mut


def test_bat_checks_admin_before_first_scan_and_every_called_label_exists():
    assert BAT.index("net session") < BAT.index("call :run_scan")
    called = set(re.findall(r"(?im)^\s*(?:call|goto)\s+:(\w+)", BAT)) - {"eof"}
    defined = set(re.findall(r"(?m)^:(\w+)\s*$", BAT))
    assert called <= defined, called - defined


def test_bat_has_no_label_glued_to_comment_and_uses_crlf():
    assert not re.search(r"[A-Za-z_]REM ={5,}", BAT)                    # insiden 'rollback_screenlockREM'
    raw = (ROOT / "run_scenarios.bat").read_bytes()
    assert raw.count(b"\r\n") == raw.count(b"\n")                       # cmd.exe tidak andal pada LF-only (label call/goto)


def test_bat_scan_labels_are_the_ones_the_summarizer_understands():
    labels = re.findall(r"call :run_scan (\w+)", BAT)
    assert labels[0] == "baseline" and len(labels) == len(set(labels))  # unik
    assert all(l == "baseline" or l.startswith(("before_", "after_", "rollback_")) for l in labels)
    assert not any(S.extract_label(l + ".json") != l for l in labels)   # nama file = label (tidak terpotong)
