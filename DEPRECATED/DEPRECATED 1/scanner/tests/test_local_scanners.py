"""
Test scanner target-local (tanpa jaringan, tanpa lynis/PowerShell asli).

Jalankan dari root project:
    python scanner/tests/test_local_scanners.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.common import beacon_contract as bc  # noqa: E402
from scanner.common.spool import flush_spool, spool_payload  # noqa: E402
from scanner.linux import cis_scanner_linux as lin  # noqa: E402
from scanner.windows import cis_scanner_windows as win  # noqa: E402

LYNIS_SAMPLE = """\
# Lynis report (synthetic test fixture)
os_name=Ubuntu
os_version=22.04
hostname=test-host
hardening_index=61
tests_executed=AUTH-9286|SSH-7440|FIRE-4590
tests_skipped=NETW-3200
warning[]=SSH-7440|Weak SSH config|-|-|
suggestion[]=DEB-0280|Install libpam-tmpdir|-|-|
"""


def test_linux_parse_and_payload():
    meta, findings = lin.parse_lynis_report(LYNIS_SAMPLE)
    assert meta["hardening_index"] == 61 and meta["tests_executed"] == 3 and meta["tests_skipped"] == 1
    assert len(findings) >= 2, findings
    now = datetime.now(timezone.utc)
    res = lin.build_result(LYNIS_SAMPLE, now, now)
    p = res.to_dict()
    assert p["contract_version"] == "2"
    assert p["scan_id"].startswith("linux-")
    assert p["meta"]["hardening_index"] == 61 and p["meta"]["os_name"] == "Ubuntu"
    assert p["scanner"]["os"] == "linux" and p["scanner"]["version"] == lin.SCANNER_VERSION
    print("  PASSED: linux parse + payload")


def _fake_runner_all_pass(cmd: str) -> str:
    # Output yang cocok dengan expected_pattern tiap check: cari pola dari CHECKS.
    for c in win.CHECKS:
        if c["ps_command"] == cmd:
            return _passing_output(c["expected_pattern"])
    raise AssertionError("ps_command tidak dikenal")


def _passing_output(pattern: str) -> str:
    for cand in ("16", "True", "False", "Disabled", "1", "0", "5", "Manual", "Automatic"):
        import re
        if re.search(pattern, cand):
            return cand
    raise AssertionError(f"tidak ada kandidat output untuk pola {pattern!r}")


def test_windows_all_pass_and_all_fail():
    meta, findings = win.run_checks_local(runner=_fake_runner_all_pass)
    assert findings == [] and meta["hardening_index"] == 100, (meta, findings)
    assert meta["tests_executed"] == len(win.CHECKS)

    meta2, findings2 = win.run_checks_local(runner=lambda cmd: "")
    assert len(findings2) == len(win.CHECKS) and meta2["hardening_index"] == 0
    assert all(f["severity"] in ("Critical", "High", "Medium", "Low") for f in findings2)

    def boom(cmd):
        raise RuntimeError("ps gagal")
    meta3, findings3 = win.run_checks_local(runner=boom)
    assert len(findings3) == len(win.CHECKS)  # error tidak menjatuhkan scan
    print("  PASSED: windows scoring (all pass / all fail / runner error)")


def test_windows_payload():
    meta, findings = win.run_checks_local(runner=lambda cmd: "")
    now = datetime.now(timezone.utc)
    p = win.build_result(meta, findings, now, now).to_dict()
    assert p["scan_id"].startswith("windows-") and p["scanner"]["os"] == "windows"
    assert p["severity"] in ("High", "Critical", "Medium", "Low")
    assert p["meta"]["tests_executed"] == len(win.CHECKS)
    print("  PASSED: windows payload")


def test_no_hardcoded_secret_defaults():
    src = Path(bc.__file__).read_text(encoding="utf-8")
    assert "trycloudflare" not in src
    assert 'environ.get("N8N_WEBHOOK_SECRET", "")' in src
    print("  PASSED: tidak ada default secret/URL di source")


def test_send_fails_closed_without_config():
    old = (bc.N8N_WEBHOOK_URL, bc.N8N_WEBHOOK_SECRET)
    try:
        bc.N8N_WEBHOOK_URL, bc.N8N_WEBHOOK_SECRET = "", ""
        try:
            bc.send_payload({"scan_id": "x"})
        except RuntimeError:
            pass
        else:
            raise AssertionError("harus RuntimeError saat URL/secret kosong")
    finally:
        bc.N8N_WEBHOOK_URL, bc.N8N_WEBHOOK_SECRET = old
    print("  PASSED: beacon fail-closed tanpa konfigurasi")


def test_spool_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        payload = {"scan_id": "linux-abc", "findings": []}
        spool_payload(payload, Path(d))
        sent = []
        ok, failed = flush_spool(Path(d), lambda p: sent.append(p))
        assert (ok, failed) == (1, 0) and sent == [payload]
        assert list(Path(d).glob("*.json")) == []

        spool_payload(payload, Path(d))
        def bad(_p): raise RuntimeError("n8n down")
        ok, failed = flush_spool(Path(d), bad)
        assert (ok, failed) == (0, 1) and len(list(Path(d).glob("*.json"))) == 1  # tetap ada
    print("  PASSED: spool store-and-forward")


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAILED: {t.__name__}: {exc!r}")
    print("ALL LOCAL SCANNER TESTS PASSED" if not failed else f"{failed} TEST(S) FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
