#!/usr/bin/env python3
"""
scanner/windows/cis_scanner_windows.py
--------------------------------------
Windows hardening scanner -- TARGET-LOCAL, beacon-based.

Dijalankan LANGSUNG di perangkat target sebagai Administrator:

    python scanner/windows/cis_scanner_windows.py

Alur:
    tiap check di CHECKS -> PowerShell lokal -> raw_outputs
        ->  score_checks_from_outputs()   (VERBATIM dari hardening_scanner_windows.py)
        ->  ScanResult  ->  HTTPS POST ke n8n (beacon)

TIDAK ada WinRM/pywinrm, TIDAK ada koneksi PostgreSQL, TIDAK ada Ansible.
CHECKS dan logika PASS/FAIL tidak diubah -- hanya sumber eksekusinya yang
berganti (WinRM remote -> PowerShell lokal).

Exit code: 0 = scan + beacon OK | 1 = scan gagal | 2 = scan OK, beacon gagal (di-spool)
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.common import beacon_contract as bc  # noqa: E402
from scanner.common.spool import default_spool_dir, flush_spool, spool_payload  # noqa: E402
from scanner.windows.beacon import send as beacon_send  # noqa: E402

logger = logging.getLogger("cis_scanner_windows")

SCANNER_VERSION = "2.0.0"


# =========================================================
# DEFINISI CHECKS — CIS Benchmark for Windows (14 item kritis terkurasi)
# =========================================================
# Tiap check: jalankan ps_command, ambil output, cocokin ke expected_pattern.
# Kalau match -> PASS (tidak disimpan sebagai finding).
# Kalau tidak match -> FAIL (disimpan ke hardening_findings, dengan severity).

CHECKS = [
    {
        "check_id": "WIN-PASS-MINLEN",
        "severity": "High",
        "description": "Minimum password length harus >= 14 karakter",
        "ps_command": "net accounts | Select-String 'Minimum password length'",
        "expected_pattern": r"1[4-9]|[2-9]\d",  # >= 14
        "recommended_value": ">= 14",
    },
    {
        "check_id": "WIN-PASS-COMPLEX",
        "severity": "High",
        "description": "Password complexity harus di-enable",
        # Coba Group Policy AD dulu (domain-joined); kalau gagal (standalone/workgroup),
        # fallback ke secedit local security policy. Salah satu dari dua ini akan
        # cocok tergantung apakah target domain-joined atau tidak.
        "ps_command": "(Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue).ComplexityEnabled; "
                        "if (-not $?) { (secedit /export /cfg $env:TEMP\\secpol.cfg /quiet); "
                        "Select-String -Path $env:TEMP\\secpol.cfg -Pattern 'PasswordComplexity' }",
        "expected_pattern": r"True|PasswordComplexity\s*=\s*1",
        "recommended_value": "Enabled",
    },
    {
        "check_id": "WIN-ACCT-LOCKOUT",
        "severity": "High",
        "description": "Account lockout threshold harus diaktifkan (<=5 attempts)",
        "ps_command": "net accounts | Select-String 'Lockout threshold'",
        "expected_pattern": r"[1-5]\b",
        "recommended_value": "<= 5 attempts",
    },
    {
        "check_id": "WIN-RDP-NLA",
        "severity": "Critical",
        "description": "Network Level Authentication (NLA) untuk RDP harus aktif",
        "ps_command": "(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices "
                        "-Filter 'TerminalName=\"RDP-tcp\"').UserAuthenticationRequired",
        "expected_pattern": r"^1$",
        "recommended_value": "1 (enabled)",
    },
    {
        "check_id": "WIN-FW-DOMAIN",
        "severity": "Critical",
        "description": "Windows Firewall profile Domain harus ON",
        "ps_command": "(Get-NetFirewallProfile -Profile Domain).Enabled",
        "expected_pattern": r"^True$",
        "recommended_value": "True",
    },
    {
        "check_id": "WIN-FW-PRIVATE",
        "severity": "Critical",
        "description": "Windows Firewall profile Private harus ON",
        "ps_command": "(Get-NetFirewallProfile -Profile Private).Enabled",
        "expected_pattern": r"^True$",
        "recommended_value": "True",
    },
    {
        "check_id": "WIN-FW-PUBLIC",
        "severity": "Critical",
        "description": "Windows Firewall profile Public harus ON",
        "ps_command": "(Get-NetFirewallProfile -Profile Public).Enabled",
        "expected_pattern": r"^True$",
        "recommended_value": "True",
    },
    {
        "check_id": "WIN-SMB1-DISABLED",
        "severity": "Critical",
        "description": "SMBv1 (protokol usang, rawan EternalBlue/WannaCry) harus disabled",
        "ps_command": "(Get-SmbServerConfiguration).EnableSMB1Protocol",
        "expected_pattern": r"^False$",
        "recommended_value": "False",
    },
    {
        "check_id": "WIN-GUEST-DISABLED",
        "severity": "Medium",
        "description": "Akun Guest bawaan harus disabled",
        "ps_command": "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled",
        "expected_pattern": r"^False$",
        "recommended_value": "False",
    },
    {
        "check_id": "WIN-UAC-ENABLED",
        "severity": "High",
        "description": "User Account Control (UAC) harus enabled",
        "ps_command": "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                        "-Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA",
        "expected_pattern": r"^1$",
        "recommended_value": "1 (enabled)",
    },
    {
        "check_id": "WIN-REMOTEREG-DISABLED",
        "severity": "Medium",
        "description": "Remote Registry service sebaiknya disabled kalau tidak dipakai",
        "ps_command": "(Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue).StartType",
        "expected_pattern": r"Disabled",
        "recommended_value": "Disabled",
    },
    {
        "check_id": "WIN-LMHASH-DISABLED",
        "severity": "High",
        # CATATAN FALSE-POSITIVE: Windows Vista/Server 2008 ke atas SUDAH TIDAK
        # menyimpan LM hash secara default, walaupun key NoLMHash ini nggak
        # eksplisit di-set (key kosong). Jadi hasil FAIL dari check ini di OS
        # modern SERING kali false-positive -- perlu diverifikasi manual dulu
        # sebelum ditindaklanjuti sebagai temuan beneran, terutama kalau
        # current_value-nya "(kosong/tidak terdeteksi)" (key belum di-set,
        # bukan berarti di-set ke 0/aktif menyimpan LM hash).
        "description": "Penyimpanan LM hash (algoritma lemah) harus disabled",
        "ps_command": "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name NoLMHash "
                        "-ErrorAction SilentlyContinue).NoLMHash",
        "expected_pattern": r"^1$",
        "recommended_value": "1 (LM hash storage disabled)",
    },
    {
        "check_id": "WIN-SCREENLOCK-TIMEOUT",
        "severity": "Low",
        # FIX: versi awal baca HKCU (registry user yang connect WinRM --
        # biasanya akun admin lu sendiri, BUKAN kebijakan server yang
        # sebenarnya berlaku buat user lain). Sekarang baca Group Policy
        # machine-wide (HKLM) yang beneran merepresentasikan kebijakan
        # server, konsisten sama check lain yang semuanya machine-scope.
        "description": "Screen lock inactivity timeout (Group Policy) harus <= 900 detik (15 menit)",
        "ps_command": "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop' "
                        "-Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut",
        "expected_pattern": r"^([1-9]\d{0,2}|900)$",  # 1-900
        "recommended_value": "<= 900 (via Group Policy)",
    },
    {
        "check_id": "WIN-DEFENDER-ENABLED",
        "severity": "Critical",
        "description": "Windows Defender real-time protection harus enabled",
        "ps_command": "(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled",
        "expected_pattern": r"^True$",
        "recommended_value": "True",
    },
]


# =========================================================
# SCORING (VERBATIM) -- tidak peduli dari mana raw_outputs berasal
# =========================================================

def _category_from_check_id(check_id: str) -> str:
    """WIN-PASS-MINLEN -> PASS, WIN-RDP-NLA -> RDP, dst. Dipakai buat
    breakdown per kategori di /api/hardening/findings/summary, biar
    hasil scan Windows nggak numpuk jadi satu kategori 'WIN' doang."""
    parts = check_id.split("-")
    return parts[1] if len(parts) > 1 else check_id


def score_checks_from_outputs(raw_outputs: dict) -> tuple[dict, list]:
    """
    Inti logic scoring -- TIDAK PEDULI dari mana raw_outputs berasal
    (langsung WinRM lewat pywinrm, ATAU dari Ansible via run_and_ingest.py).
    Ini yang bikin migrasi ke Ansible aman: cuma sumber eksekusinya yang
    ganti, keputusan PASS/FAIL tetap 1 kode yang sama, sudah teruji.

    raw_outputs: dict {check_id: output_string}
    Returns: (meta, findings) -- format sama persis kayak fungsi lama.
    """
    findings = []
    passed_count = 0
    checked_ids = set()

    for check in CHECKS:
        checked_ids.add(check["check_id"])
        output = (raw_outputs.get(check["check_id"]) or "").strip()
        is_pass = bool(re.search(check["expected_pattern"], output))

        if is_pass:
            passed_count += 1
        else:
            findings.append({
                "check_id": check["check_id"],
                "category": _category_from_check_id(check["check_id"]),
                "finding_type": "cis_check",
                "severity": check["severity"],
                "description": check["description"],
                "detail_field": check["check_id"],
                "current_value": output[:150] if output else "(kosong/tidak terdeteksi)",
                "recommended_value": check["recommended_value"],
            })

    # Guard rail: kalau raw_outputs punya check_id yang nggak dikenal
    # CHECKS (misal windows_checks.yml di-edit tapi Python lupa diupdate,
    # atau kebalikannya), lempar error jelas -- daripada diam-diam salah
    # skor. Ini nutup risiko drift YAML vs Python yang disebut di
    # windows_checks.yml.
    unknown_ids = set(raw_outputs.keys()) - checked_ids
    if unknown_ids:
        raise ValueError(
            f"raw_outputs punya check_id yang tidak dikenal di CHECKS: {unknown_ids}. "
            f"windows_checks.yml dan CHECKS di file ini sudah tidak sinkron -- perbaiki dulu sebelum lanjut."
        )

    total = len(CHECKS)
    hardening_index = round(100 * passed_count / total) if total else 0

    meta = {
        "os_name": "Windows",
        "os_version": None,
        "hostname": None,
        "hardening_index": hardening_index,
        "tests_executed": total,
        "tests_skipped": 0,
    }
    return meta, findings


# =========================================================
# EKSEKUSI LOKAL (pengganti run_checks_over_winrm)
# =========================================================

def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _run_powershell(ps_command: str, timeout: int = 60) -> str:
    """Jalankan satu perintah PowerShell lokal, kembalikan stdout.

    Pakai -EncodedCommand (UTF-16LE base64) supaya quoting/`$`/tanda kutip di
    ps_command tidak rusak oleh parsing command-line Windows.
    """
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise FileNotFoundError("powershell/pwsh tidak ditemukan di PATH")
    script = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + ps_command
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    proc = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, timeout=timeout,
    )
    return proc.stdout.decode("utf-8", errors="replace").strip()


def run_checks_local(runner: Callable[[str], str] = _run_powershell) -> tuple[dict, list]:
    """Jalankan semua CHECKS lewat `runner`, lalu skor dengan logika asli.

    `runner` bisa diganti (dipakai test) -- signature: runner(ps_command) -> str.
    """
    raw_outputs: dict[str, str] = {}
    for check in CHECKS:
        try:
            raw_outputs[check["check_id"]] = runner(check["ps_command"])
        except Exception as exc:  # noqa: BLE001
            raw_outputs[check["check_id"]] = f"__ERROR__: {exc}"

    meta, findings = score_checks_from_outputs(raw_outputs)
    meta["hostname"] = socket.gethostname()
    meta["os_version"] = platform.version()
    return meta, findings


def build_result(meta: dict, findings: list, started: datetime, finished: datetime) -> bc.ScanResult:
    return bc.findings_from_windows_scan(
        meta=meta,
        findings=findings,
        source_ip=bc.detect_source_ip(),
        hostname=meta.get("hostname") or "",
        device_id=bc.detect_device_id(),
        scanner_version=SCANNER_VERSION,
        extra_meta={
            "scan_started_at": started.isoformat(),
            "scan_finished_at": finished.isoformat(),
        },
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Target-local Windows hardening scanner (beacon).")
    ap.add_argument("--dry-run", action="store_true", help="Cetak payload, jangan kirim beacon.")
    ap.add_argument("--flush-spool", action="store_true", help="Kirim ulang payload yang tertahan di spool lalu keluar.")
    ap.add_argument("--spool-dir", help="Direktori spool (default: SCANNER_SPOOL_DIR atau C:/ProgramData/GeoThreatScanner/spool).")
    ap.add_argument("--allow-non-admin", action="store_true", help="Lewati cek Administrator (hasil check bisa tidak akurat).")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    spool_dir = Path(args.spool_dir) if args.spool_dir else default_spool_dir("windows")

    if args.flush_spool:
        ok, failed = flush_spool(spool_dir, bc.send_payload)
        print(f"spool flush: terkirim={ok} gagal={failed}")
        return 0 if failed == 0 else 2

    if not args.allow_non_admin and not _is_admin():
        logger.error("Scanner Windows harus dijalankan sebagai Administrator.")
        return 1

    try:
        started = datetime.now(timezone.utc)
        meta, findings = run_checks_local()
        finished = datetime.now(timezone.utc)
        result = build_result(meta, findings, started, finished)
    except Exception as exc:  # noqa: BLE001
        logger.error("Scan gagal: %s", exc)
        return 1

    payload = result.to_dict()
    m = payload["meta"]
    print(f"Scan selesai: host={payload['hostname']} hardening_index={m.get('hardening_index')} "
          f"gagal={len(payload['findings'])}/{m.get('tests_executed')} scan_id={payload['scan_id']}")

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    try:
        beacon_send(result)
        print(f"Beacon terkirim: scan_id={result.scan_id}")
        return 0
    except Exception as exc:  # noqa: BLE001
        path = spool_payload(payload, spool_dir)
        logger.error("Beacon gagal (%s). Hasil scan disimpan di %s -- kirim ulang dengan --flush-spool", exc, path)
        return 2


if __name__ == "__main__":
    sys.exit(main())
