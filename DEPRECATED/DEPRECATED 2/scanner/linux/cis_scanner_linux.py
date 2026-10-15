#!/usr/bin/env python3
"""
scanner/linux/cis_scanner_linux.py
----------------------------------
Linux hardening scanner -- TARGET-LOCAL, beacon-based.

Dijalankan LANGSUNG di perangkat target (butuh root):

    sudo python3 scanner/linux/cis_scanner_linux.py

Alur:
    lynis audit system (lokal)  ->  /var/log/lynis-report.dat
        ->  parse_lynis_report()        (VERBATIM dari hardening_scanner_v2.py)
        ->  ScanResult  ->  HTTPS POST ke n8n (beacon)

TIDAK ada SSH/paramiko, TIDAK ada koneksi PostgreSQL, TIDAK ada Ansible.
Hasil scan tidak pernah bergantung pada keberhasilan beacon: kalau n8n
tidak terjangkau, payload disimpan ke spool dan dikirim ulang dengan
`--flush-spool`.

Exit code: 0 = scan + beacon OK | 1 = scan gagal | 2 = scan OK, beacon gagal (di-spool)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.common import beacon_contract as bc  # noqa: E402
from scanner.common.spool import default_spool_dir, flush_spool, spool_payload  # noqa: E402
from scanner.linux.beacon import send as beacon_send  # noqa: E402

logger = logging.getLogger("cis_scanner_linux")

SCANNER_VERSION = "2.0.0"
LYNIS_REPORT_PATH = "/var/log/lynis-report.dat"


# =========================================================
# PARSING lynis-report.dat -> temuan granular
# =========================================================

SET_PATTERN = re.compile(r"^(\S+)\s*\(set\s+(.+?)\s+to\s+(.+?)\)$")
DETAIL_KV_PATTERN = re.compile(r"(\w+):([^;]*);")


def parse_lynis_report(report_text):
    """
    Parse lynis-report.dat jadi:
    - meta: dict (os_name, os_version, hardening_index, tests_executed, tests_skipped, hostname)
    - findings: list of dict (check_id, category, finding_type, description,
                               detail_field, current_value, recommended_value)
    """
    meta = {
        "os_name": None,
        "os_version": None,
        "hostname": None,
        "hardening_index": 0,
        "tests_executed": 0,
        "tests_skipped": 0,
    }
    findings = []

    for line in report_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # --- meta fields ---
        if line.startswith("os_name="):
            meta["os_name"] = line.split("=", 1)[1]
        elif line.startswith("os_version="):
            meta["os_version"] = line.split("=", 1)[1]
        elif line.startswith("hostname="):
            meta["hostname"] = line.split("=", 1)[1]
        elif line.startswith("hardening_index="):
            meta["hardening_index"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("tests_executed="):
            executed_list = line.split("=", 1)[1]
            meta["tests_executed"] = len([x for x in executed_list.split("|") if x])
        elif line.startswith("tests_skipped="):
            skipped_list = line.split("=", 1)[1]
            meta["tests_skipped"] = len([x for x in skipped_list.split("|") if x])

        # --- warning[] dan suggestion[] ---
        elif line.startswith("warning[]=") or line.startswith("suggestion[]="):
            finding_type = "warning" if line.startswith("warning[]=") else "suggestion"
            payload = line.split("=", 1)[1]
            parts = payload.split("|")
            # format: CHECKID|description|extra_detail|extra2|
            check_id = parts[0] if len(parts) > 0 else "UNKNOWN"
            description = parts[1] if len(parts) > 1 else ""
            extra = parts[2] if len(parts) > 2 else ""

            category = check_id.split("-")[0] if "-" in check_id else check_id

            detail_field = current_value = recommended_value = None
            m = SET_PATTERN.match(extra.strip())
            if m:
                detail_field, current_value, recommended_value = m.groups()

            findings.append({
                "check_id": check_id,
                "category": category,
                "finding_type": finding_type,
                "description": description,
                "detail_field": detail_field,
                "current_value": current_value,
                "recommended_value": recommended_value,
            })

        # --- details[] (biasanya sysctl / config mismatch granular) ---
        elif line.startswith("details[]="):
            payload = line.split("=", 1)[1]
            parts = payload.split("|")
            check_id = parts[0] if len(parts) > 0 else "UNKNOWN"
            component = parts[1] if len(parts) > 1 else ""
            kv_blob = parts[2] if len(parts) > 2 else ""

            category = check_id.split("-")[0] if "-" in check_id else check_id
            kv = dict(DETAIL_KV_PATTERN.findall(kv_blob))

            field = kv.get("field")
            prefval = kv.get("prefval")
            value = kv.get("value")
            desc = kv.get("desc", "")

            # cuma masukin sebagai temuan kalau prefval != value (beneran mismatch)
            if field and prefval is not None and value is not None and prefval != value:
                findings.append({
                    "check_id": check_id,
                    "category": category,
                    "finding_type": "sysctl_mismatch",
                    "description": desc or f"{component} config mismatch on {field}",
                    "detail_field": field,
                    "current_value": value,
                    "recommended_value": prefval,
                })

        # --- manual[] : item yang butuh verifikasi manusia, dicatat juga ---
        elif line.startswith("manual[]="):
            description = line.split("=", 1)[1]
            findings.append({
                "check_id": "MANUAL",
                "category": "MANUAL",
                "finding_type": "manual",
                "description": description,
                "detail_field": None,
                "current_value": None,
                "recommended_value": None,
            })

    return meta, findings


# =========================================================
# EKSEKUSI LOKAL (pengganti run_lynis_over_ssh)
# =========================================================

def run_lynis_local(timeout: int = 900) -> tuple[str, datetime, datetime]:
    """Jalankan lynis di mesin ini, kembalikan (isi report, mulai, selesai)."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("Scanner Linux harus dijalankan sebagai root (sudo).")
    lynis = shutil.which("lynis")
    if not lynis:
        raise FileNotFoundError("lynis tidak ditemukan di PATH (apt install lynis / yum install lynis).")

    started = datetime.now(timezone.utc)
    proc = subprocess.run(
        [lynis, "audit", "system", "--quiet", "--no-colors"],
        capture_output=True, text=True, timeout=timeout,
    )
    finished = datetime.now(timezone.utc)
    if proc.returncode != 0:
        logger.warning("lynis exit status %s. stderr: %s", proc.returncode, (proc.stderr or "")[:500])

    report_text = Path(LYNIS_REPORT_PATH).read_text(encoding="utf-8", errors="replace")
    return report_text, started, finished


def build_result(report_text: str, started: datetime, finished: datetime) -> bc.ScanResult:
    meta, findings = parse_lynis_report(report_text)
    return bc.findings_from_linux_scan(
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
    ap = argparse.ArgumentParser(description="Target-local Linux hardening scanner (beacon).")
    ap.add_argument("--report-file", help="Parse lynis-report.dat yang sudah ada, JANGAN jalankan lynis (untuk test).")
    ap.add_argument("--dry-run", action="store_true", help="Cetak payload, jangan kirim beacon.")
    ap.add_argument("--flush-spool", action="store_true", help="Kirim ulang payload yang tertahan di spool lalu keluar.")
    ap.add_argument("--spool-dir", help="Direktori spool (default: SCANNER_SPOOL_DIR atau /var/lib/geo-threat-scanner/spool).")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    spool_dir = Path(args.spool_dir) if args.spool_dir else default_spool_dir("linux")

    if args.flush_spool:
        ok, failed = flush_spool(spool_dir, bc.send_payload)
        print(f"spool flush: terkirim={ok} gagal={failed}")
        return 0 if failed == 0 else 2

    try:
        if args.report_file:
            now = datetime.now(timezone.utc)
            report_text, started, finished = Path(args.report_file).read_text(encoding="utf-8", errors="replace"), now, now
        else:
            report_text, started, finished = run_lynis_local()
        result = build_result(report_text, started, finished)
    except Exception as exc:  # noqa: BLE001
        logger.error("Scan gagal: %s", exc)
        return 1

    payload = result.to_dict()
    m = payload["meta"]
    print(f"Scan selesai: host={payload['hostname']} os={m.get('os_name')} {m.get('os_version')} "
          f"hardening_index={m.get('hardening_index')} findings={len(payload['findings'])} scan_id={payload['scan_id']}")

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
