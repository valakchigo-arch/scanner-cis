#!/usr/bin/env python3
"""
scanner/windows/rule_scanner_windows.py
---------------------------------------
Windows hardening scanner berbasis RULE ENGINE (YAML) -- TARGET-LOCAL, beacon.

    rules/windows/*.yaml -> executor (probe -> evaluate) -> finding PASS/FAIL/ERROR
        -> contract_adapter -> ScanResult (kontrak v2) -> HTTPS POST ke n8n

Beda dengan cis_scanner_windows.py (regex): tiga status (ERROR tidak jadi FAIL
palsu), alasan error dipertahankan, kontrol ditambah cukup dengan file YAML,
dan laporan lengkap (PASS+FAIL+ERROR+evidence) bisa disimpan lokal (--report).

Exit code: 0 = scan + beacon OK | 1 = scan gagal | 2 = scan OK, beacon gagal (di-spool)
"""
from __future__ import annotations

import argparse
import json
import logging
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.common import beacon_contract as bc  # noqa: E402
from scanner.common.spool import default_spool_dir, flush_spool, spool_payload  # noqa: E402
from scanner.core import execute_rules, load_rules_from_dir  # noqa: E402
from scanner.core.contract_adapter import findings_to_contract  # noqa: E402
from scanner.core.scoring import compute_score  # noqa: E402
from scanner.windows.beacon import send as beacon_send  # noqa: E402

logger = logging.getLogger("rule_scanner_windows")
SCANNER_VERSION = "3.0.0"
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "windows"


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def run_scan(rules_dir: Path, host_os: str = "windows"):
    """Jalankan semua rule. Return (findings, meta_counts, contract_findings, score)."""
    rules = load_rules_from_dir(str(rules_dir))
    if not rules:
        raise RuntimeError(f"tidak ada rule di {rules_dir}")
    findings = execute_rules(rules, scan_id=f"win-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}", host_os=host_os)
    meta, contract_findings = findings_to_contract(findings)
    return findings, meta, contract_findings, compute_score(findings)


def build_result(meta: dict, contract_findings: list, started: datetime, finished: datetime) -> bc.ScanResult:
    full_meta = {"os_name": "Windows", "os_version": platform.version(),
                 "hostname": socket.gethostname(), **meta}
    return bc.findings_from_windows_scan(
        meta=full_meta, findings=contract_findings,
        source_ip=bc.detect_source_ip(), hostname=full_meta["hostname"],
        device_id=bc.detect_device_id(), scanner_version=SCANNER_VERSION,
        extra_meta={"scan_started_at": started.isoformat(), "scan_finished_at": finished.isoformat()},
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Windows hardening scanner (YAML rule engine, beacon).")
    ap.add_argument("--rules", default=str(DEFAULT_RULES), help="Direktori rule YAML.")
    ap.add_argument("--report", help="Simpan laporan lengkap (PASS/FAIL/ERROR + evidence) ke file JSON ini.")
    ap.add_argument("--dry-run", action="store_true", help="Cetak payload, jangan kirim beacon.")
    ap.add_argument("--flush-spool", action="store_true")
    ap.add_argument("--spool-dir")
    ap.add_argument("--min-coverage", type=int, default=70, metavar="PCT",
                    help="Batalkan (exit 1, tidak kirim) bila < PCT%% kontrol berhasil dinilai (default 70; 0 = nonaktif). "
                         "Indeks dari sebagian kecil kontrol menyesatkan.")
    ap.add_argument("--allow-non-admin", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    spool_dir = Path(args.spool_dir) if args.spool_dir else default_spool_dir("windows")

    if args.flush_spool:
        ok, failed = flush_spool(spool_dir, bc.send_payload)
        print(f"spool flush: terkirim={ok} gagal={failed}")
        return 0 if failed == 0 else 2

    if platform.system() != "Windows" and not args.dry_run:
        logger.error("Scanner ini hanya untuk Windows (gunakan --dry-run untuk uji logika).")
        return 1
    if not args.allow_non_admin and platform.system() == "Windows" and not _is_admin():
        logger.error("Harus dijalankan sebagai Administrator (secedit/Defender/SMB butuh hak admin).")
        return 1

    try:
        started = datetime.now(timezone.utc)
        findings, meta, contract_findings, score = run_scan(Path(args.rules))
        finished = datetime.now(timezone.utc)
        if meta["tests_executed"] == 0:
            raise RuntimeError("tidak ada satu pun kontrol yang berhasil dinilai (semua ERROR/N-A)")
        if meta["coverage_percent"] < args.min_coverage:
            raise RuntimeError(
                f"coverage {meta['coverage_percent']}% < --min-coverage {args.min_coverage}% "
                f"({meta['tests_errored']} kontrol ERROR: {', '.join(meta['errored_check_ids'])}). "
                f"Mesin lambat? coba SCANNER_PROBE_TIMEOUT_SCALE=3")
        result = build_result(meta, contract_findings, started, finished)
    except Exception as exc:  # noqa: BLE001
        logger.error("Scan gagal: %s", exc)
        return 1

    if args.report:
        Path(args.report).write_text(json.dumps(
            {"host": socket.gethostname(), "score": score.to_dict(), "findings": findings},
            indent=2, default=str), encoding="utf-8")

    payload = result.to_dict()
    m = payload["meta"]
    print(f"Scan selesai: host={payload['hostname']} hardening_index={m.get('hardening_index')} "
          f"gagal={len(payload['findings'])}/{m.get('tests_executed')} error={m.get('tests_errored', 0)} "
          f"coverage={m.get('coverage_percent')}% durasi={(finished - started).total_seconds():.0f}s "
          f"risk={score.risk_level} scan_id={payload['scan_id']}")
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    try:
        beacon_send(result)
        print(f"Beacon terkirim: scan_id={result.scan_id}")
        return 0
    except Exception as exc:  # noqa: BLE001
        path = spool_payload(payload, spool_dir)
        logger.error("Beacon gagal (%s). Hasil disimpan di %s -- kirim ulang dengan --flush-spool", exc, path)
        return 2


if __name__ == "__main__":
    sys.exit(main())
