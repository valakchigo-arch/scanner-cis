#!/usr/bin/env python3
"""
scanner/common/beacon_contract.py
---------------------------------
SATU-SATUNYA modul transport beacon: target-local scanner  ->  n8n.

Menggantikan `scanner/geo_threat_scanner.py` (dihapus). Nama publik yang
dipakai test lama dipertahankan (ScanResult, Finding, build_scan_result,
findings_from_linux_scan, findings_from_windows_scan, send_to_n8n) supaya
test_beacon.py cukup ganti path import.

Perubahan penting dibanding versi lama:
  1. TIDAK ADA default URL/secret di source code (fail-closed). Versi lama
     menyimpan URL tunnel + webhook secret sebagai default os.environ.get.
  2. Payload membawa blok `meta` (os_name, os_version, hardening_index,
     tests_executed, tests_skipped, waktu scan). Backend butuh ini untuk
     mengisi hardening_scans; versi lama membuangnya.
  3. `contract_version` ditambahkan ke payload.
  4. TLS diverifikasi secara default (SCANNER_VERIFY_TLS=false hanya untuk lab).
  5. Helper detect_source_ip()/detect_device_id(): scanner sekarang jalan DI
     target, jadi IP/device diambil dari mesin itu sendiri.

Scanner TIDAK bicara ke PostgreSQL / FastAPI / LLM. Hanya ke n8n.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import socket
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import requests

logger = logging.getLogger("beacon_contract")

CONTRACT_VERSION = "2"

def _env_num(name: str, default, cast, minimum):
    """Baca env numerik; nilai rusak/di bawah minimum -> default + warning (bukan crash saat import)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
        if value < minimum:
            raise ValueError("below minimum")
        return value
    except ValueError:
        logger.warning("%s=%r tidak valid, memakai default %s", name, raw, default)
        return default


# --- Konfigurasi (fail-closed: kosong = beacon menolak jalan) ---------------
N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL", "").strip()
N8N_WEBHOOK_SECRET = os.environ.get("N8N_WEBHOOK_SECRET", "").strip()
MAX_RETRIES = _env_num("SCANNER_MAX_RETRIES", 3, int, 1)
RETRY_DELAY_SEC = _env_num("SCANNER_RETRY_DELAY", 5.0, float, 0.0)
TIMEOUT_SEC = _env_num("SCANNER_TIMEOUT", 30, int, 1)
VERIFY_TLS = os.environ.get("SCANNER_VERIFY_TLS", "true").strip().lower() not in ("0", "false", "no")
MAX_BACKOFF_SEC = 60.0
# HTTP status yang TIDAK akan sembuh dengan retry (kesalahan klien). 408/429 sengaja
# dikecualikan: itu transient dan layak di-retry.
NO_RETRY_STATUS = frozenset({400, 401, 403, 404, 405, 413, 422})

_META_KEYS = (
    "os_name", "os_version", "hostname", "hardening_index",
    "tests_executed", "tests_skipped", "tests_errored", "coverage_percent", "scan_started_at", "scan_finished_at",
)


class ScanSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Finding:
    check_id: str
    description: str
    severity: Optional[str] = None
    detail_field: Optional[str] = None
    current_value: Optional[str] = None
    recommended_value: Optional[str] = None
    category: Optional[str] = None
    finding_type: Optional[str] = None


@dataclass
class ScanResult:
    scan_id: str
    source_ip: str
    hostname: str
    device_id: str
    timestamp: str
    severity: str
    findings: list[Finding]
    scanner_name: str = "geo-threat-scanner"
    scanner_version: str = "1.0.0"
    scanner_os: str = "unknown"
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "scan_id": self.scan_id,
            "source_ip": self.source_ip,
            "hostname": self.hostname,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "meta": {k: self.meta.get(k) for k in _META_KEYS if k in self.meta},
            "findings": [
                {
                    "check_id": f.check_id,
                    "description": f.description,
                    "severity": f.severity,
                    "detail_field": f.detail_field,
                    "current_value": f.current_value,
                    "recommended_value": f.recommended_value,
                    "category": f.category,
                    "finding_type": f.finding_type,
                }
                for f in self.findings
            ],
            "scanner": {
                "name": self.scanner_name,
                "os": self.scanner_os,
                "version": self.scanner_version,
            },
        }


# --- Identitas mesin lokal ---------------------------------------------------

def detect_source_ip() -> str:
    """IP utama mesin ini (interface yang dipakai untuk keluar).

    Tidak mengirim paket apa pun: UDP connect() hanya memilih route.
    Backend memakai IP ini untuk resolusi /24 -> kantor, jadi di lab boleh
    di-override dengan env SCANNER_SOURCE_IP.
    """
    override = os.environ.get("SCANNER_SOURCE_IP", "").strip()
    if override:
        return override
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1: hanya memilih route, tidak kirim data
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def detect_device_id() -> str:
    """ID perangkat stabil (hash dari machine-id / hostname), bukan data mentah."""
    override = os.environ.get("SCANNER_DEVICE_ID", "").strip()
    if override:
        return override
    raw = ""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
                if raw:
                    break
        except OSError:
            continue
    if not raw and platform.system() == "Windows":
        try:
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                raw = str(winreg.QueryValueEx(k, "MachineGuid")[0]).strip()
        except Exception:  # noqa: BLE001
            raw = ""
    if not raw:
        raw = f"{socket.gethostname()}|{platform.node()}|{uuid.getnode()}"
    return "dev-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# --- Builder -----------------------------------------------------------------

def _generate_scan_id() -> str:
    return f"gt-{uuid.uuid4()}"


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def build_scan_result(
    source_ip: str,
    hostname: str,
    device_id: str,
    severity: str = "Low",
    findings: Optional[list[Finding]] = None,
    scan_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    scanner_os: str = "unknown",
    scanner_version: str = "1.0.0",
    meta: Optional[dict[str, Any]] = None,
) -> ScanResult:
    return ScanResult(
        scan_id=scan_id or _generate_scan_id(),
        source_ip=source_ip,
        hostname=hostname,
        device_id=device_id,
        timestamp=timestamp or _now_timestamp(),
        severity=severity,
        findings=findings or [],
        scanner_os=scanner_os,
        scanner_version=scanner_version,
        meta=dict(meta or {}),
    )


def finding_from_dict(f: dict[str, Any]) -> Finding:
    return Finding(
        check_id=f.get("check_id", ""),
        description=f.get("description", ""),
        severity=f.get("severity"),
        detail_field=f.get("detail_field"),
        current_value=f.get("current_value"),
        recommended_value=f.get("recommended_value"),
        category=f.get("category"),
        finding_type=f.get("finding_type"),
    )


def _meta_for_payload(meta: dict[str, Any], hostname: str, extra: Optional[dict[str, Any]]) -> dict[str, Any]:
    out = {k: meta.get(k) for k in _META_KEYS if k in meta}
    out["hostname"] = hostname or meta.get("hostname") or ""
    if extra:
        out.update({k: v for k, v in extra.items() if k in _META_KEYS})
    return out


_SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def max_severity(findings: list[dict[str, Any]]) -> str:
    """Severity scan = severity TERTINGGI di antara finding (default Low)."""
    best = "Low"
    for f in findings:
        sev = f.get("severity")
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK[best]:
            best = sev
    return best


def findings_from_linux_scan(
    meta: dict[str, Any],
    findings: list[dict[str, Any]],
    source_ip: str,
    hostname: str,
    device_id: str,
    scanner_version: str = "1.0.0",
    extra_meta: Optional[dict[str, Any]] = None,
) -> ScanResult:
    """(meta, findings) dari parse_lynis_report() -> ScanResult."""
    result_findings = [finding_from_dict(f) for f in findings]

    # BUG FIX: sebelumnya memakai severity valid PERTAMA (urutan file lynis),
    # bukan yang tertinggi -> scan dengan temuan High bisa dilaporkan "Low".
    effective_severity = max_severity(findings)

    host = hostname or meta.get("hostname", "")
    return build_scan_result(
        source_ip=source_ip,
        hostname=host,
        device_id=device_id,
        severity=effective_severity,
        findings=result_findings,
        scan_id=f"linux-{uuid.uuid4()}",
        timestamp=_now_timestamp(),
        scanner_os="linux",
        scanner_version=scanner_version,
        meta=_meta_for_payload(meta, host, extra_meta),
    )


def findings_from_windows_scan(
    meta: dict[str, Any],
    findings: list[dict[str, Any]],
    source_ip: str,
    hostname: str,
    device_id: str,
    scanner_version: str = "1.0.0",
    extra_meta: Optional[dict[str, Any]] = None,
) -> ScanResult:
    """(meta, findings) dari score_checks_from_outputs() -> ScanResult."""
    result_findings = [finding_from_dict(f) for f in findings]

    effective_severity = max_severity(findings)

    host = hostname or meta.get("hostname", "")
    return build_scan_result(
        source_ip=source_ip,
        hostname=host,
        device_id=device_id,
        severity=effective_severity,
        findings=result_findings,
        scan_id=f"windows-{uuid.uuid4()}",
        timestamp=_now_timestamp(),
        scanner_os="windows",
        scanner_version=scanner_version,
        meta=_meta_for_payload(meta, host, extra_meta),
    )


# --- Transport ---------------------------------------------------------------

def _backoff(attempt: int) -> None:
    """Exponential backoff (delay * 2^(n-1), dibatasi MAX_BACKOFF_SEC); tidak tidur setelah percobaan terakhir."""
    if attempt < MAX_RETRIES:
        time.sleep(min(RETRY_DELAY_SEC * (2 ** (attempt - 1)), MAX_BACKOFF_SEC))


def send_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Kirim payload dict (dipakai juga untuk flush spool)."""
    if not N8N_WEBHOOK_URL:
        raise RuntimeError("N8N_WEBHOOK_URL belum di-set -- beacon tidak akan mengirim apa pun")
    if not N8N_WEBHOOK_SECRET:
        raise RuntimeError("N8N_WEBHOOK_SECRET belum di-set -- beacon tidak akan mengirim apa pun")

    if not VERIFY_TLS:
        logger.warning("[BEACON] SCANNER_VERIFY_TLS=false -- sertifikat TIDAK diverifikasi (hanya untuk lab)")

    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Secret": N8N_WEBHOOK_SECRET,
        "X-Correlation-Id": str(payload.get("scan_id", "")),
    }
    scan_id = payload.get("scan_id")
    scanner_info = payload.get("scanner")
    os_name = scanner_info.get("os") if isinstance(scanner_info, dict) else None
    last_error: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 1):
        start = time.monotonic()
        try:
            logger.info("[BEACON] scan_id=%s os=%s attempt=%d/%d", scan_id, os_name, attempt, MAX_RETRIES)
            resp = requests.post(
                N8N_WEBHOOK_URL, json=payload, headers=headers,
                timeout=TIMEOUT_SEC, verify=VERIFY_TLS,
            )
            logger.info(
                "[BEACON] scan_id=%s os=%s status=%d duration=%.3fs",
                scan_id, os_name, resp.status_code, time.monotonic() - start,
            )
            resp.raise_for_status()
            try:
                return resp.json()
            except Exception:
                return {"status_code": resp.status_code, "ok": True}

        except requests.HTTPError as e:
            last_error = e
            logger.warning("[BEACON] scan_id=%s attempt=%d/%d failed: %s", scan_id, attempt, MAX_RETRIES, e)
            status_code = e.response.status_code if e.response is not None else None
            if status_code in NO_RETRY_STATUS:  # tidak akan sembuh dengan retry
                break
            _backoff(attempt)

        except requests.RequestException as e:
            last_error = e
            logger.warning("[BEACON] scan_id=%s attempt=%d/%d failed: %s", scan_id, attempt, MAX_RETRIES, e)
            _backoff(attempt)

    raise RuntimeError(f"Failed to send scan_id={scan_id} to n8n after {MAX_RETRIES} attempts: {last_error}")


def send_to_n8n(result: ScanResult) -> dict[str, Any]:
    """Kirim ScanResult ke n8n (retry + error handling). Secret tidak pernah di-log."""
    return send_payload(result.to_dict())
