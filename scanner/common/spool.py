"""
scanner/common/spool.py
-----------------------
Store-and-forward untuk beacon. Kalau n8n tidak terjangkau saat scan selesai,
hasil scan disimpan lokal (JSON, direktori 0700 & file 0600 di POSIX) lalu
dikirim ulang lewat `--flush-spool`. Hasil scan TIDAK hilang hanya karena
jaringan putus.

Jaminan:
  * Tulis ATOMIK (file temp + os.replace) -> crash di tengah tulis tidak
    meninggalkan JSON setengah jadi.
  * Nama file disanitasi (scan_id tidak bisa keluar dari spool_dir).
  * File korup dikarantina (*.corrupt) -- tidak gagal berulang selamanya
    dan tidak dihapus diam-diam.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("beacon_spool")

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def default_spool_dir(os_kind: str) -> Path:
    env = os.environ.get("SCANNER_SPOOL_DIR", "").strip()
    if env:
        return Path(env)
    if os_kind == "windows":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "GeoThreatScanner" / "spool"
    return Path("/var/lib/geo-threat-scanner/spool")


def _safe_name(scan_id: Any) -> str:
    name = _SAFE.sub("_", str(scan_id or "")).strip("._")
    return name[:120] or "scan"


def spool_payload(payload: dict[str, Any], spool_dir: Path) -> Path:
    spool_dir = Path(spool_dir)
    spool_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(spool_dir, 0o700)
    except OSError:
        pass
    path = spool_dir / f"{_safe_name(payload.get('scan_id'))}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return path


def flush_spool(spool_dir: Path, sender: Callable[[dict[str, Any]], Any]) -> tuple[int, int]:
    """Kirim ulang semua payload di spool. Return (terkirim, gagal)."""
    ok = failed = 0
    spool_dir = Path(spool_dir)
    if not spool_dir.exists():
        return 0, 0
    for path in sorted(spool_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload bukan objek JSON")
        except (ValueError, OSError) as exc:
            quarantined = path.with_suffix(".json.corrupt")
            try:
                os.replace(path, quarantined)
            except OSError:
                pass
            logger.error("Spool %s korup (%s) -> dikarantina sebagai %s", path.name, exc, quarantined.name)
            failed += 1
            continue
        try:
            sender(payload)
            path.unlink()
            ok += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Spool %s gagal dikirim: %s", path.name, exc)
            failed += 1
    return ok, failed
