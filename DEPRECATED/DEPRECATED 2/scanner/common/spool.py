"""
scanner/common/spool.py
-----------------------
Store-and-forward untuk beacon. Kalau n8n tidak terjangkau saat scan selesai,
hasil scan disimpan lokal (JSON, permission 0600 di POSIX) lalu dikirim ulang
lewat `--flush-spool`. Hasil scan TIDAK hilang hanya karena jaringan putus.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("beacon_spool")


def default_spool_dir(os_kind: str) -> Path:
    env = os.environ.get("SCANNER_SPOOL_DIR", "").strip()
    if env:
        return Path(env)
    if os_kind == "windows":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "GeoThreatScanner" / "spool"
    return Path("/var/lib/geo-threat-scanner/spool")


def spool_payload(payload: dict[str, Any], spool_dir: Path) -> Path:
    """Persist payload atomically so an interrupted write cannot leave partial JSON."""
    scan_id = str(payload.get("scan_id", "")).strip()
    if not scan_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in scan_id):
        raise ValueError("payload scan_id is missing or contains unsafe filename characters")

    spool_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(spool_dir, 0o700)
    except OSError:
        # Windows ACLs are managed by the OS; chmod is best-effort there.
        pass

    path = spool_dir / f"{scan_id}.json"
    temp_path = spool_dir / f".{scan_id}.{uuid.uuid4().hex}.tmp"
    try:
        temp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    return path


def flush_spool(spool_dir: Path, sender: Callable[[dict[str, Any]], Any]) -> tuple[int, int]:
    """Kirim ulang semua payload di spool. Return (terkirim, gagal)."""
    ok = failed = 0
    if not spool_dir.exists():
        return 0, 0
    for path in sorted(spool_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            sender(payload)
            path.unlink()
            ok += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Spool %s gagal dikirim: %s", path.name, exc)
            failed += 1
    return ok, failed
