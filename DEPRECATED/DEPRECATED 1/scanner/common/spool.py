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
    spool_dir.mkdir(parents=True, exist_ok=True)
    path = spool_dir / f"{payload['scan_id']}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
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
