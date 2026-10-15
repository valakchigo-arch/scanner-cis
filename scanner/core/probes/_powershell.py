"""
Helper tunggal untuk menjalankan PowerShell lokal (dipakai semua probe).

Kenapa ada modul ini:
  * -EncodedCommand (UTF-16LE base64) -> quoting/`$`/kutip di command tidak
    rusak oleh parsing command-line Windows.
  * Output dipaksa UTF-8 dan didecode eksplisit (tidak bergantung code page).
  * strict=True memasang $ErrorActionPreference='Stop' sehingga kegagalan
    cmdlet / secedit yang tadinya "senyap" (output kosong, rc=0) menjadi
    error sungguhan (rc!=0) -> status ERROR, bukan FAIL palsu.
"""
from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
from typing import NamedTuple

from ..exceptions import ProbeExecutionError

logger = logging.getLogger("scanner.powershell")


def _env_number(name: str, default: float, minimum: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
        return value if value >= minimum else default
    except ValueError:
        return default


class PSResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def build_script(command: str, strict: bool = True) -> str:
    prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    if strict:
        prefix += "$ErrorActionPreference='Stop'; "
    return prefix + command


def run_powershell(command: str, timeout: int = 30, strict: bool = True) -> PSResult:
    """Jalankan PowerShell lokal.

    Env (untuk mesin lambat, mis. VM -- lihat docs/VALIDATION_RESULTS.md):
      SCANNER_PROBE_TIMEOUT_SCALE  pengali timeout (default 1.0; 0.1 .. )
      SCANNER_PS_RETRIES           retry tambahan saat TIMEOUT (default 1)
    """
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise ProbeExecutionError("powershell/pwsh not found in PATH")
    effective = timeout * _env_number("SCANNER_PROBE_TIMEOUT_SCALE", 1.0, 0.1)
    retries = int(_env_number("SCANNER_PS_RETRIES", 1, 0))
    encoded = base64.b64encode(build_script(command, strict).encode("utf-16-le")).decode("ascii")
    argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]

    for attempt in range(retries + 1):
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=effective)
            break
        except subprocess.TimeoutExpired:
            if attempt < retries:
                logger.warning("PowerShell timeout %.0fs (percobaan %d/%d), mengulang", effective, attempt + 1, retries + 1)
                continue
            raise ProbeExecutionError(f"PowerShell timed out after {effective:g}s ({retries + 1} percobaan)")
    return PSResult(
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace").strip(),
        proc.stderr.decode("utf-8", errors="replace").strip(),
    )
