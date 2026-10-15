import subprocess
from .base import ProbeResult
from ..exceptions import ProbeExecutionError


def run(params: dict) -> ProbeResult:
    """
    params:
      path: str   — registry path (e.g. "HKLM\\SYSTEM\\...")
      key: str    — value name
      timeout: int — optional, default 15
    """
    path = params.get("path")
    key = params.get("key")
    timeout = params.get("timeout", 15)

    if not path or not key:
        raise ProbeExecutionError("windows.registry: 'path' and 'key' required")

    # PowerShell command — pakai Get-ItemProperty
    command = (
        f"$v = (Get-ItemProperty -Path 'Registry::{path}' "
        f"-Name '{key}' -ErrorAction SilentlyContinue).'{key}'; "
        f"if ($v -ne $null) {{ Write-Output $v }} else {{ Write-Output '__NOT_FOUND__' }}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ProbeExecutionError(f"Registry read timeout: {path}\\{key}")
    except FileNotFoundError:
        raise ProbeExecutionError("powershell not found in PATH")

    raw = result.stdout.strip()

    # Case: key tidak ada → marker khusus
    if raw == "__NOT_FOUND__":
        return ProbeResult(
            value=None,
            evidence={
                "source": "registry",
                "path": path,
                "key": key,
                "observed": None,
                "note": "value_not_present",
            },
            raw_output=raw,
        )

    return ProbeResult(
        value=raw,   # ← RAW STRING, sama kayak powershell provider
        evidence={
            "source": "registry",
            "path": path,
            "key": key,
            "observed": raw,
        },
        raw_output=raw,
    )