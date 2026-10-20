import sys

from .base import ProbeResult
from ._powershell import run_powershell
from ..exceptions import ProbeExecutionError

_NOT_FOUND = "__NOT_FOUND__"

_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKU": "HKEY_USERS", "HKEY_USERS": "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT", "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
}


def _q(value: str) -> str:
    """Escape untuk literal PowerShell single-quote (' -> '')."""
    return str(value).replace("'", "''")


def _native_available() -> bool:
    try:
        import winreg  # noqa: F401
        return True
    except ImportError:
        return False


def _format(value) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    return str(value)


def _read_native(path: str, key: str):
    """Baca value lewat winreg (stdlib Windows): ~ms, tanpa spawn PowerShell.

    Mengembalikan None bila key/value TIDAK ADA; error lain -> ProbeExecutionError.
    KEY_WOW64_64KEY: view 64-bit walau Python-nya 32-bit.
    """
    import winreg
    hive_name, _, subkey = path.replace("/", "\\").partition("\\")
    attr = _HIVES.get(hive_name.upper())
    if not attr:
        raise ProbeExecutionError(f"unsupported registry hive: {hive_name!r}")
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        with winreg.OpenKey(getattr(winreg, attr), subkey, 0, access) as handle:
            value, _type = winreg.QueryValueEx(handle, key)
    except FileNotFoundError:          # harus sebelum OSError
        return None
    except OSError as exc:
        raise ProbeExecutionError(f"Registry read failed: {path}\\{key}: {exc}")
    return value


def _read_powershell(path: str, key: str, timeout: int):
    command = (
        f"$v = (Get-ItemProperty -Path 'Registry::{_q(path)}' "
        f"-Name '{_q(key)}' -ErrorAction SilentlyContinue).'{_q(key)}'; "
        f"if ($null -ne $v) {{ Write-Output $v }} else {{ Write-Output '{_NOT_FOUND}' }}"
    )
    # strict=False: ketiadaan value adalah kondisi NORMAL (marker), bukan error.
    res = run_powershell(command, timeout=timeout, strict=False)
    if res.returncode != 0:
        raise ProbeExecutionError(
            f"Registry read failed (rc={res.returncode}): {res.stderr or res.stdout}"
        )
    return None if res.stdout == _NOT_FOUND else res.stdout


def run(params: dict) -> ProbeResult:
    """
    params:
      path: str    -- registry path (mis. "HKLM\\SYSTEM\\...")
      key: str     -- nama value
      timeout: int -- optional (jalur PowerShell), default 15

    Value tidak ada  -> ProbeResult(value=None)   (bisa PASS/FAIL sesuai rule)
    Pembacaan gagal  -> ProbeExecutionError       (status ERROR, bukan FAIL palsu)
    Urutan: winreg native (Windows) -> fallback PowerShell (mis. dev/CI non-Windows).
    """
    path = params.get("path")
    key = params.get("key")
    timeout = params.get("timeout", 15)

    if not path or not key:
        raise ProbeExecutionError("windows.registry: 'path' and 'key' required")

    if _native_available():
        raw, method = _read_native(path, key), "winreg"
    else:
        raw, method = _read_powershell(path, key, timeout), "powershell"

    if raw is None:
        return ProbeResult(
            value=None,
            evidence={"source": "registry", "path": path, "key": key,
                      "observed": None, "note": "value_not_present", "method": method},
            raw_output=_NOT_FOUND,
        )
    value = _format(raw)
    return ProbeResult(
        value=value,
        evidence={"source": "registry", "path": path, "key": key, "observed": value, "method": method},
        raw_output=value,
    )
