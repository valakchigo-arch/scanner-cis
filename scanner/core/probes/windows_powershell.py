from .base import ProbeResult
from ._powershell import run_powershell
from ..exceptions import ProbeExecutionError


def run(params: dict) -> ProbeResult:
    """
    params:
      command: str  -- PowerShell command
      timeout: int  -- optional, default 30s
      strict:  bool -- optional, default True ($ErrorActionPreference='Stop').
                       Kegagalan command => ProbeExecutionError (status ERROR),
                       BUKAN output kosong yang dinilai FAIL.
    """
    command = params.get("command")
    timeout = params.get("timeout", 30)
    strict = params.get("strict", True)

    if not command:
        raise ProbeExecutionError("windows.powershell: 'command' is required")

    res = run_powershell(command, timeout=timeout, strict=strict)
    if res.returncode != 0:
        raise ProbeExecutionError(
            f"PowerShell failed (rc={res.returncode}): {res.stderr or res.stdout}"
        )

    # Raw string -- evaluator melakukan coercion sesuai tipe expected_value.
    return ProbeResult(
        value=res.stdout,
        evidence={"source": "powershell", "command": command, "observed": res.stdout},
        raw_output=res.stdout,
    )
