import subprocess
from .base import ProbeResult
from ..exceptions import ProbeExecutionError


def run(params: dict) -> ProbeResult:
    """
    params:
      command: str — PowerShell command
      timeout: int — optional, default 30s
    """
    command = params.get("command")
    timeout = params.get("timeout", 30)

    if not command:
        raise ProbeExecutionError("windows.powershell: 'command' is required")

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ProbeExecutionError(
            f"PowerShell command timed out after {timeout}s: {command}"
        )
    except FileNotFoundError:
        raise ProbeExecutionError("powershell not found in PATH")

    if result.returncode != 0:
        raise ProbeExecutionError(
            f"PowerShell failed (rc={result.returncode}): {result.stderr.strip()}"
        )

    raw = result.stdout.strip()

    # Return raw string — evaluator handles coercion based on expected_value type
    return ProbeResult(
        value=raw,
        evidence={
            "source": "powershell",
            "command": command,
            "observed": raw,
        },
        raw_output=raw,
    )