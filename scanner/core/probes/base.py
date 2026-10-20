from dataclasses import dataclass
from typing import Any


@dataclass
class ProbeResult:
    """Hasil probe."""
    value: Any                    # actual value untuk comparison
    evidence: dict                # {source, path, key, observed, ...}
    raw_output: str = ""          # opsional, untuk debugging