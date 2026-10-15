#!/usr/bin/env python3
"""
scanner/windows/thor_scanner.py
--------------------------------
THOR Lite threat scanner integration for Windows targets.
Runs THOR, parses JSON output, sends findings via beacon.

Architecture: same beacon infrastructure as CIS hardening scanner.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scanner.common import beacon_contract as bc
from scanner.common.spool import default_spool_dir, flush_spool, spool_payload
from scanner.windows.beacon import send as beacon_send

logger = logging.getLogger("thor_scanner")

SCANNER_VERSION = "1.0.0"
THOR_DEFAULT_PATHS = [
    r"C:\Program Files\THOR\thor64.exe",
    r"C:\thor\thor64-lite.exe",
    r"C:\tools\thor\thor64-lite.exe",
    "./thor64-lite.exe",
]

THOR_DEFAULT_SIGNATURES = [
    r"C:\Program Files\THOR\signatures",
    r"C:\thor\signatures",
    r"C:\tools\thor\signatures",
    "./signatures",
]


def find_thor_executable(custom_path: Optional[str] = None) -> Optional[str]:
    """Locate THOR executable."""
    if custom_path and Path(custom_path).exists():
        return custom_path
    for p in THOR_DEFAULT_PATHS:
        if Path(p).exists():
            return p
    return None


def find_thor_signatures(custom_path: Optional[str] = None) -> Optional[str]:
    """Locate THOR signatures directory."""
    if custom_path and Path(custom_path).exists():
        return custom_path
    for p in THOR_DEFAULT_SIGNATURES:
        if Path(p).exists():
            return p
    return None


def run_thor(
    thor_path: str,
    signatures_path: str,
    output_file: str,
    quick: bool = True,
    threads: int = 4,
    extra_args: Optional[list[str]] = None,
) -> tuple[int, str, str]:
    """Run THOR and return (exit_code, stdout, stderr)."""
    cmd = [
        thor_path,
        "--signatures", signatures_path,
        "--jsonfile", output_file,
        "--threads", str(threads),
    ]

    if quick:
        cmd.append("--quick")
    else:
        cmd.append("--intense")

    if extra_args:
        cmd.extend(extra_args)

    logger.info("Running THOR: %s", " ".join(cmd))
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    duration = time.time() - started
    logger.info("THOR finished in %.1fs, exit_code=%d", duration, proc.returncode)
    return proc.returncode, proc.stdout, proc.stderr


def parse_thor_json(json_path: Path) -> list[dict[str, Any]]:
    """Parse THOR JSON output to list of findings."""
    findings = []
    with open(json_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("Type") in ("Alert", "Warning", "Notice"):
                    findings.append(entry)
            except json.JSONDecodeError:
                continue
    return findings


def map_thor_to_finding(entry: dict[str, Any]) -> dict[str, Any]:
    """Map THOR alert entry to our common finding schema."""
    thor_type = entry.get("Type", "Notice")
    module = entry.get("Module", "UNKNOWN")
    message = entry.get("Message", "")
    reason = entry.get("Reason", "")
    file_path = entry.get("File", "")
    score = entry.get("Score", 0)

    # Map THOR severity to our severity
    if score >= 80 or thor_type == "Alert":
        severity = "CRITICAL"
    elif score >= 60 or thor_type == "Warning":
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Generate control_id from module + reason
    control_id = f"THOR-{module.upper()}-{abs(hash(reason)) % 10000:04d}"

    # Confidence based on module type
    confidence_map = {
        "YARA": "DIRECT",
        "IOC": "DIRECT",
        "Sigma": "INFERRED",
        "Process": "DIRECT",
        "FileSystem": "DIRECT",
        "Registry": "DIRECT",
        "Eventlog": "INFERRED",
        "ScheduledTask": "DIRECT",
        "Service": "DIRECT",
        "WMI": "INFERRED",
    }
    confidence = confidence_map.get(module, "INFERRED")

    return {
        "check_id": control_id,
        "title": f"THOR {module}: {message[:80]}",
        "category": "threat_detection",
        "finding_type": "threat",
        "severity": severity,
        "confidence": confidence,
        "description": f"THOR {module} detection: {message}. Reason: {reason}",
        "comparison": {
            "operator": "exists",
            "expected": "no detection",
            "actual": "detection found",
        },
        "evidence": {
            "source": "THOR",
            "module": module,
            "file": file_path,
            "score": score,
            "reason": reason,
            "raw_entry": entry,
        },
        "remediation": {
            "action": f"Investigate {module} alert: {message}",
            "reference": "https://www.nextron-systems.com/thor/",
        },
    }


def build_thor_scan_result(
    meta: dict[str, Any],
    findings: list[dict[str, Any]],
    source_ip: str,
    hostname: str,
    device_id: str,
) -> bc.ScanResult:
    """Convert THOR findings to beacon ScanResult."""
    result_findings = [bc.finding_from_dict(f) for f in findings]

    effective_severity = "Low"
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for f in findings:
        sev = f.get("severity", "Low")
        if severity_rank.get(sev, 0) > severity_rank.get(effective_severity, 0):
            effective_severity = sev

    return bc.build_scan_result(
        source_ip=source_ip,
        hostname=hostname,
        device_id=device_id,
        severity=effective_severity,
        findings=result_findings,
        scan_id=f"thor-{bc._generate_scan_id()}",
        timestamp=bc._now_timestamp(),
        scanner_os="windows",
        scanner_version=SCANNER_VERSION,
        meta=meta,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="THOR Lite threat scanner (beacon).")
    ap.add_argument("--thor-path", help="Path to thor64-lite.exe")
    ap.add_argument("--signatures-path", help="Path to THOR signatures directory")
    ap.add_argument("--quick", action="store_true", default=True, help="Quick scan (default)")
    ap.add_argument("--intense", action="store_true", help="Intense scan")
    ap.add_argument("--threads", type=int, default=4, help="Number of threads")
    ap.add_argument("--dry-run", action="store_true", help="Print payload, don't send beacon")
    ap.add_argument("--flush-spool", action="store_true", help="Flush spool and exit")
    ap.add_argument("--spool-dir", help="Spool directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    spool_dir = Path(args.spool_dir) if args.spool_dir else default_spool_dir("thor")

    if args.flush_spool:
        ok, failed = flush_spool(spool_dir, bc.send_payload)
        print(f"spool flush: sent={ok} failed={failed}")
        return 0 if failed == 0 else 2

    # Locate THOR
    thor_path = find_thor_executable(args.thor_path)
    if not thor_path:
        logger.error("THOR executable not found. Set --thor-path or install THOR.")
        return 1

    signatures_path = find_thor_signatures(args.signatures_path)
    if not signatures_path:
        logger.error("THOR signatures not found. Set --signatures-path.")
        return 1

    quick = not args.intense

    # Run THOR
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json_output = tf.name

    try:
        exit_code, stdout, stderr = run_thor(
            thor_path=thor_path,
            signatures_path=signatures_path,
            output_file=json_output,
            quick=quick,
            threads=args.threads,
        )

        if exit_code not in (0, 1, 2):  # 0=clean, 1=warnings, 2=alerts
            logger.error("THOR failed: %s", stderr[:500])
            return 1

        # Parse results
        thor_findings = parse_thor_json(Path(json_output))
        logger.info("THOR found %d alerts/warnings/notices", len(thor_findings))

        # Map to our schema
        mapped_findings = [map_thor_to_finding(f) for f in thor_findings]

        # Build metadata
        meta = {
            "scan_type": "threat",
            "scanner": "THOR Lite",
            "thor_version": "10.7",
            "scan_mode": "quick" if quick else "intense",
            "total_alerts": len([f for f in thor_findings if f.get("Type") == "Alert"]),
            "total_warnings": len([f for f in thor_findings if f.get("Type") == "Warning"]),
            "total_notices": len([f for f in thor_findings if f.get("Type") == "Notice"]),
        }

        # Build scan result
        result = build_thor_scan_result(
            meta=meta,
            findings=mapped_findings,
            source_ip=bc.detect_source_ip(),
            hostname=bc.detect_source_ip(),  # fallback
            device_id=bc.detect_device_id(),
        )

        payload = result.to_dict()

        print(f"Scan complete: {len(mapped_findings)} findings, "
              f"{meta['total_alerts']} alerts, {meta['total_warnings']} warnings")

        if args.dry_run:
            print(json.dumps(payload, indent=2))
            return 0

        # Send beacon
        beacon_send(result)
        print(f"Beacon sent: scan_id={result.scan_id}")
        return 0

    except subprocess.TimeoutExpired:
        logger.error("THOR scan timeout")
        return 1
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        return 1
    finally:
        try:
            Path(json_output).unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())