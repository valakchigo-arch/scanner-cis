"""
scanner/windows/beacon.py
-----------------------
Adapter tipis Windows scanner -> beacon_contract.send_to_n8n().
Kegagalan beacon TIDAK mengubah hasil scan; pemanggil yang memutuskan
(log / spool / retry).
"""

from __future__ import annotations

import logging

from scanner.common.beacon_contract import ScanResult, send_to_n8n

logger = logging.getLogger("beacon_windows")


def send(result: ScanResult) -> dict:
    if result.scanner_os != "windows":
        logger.warning(
            "Expected scanner_os='windows' but got '%s' -- proceeding anyway",
            result.scanner_os,
        )
    logger.info("Windows beacon: sending scan_id=%s for %s (%s)", result.scan_id, result.hostname, result.source_ip)
    try:
        response = send_to_n8n(result)
        logger.info("Windows beacon: scan_id=%s delivered", result.scan_id)
        return response
    except Exception as exc:
        logger.error("Windows beacon: scan_id=%s FAILED -- %s", result.scan_id, exc)
        raise
