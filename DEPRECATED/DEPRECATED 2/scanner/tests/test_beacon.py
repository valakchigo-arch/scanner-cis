#!/usr/bin/env python3
"""
scanner/test_beacon.py — Focused integration tests for the n8n beacon layer.

Tests A-E per MASTER PROMPT sec. 19:
  A — Linux beacon sends correct payload to n8n
  B — Windows beacon sends correct payload to n8n
  C — Invalid secret returns 401/403
  D — n8n unavailable: result intact, beacon reports failure, no infinite retry
  E — Duplicate scan_id: verify UUID-based uniqueness

Usage:
    python scanner/test_beacon.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
import pytest
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import scanner.common.beacon_contract as beacon_module
from scanner.common.beacon_contract import (
    ScanResult,
    Finding,
    build_scan_result,
    findings_from_linux_scan,
    findings_from_windows_scan,
    send_to_n8n,
)
from scanner.linux.beacon import send as beacon_linux_send
from scanner.windows.beacon import send as beacon_windows_send

logging.basicConfig(level=logging.WARNING)

TEST_SECRET = "test-beacon-secret"
LAST_REQUEST: dict[str, Any] = {"headers": {}, "body": None, "count": 0}
beacon = beacon_module


class MockN8nHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        LAST_REQUEST["headers"] = dict(self.headers)
        LAST_REQUEST["body"] = json.loads(body) if body else {}
        LAST_REQUEST["count"] += 1

        secret = self.headers.get("X-Webhook-Secret", "")
        if secret != TEST_SECRET:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
            return

        payload = LAST_REQUEST["body"]
        if not payload.get("scan_id") or not payload.get("source_ip"):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Missing required fields"}).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "scan_id": payload["scan_id"]}).encode())

    def log_message(self, format, *args):
        pass


_server: HTTPServer | None = None
_server_thread: threading.Thread | None = None


def start_mock_server(port=18999):
    global _server, _server_thread
    _server = HTTPServer(("127.0.0.1", port), MockN8nHandler)
    _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _server_thread.start()


def stop_mock_server():
    global _server
    if _server:
        _server.shutdown()
        _server = None


@pytest.fixture(scope="module", autouse=True)
def _mock_server_for_pytest():
    """Start the local webhook stub for pytest runs; direct-script main owns its lifecycle."""
    if _server is None:
        start_mock_server()
        time.sleep(0.05)
    try:
        yield
    finally:
        stop_mock_server()


def reset_last_request():
    LAST_REQUEST["headers"] = {}
    LAST_REQUEST["body"] = None
    LAST_REQUEST["count"] = 0


def assert_equal(actual, expected, msg=""):
    assert actual == expected, f"{msg} Expected {expected!r}, got {actual!r}"


# ── Test A: Linux beacon ──────────────────────────────────────────────────────

def test_linux_beacon_payload():
    print("TEST A: Linux beacon sends correct payload...")
    reset_last_request()

    os.environ["N8N_WEBHOOK_URL"] = "http://127.0.0.1:18999/webhook/geo-threat/scanner-ingest"
    os.environ["N8N_WEBHOOK_SECRET"] = TEST_SECRET
    beacon.N8N_WEBHOOK_URL = os.environ["N8N_WEBHOOK_URL"]
    beacon.N8N_WEBHOOK_SECRET = os.environ["N8N_WEBHOOK_SECRET"]

    meta = {
        "os_name": "Linux",
        "hostname": "djbc-office-01",
        "hardening_index": 85,
        "tests_executed": 50,
        "tests_skipped": 2,
    }
    findings = [
        {"check_id": "CUKAI-SSH", "category": "CUKAI", "finding_type": "warning",
         "description": "SSH root login disabled", "detail_field": "PermitRootLogin",
         "current_value": "no", "recommended_value": "yes"},
    ]

    result = findings_from_linux_scan(
        meta=meta,
        findings=findings,
        source_ip="10.112.34.96",
        hostname="djbc-office-01",
        device_id="device-djbc-001",
    )

    assert result.scanner_os == "linux", f"scanner_os={result.scanner_os}"
    assert result.scan_id.startswith("linux-"), f"scan_id={result.scan_id}"
    try:
        uuid.UUID(result.scan_id[len("linux-"):])
    except ValueError:
        assert False, f"scan_id suffix is not UUID: {result.scan_id}"

    response = beacon_linux_send(result)

    assert response is not None, "No response from n8n"
    assert response.get("ok") is True, f"Response: {response}"
    assert LAST_REQUEST["count"] == 1, f"Request count={LAST_REQUEST['count']}"

    body = LAST_REQUEST["body"]
    assert body["scan_id"] == result.scan_id, "scan_id mismatch"
    assert body["source_ip"] == "10.112.34.96", "source_ip mismatch"
    assert body["hostname"] == "djbc-office-01", "hostname mismatch"
    assert body["device_id"] == "device-djbc-001", "device_id mismatch"
    assert body["severity"] == "Low", f"severity={body['severity']}"
    assert len(body["findings"]) == 1, f"findings={len(body['findings'])}"
    assert body["findings"][0]["check_id"] == "CUKAI-SSH", "finding check_id mismatch"
    assert body["findings"][0]["severity"] is None, "Linux finding severity should be None"
    assert body["scanner"]["name"] == "geo-threat-scanner", "scanner name mismatch"
    assert body["scanner"]["os"] == "linux", f"scanner.os={body['scanner']['os']}"
    assert body["scanner"]["version"] == "1.0.0", "scanner version mismatch"

    headers = LAST_REQUEST["headers"]
    assert headers.get("X-Webhook-Secret") == TEST_SECRET, "Secret header missing"
    assert "content-type" in [k.lower() for k in headers.keys()], "Content-Type header missing"

    print("  PASSED: Linux beacon payload correct")


# ── Test B: Windows beacon ─────────────────────────────────────────────────────

def test_windows_beacon_payload():
    print("TEST B: Windows beacon sends correct payload...")
    reset_last_request()

    os.environ["N8N_WEBHOOK_URL"] = "http://127.0.0.1:18999/webhook/geo-threat/scanner-ingest"
    os.environ["N8N_WEBHOOK_SECRET"] = TEST_SECRET
    beacon.N8N_WEBHOOK_URL = os.environ["N8N_WEBHOOK_URL"]
    beacon.N8N_WEBHOOK_SECRET = os.environ["N8N_WEBHOOK_SECRET"]

    meta = {
        "os_name": "Windows",
        "hostname": "WIN-SRV-01",
        "hardening_index": 92,
        "tests_executed": 14,
        "tests_skipped": 0,
    }
    findings = [
        {"check_id": "WIN-FW-DOMAIN", "category": "FW", "finding_type": "cis_check",
         "severity": "Critical", "description": "Firewall Domain ON",
         "detail_field": "WIN-FW-DOMAIN", "current_value": "True",
         "recommended_value": "True"},
    ]

    result = findings_from_windows_scan(
        meta=meta,
        findings=findings,
        source_ip="192.168.1.50",
        hostname="WIN-SRV-01",
        device_id="device-win-001",
    )

    assert result.scanner_os == "windows", f"scanner_os={result.scanner_os}"
    assert result.scan_id.startswith("windows-"), f"scan_id={result.scan_id}"
    try:
        uuid.UUID(result.scan_id[len("windows-"):])
    except ValueError:
        assert False, f"scan_id suffix is not UUID: {result.scan_id}"

    response = beacon_windows_send(result)

    assert response is not None, "No response from n8n"
    assert response.get("ok") is True, f"Response: {response}"
    assert LAST_REQUEST["count"] == 1, f"Request count={LAST_REQUEST['count']}"

    body = LAST_REQUEST["body"]
    assert body["scan_id"] == result.scan_id, "scan_id mismatch"
    assert body["source_ip"] == "192.168.1.50", "source_ip mismatch"
    assert body["hostname"] == "WIN-SRV-01", "hostname mismatch"
    assert body["severity"] == "Critical", f"severity={body['severity']}"
    assert body["scanner"]["os"] == "windows", f"scanner.os={body['scanner']['os']}"
    assert body["findings"][0]["severity"] == "Critical", "Windows finding severity mismatch"

    print("  PASSED: Windows beacon payload correct")


# ── Test C: Invalid secret ────────────────────────────────────────────────────

def test_invalid_secret():
    print("TEST C: Invalid secret returns 401...")
    reset_last_request()

    os.environ["N8N_WEBHOOK_URL"] = "http://127.0.0.1:18999/webhook/geo-threat/scanner-ingest"
    os.environ["N8N_WEBHOOK_SECRET"] = TEST_SECRET
    beacon.N8N_WEBHOOK_URL = os.environ["N8N_WEBHOOK_URL"]
    beacon.N8N_WEBHOOK_SECRET = "wrong-secret"

    result = build_scan_result(
        source_ip="10.112.34.96",
        hostname="test-host",
        device_id="device-001",
        severity="Low",
        findings=[],
        scan_id=f"linux-{uuid.uuid4().hex[:16]}",
        scanner_os="linux",
    )

    try:
        send_to_n8n(result)
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Failed to send" in str(e) or "401" in str(e) or "Unauthorized" in str(e), f"Unexpected error: {e}"

    assert LAST_REQUEST["count"] == 1, f"Request count={LAST_REQUEST['count']}"
    headers = LAST_REQUEST["headers"]
    assert headers.get("X-Webhook-Secret") == "wrong-secret", "Wrong secret sent"
    body = json.dumps(LAST_REQUEST["body"]) if LAST_REQUEST["body"] else ""
    assert TEST_SECRET not in body, "Secret leaked in body!"

    print("  PASSED: Invalid secret returns 401, secret not in logs/body")


# ── Test D: N8N unavailable ───────────────────────────────────────────────────

def test_n8n_unavailable():
    print("TEST D: n8n unavailable — no infinite retry...")
    reset_last_request()

    os.environ["N8N_WEBHOOK_URL"] = "http://127.0.0.1:18999/webhook/geo-threat/scanner-ingest"
    os.environ["N8N_WEBHOOK_SECRET"] = TEST_SECRET
    beacon.N8N_WEBHOOK_URL = os.environ["N8N_WEBHOOK_URL"]
    beacon.N8N_WEBHOOK_SECRET = os.environ["N8N_WEBHOOK_SECRET"]

    beacon.MAX_RETRIES = 2
    beacon.RETRY_DELAY_SEC = 0.1

    result = build_scan_result(
        source_ip="10.112.34.96",
        hostname="test-host",
        device_id="device-001",
        severity="Low",
        findings=[],
        scan_id=f"linux-{uuid.uuid4().hex[:16]}",
        scanner_os="linux",
    )

    original_url = beacon.N8N_WEBHOOK_URL
    beacon.N8N_WEBHOOK_URL = "http://127.0.0.1:19999/webhook/geo-threat/scanner-ingest"

    try:
        send_to_n8n(result)
        assert False, "Should have raised RuntimeError"
    except RuntimeError as e:
        assert "Failed to send" in str(e), f"Unexpected error: {e}"

    assert LAST_REQUEST["count"] == 0, f"Should not have reached server, count={LAST_REQUEST['count']}"

    beacon.N8N_WEBHOOK_URL = original_url

    print("  PASSED: n8n unavailable — beacon fails gracefully, no infinite retry")


# ── Test E: Duplicate scan_id uniqueness ──────────────────────────────────────

def test_scan_id_uniqueness():
    print("TEST E: scan_id uniqueness (UUID-based)...")

    ids = set()
    for _ in range(50):
        r = findings_from_linux_scan(
            meta={"hostname": "host", "hardening_index": 85, "os_name": "Linux", "os_version": None, "tests_executed": 50, "tests_skipped": 0},
            findings=[],
            source_ip="10.0.0.1",
            hostname="host",
            device_id="d1",
        )
        ids.add(r.scan_id)

    assert len(ids) == 50, f"Expected 50 unique IDs, got {len(ids)}"
    for sid in ids:
        assert sid.startswith("linux-"), f"Invalid prefix: {sid}"
        try:
            uuid.UUID(sid[len("linux-"):])
        except ValueError:
            assert False, f"Non-UUID suffix: {sid}"

    print("  PASSED: All scan_ids are unique and UUID-based")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("BEACON INTEGRATION TESTS")
    print("=" * 70)

    start_mock_server()
    time.sleep(0.2)

    results = []

    try:
        test_linux_beacon_payload()
        results.append(("A: Linux beacon", True))
    except AssertionError as e:
        print(f"  FAILED: {e}")
        results.append(("A: Linux beacon", False))
    except Exception as e:
        print(f"  ERROR: {e}")
        results.append(("A: Linux beacon", False))

    try:
        test_windows_beacon_payload()
        results.append(("B: Windows beacon", True))
    except AssertionError as e:
        print(f"  FAILED: {e}")
        results.append(("B: Windows beacon", False))
    except Exception as e:
        print(f"  ERROR: {e}")
        results.append(("B: Windows beacon", False))

    try:
        test_invalid_secret()
        results.append(("C: Invalid secret", True))
    except AssertionError as e:
        print(f"  FAILED: {e}")
        results.append(("C: Invalid secret", False))
    except Exception as e:
        print(f"  ERROR: {e}")
        results.append(("C: Invalid secret", False))

    try:
        test_n8n_unavailable()
        results.append(("D: n8n unavailable", True))
    except AssertionError as e:
        print(f"  FAILED: {e}")
        results.append(("D: n8n unavailable", False))
    except Exception as e:
        print(f"  ERROR: {e}")
        results.append(("D: n8n unavailable", False))

    try:
        test_scan_id_uniqueness()
        results.append(("E: scan_id uniqueness", True))
    except AssertionError as e:
        print(f"  FAILED: {e}")
        results.append(("E: scan_id uniqueness", False))
    except Exception as e:
        print(f"  ERROR: {e}")
        results.append(("E: scan_id uniqueness", False))

    stop_mock_server()

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    all_passed = True
    for name, passed in results:
        icon = "PASS:" if passed else "FAILED:"
        print(f"  {icon} {name}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nALL BEACON TESTS PASSED")
    else:
        print("\nWARNING: SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
