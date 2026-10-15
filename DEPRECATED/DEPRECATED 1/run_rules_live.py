"""
run_rules_live.py -- jalankan semua rule Windows di mesin ASLI dan simpan hasilnya.

Taruh di ROOT project (sejajar dengan folder scanner/ dan rules/).
Jalankan dari PowerShell *as Administrator*:

    python run_rules_live.py --label baseline
    python run_rules_live.py --label firewall_private_off

Output:
  - tabel ringkas di layar
  - results/<label>_<hostname>_<timestamp>.json  (lengkap: nilai mentah + evidence + error asli)

Beda dengan execute_rules(): script ini MENYIMPAN pesan error probe.
(executor asli membuang alasan error saat status ERROR.)
"""
import argparse
import ctypes
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from scanner.core import (  # noqa: E402
    load_rules_from_dir, execute_probe, evaluate_condition, emit_finding,
)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default="run", help="nama skenario, mis. baseline")
    ap.add_argument("--rules", default=os.path.join(ROOT, "rules", "windows"))
    args = ap.parse_args()

    if platform.system() != "Windows":
        sys.exit("Script ini harus dijalankan di Windows.")
    if not is_admin():
        print("PERINGATAN: bukan Administrator. Beberapa probe (SMB1, Defender, "
              "secedit) bisa ERROR atau memberi nilai salah.\n")

    rules = load_rules_from_dir(args.rules)
    scan_id = f"live-{args.label}"
    findings = []

    for i, rule in enumerate(rules, start=1):
        error = None
        try:
            probe = execute_probe(rule)
            passed = evaluate_condition(rule, probe.value)
            status = "PASS" if passed else "FAIL"
            f = emit_finding(rule, scan_id, i, status, probe.value, probe)
        except Exception as e:  # simpan alasan error asli
            error = f"{type(e).__name__}: {e}"
            status = "ERROR"
            f = emit_finding(rule, scan_id, i, status, None, None)
        f["error_detail"] = error
        findings.append(f)

    # tabel ringkas
    print(f"{'RULE':26} {'STATUS':6} {'EXPECTED':16} OBSERVED")
    print("-" * 78)
    for f in findings:
        exp = str(f["comparison"]["expected"])[:15]
        obs = repr(f["comparison"]["actual"]) if f["status"] != "ERROR" else f["error_detail"]
        print(f"{f['control_id']:26} {f['status']:6} {exp:16} {str(obs)[:60]}")

    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in ("PASS", "FAIL", "ERROR")}
    print("\nTotal:", counts)

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = socket.gethostname()
    out = os.path.join(ROOT, "results", f"{args.label}_{host}_{ts}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({
            "label": args.label,
            "hostname": host,
            "os": platform.platform(),
            "is_admin": is_admin(),
            "timestamp": ts,
            "counts": counts,
            "findings": findings,
        }, fh, indent=2, default=str)
    print("Disimpan:", out)


if __name__ == "__main__":
    main()
