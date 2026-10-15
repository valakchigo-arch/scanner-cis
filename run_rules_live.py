"""
run_rules_live.py -- jalankan semua rule Windows di mesin ASLI dan simpan hasilnya.

Taruh di ROOT project (sejajar dengan folder scanner/ dan rules/).
Jalankan dari PowerShell *as Administrator*:

    python run_rules_live.py --label baseline
    python run_rules_live.py --label firewall_private_off

Output:
  - tabel ringkas di layar
  - results/<label>_<hostname>_<timestamp>.json  (lengkap: nilai mentah + evidence + error asli)

Alasan error probe kini dibawa executor sendiri (finding["error_detail"]).
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

from scanner.core import load_rules_from_dir, execute_rules  # noqa: E402


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
    findings = execute_rules(rules, scan_id, host_os="windows")
    for f in findings:
        f.setdefault("error_detail", None)

    # tabel ringkas
    print(f"{'RULE':26} {'STATUS':6} {'EXPECTED':16} OBSERVED")
    print("-" * 78)
    for f in findings:
        exp = str(f["comparison"]["expected"])[:15]
        obs = repr(f["comparison"]["actual"]) if f["status"] != "ERROR" else f["error_detail"]
        print(f"{f['control_id']:26} {f['status']:6} {exp:16} {str(obs)[:60]}")

    counts = {s: sum(1 for f in findings if f["status"] == s)
              for s in ("PASS", "FAIL", "ERROR", "NOT_APPLICABLE")}
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
