"""
tools/bat_baseline_guard.py -- penjaga untuk run_scenarios.bat.

Rollback di bat di-hardcode untuk baseline Windows DEFAULT. Bila mesin punya baseline lain (mis. GPO),
"rollback" justru akan MENGUBAH mesin secara permanen. Guard ini membaca hasil scan baseline
(keluaran run_rules_live.py / bat) dan menolak (exit 1) bila ada kontrol yang menyimpang dari asumsi bat.
Dipanggil SEBELUM skenario apa pun mengubah setelan.

    python tools/bat_baseline_guard.py results/scenarios/baseline.json
"""
import json
import sys

# nilai terbaca (probe) yang diasumsikan rollback hard-coded di run_scenarios.bat; None = key tidak ada
ASSUMED = {
    "WIN-SCREENLOCK-TIMEOUT": None,     # S1: rollback = reg delete (akan MENGHAPUS nilai yang sudah ada)
    "WIN-PASS-MINLEN": "0",             # S2: net accounts /minpwlen:0
    "WIN-ACCT-LOCKOUT": "10",           # S3: /lockoutthreshold:10
    "WIN-GUEST-DISABLED": "False",      # S4
    "WIN-REMOTEREG-DISABLED": "4",      # S5: start= disabled
    "WIN-FW-PRIVATE": "True",           # S6
    "WIN-FW-PUBLIC": "True",            # S7
    "WIN-LMHASH-DISABLED": "1",         # S8: NoLMHash=1
    "WIN-RDP-NLA": "1",                 # S9: UserAuthentication=1
    "WIN-UAC-ENABLED": "1",             # S11: EnableLUA=1
}                                       # S10 (complexity) memulihkan dari ekspor asli: tidak perlu diasumsikan


def norm(v):
    return None if v is None else str(v).strip()


def check(findings: list) -> list:
    """Daftar ketidaksesuaian (kosong = aman). Kontrol hilang / ERROR juga dianggap tidak aman."""
    by = {f["control_id"]: f for f in findings}
    problems = []
    for cid, want in ASSUMED.items():
        f = by.get(cid)
        if f is None:
            problems.append(f"{cid}: tidak ada di hasil baseline")
        elif f.get("status") == "ERROR":
            problems.append(f"{cid}: baseline ERROR (nilai tidak diketahui)")
        else:
            got = norm((f.get("comparison") or {}).get("actual"))
            if got != want:
                problems.append(f"{cid}: baseline {got!r}, bat mengasumsikan {want!r}")
    return problems


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("pemakaian: bat_baseline_guard.py <baseline.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as fh:
            findings = json.load(fh)["findings"]
    except (OSError, ValueError, KeyError) as exc:
        print(f"[GUARD] tidak bisa membaca baseline: {exc}", file=sys.stderr)
        return 1
    problems = check(findings)
    for p in problems:
        print(f"[GUARD] {p}")
    print("[GUARD] baseline default: aman" if not problems else f"[GUARD] {len(problems)} ketidaksesuaian: DITOLAK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
