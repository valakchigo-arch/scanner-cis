"""
summarize_scenarios.py -- ringkas hasil run_scenarios.bat (results/scenarios/*.json).

Perbaikan atas versi lama:
  * label diambil dengan benar untuk KEDUA pola nama: `<label>.json` (keluaran bat) dan `<label>_<host>_<timestamp>.json`
    (versi lama memotong `after_screenlock_1800` menjadi `after`, sehingga skenario saling menimpa dan cek rollback dilewati diam-diam);
  * perbandingan memakai (status, nilai terbaca) SEMUA kontrol, bukan hanya himpunan ID yang FAIL
    (arah FAIL->PASS dan nilai yang berubah tanpa flip status ikut terlihat);
  * exit code 2 bila ada rollback yang tidak kembali ke baseline atau skenario `after_*` yang tidak mengubah apa pun (curiga no-op).
"""
import glob
import json
import os
import re
import sys

LABEL_WITH_HOST_TS = re.compile(r"^(?P<label>.+?)_(?P<host>[^_]+)_(?P<ts>\d{8}T\d{6}Z)$")


def extract_label(path: str) -> str:
    name = os.path.basename(path)
    name = name[:-5] if name.endswith(".json") else name
    m = LABEL_WITH_HOST_TS.match(name)
    return m.group("label") if m else name


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    for f in data.get("findings", []):
        actual = (f.get("comparison") or {}).get("actual")
        out[f.get("control_id", "?")] = (f.get("status", "UNKNOWN"), None if actual is None else str(actual).strip())
    return out


def diff(base: dict, other: dict) -> list:
    """[(control, (status, observed) di baseline, (status, observed) sekarang)] untuk yang berbeda atau hilang."""
    return [(c, base.get(c), other.get(c)) for c in sorted(set(base) | set(other)) if base.get(c) != other.get(c)]


def fmt(x) -> str:
    return "-" if x is None else f"{x[1]!r}/{x[0]}"


def summarize(directory: str) -> tuple:
    files = sorted(glob.glob(os.path.join(directory, "*.json")), key=os.path.getmtime)
    runs = {}
    for f in files:
        label = extract_label(f)
        try:
            runs[label] = load(f)                      # label sama: yang terbaru menang
        except (OSError, ValueError) as exc:
            print(f"{label:<34} [parse error: {exc}]")
    lines, anomalies = [], 0
    if "baseline" not in runs:
        return ["[WARN] baseline tidak ditemukan; tidak ada yang bisa dibandingkan."], 1
    base = runs["baseline"]
    lines.append(f"{'scan':<34} {'PASS':>5} {'FAIL':>5} {'ERROR':>5}")
    for label, r in runs.items():
        c = {s: sum(1 for st, _ in r.values() if st == s) for s in ("PASS", "FAIL", "ERROR")}
        lines.append(f"{label:<34} {c['PASS']:>5} {c['FAIL']:>5} {c['ERROR']:>5}")
    lines += ["", "ROLLBACK harus sama persis dengan baseline (status DAN nilai, semua kontrol):"]
    for label, r in runs.items():
        if label.startswith("rollback_"):
            d = diff(base, r)
            if d:
                anomalies += 1
                lines.append(f"[WARN] {label}: TIDAK kembali ke baseline")
                lines += [f"         {c}: {fmt(b)} -> {fmt(n)}" for c, b, n in d]
            else:
                lines.append(f"[OK]   {label}")
    lines += ["", "AFTER: kontrol yang berubah dibanding baseline (kosong = skenario tidak berpengaruh, curiga no-op):"]
    for label, r in runs.items():
        if label.startswith("after_"):
            d = diff(base, r)
            if d:
                lines.append(f"[OK]   {label}")
                lines += [f"         {c}: {fmt(b)} -> {fmt(n)}" for c, b, n in d]
            else:
                anomalies += 1
                lines.append(f"[WARN] {label}: tidak ada perubahan vs baseline")
    return lines, anomalies


def main(argv=None) -> int:
    root = os.path.dirname(os.path.abspath(__file__))
    directory = (argv or sys.argv[1:] or [os.path.join(root, "results", "scenarios")])[0]
    if not glob.glob(os.path.join(directory, "*.json")):
        print(f"[WARN] Tidak ada file JSON di {directory}")
        return 1
    lines, anomalies = summarize(directory)
    print("\n".join(lines))
    print(f"\nAnomali: {anomalies}")
    return 2 if anomalies else 0


if __name__ == "__main__":
    sys.exit(main())
