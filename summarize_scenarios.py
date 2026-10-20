"""
summarize_scenarios.py
======================
Baca semua hasil scenario testing, print tabel PASS/FAIL/ERROR per skenario.
"""
import json
import os
import re
import glob
import sys


def extract_label(filename: str) -> str:
    """baseline_DESKTOP-XXX_20261012T160258Z.json → baseline"""
    name = os.path.basename(filename).replace('.json', '')
    parts = name.rsplit('_', 2)
    return parts[0] if len(parts) >= 3 else name


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    pattern = os.path.join(root, 'results', 'scenarios', '*.json')
    files = sorted(glob.glob(pattern), key=os.path.getmtime)

    if not files:
        print("[WARN] Tidak ada file JSON ditemukan di results/scenarios/")
        return 1

    print()
    print("=" * 72)
    print(f"{'Scenario':<32} {'PASS':>6} {'FAIL':>6} {'ERROR':>6}")
    print("-" * 72)

    baseline_fails = None
    results = {}

    for f in files:
        label = extract_label(f)
        try:
            with open(f, encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"{label:<32} [parse error: {e}]")
            continue

        counts = {'PASS': 0, 'FAIL': 0, 'ERROR': 0}
        fail_rules = []
        for finding in data.get('findings', []):
            s = finding.get('status', 'UNKNOWN')
            if s in counts:
                counts[s] += 1
            if s == 'FAIL':
                fail_rules.append(finding.get('control_id', '?'))

        results[label] = (counts, fail_rules)

        if label == 'baseline':
            baseline_fails = set(fail_rules)

        print(f"{label:<32} {counts['PASS']:>6} {counts['FAIL']:>6} {counts['ERROR']:>6}")

    print("=" * 72)

    # Analysis
    print()
    print("=" * 72)
    print("ANALISIS")
    print("=" * 72)

    if baseline_fails is None:
        print("[WARN] Baseline tidak ditemukan. Rollback check dilewati.")
    else:
        print(f"Baseline FAIL rules: {sorted(baseline_fails)}")
        print()

        # Cek rollback konsisten dengan baseline
        for label, (counts, fail_rules) in results.items():
            if not label.startswith('rollback_'):
                continue
            rollback_fails = set(fail_rules)
            if rollback_fails == baseline_fails:
                print(f"[OK]   {label:<30} = baseline (rollback sukses)")
            else:
                diff_only_in_rollback = rollback_fails - baseline_fails
                diff_only_in_baseline = baseline_fails - rollback_fails
                print(f"[WARN] {label:<30} BEDA dari baseline!")
                if diff_only_in_rollback:
                    print(f"         Extra FAIL: {sorted(diff_only_in_rollback)}")
                if diff_only_in_baseline:
                    print(f"         Missing FAIL: {sorted(diff_only_in_baseline)}")

        print()
        # Cek after_* mengubah rule yang benar
        print("Expected changes per skenario:")
        for label, (counts, fail_rules) in results.items():
            if not label.startswith('after_'):
                continue
            new_fails = set(fail_rules) - baseline_fails
            if new_fails:
                print(f"[OK]   {label:<30} new FAIL: {sorted(new_fails)}")
            else:
                print(f"[WARN] {label:<30} TIDAK ADA FAIL baru (ekspektasi: 1)")

    print("=" * 72)
    print()
    print("Cara baca:")
    print("  - 'rollback_*' harus PERSIS sama dengan baseline")
    print("  - 'after_*' harus ada 1 FAIL baru (rule target)")
    print("  - Kalau rule lain ikut berubah = BUG dependency")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())