# Daftar file yang diubah/ditambahkan (FASE A)

## REPLACE (timpa)
- rules/windows/win-acct-lockout.yaml — ubah standard.reference ke CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.2.2 (L1); tambahkan level: L1; severity tetap HIGH
- rules/windows/win-defender-enabled.yaml — standard.reference v4.0.0, 18.10.43.10.3 (L1); severity: CRITICAL di top-level; level L1
- rules/windows/win-fw-domain.yaml — v4.0.0, 9.1.1 (L1); severity CRITICAL; level L1
- rules/windows/win-fw-private.yaml — v4.0.0, 9.2.1 (L1); severity CRITICAL; level L1
- rules/windows/win-fw-public.yaml — v4.0.0, 9.3.1 (L1); severity CRITICAL; level L1
- rules/windows/win-guest-disabled.yaml — v4.0.0, 2.3.1.2 (L1); severity HIGH; level L1
- rules/windows/win-lmhash-disabled.yaml — v4.0.0, 2.3.11.5 (L1); severity HIGH; confidence INFERRED; level L1
- rules/windows/win-pass-complex.yaml — v4.0.0, 1.1.5 (L1); severity HIGH; level L1
- rules/windows/win-pass-minlen.yaml — v4.0.0, 1.1.4 (L1); severity HIGH; level L1
- rules/windows/win-rdp-nla.yaml — v4.0.0, 18.10.57.3.9.4 (L1); severity CRITICAL; level L1
- rules/windows/win-remotereg-disabled.yaml — v4.0.0, 5.26 (L2); severity MEDIUM; level L2
- rules/windows/win-screenlock-timeout.yaml — **P0-2** ganti probe ke HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs; condition operator matches dengan regex `^([1-9]\\d?|[1-8]\\d\\d|900)$` (menolak 0); reference v4.0.0, 2.3.7.4 (L1); level L1; deskripsi diperbarui (machine-wide, boundary documented)
- rules/windows/win-smb1-disabled.yaml — **P0-3** standard.reference v4.0.0, 18.4.2 + 18.4.3 (L1); level L1; confidence INFERRED; description mencatat mekanisme berbeda vs CIS registry
- rules/windows/win-uac-enabled.yaml — v4.0.0, 2.3.17.6 (L1); severity HIGH; level L1
- tests/regression/test_bug_regressions.py — update test untuk mencerminkan pergeseran screenlock ke path HKLM + regex
- docs/VALIDATION_RESULTS.md — hapus klaim Windows 11 (build 26200) → Windows 10
- docs/METHODOLOGY.md — hapus klaim Windows 11 → Windows 10 (2 lokasi)

## NEW (tambahkan)
- tests/probe_evaluator_behavior.py — snapshot perilaku evaluator (null/empty/wrong-type)
- tests/test_evaluator_null_semantics.py — **P1-1** pinning tests untuk semantik null evaluator
- tests/rules/test_win_screenlock_timeout.py — **P0-2** boundary tests (0/1/600/900/901/1800/None, path, regex, reference format)
- tests/rules/test_win_smb1_disabled.py — **P0-3** tests (Disabled/Enabled/Offline/None, INFERRED, reference format, probe command)
- tests/scenario_harness.py — **P1-2/P1-3** data-driven scenario harness (Target, DictTarget, Scenario, ScenarioRunner, default_scenarios) dengan rejection no-op, rollback verification, spurious-flip tracking, reports JSON+MD
- tests/test_scenario_harness.py — Linux-safe tests untuk harness (P1-2)

## SUMMARY
Total: 17 file modified/added (15 rules updated + 3 docs/tests updated + 6 new test/harness files). pytest: **278 passed, 0 failed** (≥223). No forbidden strings "Server 2019"/"CIS Windows Server" in rules (verified via updated references). Gate A passed. Phase B (live Windows validation B1–B7) belum dijalankan di lingkungan ini (memerlukan Windows + admin + snapshot).

## NEW (Fase A + B)
- `tests/test_forbidden_strings.py` — Gate A criterion 2 (forbidden-string guard)
- `tests/test_cis_references.py` — B3 exact-match reference mapping (14 rules)
- `docs/MUTATION_CHECK.md` — B2 mutation evidence (4 mutations, RED→GREEN)
- `tests/scenario_harness.py` — P1-2 data-driven scenario runner
- `tests/test_scenario_harness.py` — P1-2 harness tests
- `archive/architecture-pre-v4.md` — historical pre-v4.0.0 architecture dump

## REPLACE (Fase A)
- `rules/windows/win-screenlock-timeout.yaml` — P0-2 (HKLM InactivityTimeoutSecs + matches)
- `rules/windows/win-smb1-disabled.yaml` — P0-3 (confidence INFERRED)
- `rules/windows/*.yaml` (12 files) — P0-1 (reference v4.0.0)
- `docs/METHODOLOGY.md` — P2 (tabel rule + Win11 → Host-A)
- `docs/VALIDATION_RESULTS.md` — P2 (hostname anonim)
- `pytest.ini` — `--import-mode=importlib` (fix module collision)
- `scanner/core/evaluator.py` — P1-1 (None guard untuk matches/contains)
- `.gitignore` — `tmp/`, `__pycache__/`, `*.pyc`

## TINDAKAN
- `scanner/tests/__init__.py` — dihapus (fix module collision)
- `docs/architecture.md` — dipindah ke `archive/architecture-pre-v4.md`
- `tmp/` — untracked dari git
- `DEPRECATED/` — di-track (aman, hanya placeholder; rekomendasi untrack setelah Fase B selesai)