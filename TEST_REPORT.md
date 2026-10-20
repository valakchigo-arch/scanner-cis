# Laporan pengujian

Tanggal: 2026-10-19 · Lingkungan: Linux (sandbox), pytest 9.1.1 · **Bukan Windows**.

## Hasil
```
python -m pytest -q   →   340 passed, 2 skipped
```
- 2 skipped = `tests/core/test_win_fw_domain_e2e.py` (butuh Windows PowerShell) **[NOT RUN]**.
- Sebelum patch: 285 passed, 2 skipped. Selisih 55 = test baru (lihat `FILES.md`).

## Yang DIBUKTIKAN
- Logika rule engine, evaluator, adapter kontrak, harness (Windows palsu + rule YAML asli), guard baseline, summarizer, dan struktur statis bat.
- Mutation testing: harness **11/11**, perbaikan bat/summarizer/guard **6/6** mutan ditangkap.
- Test baru **gagal** pada keadaan sebelum perbaikan (tabel per basis pembanding di `docs/MUTATION_CHECK.md` addendum §1).
- Kunci kontrak beacon v2 identik sebelum dan sesudah patch.

## TIDAK dibuktikan (jangan diklaim di skripsi)
- Seluruh perintah perubahan setelan (`scenarios/windows_scenarios.yaml`, `run_scenarios.bat`) pada Windows nyata **[NOT RUN]**. Sandbox tidak punya PowerShell, sehingga sintaks skrip PowerShell multi-baris (mis. `complexity_on`) hanya diperiksa strukturnya.
- Perilaku `secedit /configure`, `Set-MpPreference`, `Enable-WindowsOptionalFeature` **[NOT RUN]**.
- Nomor CIS dibandingkan ke PDF: **[ASSUMED]** (tabel dari pemilik project; PDF tidak tersedia di lingkungan ini).
- Klaim "terbukti PASS→FAIL→PASS" (Guest, RemoteRegistry, Firewall, LMHash, RDP-NLA, UAC) dan klaim bat pernah live-sukses (14 scan, 15 Okt): **[ASSUMED]**, data mentah tidak ada di repo.
- Backend (`hardening_parser.py`, n8n) tidak ada di repo ini.
