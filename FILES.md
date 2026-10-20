# Patch v3 (rev 2): daftar file (REPLACE / NEW / TINDAKAN)

Diterapkan **di atas** repo `scanner_clear` (285 passed, 2 skipped sebelum patch). Sesudah patch: **340 passed, 2 skipped** [VERIFIED: pytest, Linux].
Arsitektur beacon/n8n/backend tidak diubah; kunci kontrak v2 (finding dan meta) identik [VERIFIED].

## REPLACE
| file | alasan | pembuktian |
|---|---|---|
| `scanner/core/rule_model.py`, `rule_loader.py`, `finding_emitter.py`, `contract_adapter.py` | `Condition.display` opsional: regex `matches` tidak lagi bocor ke `recommended_value` (dashboard/AI). **Di luar daftar Gate A, lihat Addendum** | `tests/rules/test_condition_display.py` (gagal: `orig` 3, `pre` 5) |
| `rules/windows/win-screenlock-timeout.yaml` | tambah `display`; judul tidak lagi menyiratkan nilai 0 lolos | idem |
| `run_scenarios.bat` | **diperbaiki, bukan dihapus**: blok persiapan hilang ditulis ulang (variabel + cek admin), blok Skenario 1 dipindah setelah baseline, baris `rollback_screenlockREM` dipisah, guard baseline sebelum perubahan apa pun, Skenario 10 membaca dengan `Select-String` dan menulis INF `-Encoding Unicode` (`findstr` tidak andal pada UTF-16), CRLF | `tests/test_bat_tools.py`, `tests/test_repo_hygiene.py` |
| `summarize_scenarios.py` | **ditulis ulang**: label file bat (`after_screenlock_1800.json`) sebelumnya dipotong jadi `after` (skenario saling menimpa, "Expected changes" kosong diam-diam, rollback berlabel 2+ underscore dilewati); sekarang membandingkan (status, nilai) semua kontrol | `tests/test_bat_tools.py` (12 gagal pada versi lama) |
| `docs/METHODOLOGY.md` | tabel semantik evaluator (dihasilkan dari kode), ancaman validitas 9-17, dua jalur live; koreksi "3 host Win11" menjadi 2 mesin | `tests/test_methodology_sync.py` |
| `docs/MUTATION_CHECK.md` | **addendum** (isi lama tidak diubah): basis pembanding, koreksi hasil vacuous, celah cakupan 9 test lama, keterbatasan allowlist | - |
| `tests/test_scenario_harness.py` | menguji harness baru (32 test; Windows palsu + rule YAML asli) | 11/11 mutan ditangkap |
| `FILES.md`, `TEST_REPORT.md` | versi lama basi | - |

## NEW
`tools/__init__.py`, `tools/scenario_harness.py`, `tools/semantics_matrix.py`, `tools/bat_baseline_guard.py`, `scenarios/windows_scenarios.yaml` (19 skenario),
`tests/rules/test_condition_display.py`, `tests/test_repo_hygiene.py`, `tests/test_methodology_sync.py`, `tests/test_bat_tools.py`, `docs/B4_RUNBOOK.md`.

## TINDAKAN
- **Hapus hanya** `tests/scenario_harness.py`: `_scan()` memasang mock probe secara permanen (provider asli tidak dipulihkan); `CompositeTarget` memakai `DictTarget` untuk registry (tidak pernah menyentuh registry nyata); rollback pada target non-registry menulis `None`. Terbukti eksperimen: `complexity_1_pass` → `detected=False`.
- **Tidak dihapus**: `run_scenarios.bat`, `summarize_scenarios.py` (dipertahankan sebagai jalur validasi kedua; mekanismenya berbeda dari harness sehingga bisa saling menguji).
- Opsional: `archive/architecture-pre-v4.md` memuat username/URL GitHub; anonimkan bila skripsi memerlukannya.

## Kepatuhan terhadap ROLE (per item, jujur)
| item | status |
|---|---|
| P0-1, P0-2, P0-3 | dikerjakan pemilik project (mutation check nyata: 12 test gagal pada `orig`); patch ini hanya menambah `display` pada P0-2 |
| P1-1 | **test lock-in sudah ada dan sesuai spec** (`tests/test_evaluator_null_semantics.py`, 37 test, milik pemilik project; 37/37 lulus pada `orig` karena memang tidak ada perubahan perilaku). `evaluator.py` identik dengan `orig`. **Dokumentasi tabel belum ada** sebelum patch ini (tabel kini ada di METHODOLOGY §9) |
| P1-2, P1-3 | harness lama tidak memenuhi (tidak menguji probe nyata); diganti harness baru + 19 skenario (termasuk seluruh matriks P1-3). Eksekusi Windows **[NOT RUN]** |
| P2 | ancaman validitas ditambah (METHODOLOGY §7 butir 9-17) |

## Addendum: perubahan di luar daftar Gate A
`Condition.display` (4 file inti + 1 rule) **tidak ada di daftar P0-P2**. Alasan: setelah P0-2, kondisi `matches` membuat `recommended_value` berisi regex mentah
(`matches ^([1-9]\d?|[1-8]\d\d|900)$`) yang dikonsumsi dashboard dan AI BC (terverifikasi). Perubahannya aditif (default kosong), kunci kontrak v2 tidak berubah.
Bila tidak diinginkan: hapus 4 perubahan inti, kembalikan rule, dan hapus `tests/rules/test_condition_display.py`. Patch ini **tidak** mengklaim "patuh penuh ROLE"; yang benar: P0-P2 + 1 addendum.
Perubahan lain di luar daftar: `bat_baseline_guard.py` dan perbaikan bat/summarizer (diperlukan agar jalur validasi kedua dapat dipakai dengan aman).

## Sengaja tidak dilakukan
Test khusus nama file `run_harness.py`: redundan dan lebih lemah daripada penjaga umum (semua berkas sumber < 10 byte). Bukti penangkapan kini lewat pohon sintetik
(`test_tiny_file_finder_catches_the_real_incident`: berkas 3 byte berisi BOM terdeteksi).

## Belum dilakukan / [NOT RUN]
B4 (live Windows), B5 (ground truth independen), B6 pada mesin nyata; eksekusi bat setelah perbaikan; seluruh perintah di `scenarios/windows_scenarios.yaml`. Lihat `docs/B4_RUNBOOK.md`.
