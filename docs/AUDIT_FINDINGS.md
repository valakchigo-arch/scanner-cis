# Audit Findings — clear_scanner

Audit dilakukan dengan (1) membaca seluruh kode, (2) mereproduksi tiap dugaan bug terhadap **kode asli**
sebelum diperbaiki, (3) menulis regression test yang gagal di kode lama dan lulus di kode baru.
Test: `pytest` → **221 passed, 2 skipped** (2 skip = butuh Windows PowerShell). Sebelumnya `pytest` polos: 3 failed.

| ID | Sev. | Lokasi | Temuan | Dampak | Perbaikan | Test |
|---|---|---|---|---|---|---|
| F-01 | **Kritis** | `cis_scanner_windows.py` WIN-ACCT-LOCKOUT | Regex `[1-5]\b` mencocokkan digit terakhir: threshold **15, 25, 35, 45, 55** dinilai PASS | *False negative keamanan*: lockout longgar dilaporkan patuh | `(?<!\d)[1-5](?!\d)` | `test_lockout_only_1_to_5` |
| F-02 | Tinggi | probe PowerShell/registry, scanner legacy | Kegagalan probe dinilai **FAIL** (output kosong / `__ERROR__` / rc diabaikan). Run non-admin pada data asli: 3 FAIL palsu (nilai `''`) | False positive massal; `hardening_index` menyesatkan | Status 3-keadaan: probe gagal → `ERROR`, tidak masuk temuan, tidak menurunkan indeks; `$ErrorActionPreference='Stop'`; rc dicek | `test_*_error_*`, `test_registry_probe_failure_*` |
| F-03 | Sedang | WIN-SCREENLOCK-TIMEOUT | Regex `[1-9]\d{0,2}` menerima 901–999 | Timeout >15 menit lolos | `^([1-9]\d?\|[1-8]\d\d\|900)$` | `test_screenlock_max_900` |
| F-04 | Sedang | WIN-PASS-MINLEN | Nilai tertentu ≥100 (mis. 100) dinilai FAIL | False positive | `(?<!\d)(1[4-9]\|[2-9]\d\|1\d\d)(?!\d)` | `test_minlen_14_and_above` |
| F-05 | Sedang | `evaluator.py` | `contains`/`matches` pada nilai **tidak ada** (None) memakai `str(None)="None"`: `contains "Non"` → True | Rule bisa PASS karena artefak | None → False | `test_missing_value_never_matches_string_None` |
| F-06 | Sedang | rule `secedit` ×3 | File temp **bernama tetap**, tidak dihapus, exit code `secedit` tidak dicek | *Potensi* (belum direproduksi): run non-admin dapat membaca file basi dari run admin; hasil export kebijakan tertinggal di `%TEMP%` | GUID unik + `try/finally Remove-Item` + cek `$LASTEXITCODE` | `test_secedit_rules_use_unique_temp_and_cleanup` |
| ~~F-07~~ | — | rule WIN-SCREENLOCK-TIMEOUT | **DITARIK KEMBALI.** Versi pertama audit menyebut `HKCU` sebagai bug dan menggantinya ke `HKLM\SOFTWARE\Policies\...` (disalin dari scanner legacy, **tidak diverifikasi**). Group Policy *Screen saver timeout* adalah policy per-user; path HKLM itu kemungkinan bukan lokasi policy nyata, sehingga rule akan selalu FAIL. Path `HKCU` terbukti responsif pada uji live (1800 terbaca). | — | Dikembalikan ke `HKCU`; scope per-user didokumentasikan; padanan machine-wide = `InactivityTimeoutSecs` | `test_screenlock_rule_keeps_live_validated_hkcu_path` |
| F-08 | Sedang | `executor.py` | Alasan `ERROR` dibuang; probe yang mengembalikan tipe salah menghentikan scan; `rule.os` tidak pernah dicek | Sulit didiagnosis; rule Windows di Linux jadi 14 ERROR | `error_detail`, tangkap semua exception, `host_os` → `NOT_APPLICABLE` | `test_error_reason_*`, `test_host_os_gate_*` |
| F-09 | Sedang | `windows_registry.py` | `path`/`key` diinterpolasi ke PowerShell tanpa escape `'`; rc diabaikan | Injeksi bila file rule tidak tepercaya; FAIL palsu | Gandakan `'`; cek rc; `-EncodedCommand` | `test_registry_probe_escapes_single_quotes` |
| F-10 | Sedang | `beacon_contract.py` + parser Linux | Severity scan Linux = temuan **pertama**, bukan tertinggi; Lynis tak punya severity → selalu `Low` | Dashboard meremehkan risiko Linux | `max_severity()`; heuristik `warning→High, sysctl→Medium, saran→Low` (**heuristik, bukan CVSS**) | `test_linux_scan_severity_is_max_*`, `test_lynis_severity_*` |
| F-11 | Rendah | `beacon_contract.py` | `int(os.environ[...])` saat import: nilai rusak = crash | Scanner mati sebelum jalan | `_env_num` + fallback + warning | `test_bad_env_numbers_*` |
| F-12 | Rendah | `send_payload` | Retry untuk 404/413/422; delay tetap | Buang waktu, beban ke n8n | Retry hanya transient (5xx/429/408/jaringan) + exponential backoff (cap 60s) | `test_retry_only_transient`, `test_backoff_*` |
| F-13 | Rendah | `spool.py` | Tulis tidak atomik; `scan_id` jadi nama file tanpa sanitasi; file korup gagal selamanya | Data hilang/rusak; path traversal | tmp+`os.replace`, sanitasi nama, karantina `.corrupt`, dir 0700 | `test_spool_*` |
| F-14 | Rendah | `scoring.py` | Semua ERROR → `hardening_index=100` tanpa penanda; contoh config di komentar menggeser threshold | Skor sempurna palsu | Field aditif `complete`/`indeterminate`; komentar dibenahi | `test_all_error_*` |
| F-15 | Rendah | `rule_loader.py` | `read_text()` tanpa encoding (cp1252 di Windows); `probe`/`condition` non-mapping → `AttributeError`; direktori hilang → `FileNotFoundError` | Pesan error tak jelas | UTF-8; `RuleValidationError` | `test_loader_*` |
| F-16 | Rendah | build/test | `scanner/requirements.txt` **tanpa PyYAML** (rule engine `ImportError` di target); `requirements-test.txt` kosong; `pytest` polos: 3 failed (mock n8n hanya nyala di `main()`) | Tidak bisa dijalankan di mesin bersih | Dependensi dilengkapi; fixture pytest | `pytest` penuh hijau |
| F-17 | **Operasional** | `scanner/.env`, `results/` | Arsip berisi **webhook secret + URL tunnel aktif** dan nama host mesin | Siapa pun pemegang arsip bisa menembak webhook | `.gitignore`; **rotasi secret** (lihat bawah); host dianonimkan di dokumen | — |
| F-19 | Sedang | probe registry/PowerShell di VM | Uji live Host-B: ≈10–25 s per probe; 6 dari 14 probe timeout (30 s/15 s) → ERROR; registry dibaca lewat proses PowerShell baru tiap rule | Cakupan 57%; indeks dari 8 kontrol saja | `winreg` native; `SCANNER_PROBE_TIMEOUT_SCALE`, `SCANNER_PS_RETRIES`; `coverage_percent` + `--min-coverage` | `test_native_registry_*`, `test_timeout_scale_*`, `test_low_coverage_*` |
| F-18 | Desain | scanner legacy vs rule engine | Dua implementasi dengan semantik berbeda; backend `hardening_parser.py` menyalin regex legacy | Drift; bug F-01/03/04 ikut tersalin ke backend | Scanner berbasis rule engine (`rule_scanner_windows.py`); panduan sinkron backend | `docs/BACKEND_SYNC.md` |

## Koreksi atas audit ini sendiri
F-07 ditarik kembali (lihat tabel). Pelajaran untuk laporan: perbaikan yang berasal dari asumsi (bukan dari uji pada mesin) harus diperlakukan sebagai hipotesis;
hasil uji live (`docs/VALIDATION_RESULTS.md`) yang menangkapnya.

## Belum bisa dibuktikan dari lingkungan audit (jujur)
0. Scanner **legacy** `cis_scanner_windows.py` masih membaca `HKLM\SOFTWARE\Policies\...\Control Panel\Desktop` untuk screen lock (pilihan penulis asli, bukan saya). Verifikasi dengan `reg query` di mesin ber-GPO; bila kunci itu tak pernah ada, check tersebut selalu FAIL.
1. **Snippet PowerShell baru** (secedit GUID, RemoteRegistry `NotInstalled`) belum dieksekusi di Windows. Jalankan checklist di `docs/METHODOLOGY.md` §8 sebelum klaim "teruji".
2. **Nomor referensi CIS** pada YAML tidak diverifikasi terhadap dokumen benchmark. Contoh yang patut dicurigai: WIN-ACCT-LOCKOUT `1.2.1` (di benchmark umum 1.2.1 = *durasi*, threshold = 1.2.2) dan WIN-SCREENLOCK `2.3.7.1`. Cocokkan satu per satu dengan PDF CIS versi yang Anda kutip, atau tulis "terinspirasi CIS".
3. `thor_scanner.py` (323 baris) hanya diperiksa sintaks & pola berbahaya (`shell=True`/`eval`: tidak ada); tidak diaudit mendalam dan tidak punya test.
4. Pemeriksaan di tingkat backend/n8n tidak termasuk (kode tidak ada di arsip ini).

## Tindakan segera (di luar kode)
- **Rotasi `N8N_WEBHOOK_SECRET`** di n8n **dan** semua target; ganti URL tunnel. File `scanner/.env` ada di arsip yang sudah beredar, anggap bocor.
- Hapus `scanner/.env` dari repo/riwayat git bila pernah di-commit.
