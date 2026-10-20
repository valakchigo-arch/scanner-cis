# PRD: GeoThreat Hardening Scanner

| | |
|---|---|
| **Versi** | 3.0 (draft, menggantikan PRD 2.0) |
| **Tanggal** | 2026-10-20 |
| **Pemilik** | DJBC / GeoThreat (proyek magang yang dikembangkan menjadi skripsi) |
| **Status** | Fase A selesai; B1–B3 dan B7 selesai oleh pemilik; B4–B6 (validasi live Windows) menunggu |
| **Dasar penulisan** | Pembacaan kode, dokumen, dan data mentah di snapshot repo. Test suite **tidak dijalankan** untuk dokumen ini |

**Legenda label bukti** (dipakai di semua dokumen):
`[VERIFIED: sumber]` = terlihat langsung di kode/data mentah/test yang disebut · `[ASSUMED]` = dugaan/target, belum dibuktikan · `[NOT RUN: alasan]` = belum dijalankan.

Dokumen terkait: `SYSTEM_DESIGN.md` (rancangan rinci), `ARCHITECTURE.md` (struktur dan diagram), `AGENTS.md` (aturan untuk AI), `docs/METHODOLOGY.md`, `docs/VALIDATION_RESULTS.md`, `docs/AUDIT_FINDINGS.md`.

---

## 1. Ringkasan produk

GeoThreat Hardening Scanner adalah scanner keamanan konfigurasi yang **berjalan langsung di perangkat target** (Windows dominan, Linux via Lynis). Ia menilai konfigurasi endpoint terhadap sekumpulan kontrol yang dirujuk ke CIS Benchmark, menghasilkan status **PASS / FAIL / ERROR** per kontrol beserta bukti (nilai terbaca, perintah, durasi), lalu mengirim ringkasan terstruktur (kontrak v2) lewat HTTPS ke webhook n8n untuk dipakai backend, dashboard, dan pipeline rekomendasi internal DJBC.

Scanner **tidak** melakukan perbaikan otomatis, tidak mengakses database, tidak memanggil LLM, dan tidak membuka koneksi selain HTTPS ke n8n. `[VERIFIED: scanner/README.md; tidak ada modul DB/LLM di scanner/]`

Produk ini juga merupakan **objek penelitian skripsi**: rancangan rule engine, model tiga status, dan alat validasi perturbasi dibuat agar setiap klaim bisa dibuktikan ulang.

## 2. Masalah

1. Hardening endpoint dilakukan manual dengan checklist yang berbeda antar-operator, sehingga hasilnya tidak konsisten dan tidak bisa dibandingkan antar-endpoint.
2. Hasil audit sulit dibuktikan: tidak ada bukti nilai yang dibaca, tidak ada jejak kapan dan oleh apa.
3. Alat otomatis yang naif menyamakan "gagal mengukur" dengan "kontrol dilanggar". Pada data nyata (Host-A, run tanpa Administrator), 3 dari 4 FAIL adalah artefak: nilai terbaca `''`. `[VERIFIED: docs/VALIDATION_RESULTS.md; results/scenarios/scene awal/baseline_*_20261012T133956Z.json, is_admin=false]`
4. Scanner pada mesin lambat (VM) menghasilkan temuan palsu karena timeout.

## 3. Tujuan dan non-tujuan

### Tujuan
- **G1** Menilai 14 kontrol Windows secara konsisten, tiap hasil disertai bukti yang bisa diverifikasi manual.
- **G2** Memisahkan "dilanggar" (FAIL) dari "tidak bisa dinilai" (ERROR); ERROR tidak boleh menurunkan indeks.
- **G3** Mengirim hasil ke n8n dengan kontrak v2 yang **kompatibel mundur**, dan tidak kehilangan hasil saat jaringan putus (spool).
- **G4** Menyediakan jalur validasi yang bisa direproduksi (baseline, perturbasi, rollback, bandingkan) untuk bab hasil skripsi.
- **G5** Menambah kontrol baru cukup dengan satu berkas YAML plus test, tanpa mengubah engine.

### Non-tujuan
- Remediasi otomatis, push dari pusat, atau orkestrasi jarak jauh (SSH/WinRM/Ansible).
- Cakupan penuh CIS Benchmark (14 kontrol terkurasi ≠ ratusan kontrol).
- Klaim "compliant" penuh, atau klaim cakupan OS di luar basis benchmark (lihat §10).
- Rekomendasi AI di dalam scanner. Rekomendasi AI ada di sisi n8n/BC dan data tidak keluar dari jaringan internal. `[ASSUMED: dari keterangan pemilik; n8n tidak ada di repo]`
- Manajemen secret terintegrasi, dashboard, resolusi kantor (IP→office): semuanya di backend, di luar repo ini.

## 4. Pengguna dan kebutuhan

| Pengguna | Kebutuhan | Fitur yang melayani |
|---|---|---|
| Operator endpoint | Satu perintah → laporan PASS/FAIL/ERROR; aman dijalankan ulang | `rule_scanner_windows.py`, `--dry-run`, `--report` |
| Auditor / pembimbing | Bisa memeriksa satu hasil dengan perintah manual independen | evidence per finding, `docs/METHODOLOGY.md` §8 |
| Backend / dashboard | Payload stabil, tidak pecah saat field bertambah | kontrak v2 (aditif) |
| Peneliti (skripsi / naskah ilmiah) | Data mentah, metodologi, dan keterbatasan yang jujur | `run_rules_live.py`, harness skenario, dokumen audit |
| Pengembang / AI agent | Cara menambah kontrol dan batas perubahan yang aman | `SYSTEM_DESIGN.md` §15, `AGENTS.md` |

## 5. Cakupan produk

### 5.1 Komponen
| Komponen | Status | Catatan |
|---|---|---|
| Scanner Windows berbasis rule engine YAML (`rule_scanner_windows.py`) | **Direkomendasikan** | 14 rule, 3 status |
| Scanner Windows legacy (`cis_scanner_windows.py`) | Dipertahankan karena backend meniru regex-nya | hasilnya **tidak boleh digabung** dengan jalur engine (KI-03) |
| Scanner Linux (`cis_scanner_linux.py`) | Pembungkus Lynis, **bukan CIS** | severity heuristik |
| Scanner THOR (`thor_scanner.py`) | Opsional, di luar fokus skripsi, **belum diaudit dan belum punya test** | KI-09 |
| `run_rules_live.py` | Runner baseline rule engine di mesin nyata | menulis JSON ke `results/` |
| Alat validasi skenario (`tests/scenario_harness.py`, `run_scenarios.bat`, `summarize_scenarios.py`) | Ada, **keduanya bermasalah di snapshot ini** | KI-04, KI-05, KI-06 |

### 5.2 Katalog 14 kontrol Windows (jalur rule engine)
Referensi: *CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0* (hanya nomor bagian; teks benchmark tidak disalin). Tabel dibaca dari `rules/windows/*.yaml`. `[VERIFIED: rules/windows/*.yaml]`

| Rule ID | Severity | Confidence | Kondisi PASS | Sumber nilai | CIS |
|---|---|---|---|---|---|
| WIN-PASS-MINLEN | HIGH | DIRECT | `gte 14` | secedit (PowerShell) | 1.1.4 L1 |
| WIN-PASS-COMPLEX | HIGH | DIRECT | `equals 1` | secedit | 1.1.5 L1 |
| WIN-ACCT-LOCKOUT | HIGH | DIRECT | `in [1..5]` (0 = FAIL) | secedit | 1.2.2 L1 |
| WIN-GUEST-DISABLED | HIGH | DIRECT | `equals false` | `Get-LocalUser` | 2.3.1.2 L1 |
| WIN-SCREENLOCK-TIMEOUT | MEDIUM | DIRECT | `matches` bilangan 1..900 (0 = FAIL) | registry HKLM `Policies\System\InactivityTimeoutSecs` | 2.3.7.4 L1 |
| WIN-LMHASH-DISABLED | HIGH | **INFERRED** | `not_in [0,"0"]` (key tidak ada = PASS) | registry `Lsa\NoLMHash` | 2.3.11.5 L1 |
| WIN-UAC-ENABLED | HIGH | DIRECT | `equals 1` | registry `EnableLUA` | 2.3.17.6 L1 |
| WIN-REMOTEREG-DISABLED | MEDIUM | DIRECT | `equals 4` | registry `RemoteRegistry\Start` | 5.26 **L2** |
| WIN-FW-DOMAIN / -PRIVATE / -PUBLIC | CRITICAL | DIRECT | `equals true` | `Get-NetFirewallProfile` | 9.1.1 / 9.2.1 / 9.3.1 L1 |
| WIN-SMB1-DISABLED | CRITICAL | **INFERRED** | `equals "Disabled"` | `Get-WindowsOptionalFeature SMB1Protocol` | 18.4.2 + 18.4.3 L1 |
| WIN-DEFENDER-ENABLED | CRITICAL | DIRECT | `DisableRealtimeMonitoring equals false` | `Get-MpPreference` | 18.10.43.10.3 L1 |
| WIN-RDP-NLA | CRITICAL | DIRECT | `equals 1` | registry `RDP-Tcp\UserAuthentication` | 18.10.57.3.9.4 L1 |

Komposisi: 13 L1 + 1 L2. `[VERIFIED: tests/test_cis_references.py]` Pemetaan nomor bagian berasal dari tabel pemilik hasil pencocokan ke PDF; penulis dokumen ini **tidak** memeriksa ulang ke PDF `[ASSUMED]`.

Catatan tafsir: "Kondisi PASS" adalah nilai mentah yang lolos, bukan kata "enabled". Contoh: Defender memakai `DisableRealtimeMonitoring = false`; RemoteRegistry `Start = 4` berarti Disabled.

## 6. Persyaratan fungsional

Kolom status: **Impl.** = ada di kode `[VERIFIED: kode]`; **Test** = ada test di repo (tidak dijalankan di sini); **Live** = ada data mentah dari mesin nyata.

| ID | Persyaratan | Impl. | Test | Live |
|---|---|---|---|---|
| FR-1 | **Rule engine**: muat dan validasi YAML; tolak `rule_id` ganda, field wajib hilang, enum salah; rule `os` ≠ host → `NOT_APPLICABLE`; executor tidak pernah melempar exception ke pemanggil | ✔ | ✔ | ✔ (Host-A) |
| FR-2 | **Probe**: `windows.registry` (winreg native, tampilan 64-bit, fallback PowerShell), `windows.powershell` (strict `$ErrorActionPreference='Stop'`, `-EncodedCommand`, timeout + retry); mengembalikan **string mentah** | ✔ | ✔ | ✔ (Host-A, `method: winreg`) |
| FR-3 | **Evaluator**: coerce `actual` ke tipe `expected`; tolak NaN/Inf/`"1_000"`/`"14.0"` untuk int; `None` → FAIL kecuali `not_exists`/`not_in` | ✔ | ✔ | ✔ |
| FR-4 | **Model status** PASS/FAIL/ERROR(+NOT_APPLICABLE): ERROR bukan temuan dan tidak menurunkan indeks; `hardening_index = PASS/(PASS+FAIL)`, `None` bila tidak ada yang dinilai; `coverage_percent`; scan ditolak bila coverage < `--min-coverage` (default 70) | ✔ | ✔ | sebagian |
| FR-5 | **Kontrak beacon v2** (aditif); HTTPS; header `X-Webhook-Secret`, `X-Correlation-Id`; fail-closed tanpa URL/secret | ✔ | ✔ | ✘ |
| FR-6 | **Retry**: exponential backoff untuk 5xx/429/408/error jaringan; **tidak** retry untuk 400/401/403/404/405/413/422 | ✔ | ✔ | ✘ |
| FR-7 | **Spool**: tulis atomik, nama berkas disanitasi, berkas korup dikarantina `.corrupt`, `--flush-spool` | ✔ | ✔ | ✘ |
| FR-8 | **Laporan lokal** `--report` (PASS/FAIL/ERROR + evidence + skor) | ✔ | sebagian | ✘ |
| FR-9 | **Jalur validasi**: baseline, perturbasi, rollback, perbandingan | ada tetapi rusak (KI-04, KI-05) | ✔ (menguji simulasi, bukan probe nyata) | log lama ada |
| FR-10 | **Linux**: parse laporan Lynis; severity heuristik `warning→High`, `sysctl_mismatch→Medium`, `suggestion→Low` | ✔ | ✔ | contoh output ada |

### Perilaku kunci yang tidak boleh berubah tanpa persetujuan
- Probe yang gagal → ERROR, **bukan** FAIL.
- Evaluator mengkoersi ke tipe `expected` (dilarang `normalize()` buta tipe karena `True == 1`).
- Kontrak v2 hanya boleh bertambah field opsional.

## 7. Persyaratan non-fungsional

| Kategori | Persyaratan | Status |
|---|---|---|
| Akurasi | Setiap PASS/FAIL bisa diverifikasi dengan perintah manual independen | Baseline default Host-A cocok dengan `independent_check.txt` `[VERIFIED: results/scenarios/scene awal/independent_check.txt]`; verifikasi ulang untuk rule pasca-perubahan `[NOT RUN: butuh Windows]` |
| Keandalan | Kegagalan probe tidak menjatuhkan scan; hasil tidak hilang saat n8n tidak terjangkau | Ada di kode dan test `[VERIFIED]`; uji ketahanan beacon terukur (delivery rate, loss, duplikat) `[NOT RUN]` |
| Kinerja | Target 14 rule: ≤ 20 s mesin fisik, ≤ 5 menit VM `[ASSUMED: target]` | Fisik teramati ≈ 16 s per scan `[VERIFIED: results/scenarios/scenarios DEVICE VALAK/SCENARIOS DEVICE VALAK 2.txt, selisih timestamp finding]`; VM dengan kode terbaru `[NOT RUN]` (data VM lama: 10–28× lebih lambat, 6 probe timeout → ERROR) |
| Keamanan | Tanpa secret di repo; TLS diverifikasi default; spool 0700/0600 di POSIX; tanpa `shell=True`/`eval` | Kode `[VERIFIED]`; pemindaian riwayat git `[NOT RUN]`; spool di Windows bergantung ACL `ProgramData` `[ASSUMED]` (KI-10) |
| Auditabilitas | Setiap perbaikan punya test RED→GREEN | 4 mutation terdokumentasi `[VERIFIED: docs/MUTATION_CHECK.md]` |
| Reproducibility | Versi rule, versi scanner, OS build, hak akses, waktu tercatat di hasil | Sebagian (OS, `is_admin`, timestamp ada; **hash rule dan versi scanner di `run_rules_live` tidak ada**, KI-16) |
| Portabilitas | Logika diuji di Linux; probe nyata hanya di Windows | `[VERIFIED: skip test e2e Windows pada OS lain]` |

## 8. Kriteria penerimaan dan metrik

### 8.1 Gerbang rekayasa (Fase A)
| Kriteria | Target | Status |
|---|---|---|
| Suite pytest hijau, 0 gagal | seluruhnya | **Angka tidak konsisten antar-dokumen** (README 206, FILES.md 278, TEST_REPORT 148, AUDIT 221, PRD lama 315). Angka resmi = keluaran `python -m pytest` terakhir; catat di `TEST_REPORT.md`. `[NOT RUN]` di sini |
| String terlarang di `rules/` dan `docs/` | 0 | Ada penjaga `tests/test_forbidden_strings.py` `[VERIFIED]`; `docs/MUTATION_CHECK.md` dikecualikan dari pemindaian |
| 14 rule cocok persis dengan tabel referensi | 14/14 | Ada test exact-match `[VERIFIED: tests/test_cis_references.py]` |
| Mutation RED→GREEN terdokumentasi | ≥ 4 | 4 `[VERIFIED: docs/MUTATION_CHECK.md]` |

### 8.2 Metrik validasi live (Fase B4–B6, bahan Bab IV)
| Metrik | Definisi | Target | Status |
|---|---|---|---|
| `detection_rate` | skenario valid yang status akhirnya sesuai harapan ÷ skenario valid | 100% | **belum diukur dengan alat yang benar** |
| `rollback_ok` | mesin kembali ke baseline (nilai dan status, semua kontrol) | 100% | belum |
| `spurious_flips` | kontrol yang tidak disentuh berubah status | 0 | sebagian: tidak terlihat pada log Host-A |
| `ERROR_rate` baseline | ERROR ÷ total kontrol | 0% pada admin | Host-A 0%; non-admin dan VM lambat > 0 |
| `coverage_percent` | dinilai ÷ (dinilai + ERROR) | ≥ 70 untuk kirim | ada di kode |
| Durasi scan | median dan p95, VM dan fisik dipisah | lihat §7 | sebagian |

## 9. Status bukti

### 9.1 Terbukti (dari data mentah di repo)
Pada satu mesin fisik (Host-A, 15 Okt, kode pada saat itu):
- Perubahan setelan **terbaca** di run berikutnya dan status berubah PASS→FAIL lalu kembali PASS setelah rollback: Guest, RemoteRegistry, Firewall Private, Firewall Public, LM hash (`NoLMHash=0`), RDP-NLA, UAC (`EnableLUA=0`, hanya registry). `[VERIFIED: results/scenarios/_scenario_log.txt]`
- Nilai ambang terbaca persis (MinLen 8 → FAIL, Lockout 0 → FAIL), dan kontrol yang tidak disentuh tidak berubah. `[VERIFIED: log yang sama]`
- Model 3-status bekerja: saat VM kehabisan waktu, 6 kontrol tercatat **ERROR** dengan alasan, bukan 6 FAIL palsu. `[VERIFIED: results/scenarios/scenarios VM/.../after_remotereg_on_*.json]`
- Mesin yang sudah diperbaiki (winreg native, secedit dengan GUID dan `$LASTEXITCODE`) menghasilkan nilai yang benar di Host-A (`method: winreg`, `duration_ms: 0` untuk registry). `[VERIFIED: SCENARIOS DEVICE VALAK 2.txt]`

### 9.2 Belum terbukti (jangan diklaim di skripsi)
- Sisi PASS untuk ambang numerik pada rule **baru**: MinLen 14, Lockout 5 (dan 6 → FAIL), Complexity 0→1, ScreenLock 900/901/0 (rule HKLM yang baru).
- Defender, Firewall Domain, SMB1: belum pernah dibalik di mesin nyata.
- Semua data live memakai **versi rule sebelum** pemetaan CIS Win10 v4.0.0 dan rule ScreenLock HKLM (berkas JSON masih berisi referensi benchmark versi lama). Validasi ulang (B4) wajib.
- VM (Host-B) dengan kode terbaru; beberapa host berbeda edisi/bahasa/domain.
- Kesesuaian dengan tool pembanding independen (CIS-CAT/OpenSCAP) dan keandalan beacon terukur.
- Backend/n8n/dashboard tidak ada di repo, sehingga kompatibilitas payload dengan backend nyata `[NOT RUN]`.

## 10. Batasan dan asumsi

- **Benchmark terkunci**: *CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0 (05/23/2025)*. Klaim yang boleh: "**CIS-aligned (state efektif)** terhadap benchmark tersebut". **Dilarang**: klaim kepatuhan penuh, klaim cakupan Win11 atau edisi Server (benchmark-nya tidak diperiksa). Mesin uji Host-A adalah Win11: ini fakta uji yang wajib ditulis sebagai ancaman validitas.
- **Hak cipta CIS**: hanya nomor bagian dan judul singkat; jangan salin teks rekomendasi; jangan masukkan PDF ke repo.
- **Privasi**: anonimkan hostname (Host-A = Win11 fisik, Host-B = Win10 VM); jangan commit `scanner/.env`, secret, atau hasil scan organisasi.
- **Windows wajib** untuk validasi live; Linux hanya untuk uji logika.
- Dua jalur Windows (engine vs legacy) **tidak boleh digabung** hasilnya tanpa menyebut sumber (KI-03).

## 11. Risiko dan ancaman validitas

| Risiko | Dampak | Mitigasi |
|---|---|---|
| Hanya 2 mesin standalone (1 fisik, 1 VM) | Tidak mewakili domain/server | Nyatakan sebagai batasan; tambah mesin bila bisa |
| State efektif ≠ nilai GPO (FW, Defender, RDP-NLA) | Hasil bisa beda dari audit CIS ketat | Dokumentasikan, confidence DIRECT hanya bila mekanisme setara |
| LMHASH dan SMB1 memakai mekanisme berbeda dari CIS | PASS tidak menjamin audit CIS ikut PASS | Confidence `INFERRED` |
| ScreenLock default (key tidak ada) → FAIL di hampir semua mesin non-GPO | Terlihat "banyak temuan" | Dokumentasikan sebagai "belum dikonfigurasi" |
| Alat validasi lama menghasilkan bukti palsu | Bab IV tidak bisa dipertahankan | Ganti dengan harness yang menjalankan probe nyata (patch v3) |
| Evaluator tidak bisa membedakan output sampah dari pelanggaran untuk operator numerik/boolean | FAIL palsu bila probe tidak melempar error | Probe wajib melempar error pada output rusak |
| Dokumen tidak sinkron dengan kode | Reviewer menemukan klaim keliru | Tabel dokumen dihasilkan dari kode; satu daftar KI |

## 12. Roadmap

| Fase | Isi | Status |
|---|---|---|
| A (IMPROVE) | P0-1..P2: referensi CIS, rule ScreenLock HKLM, SMB1 `INFERRED`, kunci semantik evaluator | selesai oleh pemilik; sisa: KI-02, KI-05 |
| B1–B3, B7 | statis, mutation, pemetaan, keamanan | selesai |
| **B4** | validasi live (VM dengan snapshot dulu, lalu host fisik) memakai harness yang benar | **berikutnya** |
| B5 | ground truth independen (5 kontrol acak dengan perintah manual) | menunggu B4 |
| B6 | regresi kinerja dan ketahanan (`SCANNER_PROBE_TIMEOUT_SCALE=0.1` memaksa timeout → ERROR, tidak kirim) | menunggu B4 |
| C (pasca-skripsi) | harness diperluas, deprecate jalur legacy, kontrol tambahan (target 30–40), jalur Linux native | rencana |

## 13. Keputusan terbuka (butuh pemilik)

1. **SMB1**: opsi (a) `INFERRED` dengan satu rule (dipilih sekarang) atau opsi (b) dua rule registry (`mrxsmb10:Start`, `LanmanServer\Parameters:SMB1`) untuk paritas CIS.
2. **`Condition.display`**: rule `matches` membocorkan regex mentah ke `recommended_value` (KI-02). Terima penambahan field `display` opsional atau ubah format di adapter.
3. **Nasib jalur legacy**: dipertahankan sampai backend disinkronkan, atau dijadwalkan dihapus.
4. **Folder `DEPRECATED/`, `results/`, `archive/`** di repo utama: pindahkan ke tag/branch atau `.gitignore` demi privasi dan kejelasan.

## 14. Glosarium

- **Rule**: satu kontrol dalam berkas YAML. **Probe**: pembaca nilai (registry/PowerShell). **Finding**: hasil satu rule.
- **Beacon**: pengiriman HTTPS dari target ke n8n. **Spool**: antrean berkas lokal untuk kiriman yang gagal.
- **Perturbation testing**: mengubah satu setelan, scan, mengembalikan, scan lagi, untuk membuktikan scanner mendeteksi perubahan.
- **INFERRED**: nilai/mekanisme setara tetapi tidak identik dengan yang diaudit CIS.
- **KI-nn**: nomor di daftar masalah yang diketahui (`SYSTEM_DESIGN.md` §14).
