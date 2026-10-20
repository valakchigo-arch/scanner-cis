# SYSTEM DESIGN: GeoThreat Hardening Scanner

| | |
|---|---|
| **Versi** | 1.0 (draft) · 2026-10-20 |
| **Dasar** | Pembacaan kode snapshot repo (static). Test suite dan skrip Windows **tidak dijalankan** untuk dokumen ini |
| **Pendamping** | `PRD.md` (apa dan mengapa), `ARCHITECTURE.md` (struktur dan diagram), `AGENTS.md` (aturan AI) |

Legenda: `[VERIFIED: sumber]` terlihat di kode/data · `[ASSUMED]` dugaan/target · `[NOT RUN: alasan]` belum dijalankan.

Dokumen ini menjelaskan **bagaimana** sistem bekerja: model data, alur eksekusi, semantik evaluasi, kontrak, kegagalan, dan keputusan desain. Struktur komponen dan diagram ada di `ARCHITECTURE.md`.

---

## 1. Prinsip desain

| # | Prinsip | Wujud di kode |
|---|---|---|
| P1 | **Gagal mengukur ≠ pelanggaran** | probe gagal → `ERROR` (bukan `FAIL`); ERROR tidak jadi temuan dan tidak menurunkan indeks |
| P2 | **Fail-closed** | tanpa `N8N_WEBHOOK_URL`/`N8N_WEBHOOK_SECRET` beacon menolak kirim; coverage < `--min-coverage` → scan dibatalkan |
| P3 | **Target-lokal** | scanner berjalan di endpoint; tidak ada SSH/WinRM/DB/LLM; satu-satunya egress: HTTPS ke n8n |
| P4 | **Kontrak aditif** | kontrak v2 hanya boleh bertambah field opsional; backend lama tetap jalan |
| P5 | **Data, bukan kode** | kontrol = berkas YAML; engine tidak berubah saat kontrol bertambah |
| P6 | **Bukti per temuan** | tiap finding membawa nilai terbaca, sumber, perintah/path, durasi, alasan error |
| P7 | **Tidak ada remediasi otomatis** | `remediation.action` hanya teks |
| P8 | **Bisa direproduksi** | hasil lengkap disimpan sebagai JSON; validasi lewat baseline → perturbasi → rollback |

## 2. Model data

### 2.1 Rule (berkas `rules/windows/*.yaml`)
Divalidasi oleh `Rule.validate()` `[VERIFIED: scanner/core/rule_model.py, rule_loader.py]`.

| Field | Wajib | Nilai / catatan |
|---|---|---|
| `rule_id` | ✔ | unik di satu direktori; duplikat → `RuleValidationError` |
| `title` | ✔ | teks singkat |
| `category` | ✔ | `authentication`, `authorization`, `network_security`, `logging`, `cryptography`, `patching`, `services`, `filesystem`, `audit`, `update`, `compromise_indicators` |
| `os` | ✔ | `windows` \| `linux` \| `any` |
| `standard` | ✔ | mapping dengan `name` wajib; `reference` dan `level` adalah metadata (tidak dibaca kode lain) |
| `severity` | ✔ | `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` `UNCLASSIFIED` |
| `confidence` | ✔ | `DIRECT` (mekanisme setara audit CIS) · `INFERRED` (setara tetapi tidak identik) · `MANUAL` |
| `condition` | ✔ | `operator` (13 jenis, §4) + `expected_value` |
| `probe` | ✔ | `provider` (`windows.registry` \| `windows.powershell`) + `params` |
| `remediation` | ✔ | mapping dengan `action` wajib (hanya teks) |
| `description`, `version` | – | `version` default `"1.0"` |

`condition` dan `probe` yang bukan mapping ditolak dengan `RuleValidationError`; direktori rule tidak ada → `RuleValidationError`. File dibaca UTF-8.

### 2.2 ProbeResult
`ProbeResult(value, evidence, raw_output)`. `value` adalah **string mentah** atau `None` (nilai tidak ada). Evaluator, bukan probe, yang mengubah tipe.

### 2.3 Finding (rule engine)
Kunci: `finding_id`, `control_id`, `title`, `category`, `status`, `severity`, `confidence`, `timestamp`, `standard`, `description`, `comparison{operator, expected, actual}`, `evidence`, `remediation`; opsional `error_detail` (alasan ERROR/NOT_APPLICABLE) dan `duration_ms` (PASS/FAIL/ERROR; tidak untuk NOT_APPLICABLE). `[VERIFIED: finding_emitter.py, executor.py]`

Status: `PASS`, `FAIL`, `ERROR`, `NOT_APPLICABLE` (scoring juga mengenal `MANUAL`, `UNKNOWN`).

### 2.4 Kontrak beacon v2
Payload (`ScanResult.to_dict()`) `[VERIFIED: scanner/common/beacon_contract.py]`:

```
contract_version, scan_id, source_ip, hostname, device_id, timestamp, severity,
meta{ os_name, os_version, hostname, hardening_index, tests_executed, tests_skipped,
      tests_errored, coverage_percent, scan_started_at, scan_finished_at },
findings[{ check_id, description, severity, detail_field, current_value,
           recommended_value, category, finding_type }],
scanner{ name, os, version }
```

- `meta` hanya memuat kunci di whitelist `_META_KEYS`. **`errored_check_ids` sengaja/tidak sengaja tidak termasuk** → tidak terkirim (KI-01).
- `scan_id`: `windows-<uuid>`, `linux-<uuid>` (default `gt-<uuid>`).
- `severity` payload = severity **tertinggi** di antara temuan (`max_severity`); `Low` bila tidak ada.
- `device_id` = `dev-` + 16 hex pertama SHA-256 dari `/etc/machine-id` (Linux) atau `MachineGuid` (Windows), cadangan hostname/MAC. `source_ip` ditentukan lewat `connect()` UDP ke 192.0.2.1 (tanpa mengirim paket), bisa di-override `SCANNER_SOURCE_IP`.

## 3. Alur eksekusi rule engine

```
load_rules_from_dir ──► untuk tiap rule: execute_rule(rule, scan_id, index, host_os)
                          1. host_os diberikan dan rule.os ∉ {any, host_os}  → NOT_APPLICABLE
                          2. execute_probe → registry.get(provider)(params)
                                gagal / bukan ProbeResult                     → ERROR (+error_detail)
                          3. evaluate_condition(operator, expected, probe.value)
                                True → PASS · False → FAIL · EvaluationError  → ERROR
                          4. emit_finding(...)  (+ duration_ms)
```

Jaminan: `execute_rule` **menangkap semua exception** dan mengembalikan finding berstatus ERROR; satu rule rusak tidak menggagalkan scan. `[VERIFIED: executor.py]`

## 4. Semantik evaluator

### 4.1 Koersi (`_coerce`, tipe `expected` menentukan target)
| Target | Diterima | Ditolak |
|---|---|---|
| `bool` | string `true/yes/enabled/on/1` dan `false/no/disabled/off/0` (tanpa peduli huruf besar), int 0/1 | string lain, int selain 0/1 |
| `int` | string `^-?\d+$` (setelah `strip`), float bulat berhingga, bool | `"1_000"`, `"14.0"`, `"abc"`, NaN, Inf |
| `float` | string integer/desimal berhingga, int, bool | NaN, Inf, teks |
| `str` | string apa adanya (cocok tipe persis), int/float/bool → `str()` | `None` |

Ketidakcocokan tipe menghasilkan **FAIL, bukan ERROR** (keputusan terkunci). Konsekuensinya: output sampah dari probe untuk operator numerik/boolean terbaca sebagai pelanggaran. Karena itu **probe wajib melempar error pada output rusak** (P1).

### 4.2 Operator
`equals`, `not_equals`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, `one_of` (alias `in`), `matches` (regex `re.search`), `contains`, `exists`, `not_exists`.
Operand salah (bukan list untuk `in`/`not_in`, regex tidak valid, `matches` dengan expected bukan string, operator tidak dikenal) → `EvaluationError` → status ERROR.

### 4.3 Perilaku nilai tidak ada / kosong (dikunci oleh `tests/test_evaluator_null_semantics.py`)
- `None` tidak pernah memenuhi perbandingan nilai (→ FAIL), **kecuali** `not_exists` (PASS) dan `not_in` (PASS).
- `not_in` memberi **PASS untuk nilai apa pun yang tidak terdaftar**, termasuk `None`, `""`, dan teks sampah. Disengaja untuk `WIN-LMHASH-DISABLED` (key hilang = default modern), tetapi artinya `not_in` tidak mendeteksi output rusak.
- `not_equals` + `None` → FAIL; `not_equals` + `""` → FAIL bila `expected` bukan string, tetapi **PASS** bila `expected` string.
- `exists` + `""` → PASS (string kosong dianggap ada); hanya `None` yang dianggap tidak ada.
- `contains`/`matches` + `None` → FAIL (bukan string `"None"`).
- `True` dikoersi ke 1 untuk target int (`lt 10 True` → PASS). Karena itu fungsi `normalize()` buta tipe **dilarang**.

Mengubah salah satu perilaku di atas adalah perubahan semantik yang harus dibenarkan di dokumen metodologi.

## 5. Probe

### 5.1 `windows.registry`
Urutan: `winreg` native (jika modul tersedia) → fallback PowerShell (non-Windows/CI). `[VERIFIED: probes/windows_registry.py]`
- Tampilan registry 64-bit (`KEY_WOW64_64KEY`) walau Python 32-bit; hive didukung `HKLM/HKCU/HKU/HKCR`, selain itu `ProbeExecutionError`.
- Value **tidak ada** → `value=None` dan `evidence.note="value_not_present"`; error lain (izin, dsb.) → `ProbeExecutionError`.
- Nilai non-string diformat ke string (`bytes` → hex, list → baris).
- Jalur PowerShell meng-escape `'` (digandakan) dan memakai marker `__NOT_FOUND__`; `strict=False` karena ketiadaan value adalah kondisi normal.
- `evidence.method` = `winreg` atau `powershell`.

### 5.2 `windows.powershell`
- Skrip dikirim via `-EncodedCommand` (UTF-16LE base64), keluaran dipaksa UTF-8, `$ErrorActionPreference='Stop'` secara default (`strict=true`) sehingga kegagalan cmdlet/secedit menjadi `rc≠0` → ERROR. `[VERIFIED: probes/_powershell.py, windows_powershell.py]`
- Timeout default 30 s (registry fallback 15 s), dikalikan `SCANNER_PROBE_TIMEOUT_SCALE` (default 1.0, minimum 0.1); retry saat timeout `SCANNER_PS_RETRIES` (default 1).
- Tiga rule `secedit` memakai berkas sementara dengan GUID, memeriksa `$LASTEXITCODE`, mengekstrak angka dengan regex, dan menghapus berkas di `finally`. `[VERIFIED: rules/windows/win-pass-*.yaml, win-acct-lockout.yaml]`

## 6. Status, indeks, dan skor

### 6.1 Adapter kontrak (`contract_adapter.findings_to_contract`)
| Status | Perlakuan |
|---|---|
| PASS | tidak dikirim; dihitung di `tests_executed` |
| FAIL | menjadi satu finding kontrak |
| ERROR/UNKNOWN | **bukan** temuan; dihitung di `tests_errored` dan `tests_skipped` |
| NOT_APPLICABLE | tidak dikirim; dihitung di `tests_skipped` |

Rumus: `assessed = PASS + FAIL`; `hardening_index = round(100·PASS/assessed)` atau **`None`** bila `assessed = 0`; `tests_executed = assessed`; `tests_skipped = ERROR + N/A`; `coverage_percent = round(100·assessed/(assessed+ERROR))` (0 bila penyebut 0).

Pemetaan finding FAIL: `severity` → `Critical/High/Medium/Low` (`INFO` dan `UNCLASSIFIED` → `Low`); `finding_type="cis_check"`; `description` = judul rule; `detail_field` = rule_id; `current_value` dipotong 150 karakter atau `"(kosong/tidak terdeteksi)"`; `recommended_value` = operator + expected (mis. `>= 14`, `= 1`, `in [1, 2, 3, 4, 5]`). Untuk operator `matches`, `recommended_value` berisi **regex mentah** (KI-02).

### 6.2 Skor (`scoring.compute_score`)
Bobot: CRITICAL 10, HIGH 7, MEDIUM 4, LOW 1, INFO 0, UNCLASSIFIED 0 (dapat diganti via JSON). `risk_score = Σ bobot(FAIL) / Σ bobot(PASS+FAIL+MANUAL) × 100`. Level (batas bawah): MEDIUM ≥ 25, HIGH ≥ 50, CRITICAL ≥ 75, selain itu LOW. Bidang tambahan `complete` (tanpa ERROR/UNKNOWN) dan `indeterminate` (tidak ada kontrol yang dinilai).

Catatan: untuk kasus "tidak ada yang dinilai", `scoring` mengembalikan `hardening_index = 100.0` (dengan `indeterminate=true`) sedangkan adapter mengembalikan `None` (KI-08). Konsumen **harus** membaca flag, bukan hanya angka.

## 7. Scanner dan orkestrasi

### 7.1 `rule_scanner_windows.py` (v3.0.0, direkomendasikan)
Alur: muat rule → `execute_rules` → `findings_to_contract` → gerbang → `ScanResult` → `beacon_send` → bila gagal `spool_payload`.

| Flag | Fungsi |
|---|---|
| `--rules DIR` | direktori rule (default `<repo>/rules/windows`) |
| `--report FILE` | simpan laporan lengkap (PASS/FAIL/ERROR + evidence + skor) |
| `--dry-run` | cetak payload; boleh di non-Windows |
| `--min-coverage PCT` | default 70; di bawahnya → exit 1, tidak kirim (0 = nonaktif) |
| `--allow-non-admin` | lewati cek Administrator |
| `--flush-spool`, `--spool-dir`, `-v` | kirim ulang spool, direktori spool, verbose |

Exit code: `0` scan dan beacon OK · `1` scan gagal/ditolak · `2` scan OK tetapi beacon gagal (di-spool). Tanpa `--dry-run`, program menolak berjalan di non-Windows.

### 7.2 `cis_scanner_windows.py` (v2.1.0, legacy)
Daftar `CHECKS` (regex atas keluaran PowerShell). Tiga keadaan juga berlaku: keluaran berawalan `__ERROR__` atau kosong pada check bertanda `empty_is_error` (MinLen, Complexity, Lockout) → ERROR. Check lain yang menghasilkan keluaran kosong (mis. cmdlet dengan `SilentlyContinue`) tetap dinilai **FAIL** (KI-12). Semua tool berbeda dari jalur engine; lihat KI-03.

### 7.3 Linux (`cis_scanner_linux.py`, v2.0.0)
`lynis audit system` → `/var/log/lynis-report.dat` (butuh root) → `parse_lynis_report` → kontrak. Severity **heuristik** karena Lynis tidak memberi severity: `warning→High`, `sysctl_mismatch→Medium`, `suggestion→Low`, `manual→Low`. Skor Linux = indeks Lynis, **bukan** CIS. `--report-file` memungkinkan uji tanpa menjalankan Lynis.

### 7.4 THOR (`thor_scanner.py`)
Di luar fokus skripsi; belum diaudit dan belum punya test (KI-09).

## 8. Beacon dan spool

### 8.1 Transport `[VERIFIED: beacon_contract.send_payload]`
- Header: `Content-Type: application/json`, `X-Webhook-Secret`, `X-Correlation-Id` (= `scan_id`). Secret tidak pernah di-log.
- `verify=VERIFY_TLS` (default benar); `SCANNER_VERIFY_TLS=false` memunculkan peringatan.
- Kebijakan retry:

| Kejadian | Tindakan |
|---|---|
| 2xx | selesai |
| 400, 401, 403, 404, 405, 413, 422 | **tidak** retry (kesalahan klien) |
| 5xx, 429, 408, error jaringan/timeout | retry dengan backoff `delay·2^(n-1)`, maksimum 60 s, tanpa tidur setelah percobaan terakhir |
| habis percobaan | `RuntimeError("Failed to send …")` |

Default: `MAX_RETRIES=3`, `RETRY_DELAY=5 s`, `TIMEOUT=30 s`. Nilai env rusak/di bawah minimum → default + peringatan (tidak crash saat import).

### 8.2 Spool `[VERIFIED: scanner/common/spool.py]`
- Lokasi default: `%ProgramData%\GeoThreatScanner\spool` (Windows), `/var/lib/geo-threat-scanner/spool` (Linux), atau `SCANNER_SPOOL_DIR`.
- Tulis atomik (`.json.tmp` → `os.replace`); nama berkas = `scan_id` yang disanitasi (hanya `[A-Za-z0-9._-]`, maks 120) sehingga tidak bisa keluar dari direktori.
- Direktori 0700 dan berkas 0600 di POSIX; di Windows `chmod` tidak berefek (KI-10).
- `flush_spool` → `(terkirim, gagal)`; berkas yang bukan JSON-objek atau korup dikarantina `*.json.corrupt` (tidak dihapus, tidak gagal berulang). Berkas yang gagal dikirim tetap ada.

## 9. Konfigurasi

| Variabel | Default | Fungsi |
|---|---|---|
| `N8N_WEBHOOK_URL` | – (wajib) | URL produksi webhook (bukan `webhook-test`) |
| `N8N_WEBHOOK_SECRET` | – (wajib) | sama dengan secret di n8n |
| `SCANNER_MAX_RETRIES` / `SCANNER_RETRY_DELAY` / `SCANNER_TIMEOUT` | 3 / 5 / 30 | parameter retry dan timeout HTTP |
| `SCANNER_VERIFY_TLS` | true | `false` hanya untuk lab bersertifikat self-signed |
| `SCANNER_SOURCE_IP`, `SCANNER_DEVICE_ID` | otomatis | override identitas (lab) |
| `SCANNER_SPOOL_DIR` | lihat §8.2 | direktori spool |
| `SCANNER_PROBE_TIMEOUT_SCALE` | 1.0 | pengali timeout PowerShell (mesin lambat) |
| `SCANNER_PS_RETRIES` | 1 | retry saat timeout PowerShell |

Template: `scanner/scanner.env.example`. `scanner/.env` dan `scanner.env` **tidak boleh** di-commit.

## 10. Kegagalan dan perilaku sistem

| Kegagalan | Perilaku | Status |
|---|---|---|
| Bukan Administrator | secedit/Defender/SMB → ERROR (bukan FAIL); engine menolak jalan tanpa `--allow-non-admin` | ✔ `[VERIFIED: kode; data non-admin lama menunjukkan FAIL palsu sebelum perbaikan]` |
| VM lambat (timeout) | ERROR + retry + skala timeout; coverage < 70% → scan batal | ✔ kode; VM dengan kode terbaru `[NOT RUN]` |
| Probe mengembalikan tipe salah | ERROR | ✔ |
| Rule YAML rusak | gagal saat muat (`RuleValidationError`), scan tidak mulai | ✔ |
| n8n tidak terjangkau | retry → spool → exit 2; `--flush-spool` kemudian | ✔ kode dan test |
| Spool korup | dikarantina, sisanya tetap dikirim | ✔ |
| Semua kontrol ERROR | scan batal (exit 1), tidak kirim | ✔ |
| Output sampah untuk operator numerik/boolean | terbaca FAIL (batas desain §4.1) | diketahui |

## 11. Desain keamanan

| Aset | Ancaman | Mitigasi | Residu |
|---|---|---|---|
| Webhook secret | bocor lewat repo/log | env saja; tidak di-log; `.env` di luar repo | riwayat git belum dipindai `[NOT RUN]` |
| Payload (hostname, IP, temuan) | disadap | HTTPS + verifikasi TLS default | `VERIFY_TLS=false` di lab |
| Berkas spool | dibaca pengguna lokal lain | 0700/0600 di POSIX | ACL Windows bergantung `ProgramData` `[ASSUMED]` |
| File rule | injeksi lewat nilai `command`/`path` | `-EncodedCommand`, escape `'`, rule hanya dari direktori terpercaya | rule berbahaya yang sengaja ditulis = kepercayaan pada pemilik repo |
| Webhook endpoint | replay/tebak secret | secret statis (bukan HMAC); `scan_id` unik | tidak ada tanda tangan/timestamp (di sisi n8n) |
| Hasil di `results/` | kebocoran hostname | anonimkan sebelum dipublikasikan | KI-11 |
| Perintah skenario | merusak mesin | wajib snapshot dan VM; rollback terverifikasi | KI-05 |

Larangan: `shell=True`, `eval`/`exec`, mengeksekusi isi hasil scan, memasukkan secret ke source.

## 12. Desain pengujian dan validasi

1. **Unit/regresi**: `tests/core`, `tests/rules`, `tests/regression`, `scanner/tests`. Setiap bug yang diperbaiki punya test yang gagal pada kode lama dan lulus pada kode baru.
2. **Pernyataan kunci**: `tests/test_cis_references.py` (14 referensi persis), `tests/test_evaluator_null_semantics.py`, `tests/test_forbidden_strings.py` (hanya memindai `rules/` dan `docs/`).
3. **Mutation check manual**: `docs/MUTATION_CHECK.md` (4 mutasi, RED→GREEN).
4. **Perturbation testing (live)**: baseline → ubah satu setelan → scan → rollback → scan; verifikasi (a) rule target berubah sesuai harapan, (b) kontrol lain tidak berubah, (c) rollback kembali ke baseline. Skenario no-op (nilai target sama dengan baseline) **tidak sah**; contoh: Complexity "off" saat baseline sudah 0.
5. **Pembanding independen**: perintah manual (`net accounts`, `secedit /export`, `reg query`, `Get-NetFirewallProfile`, `sc qc`) untuk ≥ 5 kontrol acak (B5).
6. **Kondisi pengujian wajib**: VM dengan snapshot, Administrator, lalu mesin fisik.

Keterbatasan alat yang ada sekarang: lihat KI-04 s.d. KI-06.

## 13. Log keputusan (ADR ringkas)

| ID | Keputusan | Alasan | Konsekuensi |
|---|---|---|---|
| D1 | Status tiga keadaan (ERROR ≠ FAIL) | data nyata: 3 FAIL palsu (non-admin) dan 6 timeout VM | indeks bisa `None`; coverage wajib |
| D2 | Evaluator mengkoersi ke tipe `expected` | mencegah `True == 1` meloloskan nilai salah | mismatch tipe = FAIL |
| D3 | `not_in` + nilai tidak ada = PASS | LM hash tidak disimpan secara default pada Windows modern | `confidence: INFERRED` |
| D4 | ScreenLock memakai `matches ^([1-9]\d?\|[1-8]\d\d\|900)$` pada `InactivityTimeoutSecs` (HKLM) | `lte 900` meloloskan 0 (batas dinonaktifkan); HKCU hanya mewakili akun scanner | `recommended_value` berisi regex (KI-02) |
| D5 | SMB1 tetap 1 rule dengan `INFERRED` (opsi a) | kontrak 14 rule, optional-feature adalah sumber nyata yang diubah operator | mekanisme berbeda dari CIS 18.4.2/18.4.3 |
| D6 | secedit sebagai satu-satunya sumber kebijakan sandi | domain: kebijakan efektif; standalone: lokal; netral bahasa | butuh Administrator |
| D7 | Registry via `winreg` native | PowerShell per-baca lambat di VM | jalur PowerShell hanya cadangan |
| D8 | Kontrak v2 aditif | backend tidak ada di repo dan tidak boleh pecah | field baru hanya opsional |
| D9 | Target-lokal tanpa Ansible/WinRM | arsitektur beacon sudah dipakai BC | operator menjalankan scanner di tiap target |

## 14. Daftar masalah yang diketahui (KI)

Setiap butir terbaca dari kode atau data di snapshot repo `[VERIFIED]` kecuali ditandai lain. Severity: Tinggi / Sedang / Rendah.

| ID | Sev. | Masalah | Bukti | Arah perbaikan |
|---|---|---|---|---|
| KI-01 | Rendah | `errored_check_ids` dihitung adapter tetapi **tidak terkirim** (tidak ada di `_META_KEYS`); `docs/BACKEND_SYNC.md` dan PRD lama menyebutnya sebagai field payload | `beacon_contract._META_KEYS`, `contract_adapter` | tambahkan ke whitelist **atau** koreksi dokumen |
| KI-02 | Sedang | `recommended_value` rule `matches` berisi regex mentah (`matches ^(...)$`) ke dashboard/AI | `contract_adapter._fmt_expected` | field `condition.display` opsional (tersedia di patch v3) |
| KI-03 | Tinggi (desain) | Dua jalur Windows berbeda: severity (Guest HIGH vs Medium; ScreenLock MEDIUM vs Low), mekanisme (MinLen/Lockout: secedit vs `net accounts` bahasa Inggris; SMB1: optional-feature vs `Get-SmbServerConfiguration`), LMHASH (key hilang = PASS vs FAIL), ScreenLock legacy membaca path HKLM Policies yang tidak terverifikasi | `rules/windows/*.yaml` vs `CHECKS` | jangan gabungkan hasil; sinkronkan backend lalu hapus legacy |
| KI-04 | Tinggi | `tests/scenario_harness.py` memasang **mock provider** (tidak pernah menjalankan probe nyata), tidak memulihkan provider global, `CompositeTarget` memakai `DictTarget` untuk registry, rollback pada target non-registry menulis `None`; 9 test hijau tidak menangkapnya | eksperimen pada versi harness yang sama (skenario `complexity_1_pass` → `detected=False`) | ganti dengan harness yang memanggil `execute_rules` asli (`tools/scenario_harness.py` di patch v3) |
| KI-05 | Tinggi | `run_scenarios.bat` di snapshot: tidak ada blok persiapan (`%PYTHON%`, `%LOG%`, `%RESULTS%`, `%SCENARIOS%` tidak didefinisikan), baris `rollback_screenlockREM` menyatu, Skenario 1 sebelum baseline, tanpa cek admin, rollback hard-coded; log 15 Okt membuktikan versi lama pernah jalan | isi `run_scenarios.bat`, `results/scenarios/_scenario_log.txt` | patch v3 (persiapan ditulis ulang + guard baseline) |
| KI-06 | Sedang | `summarize_scenarios.py` memotong label bernama `after_x_y` jadi `after` (skenario saling menimpa, cek rollback dilewati) dan hanya membandingkan himpunan FAIL | `extract_label` memakai `rsplit('_', 2)` | versi baru (patch v3) membandingkan status dan nilai semua kontrol |
| KI-07 | Sedang | Dokumentasi tidak sinkron: jumlah test (206/278/148/221/315 di lima dokumen); `AUDIT_FINDINGS` masih menyebut referensi CIS "belum diverifikasi"; README mengarahkan menyalin hanya `scanner/` padahal `rule_scanner_windows` membutuhkan `rules/` | README, FILES.md, TEST_REPORT.md, AUDIT_FINDINGS.md | satu sumber angka (output pytest); tabel dokumen dihasilkan dari kode |
| KI-08 | Rendah | `compute_score` → `hardening_index=100.0` saat tidak ada kontrol dinilai; adapter → `None` | `scoring.py`, `contract_adapter.py` | baca `indeterminate`; seragamkan di rilis berikut |
| KI-09 | Sedang | THOR: severity huruf besar (`CRITICAL`) vs peringkat berkunci kapital-awal sehingga severity payload selalu `Low`; `hostname` diisi IP; `control_id` memakai `hash()` (tidak stabil antar proses); `default_spool_dir("thor")` menghasilkan path Linux di Windows; meta tambahan terbuang oleh whitelist; tanpa test | `thor_scanner.py` | di luar skripsi; tandai eksperimental atau perbaiki bila dipakai |
| KI-10 | Sedang | Spool di Windows: `chmod` tidak berefek; ACL `ProgramData` mungkin mengizinkan pengguna lokal lain membaca `[ASSUMED: perlu dicek dengan icacls]` | `spool.py` | set ACL eksplisit atau pindah ke direktori khusus admin |
| KI-11 | Sedang | `results/` berisi hostname asli; `archive/` memuat identitas pribadi; `DEPRECATED/` memuat dua salinan lama seluruh proyek (kode dan hasil) | pohon repo | pindahkan ke tag/branch atau `.gitignore`; anonimkan sebelum publikasi |
| KI-12 | Sedang | Legacy: check tanpa `empty_is_error` (Defender, FW, UAC, Guest, dll.) yang keluarannya kosong karena error ditelan `SilentlyContinue` dinilai FAIL | `CHECKS` | gunakan jalur engine (strict) |
| KI-13 | Rendah | Evaluator: output sampah → FAIL (numerik/boolean) atau PASS (`not_in`) | `evaluator.py` | probe yang menjamin format; atau tambahkan operator `strict` bila perlu |
| KI-14 | Rendah | UAC hanya diuji di registry; efek penuh butuh restart | `WIN-UAC-ENABLED` | dokumentasikan; tidak mewakili perilaku UAC |
| KI-15 | Sedang | `run_rules_live.py` tidak mencatat hash rule, versi scanner, versi Python; klaim reproducibility di PRD lama tidak terpenuhi | `run_rules_live.py` | tambahkan metadata ke JSON hasil |
| KI-16 | Rendah | `pytest_out.txt` biner di akar repo | pohon repo | hapus atau abaikan |

## 15. Panduan perluasan

### 15.1 Menambah kontrol Windows
1. Tentukan nomor bagian dan level dari **PDF benchmark** (jangan dari ingatan atau AI).
2. Buat `rules/windows/win-<nama>.yaml` dengan field §2.1; pilih `confidence` sesuai kesetaraan mekanisme.
3. Probe: pakai `windows.registry` bila nilai ada di registry; PowerShell harus memeriksa `$LASTEXITCODE`/melempar error pada output rusak, tidak boleh membuang error.
4. Bila memakai `matches`, isi tampilan yang ramah baca (lihat KI-02) dan uji batas (nilai di bawah, tepat, di atas, 0, `None`).
5. Tambahkan test di `tests/rules/` (PASS, FAIL, nilai tidak ada, batas) dan perbarui `tests/test_cis_references.py`.
6. Perbarui tabel katalog di dokumen metodologi; jalankan seluruh test.
7. Verifikasi live (B4): minimal satu skenario PASS→FAIL→PASS dengan rollback terverifikasi.

### 15.2 Menambah provider probe
Daftarkan di `scanner/core/__init__.py` (`registry.register`). Fungsi menerima `params` dan mengembalikan `ProbeResult` (string mentah atau `None`), atau melempar `ProbeExecutionError`. Jangan membuang kegagalan menjadi output kosong.

### 15.3 Mengubah kontrak
Hanya tambah field **opsional**; perbarui `_META_KEYS`/`to_dict`, tes kontrak (`scanner/tests`), dan `docs/BACKEND_SYNC.md`. Perubahan yang bukan aditif memerlukan `contract_version` baru dan persetujuan pemilik backend.
