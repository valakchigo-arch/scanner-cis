# Metodologi — Hardening Scanner Target-Lokal

## 1. Arsitektur
```
rules/*.yaml ──> rule_loader ──> executor ──> probe (PowerShell/registry) ──> evaluator ──> finding
                                                                                   │
              scoring (hardening index, risk score) <────────────────────────────┤
              contract_adapter ──> beacon_contract ──HTTPS+secret──> n8n ──> backend ──> dashboard
                                         └── spool (store-and-forward bila n8n tidak terjangkau)
```
Scanner berjalan **di target** (tanpa SSH/WinRM/DB/LLM dari scanner). Satu-satunya egress: HTTPS ke n8n.

## 2. Model status tiga-keadaan (kontribusi desain utama)
| Status | Arti | Masuk temuan? | Menurunkan indeks? |
|---|---|---|---|
| PASS | kondisi terpenuhi | tidak | tidak |
| FAIL | kondisi **dinilai** dan dilanggar | **ya** | ya |
| ERROR | probe/evaluasi gagal — *tidak diketahui* | tidak (dihitung `tests_errored`) | tidak |
| NOT_APPLICABLE | rule tidak untuk OS host | tidak | tidak |

Alasan: kegagalan alat ukur bukan bukti pelanggaran kontrol. Versi awal menyamakan keduanya;
pada data nyata (Host-A, run tanpa Administrator) 3 dari 4 FAIL adalah artefak (nilai `''`).

## 3. Rumus
- `hardening_index = PASS / (PASS + FAIL) × 100` atas kontrol yang dinilai; **`None`** bila tidak ada yang dinilai.
- `risk_score = Σ bobot(FAIL) / Σ bobot(PASS+FAIL+MANUAL) × 100`, bobot: CRITICAL 10, HIGH 7, MEDIUM 4, LOW 1.
- Level risiko (batas bawah): MEDIUM ≥25, HIGH ≥50, CRITICAL ≥75.
- `coverage_percent = dinilai / (dinilai + ERROR) × 100` (N/A tidak dihitung); scanner menolak mengirim bila < `--min-coverage` (default 70)
- `complete = (ERROR==0 ∧ UNKNOWN==0)`; `indeterminate = tidak ada kontrol yang dinilai`.
- Severity scan pada kontrak = severity **tertinggi** di antara temuan.

## 4. Prinsip keamanan rancangan
Fail-closed (tanpa URL/secret bawaan; scan batal bila semua kontrol ERROR); secret via env, tak pernah di-log;
TLS diverifikasi default; spool atomik 0600/0700; `-EncodedCommand` + escape literal; payload dibatasi (n8n: ≤500 temuan).

## 5. Katalog kontrol (dihasilkan dari YAML)
| Rule ID | Kategori | Severity | Kondisi PASS | Sumber nilai | Referensi CIS (verifikasi!) |
|---|---|---|---|---|---|
| `WIN-ACCT-LOCKOUT` | authentication | HIGH | `in [1, 2, 3, 4, 5]` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.2.2 (L1) |
| `WIN-DEFENDER-ENABLED` | compromise_indicators | CRITICAL | `equals False` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.10.43.10.3 (L1) |
| `WIN-FW-DOMAIN` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.1.1 (L1) |
| `WIN-FW-PRIVATE` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.2.1 (L1) |
| `WIN-FW-PUBLIC` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 9.3.1 (L1) |
| `WIN-GUEST-DISABLED` | authentication | HIGH | `equals False` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.1.2 (L1) |
| `WIN-LMHASH-DISABLED` | cryptography | HIGH | `not_in [0, '0']` | registry: Lsa\NoLMHash | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.11.5 (L1) |
| `WIN-PASS-COMPLEX` | authentication | HIGH | `equals 1` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.1.5 (L1) |
| `WIN-PASS-MINLEN` | authentication | HIGH | `gte 14` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 1.1.4 (L1) |
| `WIN-RDP-NLA` | network_security | CRITICAL | `equals 1` | registry: RDP-Tcp\UserAuthentication | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.10.57.3.9.4 (L1) |
| `WIN-REMOTEREG-DISABLED` | services | MEDIUM | `equals 4` | registry: RemoteRegistry\Start | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 5.26 (L2) |
| `WIN-SCREENLOCK-TIMEOUT` | authentication | MEDIUM | `matches ^([1-9]\d?|[1-8]\d\d|900)$` | registry: Policies\\System\\InactivityTimeoutSecs | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.7.4 (L1) |
| `WIN-SMB1-DISABLED` | network_security | CRITICAL | `equals Disabled` | powershell: (perintah PowerShell) | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 18.4.2 + 18.4.3 (L1) |
| `WIN-UAC-ENABLED` | authorization | HIGH | `equals 1` | registry: System\EnableLUA | CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0, 2.3.17.6 (L1) |

Catatan membaca tabel: "Kondisi PASS" adalah nilai mentah yang lolos, bukan selalu kata "enabled"
(mis. Defender memakai `DisableRealtimeMonitoring equals False`; RemoteRegistry `Start equals 4` = Disabled).
WIN-LMHASH memakai `not_in [0, '0']`: kunci **tidak ada** dianggap PASS karena Windows modern tidak menyimpan LM hash secara bawaan.

## 6. Bukti empiris
Lihat **`docs/VALIDATION_RESULTS.md`**: 18 run pada 2 mesin (Host-A = Win11 fisik, Host-B = Win10 VM) dengan perturbation testing
— tabel sensitivitas, apa yang terbukti/belum, dan pengukuran kinerja (VM 10–30× lebih lambat; 6 probe timeout → ERROR, bukan FAIL palsu).
Pada Windows bawaan, empat kontrol akun/kata sandi gagal konsisten (MinLen=0, Complexity=0, Lockout=10, ScreenLock tidak diatur); Host-B juga memiliki SMBv1 aktif.

## 7. Ancaman terhadap validitas (tulis di Bab Pembahasan)
1. **Cakupan terbatas**: 14 kontrol terkurasi ≠ CIS Benchmark penuh; Linux = indeks Lynis, bukan CIS.
2. **Heuristik severity Linux** (warning/sysctl/saran) bukan skor standar.
3. **Baseline kecil**: 2 mesin standalone (Host-A fisik, Host-B VM); tidak mewakili server domain (lihat juga item 15).
4. **Ground truth**: `results/independent_check.txt` memverifikasi manual — pertahankan sebagai validasi eksternal.
5. **Lokalisasi**: scanner legacy membaca `net accounts` (bahasa Inggris); rule engine memakai `secedit` (netral bahasa).
6. **Waktu eksekusi bergantung mesin**: VM lambat menghasilkan ERROR (bukan FAIL); atur `SCANNER_PROBE_TIMEOUT_SCALE`.
7. **Ambang numerik belum diuji sisi PASS** (lihat VALIDATION_RESULTS §3).
8. **Antivirus pihak ketiga** dapat membuat WIN-DEFENDER FAIL walau perlindungan aktif.
9. **Basis benchmark ≠ OS mesin uji**: seluruh rule dirujuk ke *CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0*, sedangkan Host-A adalah Win11 fisik (Host-B: Win10 VM). Benchmark untuk Win11 tidak diperiksa. Klaim yang boleh: "CIS-aligned (state efektif) terhadap Win10 Enterprise v4.0.0"; **bukan** "compliant" dan bukan klaim cakupan Win11.
10. **State efektif vs nilai policy**: probe membaca state efektif (cmdlet/secedit/registry), sedangkan audit CIS membaca key GPO. FW×3, Defender, dan RDP-NLA bertujuan sama tetapi sumber berbeda, sehingga di mesin tanpa GPO hasilnya dapat berbeda dari audit CIS yang ketat. LMHASH memperlakukan key yang tidak ada sebagai PASS (CIS meminta `NoLMHash=1` eksplisit), karena itu confidence `INFERRED`.
11. **UAC hanya diuji pada registry**: `EnableLUA` terbaca segera setelah diubah, tetapi efek penuh baru berlaku setelah restart. Skenario UAC memvalidasi *pembacaan nilai*, bukan perilaku UAC.
12. **SMB1 memakai mekanisme berbeda dari CIS 18.4.2/18.4.3** (state fitur opsional vs dua nilai registry), sehingga `INFERRED`. State pending-restart (`EnablePending`/`DisablePending`) dinilai FAIL secara konservatif.
13. **Screen lock**: mesin default (nilai `InactivityTimeoutSecs` tidak ada) menghasilkan FAIL. Itu benar untuk kontrol yang belum dikonfigurasi, tetapi hampir semua mesin non-GPO akan menampilkannya. Nilai 0 (dinonaktifkan) = FAIL.
14. **Semantik evaluator tidak simetris** (lihat bagian 9): `not_in` menganggap nilai apa pun yang tidak terdaftar, termasuk teks sampah, sebagai PASS; `not_equals` dengan nilai tidak ada = FAIL. Penulis rule wajib membaca tabelnya.
15. **Hanya 2 mesin** (1 fisik, 1 VM), keduanya standalone. Tidak mewakili domain/server, edisi lain, maupun bahasa OS lain.
16. **Riwayat alat uji (kejujuran metode)**: harness pertama (`tests/scenario_harness.py`) memasang *mock probe* sehingga tidak pernah menguji probe nyata, dan rollback-nya menulis `None` ke target non-registry. Sembilan test-nya tetap hijau karena hanya menguji `DictTarget` dan unit `CompositeTarget` (lihat `docs/MUTATION_CHECK.md` addendum §3). Harness itu diganti `tools/scenario_harness.py`. Hasil dari harness lama **tidak** boleh dipakai sebagai bukti validasi.
17. **`run_scenarios.bat` bersifat legacy**: rollback-nya hard-coded untuk baseline Windows default dan bergantung pada `net`/`netsh`/`sc`/`secedit`. Guard (`tools/bat_baseline_guard.py`) menolak mesin non-default sebelum mengubah apa pun, tetapi bat tidak memiliki penolakan no-op per skenario seperti harness. Skenario 10 (Complexity via `secedit /configure` dengan INF hasil ekspor penuh) belum pernah dijalankan setelah perbaikan; silang-ujikan dengan skenario `complexity_on` pada harness.

## 8. Checklist verifikasi di Windows (WAJIB sebelum klaim "teruji")
PowerShell **as Administrator** di mesin yang sudah punya baseline:
1. `python -m pytest` → hijau.
2. `python run_rules_live.py --label verify` → nilai MinLen/Complexity/Lockout **sama** dengan baseline (0/0/10), ERROR=0.
3. Cek `%TEMP%`: **tidak ada** `secpol_*.inf` tertinggal.
4. Jalankan lagi **tanpa** Administrator → MinLen/Complexity/Lockout = **ERROR** (bukan FAIL `''`).
5. `python scanner/windows/rule_scanner_windows.py --dry-run` → payload valid; lalu uji beacon ke n8n (staging).
6. `python scanner/windows/cis_scanner_windows.py --dry-run` → RemoteRegistry `PASS` atau `NotInstalled`, Complexity terbaca.

## 9. Semantik evaluator: nilai tidak ada / kosong / tipe salah
Tabel di bawah **dihasilkan dari kode** (`tools/semantics_matrix.py`) dan dijaga `tests/test_methodology_sync.py`; perilakunya dikunci
oleh `tests/test_evaluator_null_semantics.py`. Mengubahnya = perubahan semantik yang wajib dibenarkan di sini.
`PASS`/`FAIL` = hasil kondisi; `ERROR` = operand rule salah (bukan nilai probe).

<!-- BEGIN:semantics_matrix -->
| operator `expected` | actual=None | actual='' | actual='abc' | actual='5' | actual='  ' |
|---|---|---|---|---|---|
| `equals 1` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `equals 'x'` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `equals True` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `not_equals 0` | FAIL | FAIL | FAIL | PASS | FAIL |
| `not_equals 'x'` | FAIL | PASS | PASS | PASS | PASS |
| `gt 5` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `gte 5` | FAIL | FAIL | FAIL | PASS | FAIL |
| `lt 5` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `lte 5` | FAIL | FAIL | FAIL | PASS | FAIL |
| `in [1, 2, 3]` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `not_in [0, '0']` | PASS | PASS | PASS | PASS | PASS |
| `not_in [1, 2]` | PASS | PASS | PASS | PASS | PASS |
| `one_of [1, 2, 3]` | FAIL | FAIL | FAIL | FAIL | FAIL |
| `matches '^[0-9]+$'` | FAIL | FAIL | FAIL | PASS | FAIL |
| `contains 'ab'` | FAIL | FAIL | PASS | FAIL | FAIL |
| `exists None` | FAIL | PASS | PASS | PASS | PASS |
| `not_exists None` | PASS | FAIL | FAIL | FAIL | FAIL |
<!-- END:semantics_matrix -->

Hal yang sengaja dan perlu diperhatikan penulis rule:
- `not_in` + nilai tidak ada/kosong/sampah = **PASS** (dipakai `WIN-LMHASH-DISABLED`: key hilang = default modern).
- `not_equals` + `None` = **FAIL** (tidak dapat dibandingkan); `not_equals` + `""` = FAIL bila expected bukan string, tetapi **PASS** bila expected string.
- `exists` + `""` = PASS (string kosong dianggap ada); hanya `None` yang tidak ada.
- `contains`/`matches` + `None` = FAIL (bukan string `"None"`).
- Tipe salah pada operator numerik/boolean = FAIL, bukan ERROR; probe bertanggung jawab melempar error bila outputnya rusak.

## 10. Jalur validasi live (B4): `tools/scenario_harness.py`
Dua jalur dengan **mekanisme berbeda** sehingga dapat saling menguji: (a) `tools/scenario_harness.py` (utama; cmdlet PowerShell, penolakan no-op, rollback sadar-baseline) dan
(b) `run_scenarios.bat` + `summarize_scenarios.py` (legacy; `net`/`netsh`/`sc`/`reg`, dijaga `tools/bat_baseline_guard.py`). Kesepakatan kedua jalur pada kontrol yang sama
memperkuat bukti; ketidaksepakatan adalah temuan yang harus dianalisis (bukan disembunyikan). Status bat setelah perbaikan: struktur statis dan logika Python **[VERIFIED]**, eksekusi **[NOT RUN]**.
Harness menjalankan **rule dan probe nyata** (`execute_rules`), mengubah setelan lewat PowerShell (`scenarios/windows_scenarios.yaml`,
19 skenario), memverifikasi rollback, dan menghitung metrik. Ia **menolak sebelum menyentuh sistem** bila: nilai harapan sama dengan baseline (no-op),
prasyarat `baseline_must_be` tidak terpenuhi, atau rollback tidak aman (nilai baseline hanya disubstitusi bila berbentuk bilangan bulat).
Rollback dijalankan di `finally`; bila rollback gagal, seluruh run dihentikan (exit code 3).

| outcome | arti |
|---|---|
| `DETECTED` | nilai berubah sesuai harapan dan status rule benar |
| `DETECTION_FAILURE` | nilai berubah sesuai harapan tetapi status rule salah (**temuan nyata tentang scanner**) |
| `SET_INEFFECTIVE` | setelan tidak berlaku (Tamper Protection, pending-restart); **bukan** kesalahan scanner, tidak masuk penyebut detection_rate |
| `ERROR_AFTER` | probe ERROR setelah perubahan (mis. timeout) |
| `REJECTED_NOOP` / `REJECTED_NO_ROLLBACK` / `SKIPPED_*` | tidak dijalankan, beserta alasan |

```
python tools/scenario_harness.py --dry-run --baseline-json results\baseline_X.json                          # aman: hanya menilai validitas
python tools/scenario_harness.py --host-kind vm --host-alias Host-B --confirm-snapshot --only minlen_14    # uji asap 1 skenario
python tools/scenario_harness.py --host-kind vm --host-alias Host-B --confirm-snapshot                     # penuh
python tools/scenario_harness.py --aggregate results\                                                      # VM vs fisik dipisah
```
Status verifikasi: logika harness **[VERIFIED: 9/9 mutan ditangkap pytest]**; perintah Windows pada skenario **[NOT RUN: butuh Windows + snapshot]**.
Artefak keluaran memakai `host_alias` (hostname asli tidak ditulis).

