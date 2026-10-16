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
| `WIN-ACCT-LOCKOUT` | authentication | HIGH | `in [1, 2, 3, 4, 5]` | powershell: (perintah PowerShell) | CIS Windows Server 2019 1.2.1 |
| `WIN-DEFENDER-ENABLED` | compromise_indicators | CRITICAL | `equals False` | powershell: (perintah PowerShell) | CIS Windows Server 2019 10.1.1 |
| `WIN-FW-DOMAIN` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Windows Server 2019 9.1.1 |
| `WIN-FW-PRIVATE` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Windows Server 2019 9.1.2 |
| `WIN-FW-PUBLIC` | network_security | CRITICAL | `equals True` | powershell: (perintah PowerShell) | CIS Windows Server 2019 9.1.3 |
| `WIN-GUEST-DISABLED` | authentication | HIGH | `equals False` | powershell: (perintah PowerShell) | CIS Windows Server 2019 2.3.1.5 |
| `WIN-LMHASH-DISABLED` | cryptography | HIGH | `not_in [0, '0']` | registry: Lsa\NoLMHash | CIS Windows Server 2019 2.3.11.6 |
| `WIN-PASS-COMPLEX` | authentication | HIGH | `equals 1` | powershell: (perintah PowerShell) | CIS Windows Server 2019 1.1.5 |
| `WIN-PASS-MINLEN` | authentication | HIGH | `gte 14` | powershell: (perintah PowerShell) | CIS Windows Server 2019 1.1.4 |
| `WIN-RDP-NLA` | network_security | CRITICAL | `equals 1` | registry: RDP-Tcp\UserAuthentication | CIS Windows Server 2019 18.9.63.1 |
| `WIN-REMOTEREG-DISABLED` | services | MEDIUM | `equals 4` | registry: RemoteRegistry\Start | CIS Windows Server 2019 5.30 |
| `WIN-SCREENLOCK-TIMEOUT` | authentication | MEDIUM | `lte 900` | registry: Desktop\ScreenSaveTimeOut | CIS Windows Server 2019 2.3.7.1 |
| `WIN-SMB1-DISABLED` | network_security | CRITICAL | `equals Disabled` | powershell: (perintah PowerShell) | CIS Windows Server 2019 9.2.1 |
| `WIN-UAC-ENABLED` | authorization | HIGH | `equals 1` | registry: System\EnableLUA | CIS Windows Server 2019 2.3.1.3 |

Catatan membaca tabel: "Kondisi PASS" adalah nilai mentah yang lolos, bukan selalu kata "enabled"
(mis. Defender memakai `DisableRealtimeMonitoring equals False`; RemoteRegistry `Start equals 4` = Disabled).
WIN-LMHASH memakai `not_in [0]`: kunci **tidak ada** dianggap PASS karena Windows modern tidak menyimpan LM hash secara bawaan.

## 6. Bukti empiris
Lihat **`docs/VALIDATION_RESULTS.md`**: 18 run pada 2 mesin (Windows 10 fisik, Windows 10 VM) dengan perturbation testing
— tabel sensitivitas, apa yang terbukti/belum, dan pengukuran kinerja (VM 10–30× lebih lambat; 6 probe timeout → ERROR, bukan FAIL palsu).
Pada Windows bawaan, empat kontrol akun/kata sandi gagal konsisten (MinLen=0, Complexity=0, Lockout=10, ScreenLock tidak diatur); Host-B juga memiliki SMBv1 aktif.

## 7. Ancaman terhadap validitas (tulis di Bab Pembahasan)
1. **Cakupan terbatas**: 14 kontrol terkurasi ≠ CIS Benchmark penuh; Linux = indeks Lynis, bukan CIS.
2. **Heuristik severity Linux** (warning/sysctl/saran) bukan skor standar.
3. **Baseline kecil**: 3 host Windows 10 standalone; tidak mewakili server domain.
4. **Ground truth**: `results/independent_check.txt` memverifikasi manual — pertahankan sebagai validasi eksternal.
5. **Lokalisasi**: scanner legacy membaca `net accounts` (bahasa Inggris); rule engine memakai `secedit` (netral bahasa).
6. **Waktu eksekusi bergantung mesin**: VM lambat menghasilkan ERROR (bukan FAIL); atur `SCANNER_PROBE_TIMEOUT_SCALE`.
7. **Ambang numerik belum diuji sisi PASS** (lihat VALIDATION_RESULTS §3).
8. **Antivirus pihak ketiga** dapat membuat WIN-DEFENDER FAIL walau perlindungan aktif.

## 8. Checklist verifikasi di Windows (WAJIB sebelum klaim "teruji")
PowerShell **as Administrator** di mesin yang sudah punya baseline:
1. `python -m pytest` → hijau.
2. `python run_rules_live.py --label verify` → nilai MinLen/Complexity/Lockout **sama** dengan baseline (0/0/10), ERROR=0.
3. Cek `%TEMP%`: **tidak ada** `secpol_*.inf` tertinggal.
4. Jalankan lagi **tanpa** Administrator → MinLen/Complexity/Lockout = **ERROR** (bukan FAIL `''`).
5. `python scanner/windows/rule_scanner_windows.py --dry-run` → payload valid; lalu uji beacon ke n8n (staging).
6. `python scanner/windows/cis_scanner_windows.py --dry-run` → RemoteRegistry `PASS` atau `NotInstalled`, Complexity terbaca.
