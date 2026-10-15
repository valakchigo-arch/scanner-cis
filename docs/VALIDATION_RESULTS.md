# Hasil Uji Validasi Live (18 run, 2 mesin)

Pengujian dilakukan **dengan kode sebelum patch** (rule engine asli + `run_rules_live.py`) pada dua mesin.
Hostname dianonimkan: **Host-A** = Windows 11 (build 26200, mesin fisik); **Host-B** = Windows 10 (build 19045, VM).
Metode: *perturbation / sensitivity testing* — satu setelan diubah, scan dijalankan, setelan dikembalikan (rollback), scan diulang.

## 1. Tabel sensitivitas (nilai terbaca → status)
| Kontrol | Perturbasi | Host-A | Host-B | Menunjukkan |
|---|---|---|---|---|
| WIN-GUEST-DISABLED | Guest diaktifkan | `True` → **FAIL** (PASS 10→9) | `True` → **FAIL** (PASS 9→8) | PASS→FAIL terdeteksi ✔ |
| WIN-REMOTEREG-DISABLED | Start=2 (Automatic) | `2` → **FAIL**; rollback `4` → **PASS** | **ERROR** (timeout) | PASS→FAIL→PASS ✔ (Host-A); **belum terbukti di Host-B** |
| WIN-PASS-MINLEN | 8 dan 13 | `8`, `13` → FAIL | `8` → FAIL | nilai terbaca persis ✔; batas 13 FAIL ✔; **14 → PASS belum diuji** |
| WIN-ACCT-LOCKOUT | 0 ("never lock") | `0` → FAIL | `0` → FAIL | nilai terbaca ✔; **5 → PASS belum diuji** |
| WIN-SCREENLOCK-TIMEOUT | HKCU = 1800 | `1800` → FAIL; rollback `None` | sama | nilai terbaca ✔; **900 → PASS belum diuji** |
| Lainnya (9–10 kontrol) | tidak diubah | stabil di semua run | stabil kecuali saat timeout | **tidak ada flip spontan** |

Temuan nyata (bukan artefak): Host-B memiliki **SMBv1 `Enabled`** (WIN-SMB1-DISABLED = FAIL, CRITICAL) di semua run; Host-A `Disabled`.
Baseline kedua host: MinLen=0, Complexity=0, Lockout=10, ScreenLock tidak diatur → FAIL (default Windows, bukan anomali).

## 2. Apa yang SUDAH terbukti
1. Probe membaca **keadaan live**, bukan cache: tiap perubahan setelan muncul pada `comparison.actual` di run berikutnya.
2. Arah **PASS → FAIL** terdeteksi untuk kontrol boolean/enum (Guest, RemoteRegistry) dan pemulihan FAIL → PASS (RemoteRegistry, Host-A).
3. **Model 3-status bekerja sebagai desain**: saat Host-B kehabisan waktu (run `after_remotereg_on`), 6 kontrol dilaporkan **ERROR dengan alasan**
   (bukan FAIL palsu) — tanpa model itu, 6 temuan palsu akan tampil.
4. Stabilitas: kontrol yang tidak disentuh tidak berubah antar run.

## 3. Apa yang BELUM terbukti (jangan diklaim di skripsi)
- **Sisi PASS untuk ambang numerik**: belum ada run yang membuat MinLen/Lockout/ScreenLock **lulus**. Uji batas wajib: MinLen 13→FAIL ✔, **14→PASS ✘**; Lockout **5→PASS ✘**, 6→FAIL ✘; ScreenLock **900→PASS ✘**, 901→FAIL ✘. Tanpa ini, tidak ada bukti operator `gte/in/lte` benar-benar menghasilkan PASS pada mesin nyata.
- Kontrol tanpa perturbasi sama sekali: Firewall ×3, Defender, SMB1, UAC, RDP-NLA, LM hash, Complexity (0→1).
- RemoteRegistry di Host-B (ERROR akibat timeout).
- Hanya **kode lama** yang diuji. Patch (secedit GUID, `winreg`, retry, coverage) **belum** dijalankan di Windows.

## 4. Kinerja: temuan penting dari data
Durasi dihitung dari timestamp finding pertama → terakhir per run (kasar, abaikan rule pertama):

| Run | Host-A (fisik) | Host-B (VM) | Rasio |
|---|---|---|---|
| `before_screenlock` | 13 s | 167 s | 13× |
| `rollback_screenlock` | 10 s | 99 s | 10× |
| `after_guest_on` | 10 s | 134 s | 13× |
| `after_remotereg_on` | 10 s | 275 s | 28× |

- Host-A: ≈0,4 s per baca registry, ≈0,4–1,3 s per perintah PowerShell. Host-B: **≈10–25 s per probe**, termasuk pembacaan registry sederhana (≈9–12 s) → proses PowerShell yang dimulai berulang lambat di VM (dugaan: CPU/RAM kecil atau pemindaian real-time terhadap `powershell.exe`; **penyebab tidak diukur**).
- Run Host-B `after_remotereg_on`: 6 probe melewati batas (30 s PowerShell / 15 s registry) → ERROR. Ini **bukan bug logika deteksi**, melainkan batas waktu yang tidak cocok untuk mesin lambat.

### Respons di patch ini
| Masalah | Perbaikan |
|---|---|
| Registry dibaca lewat proses PowerShell baru tiap rule | `winreg` bawaan Python (≈ms, tanpa spawn); PowerShell hanya fallback non-Windows |
| Timeout kaku | `SCANNER_PROBE_TIMEOUT_SCALE` (pengali) + `SCANNER_PS_RETRIES` (retry saat timeout, default 1) |
| Laporan dari sebagian kecil kontrol menyesatkan (3/8 = 38%) | `meta.coverage_percent`; scanner **menolak mengirim** bila < `--min-coverage` (default 70) |
| Tidak ada data performa | `duration_ms` per finding; durasi total dicetak |

## 5. Melengkapi matriks (jalankan di VM dulu, buat snapshot; PowerShell **Administrator**)
| Uji | Set | Harapan | Kembalikan |
|---|---|---|---|
| MinLen batas | `net accounts /minpwlen:14` | PASS | `net accounts /minpwlen:0` |
| Lockout batas | `net accounts /lockoutthreshold:5` lalu `:6` | PASS lalu FAIL | `net accounts /lockoutthreshold:10` |
| ScreenLock batas | `reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f` lalu `901` | PASS lalu FAIL | `reg delete "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /f` |
| Firewall Public | `Set-NetFirewallProfile -Name Public -Enabled False` | FAIL | `... -Enabled True` |
| RemoteRegistry (Host-B) | `Set-Service RemoteRegistry -StartupType Automatic` | FAIL | `Set-Service RemoteRegistry -StartupType Disabled` |
Cek akhir Host-B (state tidak diketahui setelah run timeout): `sc qc RemoteRegistry` → harus `DISABLED`.
Lalu jalankan checklist `docs/METHODOLOGY.md` §8 dengan **kode terpatch**: nilai baseline (0/0/10, ERROR=0) harus sama persis dengan run ini.
