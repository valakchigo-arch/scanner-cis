# Runbook B4: validasi live (Windows)

Semua langkah di bawah **[NOT RUN]** sampai dijalankan di Windows. Jalankan di **VM yang sudah di-snapshot** dulu, baru mesin fisik.
Aturan: jangan lanjut ke langkah berikutnya bila langkah sebelumnya tidak sesuai harapan; tempel keluarannya, jangan menebak.

## 0. Persiapan (sekali)
1. Snapshot VM (beri nama `pra-B4`). Catat nama snapshot.
2. PowerShell **as Administrator**, `cd` ke root project, aktifkan venv, `pip install -r requirements.txt -r requirements-test.txt`.
3. `python -m pytest` → harus hijau (jumlah test = angka di `TEST_REPORT.md`; di Windows 2 test yang tadinya skip ikut berjalan).
4. Pastikan nilai awal sesuai ekspektasi: `python run_rules_live.py --label baseline` → simpan `results\baseline_*.json`. ERROR harus 0.

## 1. Uji aman (tidak mengubah apa pun)
```
python tools/scenario_harness.py --dry-run --baseline-json results\baseline_XXXX.json --host-kind vm
```
Baca kolom verdict tiap skenario. `REJECTED_NOOP` / `SKIPPED_PRECONDITION` berarti skenario itu **tidak akan dijalankan** pada mesin ini (bukan error).

## 2. Uji asap: satu skenario
```
python tools/scenario_harness.py --host-kind vm --host-alias Host-B --confirm-snapshot --only minlen_14 --fast
```
Harapan: `DETECTED`, `rollback_ok=True`. Lalu cek manual bahwa mesin kembali ke baseline: `net accounts` (Minimum password length = nilai baseline).
Bila hasilnya bukan `DETECTED`, **berhenti** dan kirim `results\scenario_*.md` + `.json`.

## 3. Uji penuh
- Cepat (disarankan di VM lambat): tambahkan `--fast`. Mengukur deteksi dan rollback, **tidak** mengukur spurious flip.
- Penuh (tanpa `--fast`): mengukur spurious flip. Perkiraan waktu **[ASSUMED, dari durasi di VALIDATION_RESULTS]**: fisik ± 7–9 menit; VM ± 1–3 jam.
```
python tools/scenario_harness.py --host-kind vm --host-alias Host-B --confirm-snapshot --fast
```
Skenario `smb1_enable` selalu dijalankan **terakhir** dan meninggalkan state pending-restart. **Setelah run selesai: restore snapshot `pra-B4`** (atau restart + pastikan `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` = Disabled).

## 3b. Silang-uji dengan jalur kedua (bat) [opsional, sangat disarankan]
Restore snapshot `pra-B4` dulu (mesin harus kembali ke baseline default), lalu di PowerShell **Administrator**:
```
.\run_scenarios.bat
```
Bat menjalankan baseline, **menolak sendiri bila baseline bukan default** (guard), lalu 11 skenario. Estimasi scan: 38 scan penuh (**[ASSUMED]** fisik ± 7–9 menit; VM ± 1–3 jam).
Ringkasan otomatis (`summarize_scenarios.py`) menandai rollback yang tidak kembali ke baseline dan skenario `after_*` yang tidak berpengaruh. Exit code 2 = ada anomali.
Bandingkan hasilnya dengan harness per kontrol (tabel: kontrol | harness | bat | sepakat?). Skenario 10 pada bat belum pernah dijalankan setelah perbaikan: bila `[SKIP]`, itu aman (tidak ada yang diubah).

## 4. Bila exit code bukan 0
| exit | arti | tindakan |
|---|---|---|
| 1 | ditolak (bukan admin / tanpa `--confirm-snapshot` / skenario tidak valid) | perbaiki penyebab, jalankan ulang |
| 2 | selesai, ada anomali (`DETECTION_FAILURE`, rollback tidak kembali, spurious flip) | **jangan sembunyikan**: itu temuan; kirim laporannya |
| 3 | perintah rollback GAGAL | **restore snapshot sekarang**, jangan jalankan skenario lain |

## 5. Verifikasi independen (B5): 5 kontrol acak
Untuk 5 kontrol, bandingkan nilai `observed` di JSON dengan perintah manual berikut, lampirkan keduanya:
`net accounts` (MinLen, Lockout) · `secedit /export /cfg x.inf` (Complexity) · `Get-NetFirewallProfile` (Firewall) · `sc qc RemoteRegistry` · `reg query <path> /v <key>`.

## 6. Yang dikirim kembali
1. `results\scenario_*.md` dan `.json` (sudah memakai `host_alias`, tanpa hostname asli).
2. Output langkah 0.3 dan 0.4.
3. Hasil B5 (5 pasang nilai).

## 7. Gabungkan banyak run
```
python tools/scenario_harness.py --aggregate results\
```
Menghasilkan detection_rate, rollback_ok_rate, median/p95 durasi, **VM dan fisik dipisah**.
