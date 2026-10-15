# Clear Scanner — GeoThreat Hardening Scanner

Scanner ini memeriksa konfigurasi keamanan pada endpoint target dan mengirim hasil melalui webhook ke n8n. Source dipertahankan pada arsitektur yang ada: rule-driven Windows scanner (`rules/` + `scanner/core/`), serta target-local Linux/Windows beacon scanner (`scanner/linux/`, `scanner/windows/`, `scanner/common/`). Tidak ada remediation otomatis.

## Arsitektur dan batas tanggung jawab

- `rules/windows/`: deklarasi kontrol Windows berbasis YAML.
- `scanner/core/`: pemuatan/validasi rule, probe, evaluator, executor, dan pembentukan finding.
- `run_rules_live.py`: menjalankan rules Windows pada host Windows lokal dan menyimpan baseline JSON; jalankan hanya pada host yang memang diizinkan untuk diuji.
- `scanner/windows/cis_scanner_windows.py`: scanner Windows target-local yang membentuk hasil dan mengirim beacon.
- `scanner/linux/cis_scanner_linux.py`: menjalankan Lynis lokal atau memproses report Lynis yang sudah tersedia.
- `scanner/common/beacon_contract.py`: kontrak payload, identitas scan, konfigurasi transport, retry, TLS, dan webhook.
- `scanner/common/spool.py`: menyimpan payload saat beacon gagal dan mengirim ulang saat koneksi tersedia.
- `scanner/tests/` dan `tests/`: unit/integration tests.

**Penting:** kedua jalur Windows tidak boleh dianggap sebagai satu implementasi identik. `run_rules_live.py` adalah runner rule YAML; scanner target-local menggunakan daftar pemeriksaan yang didefinisikan pada modul scanner-nya. Jangan menggabungkan hasilnya tanpa menyebut sumber scanner dan cakupan kontrol.

## Prasyarat

- Python 3.10+ (disarankan Python 3.11 atau 3.12 untuk lingkungan yang konsisten).
- Windows PowerShell untuk probe Windows; jalankan elevated hanya jika kontrol memang memerlukannya.
- Linux: Lynis terpasang dan hak akses yang diperlukan untuk audit lokal.
- Endpoint webhook n8n yang dapat dijangkau dari target.
- Dependensi Python sesuai `requirements.txt` dan `requirements-test.txt`.

## Instalasi lokal (Windows PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-test.txt
```

Jika execution policy memblokir aktivasi, gunakan Command Prompt:

```bat
.venv\\Scripts\\activate.bat
```

## Menjalankan test sebelum scan live

Dari root repository:

```powershell
python -m pytest -q -rs tests scanner/tests
python -m compileall -q run_rules_live.py scanner tests
```

Test webhook memakai mock HTTP server lokal; tidak perlu n8n sungguhan. Dua test end-to-end PowerShell akan dilewati pada OS non-Windows. Test pass di mesin pengembang bukan pengganti validasi pada Windows/Linux target yang sebenarnya.

## Menjalankan scanner

### Rule-based Windows baseline

Buka PowerShell pada Windows target/lab yang telah disetujui:

```powershell
python run_rules_live.py --label baseline
```

Untuk eksperimen terkontrol, simpan label yang berbeda pada tiap skenario, misalnya `baseline` dan `after_change`. Script ini hanya melakukan pemeriksaan dan menulis JSON hasil; jangan menambahkan perintah remediation ke dalam probe.

### Scanner Windows beacon

Set konfigurasi pada sesi PowerShell tanpa menaruh secret ke source control:

```powershell
$env:N8N_WEBHOOK_URL = "https://YOUR-N8N-HOST/webhook/geo-threat/scanner-ingest"
$env:N8N_WEBHOOK_SECRET = "<secret-dari-pengelola-n8n>"
$env:SCANNER_VERIFY_TLS = "true"
python scanner\\windows\\cis_scanner_windows.py --dry-run
```

Periksa payload `--dry-run` terlebih dahulu. Hapus `--dry-run` hanya saat endpoint dan secret sudah disetujui serta siap menerima data. Jangan gunakan URL `webhook-test` untuk operasi normal.

### Scanner Linux beacon

Pasang Lynis melalui package manager distribusi Linux, lalu siapkan environment variable dari secret manager atau environment service. Untuk menguji parser tanpa menjalankan audit live:

```bash
python3 scanner/linux/cis_scanner_linux.py --report-file /path/to/lynis-report.dat --dry-run
```

Untuk audit langsung, jalankan pada target yang diizinkan dengan privilege yang dibutuhkan:

```bash
sudo -E python3 scanner/linux/cis_scanner_linux.py --dry-run
```

Setelah payload diperiksa, jalankan tanpa `--dry-run` untuk mengirim. Jangan menjalankan scan privileged pada perangkat produksi tanpa persetujuan pemilik sistem.

### Spool dan retry

Jika pengiriman gagal, scanner menyimpan payload ke spool dan mengembalikan exit code yang menunjukkan scan selesai tetapi beacon gagal. Setelah webhook pulih, gunakan `--flush-spool` dengan konfigurasi environment yang sama. Jangan hapus spool sebelum payload berhasil terkirim atau dicadangkan secara aman.

## Kontrak data dan pemetaan kantor

`contract_version` saat ini `2`. Payload mencakup `scan_id`, `source_ip`, `hostname`, `device_id`, `timestamp`, `severity`, `meta`, `findings`, dan identitas scanner. Backend dapat memakai `source_ip` untuk pemetaan ke jaringan kantor, tetapi pemetaan subnet `/24` harus dikonfigurasi dan divalidasi di backend; scanner tidak boleh menebak kantor berdasarkan hostname atau data yang tidak tersedia.

`SCANNER_SOURCE_IP` hanya untuk override eksplisit di lab atau saat pemilik infrastruktur memastikan alamat yang benar. Tanpa override, scanner mencoba mendeteksi alamat interface yang dipakai untuk memilih route. Pastikan IP yang dilaporkan memang IP endpoint yang sesuai dengan inventory jaringan.

## Interpretasi hasil dan batasan penelitian

- `PASS`, `FAIL`, dan `ERROR` harus dibedakan. `ERROR` berarti pemeriksaan tidak berhasil menghasilkan bukti yang dapat dinilai, bukan bukti bahwa kontrol aman atau tidak aman.
- Skor `hardening_index` dari Lynis bukan otomatis skor kepatuhan CIS. Jangan menyebut keseluruhan scanner sebagai implementasi penuh CIS Benchmark: Windows rule yang tersedia adalah subset kontrol, bukan cakupan lengkap semua kontrol CIS.
- Output kontrol berbasis regex dapat sensitif terhadap versi OS, bahasa output, permission, dan kebijakan domain. Validasi false-positive/false-negative pada target lab yang diketahui.
- Severity dan rekomendasi adalah metadata rule; rekomendasi tidak dijalankan oleh scanner.
- Bukti dapat memuat nama host, alamat IP, konfigurasi, dan detail keamanan. Batasi akses artefak, samarkan data saat menulis skripsi, dan jangan commit hasil scan organisasi tanpa izin.
- Integrasi webhook harus memakai HTTPS dengan verifikasi TLS aktif dan secret di environment/secret manager. `SCANNER_VERIFY_TLS=false` hanya untuk lab terkendali dengan alasan yang terdokumentasi.

## Reproducibility untuk skripsi

Catat versi Python, OS/build, versi Lynis, versi scanner, daftar rule dan hash source, tanggal/waktu scan, status privilege, target lab, konfigurasi kontrol, serta test command dan hasilnya. Lakukan pengukuran baseline dan setelah perubahan kontrol hanya pada lab yang disetujui. Simpan raw evidence secara terbatas dan dokumentasikan kontrol yang tidak bisa diuji.

## Secret dan hygiene repository

Jangan menyimpan `scanner/.env`, `scanner.env`, token, webhook secret, atau konfigurasi produksi di repository/arsip. Gunakan `scanner/scanner.env.example` sebagai template, ganti placeholder di environment lokal, dan rotasi secret jika pernah ter-commit atau dibagikan.
