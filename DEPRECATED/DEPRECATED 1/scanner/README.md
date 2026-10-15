# Scanner (target-local, beacon)

Scanner dijalankan **langsung di perangkat target**. Hasilnya dikirim sebagai beacon HTTPS ke n8n.
Tidak ada SSH, WinRM, Ansible, koneksi PostgreSQL, atau panggilan LLM dari scanner.

```
scanner/
├── common/beacon_contract.py   transport + kontrak payload (satu-satunya modul beacon)
├── common/spool.py             store-and-forward kalau n8n tidak terjangkau
├── linux/cis_scanner_linux.py  lynis lokal -> parse_lynis_report (verbatim) -> beacon
├── linux/beacon.py
├── windows/cis_scanner_windows.py  PowerShell lokal -> CHECKS/score (verbatim) -> beacon
├── windows/beacon.py
├── tests/                      test_beacon.py, test_local_scanners.py
├── scanner.env.example
└── requirements.txt            (requests)
```

## Menjalankan

Salin folder `scanner/` (utuh) ke target, lalu `pip install -r scanner/requirements.txt`.
Isi konfigurasi dari `scanner.env.example`.

Linux (root, lynis terpasang):

    set -a; . scanner/scanner.env; set +a
    sudo -E python3 scanner/linux/cis_scanner_linux.py

Windows (PowerShell sebagai Administrator):

    $env:N8N_WEBHOOK_URL="http://localhost:5678/webhook/geo-threat/scanner-ingest"
    $env:N8N_WEBHOOK_SECRET="<secret>"
    python scanner\windows\cis_scanner_windows.py

Opsi umum: `--dry-run` (cetak payload, tidak kirim), `--flush-spool` (kirim ulang hasil yang tertahan),
`--spool-dir`, `-v`. Linux juga punya `--report-file <lynis-report.dat>` untuk menguji tanpa menjalankan lynis.

Exit code: `0` scan + beacon OK, `1` scan gagal, `2` scan OK tapi beacon gagal (hasil disimpan di spool).

## Kontrak payload (contract_version 2)

    scan_id, source_ip, hostname, device_id, timestamp, severity,
    meta{os_name, os_version, hostname, hardening_index, tests_executed, tests_skipped,
         scan_started_at, scan_finished_at},
    findings[{check_id, category, finding_type, severity, description,
              detail_field, current_value, recommended_value}],
    scanner{name, os, version}

`source_ip` dipakai backend untuk resolusi /24 -> kantor. Di lab, override dengan `SCANNER_SOURCE_IP`.

## Test

    python scanner/tests/test_beacon.py
    python scanner/tests/test_local_scanners.py

## Catatan jujur

- Skor Linux adalah **Lynis hardening index**, bukan CIS Benchmark resmi. Windows: 14 check CIS terkurasi.
  Kalau skripsi menyebut "CIS", jelaskan cakupan ini.
- Check Windows memakai output `net accounts` berbahasa Inggris. Di Windows berlokalisasi lain, check
  password length/lockout bisa salah baca.
