# Sinkron ke backend (`app/services/hardening_parser.py`) — DI LUAR arsip ini

Backend menyalin `CHECKS` legacy (F-18), jadi bug F-01/F-03/F-04 **ikut ada di sana**. Ganti `expected_pattern`
pada entri berikut (file backend tidak ada di arsip ini, tidak bisa saya ubah/tes langsung):

| check_id | pola lama | pola baru |
|---|---|---|
| WIN-PASS-MINLEN | `1[4-9]\|[2-9]\d` | `(?<!\d)(1[4-9]\|[2-9]\d\|1\d\d)(?!\d)` |
| WIN-ACCT-LOCKOUT | `[1-5]\b` | `(?<!\d)[1-5](?!\d)` |
| WIN-SCREENLOCK-TIMEOUT | `^([1-9]\d{0,2}\|900)$` | `^([1-9]\d?\|[1-8]\d\d\|900)$` |
| WIN-REMOTEREG-DISABLED | `Disabled` | `^(Disabled\|NotInstalled)$` |
| WIN-PASS-COMPLEX | `True\|PasswordComplexity\s*=\s*1` | `^PasswordComplexity\s*=\s*1\s*$` |

Jika memakai Ansible: `ansible_hardening/playbooks/vars/windows_checks.yml` **harus** memakai `ps_command` yang sama
dengan `CHECKS` di `cis_scanner_windows.py` untuk WIN-PASS-COMPLEX dan WIN-REMOTEREG-DISABLED (kalau tidak, pola baru tidak cocok).
Jangan ubah pola tanpa mengubah perintahnya.

Payload tetap kompatibel mundur: field baru hanya `meta.tests_errored` dan `meta.errored_check_ids`
(backend membaca kunci meta yang dikenal saja). `meta.hardening_index` kini bisa `null`
(semua kontrol ERROR) — pastikan `_to_int(None)` di `hardening_ingest.py` menghasilkan NULL (sudah begitu menurut kode yang ditampilkan).
Scanner **tidak mengirim** apa pun bila semua kontrol ERROR (exit 1).
