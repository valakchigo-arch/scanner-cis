# Daftar file patch v2 (menggantikan patch v1 sepenuhnya)

## REPLACE (timpa, path sama)
- `requirements-test.txt`
- `rules/windows/win-acct-lockout.yaml`
- `rules/windows/win-pass-complex.yaml`
- `rules/windows/win-pass-minlen.yaml`
- `rules/windows/win-screenlock-timeout.yaml`
- `run_rules_live.py`
- `scanner/README.md`
- `scanner/common/beacon_contract.py`
- `scanner/common/spool.py`
- `scanner/core/evaluator.py`
- `scanner/core/executor.py`
- `scanner/core/finding_emitter.py`
- `scanner/core/probes/windows_powershell.py`
- `scanner/core/probes/windows_registry.py`
- `scanner/core/rule_loader.py`
- `scanner/core/scoring.py`
- `scanner/linux/cis_scanner_linux.py`
- `scanner/requirements.txt`
- `scanner/tests/test_beacon.py`
- `scanner/tests/test_local_scanners.py`
- `scanner/windows/cis_scanner_windows.py`

## NEW (tambahkan)
- `.gitattributes`
- `.gitignore`
- `conftest.py`
- `docs/AUDIT_FINDINGS.md`
- `docs/BACKEND_SYNC.md`
- `docs/METHODOLOGY.md`
- `docs/VALIDATION_RESULTS.md`
- `pytest.ini`
- `scanner/core/contract_adapter.py`
- `scanner/core/probes/_powershell.py`
- `scanner/windows/rule_scanner_windows.py`
- `tests/regression/__init__.py`
- `tests/regression/test_bug_regressions.py`

## TINDAKAN
- `scanner/.env` -> hapus dari repo + **rotasi N8N_WEBHOOK_SECRET** (berisi secret & URL tunnel aktif)
- `results/*` -> jangan di-commit (nama host)
- hapus semua `__pycache__/`

## Setelah menimpa
```
pip install -r requirements-test.txt
python -m pytest     # harus: 221 passed, 2 skipped
```
Lalu `docs/VALIDATION_RESULTS.md` §5 (lengkapi matriks uji) dan `docs/METHODOLOGY.md` §8 di Windows.
