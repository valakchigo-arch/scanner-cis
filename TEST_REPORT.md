# Test and hardening report

Date: 2026-10-12

## Automated checks performed

Command:

```bash
python -m pytest -q -rs tests scanner/tests
```

Result: **148 passed, 2 skipped**.

The two skipped tests are `tests/core/test_win_fw_domain_e2e.py` cases requiring Windows PowerShell. This run was performed in a non-Windows environment, so those checks must be rerun on the supported Windows target.

Syntax compilation:

```bash
python -m compileall -q run_rules_live.py scanner tests
```

Result: completed successfully.

## Changes in this package

- Added pytest fixture to start and stop the local mock webhook server for the beacon tests.
- Added atomic spool writes, filename validation for `scan_id`, and best-effort restrictive POSIX permissions.
- Removed the local `scanner/.env` file from this distribution.
- Added `.gitignore`, root dependency manifests, and a root `README.md`.
- Added a spool safety regression test.

## Not yet proven by these checks

- Live scan accuracy on each supported Windows/Linux OS version.
- Compatibility with the organization's real n8n webhook, secret configuration, TLS certificate, or downstream schema.
- Correctness of all CIS claims against the exact benchmark version and organizational policy.
- Production readiness or zero-bug status.

Before any production use, test in an approved lab, verify the payload received by n8n, validate office subnet mapping on the backend, and rotate any credential that may have been exposed in a shared archive or source repository.
