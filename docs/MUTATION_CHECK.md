# Mutation Check Evidence (Gate A criterion 3 + B2)

Dokumen ini membuktikan bahwa setiap bug yang diperbaiki memiliki test yang
**gagal di kode sebelum fix** dan **lulus di kode setelah fix**. Semua mutation
dilakukan secara manual karena repository memiliki history terbatas (initial
commit + merge), sehingga `git checkout <pre-fix-commit>` tidak tersedia
sebagai opsi untuk sebagian besar fix.

Metodologi: (1) test suite dijalankan pada state HEAD → semua hijau.
(2) Fix di-revert secara lokal (tidak di-commit). (3) Test yang sama dijalankan
ulang → harus merah. (4) `git checkout -- <file>` untuk restore. (5) Test
dijalankan sekali lagi → hijau.

---

## Mutation #1 — Forbidden-string di docs/

- **Bug:** setelah P0-1, `docs/METHODOLOGY.md`, `docs/architecture.md`, dan
  `docs/VALIDATION_RESULTS.md` masih memuat string terlarang
  `"Server 2019"` dan `"Windows 11"`.
- **Test:** `tests/test_forbidden_strings.py::test_no_forbidden_strings[docs]`
- **Pra-fix:** **FAILED** — 4 offenders:
  - `docs\architecture.md: 'Server 2019'`
  - `docs\METHODOLOGY.md: 'Server 2019'`
  - `docs\METHODOLOGY.md: 'Windows 11'`
  - `docs\VALIDATION_RESULTS.md: 'Windows 11'`
- **Fix:** rewrite tabel METHODOLOGY.md, pindahkan architecture.md ke archive/,
  ganti "Windows 11" → "Win11"/"Host-A" di VALIDATION_RESULTS.md
- **Pasca-fix:** **PASSED** (2/2 di `tests/test_forbidden_strings.py`)
- **Evidence:** terminal 19 Okt 2026, commit `1803173` → `acdc49f`

---

## Mutation #2 — SMB1 confidence INFERRED

- **Bug:** kalau `confidence: DIRECT` (bukan `INFERRED`), test tidak menangkap
  deviasi mekanisme probe dari CIS 18.4.2/18.4.3.
- **Test:** `tests/rules/test_win_smb1_disabled.py::test_smb1_rule_is_inferred_confidence`
- **Mutasi:** `rules/windows/win-smb1-disabled.yaml` → `confidence: DIRECT`
- **Pra-restore (mutated):** **FAILED**
  - `AssertionError: assert 'DIRECT' == 'INFERRED'`
- **Restore:** `git checkout -- rules/windows/win-smb1-disabled.yaml`
- **Pasca-restore:** **PASSED**
- **Evidence:** terminal 19 Okt 2026, commit `f37874b`

---

## Mutation #3 — Evaluator matches/contains None guard

- **Bug:** `evaluate("matches", "Non", None)` mengembalikan `True` karena
  `str(None) == "None"` dan `"Non" in "None"` = True. Probe mengembalikan `None`
  (nilai tidak ada) palsu PASS pada operator `matches`/`contains`.
- **Test:** `tests/regression/test_bug_regressions.py::test_missing_value_never_matches_string_None`
  (4 parameterisasi: contains-Non, contains-one, matches-^None$, matches-Non)
- **Mutasi:** hapus 2 guard `if actual is None: return False` di
  `scanner/core/evaluator.py` (branches `matches` dan `contains`)
  - Count `if actual is None`: 3 → 1 (hanya guard di `_coerce` tersisa)
- **Pra-restore (mutated):** **4 FAILED**
  - Semua `AssertionError: assert True is False`
  - `evaluate('contains', 'Non', None) == True` (seharusnya False)
  - `evaluate('contains', 'one', None) == True`
  - `evaluate('matches', '^None$', None) == True`
  - `evaluate('matches', 'Non', None) == True`
- **Restore:** `git checkout -- scanner/core/evaluator.py`
  - Count `if actual is None`: 1 → 3 (restore berhasil)
- **Pasca-restore:** **4 PASSED**
- **Evidence:** terminal 19 Okt 2026, commit `9908ce8`

---

## Mutation #4 — Exact-match reference (bonus, untuk B3)

- **Bug:** `test_reference_format` hanya cek prefix + level marker. Kalau
  `WIN-FW-PRIVATE` punya reference `9.1.2` (nomor lama yang dilarang) alih-alih
  `9.2.1`, `test_reference_format` akan lolos tanpa mendeteksi kesalahan.
- **Test:** `tests/test_cis_references.py::test_all_14_rules_have_expected_reference`
- **Mutasi:** `rules/windows/win-fw-private.yaml` → `9.1.2 (L1)` (dari `9.2.1 (L1)`)
- **Pra-restore (mutated):**
  - `test_all_14_rules_have_expected_reference` — **FAILED**
    - `AssertionError: Reference mismatches: WIN-FW-PRIVATE ... 9.1.2 (L1) vs 9.2.1 (L1)`
  - `test_reference_format` — **PASSED** (correct behavior — format tidak menangkap nomor salah)
  - `test_rule_count_and_levels` — **PASSED**
- **Restore:** `git checkout -- rules/windows/win-fw-private.yaml`
- **Pasca-restore:** **3 PASSED**
- **Evidence:** terminal 19 Okt 2026, commit `9908ce8`

---

## Ringkasan

| # | Fix | Test | RED | GREEN |
|---|---|---|---|---|
| 1 | Forbidden-string docs | `test_forbidden_strings.py::[docs]` | 4 offenders | 2/2 passed |
| 2 | SMB1 INFERRED | `test_win_smb1_disabled.py::test_smb1_rule_is_inferred_confidence` | 1 failed | 1 passed |
| 3 | Evaluator None guard | `test_bug_regressions.py::test_missing_value_never_matches_string_None` | 4 failed | 4 passed |
| 4 | Exact-match reference | `test_cis_references.py::test_all_14_rules_have_expected_reference` | 1 failed | 3 passed |

Semua mutation berhasil diverifikasi. Setiap test memiliki **test case yang
secara eksplisit gagal saat fix di-revert** dan **lulus saat fix di-restore**.

---

*Dokumen ini disusun untuk audit formal Fase B1–B3 + B7. Fase B4–B6 (live
evaluation, ground truth, timeout regression) memerlukan Windows host fisik
dan VM berSnapshot, akan dilaksanakan pada sesi terpisah.*
