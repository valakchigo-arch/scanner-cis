"""Penjaga kebersihan repo. Kasus nyata yang melatarinya:
  * run_harness.py berukuran 3 byte (kosong) lolos tanpa disadari;
  * run_scenarios.bat memakai %PYTHON%/%LOG%/%RESULTS%/%SCENARIOS% yang TIDAK PERNAH didefinisikan
    (blok persiapan hilang), tetapi 'verifikasi' hanya menghitung kemunculan teks, bukan keutuhan file."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "venv", "__pycache__", "node_modules", "results", ".pytest_cache"}
SUFFIXES = {".py", ".bat", ".ps1", ".yaml", ".yml", ".md"}
BATCH_BUILTINS = {"DATE", "TIME", "ERRORLEVEL", "TEMP", "TMP", "USERPROFILE", "COMPUTERNAME", "CD", "RANDOM",
                  "PATH", "SYSTEMROOT", "PROGRAMDATA", "APPDATA", "LOCALAPPDATA", "USERNAME", "CMDCMDLINE", "OS",
                  "COMSPEC", "HOMEDRIVE", "HOMEPATH", "PROCESSOR_ARCHITECTURE", "WINDIR"}


def _repo_files(root=ROOT):
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP):
            yield p


def find_tiny_files(root=ROOT):
    return [str(p.relative_to(root)) for p in _repo_files(root)
            if p.suffix in SUFFIXES and p.name != "__init__.py" and p.stat().st_size < 10]


def undefined_bat_vars(text: str) -> set:
    """Variabel %X% / !X! yang dipakai tetapi tidak pernah di-`set` di file batch yang sama."""
    used = set(re.findall(r"%([A-Za-z_][A-Za-z0-9_]*)%", text)) | set(re.findall(r"!([A-Za-z_][A-Za-z0-9_]*)!", text))
    # `set X=` di awal baris, setelah `do`, `(`, `&` atau `|` (mis. `for /f ... do set X=%%a`)
    defined = {m.upper() for m in re.findall(r'(?i)(?:^|[\s(&|])set\s+(?:/[ap]\s+)?"?([A-Za-z_][A-Za-z0-9_]*)=', text, re.M)}
    return {v for v in used if v.upper() not in defined and v.upper() not in BATCH_BUILTINS}


def test_no_near_empty_source_files():
    tiny = find_tiny_files()
    assert not tiny, f"file hampir kosong (mungkin rusak/BOM saja): {tiny}"


def test_tiny_file_finder_catches_the_real_incident(tmp_path):
    """Bukti 'proof of catch': run_harness.py berisi BOM saja (3 byte) HARUS terdeteksi; file normal tidak."""
    (tmp_path / "run_harness.py").write_bytes(b"\xef\xbb\xbf")                     # persis insidennya: 3 byte
    (tmp_path / "ok.py").write_text("print('hi')\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_bytes(b"")                              # __init__ kosong itu sah
    (tmp_path / "data.bin").write_bytes(b"x")                                         # bukan berkas sumber
    assert find_tiny_files(tmp_path) == ["run_harness.py"]


def test_every_batch_file_defines_the_variables_it_uses():
    bad = {}
    for p in _repo_files():
        if p.suffix == ".bat":
            missing = undefined_bat_vars(p.read_text(encoding="utf-8", errors="replace"))
            if missing:
                bad[str(p.relative_to(ROOT))] = sorted(missing)
    assert not bad, bad


def test_batch_checker_catches_the_real_incident(tmp_path):
    broken = '@echo off\ncall :run_scan base\n"%PYTHON%" run.py >> "%LOG%" 2>&1\ncopy "%RESULTS%\\a.json" "%SCENARIOS%\\b.json"\n:run_scan\nset LABEL=%~1\necho %LABEL% %date%\n'
    assert undefined_bat_vars(broken) == {"PYTHON", "LOG", "RESULTS", "SCENARIOS"}
    in_for = "@echo off\nfor /f \"tokens=3\" %%a in ('findstr x f') do set ORIG=%%a\necho %ORIG%\n"
    assert undefined_bat_vars(in_for) == set()            # set di dalam `for ... do` tetap terhitung terdefinisi
    ok = '@echo off\nset "PYTHON=python"\nset LOG=x.log\nset RESULTS=r\nset SCENARIOS=s\n"%PYTHON%" a >> "%LOG%"\ncopy %RESULTS% %SCENARIOS%\n'
    assert undefined_bat_vars(ok) == set()
