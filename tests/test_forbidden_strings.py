# Gate A criterion 2: tidak ada string terlarang di rules/ & docs/
from pathlib import Path
import pytest

FORBIDDEN_ANYWHERE = ("Server 2019", "Windows 11", "CIS-compliant")
EXCLUDE_DIRS = ("archive/", "DEPRECATED/", "results/", "tmp/")

# File yang sengaja memuat string terlarang karena MENDOKUMENTASIKAN fix-nya
# sendiri (audit trail). Setiap penambahan wajib lewat code review.
EXCLUDE_FILES = frozenset({
    "docs/MUTATION_CHECK.md",  # mendokumentasikan mutation yang me-revert forbidden strings
})


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p).replace("\\", "/")
        if any(ex in rel for ex in EXCLUDE_DIRS):
            continue
        if rel in EXCLUDE_FILES:
            continue
        if p.suffix not in (".py", ".yaml", ".yml", ".md", ".txt"):
            continue
        yield p


@pytest.mark.parametrize("root", ["rules", "docs"])
def test_no_forbidden_strings(root):
    root_path = Path(root)
    offenders = []
    for f in _iter_files(root_path):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for needle in FORBIDDEN_ANYWHERE:
            if needle in text:
                offenders.append(f"{f}: {needle!r}")
    assert not offenders, "Forbidden strings:\n" + "\n".join(offenders[:50])
