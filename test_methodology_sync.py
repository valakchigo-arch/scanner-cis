"""Tabel semantik di docs/METHODOLOGY.md harus sama dengan perilaku kode (tidak boleh menyimpang diam-diam)."""
import re
from pathlib import Path

from tools.semantics_matrix import render_markdown

DOC = Path(__file__).resolve().parents[1] / "docs" / "METHODOLOGY.md"


def test_semantics_table_in_methodology_matches_code():
    text = DOC.read_text(encoding="utf-8")
    m = re.search(r"<!-- BEGIN:semantics_matrix -->\n(.*?)\n<!-- END:semantics_matrix -->", text, re.S)
    assert m, "blok semantics_matrix tidak ada di METHODOLOGY.md"
    assert m.group(1).strip() == render_markdown().strip(), "tabel semantik tertinggal dari kode: regenerasi dengan tools/semantics_matrix.render_markdown()"
