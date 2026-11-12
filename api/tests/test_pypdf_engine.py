from io import BytesIO

import pytest
from pypdf import PdfReader, PdfWriter

from app.engine.base import EngineError
from app.engine.pypdf_engine import PypdfEngine


def make_pdf(widths):
    """PDF kosong; lebar tiap halaman jadi 'sidik jari' untuk memeriksa urutan."""
    w = PdfWriter()
    for x in widths:
        w.add_blank_page(width=x, height=200)
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def widths_of(path):
    return [round(float(p.mediabox.width)) for p in PdfReader(path).pages]


def test_urutan_mengikuti_kiriman(tmp_path):
    a = BytesIO(make_pdf([101, 102]))
    b = BytesIO(make_pdf([201]))
    c = BytesIO(make_pdf([301, 302, 303]))
    out = tmp_path / "hasil.pdf"
    PypdfEngine().merge([("c.pdf", c), ("a.pdf", a), ("b.pdf", b)], out)
    assert widths_of(out) == [301, 302, 303, 101, 102, 201]


def test_file_rusak_jadi_engine_error(tmp_path):
    bagus = BytesIO(make_pdf([100]))
    rusak = BytesIO(b"bukan pdf sama sekali")
    with pytest.raises(EngineError) as e:
        PypdfEngine().merge([("a.pdf", bagus), ("x.pdf", rusak)], tmp_path / "hasil.pdf")
    assert e.value.code == "ENGINE_MERGE_FAILED"


def test_identitas_mesin():
    e = PypdfEngine()
    assert e.name == "pypdf" and e.version().startswith("pypdf-") and e.health()