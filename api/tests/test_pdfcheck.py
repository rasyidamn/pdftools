import hashlib
from io import BytesIO

import pytest
from pypdf import PdfWriter

from app.engine.base import EngineError
from app.pdfcheck import inspect_pdf, verify_output

MB = 1024 * 1024


def make_pdf(n=1):
    w = PdfWriter()
    for _ in range(n):
        w.add_blank_page(width=100, height=100)
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def encrypted_pdf():
    w = PdfWriter()
    w.add_blank_page(width=100, height=100)
    w.encrypt("rahasia")
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def check(data, max_bytes=50 * MB, max_pages=2000):
    return inspect_pdf(BytesIO(data), max_bytes, max_pages)


def test_pdf_sah():
    data = make_pdf(3)
    r = check(data)
    assert r.problem is None and r.pages == 3
    assert r.size == len(data) and r.sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    "data,kode",
    [
        (b"", "EMPTY_FILE"),
        (b"halo ini teks biasa", "NOT_A_PDF"),
        (encrypted_pdf(), "PASSWORD_PROTECTED"),
        (b"%PDF-1.7\nsampah tanpa struktur", None),  # CORRUPT_PDF atau EMPTY_PDF
    ],
)
def test_file_bermasalah(data, kode):
    r = check(data)
    assert r.problem is not None
    if kode:
        assert r.problem[0] == kode
    else:
        assert r.problem[0] in ("CORRUPT_PDF", "EMPTY_PDF")
    assert r.problem[2] in (413, 422)


def test_terlalu_besar_dan_terlalu_banyak_halaman():
    assert check(make_pdf(1), max_bytes=100).problem[0] == "FILE_TOO_LARGE"
    assert check(make_pdf(1), max_bytes=100).problem[2] == 413
    assert check(make_pdf(5), max_pages=4).problem[0] == "TOO_MANY_PAGES"


def test_verifikasi_keluaran(tmp_path):
    p = tmp_path / "o.pdf"
    p.write_bytes(make_pdf(4))
    size, sha, pages = verify_output(p, 4)
    assert pages == 4 and size == p.stat().st_size
    assert sha == hashlib.sha256(p.read_bytes()).hexdigest()


def test_keluaran_buruk(tmp_path):
    p = tmp_path / "o.pdf"
    with pytest.raises(EngineError) as e:  # tidak ada file
        verify_output(p, 1)
    assert e.value.code == "ENGINE_BAD_OUTPUT"
    p.write_bytes(b"")
    with pytest.raises(EngineError) as e:
        verify_output(p, 1)
    assert e.value.code == "ENGINE_BAD_OUTPUT"
    p.write_bytes(b"ini bukan pdf")
    with pytest.raises(EngineError) as e:
        verify_output(p, 1)
    assert e.value.code == "ENGINE_BAD_OUTPUT"
    p.write_bytes(make_pdf(3))  # halaman kurang dari yang diharapkan
    with pytest.raises(EngineError) as e:
        verify_output(p, 4)
    assert e.value.code == "OUTPUT_MISMATCH"


def pdf_lebar(widths):
    w = PdfWriter()
    for x in widths:
        w.add_blank_page(width=x, height=200)
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_ukuran_halaman_dicatat():
    assert check(pdf_lebar([101, 202])).page_sizes == [(101, 200), (202, 200)]


def test_urutan_halaman_sesuai(tmp_path):
    p = tmp_path / "o.pdf"
    p.write_bytes(pdf_lebar([101, 202, 303]))
    _, _, pages = verify_output(p, 3, [(101, 200), (202, 200), (303, 200)])
    assert pages == 3


def test_urutan_halaman_tertukar(tmp_path):
    p = tmp_path / "o.pdf"
    p.write_bytes(pdf_lebar([303, 101, 202]))
    with pytest.raises(EngineError) as e:
        verify_output(p, 3, [(101, 200), (202, 200), (303, 200)])
    assert e.value.code == "OUTPUT_ORDER" and "halaman 1" in e.value.detail
