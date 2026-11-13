"""Validasi PDF masuk dan keluar. Berbasis isi file, bukan ekstensi."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from pypdf import PdfReader

from .engine.base import EngineError

CHUNK = 1024 * 1024
SIZE_TOLERANCE = 1  # poin; selisih pembulatan antar-mesin

PageSize = tuple[int, int]


def page_sizes(reader: PdfReader) -> list[PageSize]:
    """Ukuran (lebar, tinggi) tiap halaman dari mediabox, dibulatkan ke poin terdekat."""
    return [(round(float(p.mediabox.width)), round(float(p.mediabox.height))) for p in reader.pages]


@dataclass
class Inspected:
    size: int
    sha256: str
    pages: int | None
    problem: tuple[str, str, int] | None  # (kode, pesan untuk staf, status HTTP)
    page_sizes: list[PageSize] = field(default_factory=list)


def inspect_pdf(fp: BinaryIO, max_file_bytes: int, max_pages: int) -> Inspected:
    fp.seek(0)
    digest = hashlib.sha256()
    size = 0
    head = b""
    while True:
        chunk = fp.read(CHUNK)
        if not chunk:
            break
        if size == 0:
            head = chunk[:1024]
        digest.update(chunk)
        size += len(chunk)
    sha = digest.hexdigest()

    def bad(code: str, msg: str, status: int = 422) -> Inspected:
        fp.seek(0)
        return Inspected(size, sha, None, (code, msg, status))

    if size == 0:
        return bad("EMPTY_FILE", "File kosong.")
    if size > max_file_bytes:
        return bad(
            "FILE_TOO_LARGE",
            f"Ukuran file melebihi batas {max_file_bytes // (1024 * 1024)} MB.",
            413,
        )
    if b"%PDF-" not in head:
        return bad("NOT_A_PDF", "Bukan file PDF yang valid.")
    try:
        fp.seek(0)
        reader = PdfReader(fp, strict=False)
        if reader.is_encrypted:
            return bad(
                "PASSWORD_PROTECTED",
                "PDF ini terkunci atau terenkripsi. Buka kuncinya lebih dulu.",
            )
        sizes = page_sizes(reader)
        pages = len(sizes)
    except Exception:
        return bad("CORRUPT_PDF", "PDF rusak atau tidak bisa dibaca.")
    if pages == 0:
        return bad("EMPTY_PDF", "PDF tidak memiliki halaman.")
    if pages > max_pages:
        return bad("TOO_MANY_PAGES", f"Jumlah halaman melebihi batas {max_pages}.")
    fp.seek(0)
    return Inspected(size, sha, pages, None, sizes)


def verify_output(
    path: Path, expected_pages: int, expected_sizes: list[PageSize] | None = None
) -> tuple[int, str, int]:
    """Periksa hasil dari mesin. Mengembalikan (ukuran, sha256, jumlah halaman).

    Bila `expected_sizes` diberikan, ukuran tiap halaman hasil harus sama dengan urutan
    halaman masukan. Ini menangkap mesin yang mengubah urutan file.
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise EngineError("ENGINE_BAD_OUTPUT", "tidak ada keluaran", 502) from exc
    if size == 0:
        raise EngineError("ENGINE_BAD_OUTPUT", "keluaran kosong", 502)
    with open(path, "rb") as fp:
        head = fp.read(1024)
        if b"%PDF-" not in head:
            raise EngineError("ENGINE_BAD_OUTPUT", "keluaran bukan PDF", 502)
        fp.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: fp.read(CHUNK), b""):
            digest.update(chunk)
        fp.seek(0)
        try:
            sizes = page_sizes(PdfReader(fp, strict=False))
            pages = len(sizes)
        except Exception as exc:
            raise EngineError("ENGINE_BAD_OUTPUT", "keluaran tidak bisa dibaca", 502) from exc
    if pages != expected_pages:
        raise EngineError(
            "OUTPUT_MISMATCH",
            f"halaman hasil {pages}, seharusnya {expected_pages}",
            502,
        )
    if expected_sizes is not None:
        for i, (got, want) in enumerate(zip(sizes, expected_sizes), 1):
            if abs(got[0] - want[0]) > SIZE_TOLERANCE or abs(got[1] - want[1]) > SIZE_TOLERANCE:
                raise EngineError(
                    "OUTPUT_ORDER",
                    f"halaman {i} berukuran {got[0]}x{got[1]}, seharusnya {want[0]}x{want[1]}",
                    502,
                )
    return size, digest.hexdigest(), pages