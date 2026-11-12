"""Validasi PDF masuk dan keluar. Berbasis isi file, bukan ekstensi."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pypdf import PdfReader

from .engine.base import EngineError

CHUNK = 1024 * 1024


@dataclass
class Inspected:
    size: int
    sha256: str
    pages: int | None
    problem: tuple[str, str, int] | None  # (kode, pesan untuk staf, status HTTP)


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
        pages = len(reader.pages)
    except Exception:
        return bad("CORRUPT_PDF", "PDF rusak atau tidak bisa dibaca.")
    if pages == 0:
        return bad("EMPTY_PDF", "PDF tidak memiliki halaman.")
    if pages > max_pages:
        return bad("TOO_MANY_PAGES", f"Jumlah halaman melebihi batas {max_pages}.")
    fp.seek(0)
    return Inspected(size, sha, pages, None)


def verify_output(path: Path, expected_pages: int) -> tuple[int, str, int]:
    """Periksa hasil dari mesin. Mengembalikan (ukuran, sha256, jumlah halaman)."""
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
            pages = len(PdfReader(fp, strict=False).pages)
        except Exception as exc:
            raise EngineError("ENGINE_BAD_OUTPUT", "keluaran tidak bisa dibaca", 502) from exc
    if pages != expected_pages:
        raise EngineError(
            "OUTPUT_MISMATCH",
            f"halaman hasil {pages}, seharusnya {expected_pages}",
            502,
        )
    return size, digest.hexdigest(), pages