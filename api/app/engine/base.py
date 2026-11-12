"""Antarmuka mesin merge. Mesin bisa ditukar tanpa mengubah login, audit, atau GUI."""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Protocol, Sequence


class EngineError(Exception):
    """Kegagalan mesin. `code` masuk audit; `http_status` dipakai untuk respons ke pengguna."""

    def __init__(self, code: str, detail: str, http_status: int = 502):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.http_status = http_status


class MergeEngine(Protocol):
    name: str

    def version(self) -> str: ...

    def health(self) -> bool: ...

    def merge(self, files: Sequence[tuple[str, BinaryIO]], dest: Path) -> None:
        """Gabungkan `files` (sesuai urutan) lalu tulis hasilnya ke `dest`."""
        ...