"""Mesin cadangan berbasis pypdf. Dipakai untuk pembanding (bake-off) dengan Stirling."""
from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Sequence

from pypdf import PdfWriter
from pypdf import __version__ as pypdf_version

from .base import EngineError


class PypdfEngine:
    name = "pypdf"

    def version(self) -> str:
        return f"pypdf-{pypdf_version}"

    def health(self) -> bool:
        return True

    def merge(self, files: Sequence[tuple[str, BinaryIO]], dest: Path) -> None:
        try:
            with PdfWriter() as writer:
                for _name, fp in files:
                    writer.append(fp)
                with open(dest, "wb") as out:
                    writer.write(out)
        except Exception as exc:  # pypdf melempar banyak jenis error
            raise EngineError("ENGINE_MERGE_FAILED", f"{type(exc).__name__}: {exc}"[:300]) from exc