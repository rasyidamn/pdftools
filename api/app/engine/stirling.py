"""Mesin Stirling-PDF lewat API. Stirling hanya dijangkau dari jaringan internal Docker."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Sequence

import httpx

from .base import EngineError

MERGE_PATH = "/api/v1/general/merge-pdfs"
STATUS_PATH = "/api/v1/info/status"


class StirlingEngine:
    name = "stirling"

    def __init__(
        self, base_url: str, timeout_s: float = 300.0, version_label: str = "unknown"
    ):
        self._label = version_label
        self._client = httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(timeout_s, connect=5.0),
            follow_redirects=False,
        )

    def version(self) -> str:
        return self._label

    def health(self) -> bool:
        try:
            return self._client.get(STATUS_PATH, timeout=3.0).status_code == 200
        except httpx.HTTPError:
            return False

    def merge(self, files: Sequence[tuple[str, BinaryIO]], dest: Path) -> None:
        # Nama field 'fileInput' diulang per file (sesuai dokumentasi API Stirling).
        # sortType=orderProvided meminta Stirling mempertahankan urutan kiriman.
        multipart = [("fileInput", (name, fp, "application/pdf")) for name, fp in files]
        data = {"sortType": "orderProvided"}
        try:
            with self._client.stream(
                "POST", MERGE_PATH, files=multipart, data=data
            ) as r:
                if r.status_code != 200:
                    body = r.read()[:400].decode("utf-8", "replace")
                    raise EngineError(
                        f"ENGINE_HTTP_{r.status_code}",
                        body or "tanpa isi",
                        http_status=502,
                    )
                with open(dest, "wb") as out:
                    for chunk in r.iter_bytes():
                        out.write(chunk)
        except httpx.TimeoutException as exc:
            raise EngineError(
                "ENGINE_TIMEOUT", type(exc).__name__, http_status=504
            ) from exc
        except httpx.TransportError as exc:
            raise EngineError(
                "ENGINE_UNAVAILABLE", type(exc).__name__, http_status=503
            ) from exc
