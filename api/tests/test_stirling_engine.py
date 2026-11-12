"""Menguji StirlingEngine terhadap Stirling TIRUAN (server kecil di komputer ini).

Ini membuktikan kode kita benar terhadap bentuk API yang kita ASUMSIKAN.
Perilaku Stirling asli diperiksa nanti di VM (Langkah 9).
"""

import threading
import time
from io import BytesIO

import pytest
import uvicorn
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import Response
from pypdf import PdfReader, PdfWriter

from app.config import load_settings
from app.engine import EngineError, PypdfEngine, StirlingEngine, build_engine


def make_pdf(widths):
    w = PdfWriter()
    for x in widths:
        w.add_blank_page(width=x, height=200)
    buf = BytesIO()
    w.write(buf)
    return buf.getvalue()


def widths_of(path):
    return [round(float(p.mediabox.width)) for p in PdfReader(path).pages]


class Fake:
    def __init__(self):
        self.mode = "ok"
        self.calls = []
        app = FastAPI()

        @app.get("/api/v1/info/status")
        def status():
            return {"status": "UP"}

        @app.post("/api/v1/general/merge-pdfs")
        def merge(
            fileInput: list[UploadFile] = File(...), sortType: str | None = Form(None)
        ):
            self.calls.append(
                {"names": [f.filename for f in fileInput], "sortType": sortType}
            )
            if self.mode == "http500":
                return Response("boom internal", status_code=500)
            if self.mode == "slow":
                time.sleep(3)
            w = PdfWriter()
            for f in fileInput:
                for p in PdfReader(f.file).pages:
                    w.add_page(p)
            buf = BytesIO()
            w.write(buf)
            return Response(buf.getvalue(), media_type="application/pdf")

        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
        )
        threading.Thread(target=self.server.run, daemon=True).start()
        while not self.server.started:
            time.sleep(0.05)
        port = self.server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def fake():
    f = Fake()
    yield f
    f.server.should_exit = True


@pytest.fixture(autouse=True)
def _reset(fake):
    fake.mode = "ok"
    fake.calls.clear()


def test_merge_urutan_dan_parameter(fake, tmp_path):
    eng = StirlingEngine(fake.url, version_label="stirling-uji")
    files = [
        ("c.pdf", BytesIO(make_pdf([301, 302, 303]))),
        ("a.pdf", BytesIO(make_pdf([101, 102]))),
        ("b.pdf", BytesIO(make_pdf([201]))),
    ]
    out = tmp_path / "hasil.pdf"
    eng.merge(files, out)
    assert widths_of(out) == [301, 302, 303, 101, 102, 201]
    assert fake.calls[0]["names"] == ["c.pdf", "a.pdf", "b.pdf"]
    assert fake.calls[0]["sortType"] == "orderProvided"
    assert eng.version() == "stirling-uji" and eng.health()


def test_http_error(fake, tmp_path):
    fake.mode = "http500"
    eng = StirlingEngine(fake.url)
    with pytest.raises(EngineError) as e:
        eng.merge(
            [("a.pdf", BytesIO(make_pdf([1]))), ("b.pdf", BytesIO(make_pdf([2])))],
            tmp_path / "x.pdf",
        )
    assert (
        e.value.code == "ENGINE_HTTP_500"
        and "boom" in e.value.detail
        and e.value.http_status == 502
    )


def test_mesin_mati(tmp_path):
    eng = StirlingEngine("http://127.0.0.1:1")
    assert eng.health() is False
    with pytest.raises(EngineError) as e:
        eng.merge(
            [("a.pdf", BytesIO(make_pdf([1]))), ("b.pdf", BytesIO(make_pdf([2])))],
            tmp_path / "x.pdf",
        )
    assert e.value.code == "ENGINE_UNAVAILABLE" and e.value.http_status == 503


def test_timeout(fake, tmp_path):
    fake.mode = "slow"
    eng = StirlingEngine(fake.url, timeout_s=1.0)
    with pytest.raises(EngineError) as e:
        eng.merge(
            [("a.pdf", BytesIO(make_pdf([1]))), ("b.pdf", BytesIO(make_pdf([2])))],
            tmp_path / "x.pdf",
        )
    assert e.value.code == "ENGINE_TIMEOUT" and e.value.http_status == 504


def test_build_engine_memilih_mesin():
    base = {
        "GATEWAY_SECRET": "x" * 30,
        "DATABASE_URL": "sqlite://",
        "ADMIN_USERS": r"AD-LAB\user2",
    }
    assert isinstance(
        build_engine(load_settings({**base, "ENGINE": "pypdf"})), PypdfEngine
    )
    s = build_engine(load_settings({**base, "STIRLING_URL": "http://stirling:8080/"}))
    assert isinstance(s, StirlingEngine)
