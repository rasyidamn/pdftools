import hashlib
from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader, PdfWriter
from sqlalchemy import text

from app.config import Settings
from app.engine import EngineError, PypdfEngine
from app.main import create_app

SECRET = "rahasia-uji-" + "x" * 30
ADMIN = "AD-LAB\\admin1"
USER = "AD-LAB\\user1"


# ----------------------------------------------------------------- bantu
def make_pdf(widths):
    w = PdfWriter()
    for x in widths:
        w.add_blank_page(width=x, height=200)
    b = BytesIO()
    w.write(b)
    return b.getvalue()


def widths_of(data):
    return [round(float(p.mediabox.width)) for p in PdfReader(BytesIO(data)).pages]


def encrypted_pdf():
    w = PdfWriter()
    w.add_blank_page(width=100, height=100)
    w.encrypt("rahasia")
    b = BytesIO()
    w.write(b)
    return b.getvalue()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def upload(*blobs):
    return [("files", (n, d, "application/pdf")) for n, d in blobs]


def h(user=USER, xff="10.1.1.5"):
    out = {"X-Remote-User": user, "X-Gateway-Secret": SECRET, "User-Agent": "pytest"}
    if xff:
        out["X-Forwarded-For"] = xff
    return out


class Gagal:
    """Mesin tiruan yang selalu gagal dengan kode tertentu."""
    name, health = "gagal", staticmethod(lambda: True)

    def __init__(self, code, detail, status):
        self.err = (code, detail, status)

    def version(self):
        return "uji"

    def merge(self, files, dest):
        raise EngineError(*self.err)


class Sampah(PypdfEngine):
    name = "sampah"

    def merge(self, files, dest):
        dest.write_bytes(b"ini bukan pdf")


class BuangHalaman(PypdfEngine):
    name = "buang"

    def merge(self, files, dest):
        super().merge(files, dest)
        r = PdfReader(str(dest))
        w = PdfWriter()
        for p in list(r.pages)[:-1]:
            w.add_page(p)
        with open(dest, "wb") as f:
            w.write(f)


@pytest.fixture
def env(tmp_path):
    def buat(engine=None, **over):
        base = dict(
            gateway_secret=SECRET,
            database_url=f"sqlite:///{tmp_path / 'audit.db'}",
            admin_users=(ADMIN,),
            tmp_dir=str(tmp_path / "tmp"),
            db_auto_create=True,
        )
        base.update(over)
        app = create_app(Settings(**base), engine=engine or PypdfEngine())
        return TestClient(app), app

    yield buat
    sisa = list((tmp_path / "tmp").glob("*.pdf"))
    assert not sisa, f"file sementara tertinggal: {sisa}"


def fetch(app, rid):
    with app.state.audit.db.connect() as c:
        rows = c.execute(text("SELECT * FROM audit_log WHERE request_id = :r"), {"r": rid}).mappings().all()
        out = []
        for r in rows:
            fs = c.execute(
                text("SELECT * FROM audit_file WHERE audit_id = :i ORDER BY position"), {"i": r["id"]}
            ).mappings().all()
            out.append((dict(r), [dict(f) for f in fs]))
        return out


def jumlah(app, user):
    with app.state.audit.db.connect() as c:
        return c.execute(text("SELECT count(*) FROM audit_log WHERE username=:u"), {"u": user}).scalar_one()


A = ("a.pdf", make_pdf([101, 102]))
B = ("b.pdf", make_pdf([201]))
C = ("c.pdf", make_pdf([301, 302, 303]))


# ----------------------------------------------------------------- sukses
def test_merge_sukses_urutan_dan_audit(env):
    client, app = env()
    r = client.post("/api/merge", files=upload(C, A, B), headers=h(xff="1.2.3.4, 10.1.1.5"))
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert widths_of(r.content) == [301, 302, 303, 101, 102, 201]
    (row, files), = fetch(app, r.headers["x-request-id"])
    assert row["status"] == "SUCCESS" and row["action"] == "MERGE" and row["username"] == USER
    assert row["client_ip"] == "10.1.1.5"  # entri terkanan X-Forwarded-For
    assert row["file_count"] == 3 and row["output_pages"] == 6 and row["engine"] == "pypdf"
    assert row["output_sha256"] == sha(r.content) and row["output_bytes"] == len(r.content)
    assert [f["file_name"] for f in files] == ["c.pdf", "a.pdf", "b.pdf"]
    assert [f["sha256"] for f in files] == [sha(C[1]), sha(A[1]), sha(B[1])]
    assert [f["pages"] for f in files] == [3, 2, 1]


# ----------------------------------------------------------------- ditolak (REJECTED)
def test_satu_file(env):
    client, app = env()
    r = client.post("/api/merge", files=upload(A), headers=h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "TOO_FEW_FILES"
    row, _ = fetch(app, r.headers["x-request-id"])[0]
    assert row["status"] == "REJECTED" and row["error_code"] == "TOO_FEW_FILES"


def test_tanpa_file(env):
    client, _ = env()
    r = client.post("/api/merge", headers=h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "TOO_FEW_FILES"


def test_terlalu_banyak_file(env):
    client, _ = env(max_files=3)
    r = client.post("/api/merge", files=upload(A, B, C, ("d.pdf", make_pdf([1]))), headers=h())
    assert r.status_code == 413 and r.json()["detail"]["code"] == "TOO_MANY_FILES"


def test_bukan_pdf_tercatat_lengkap(env):
    client, app = env()
    palsu = b"halo ini teks biasa"
    r = client.post("/api/merge", files=upload(A, ("palsu.pdf", palsu)), headers=h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "NOT_A_PDF"
    assert "palsu.pdf" in r.json()["detail"]["message"]
    row, files = fetch(app, r.headers["x-request-id"])[0]
    assert row["status"] == "REJECTED" and row["error_code"] == "NOT_A_PDF"
    assert [f["file_name"] for f in files] == ["a.pdf", "palsu.pdf"]
    assert files[1]["sha256"] == sha(palsu)


def test_terenkripsi(env):
    client, _ = env()
    r = client.post("/api/merge", files=upload(A, ("kunci.pdf", encrypted_pdf())), headers=h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "PASSWORD_PROTECTED"


def test_file_kosong(env):
    client, _ = env()
    r = client.post("/api/merge", files=upload(A, ("kosong.pdf", b"")), headers=h())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "EMPTY_FILE"


def test_file_terlalu_besar(env):
    client, _ = env(max_file_bytes=300)
    r = client.post("/api/merge", files=upload(A, B), headers=h())
    assert r.status_code == 413 and r.json()["detail"]["code"] == "FILE_TOO_LARGE"


def test_total_halaman_melebihi_batas(env):
    client, _ = env(max_pages=4)
    r = client.post("/api/merge", files=upload(A, C), headers=h())  # 2 + 3 halaman
    assert r.status_code == 422 and r.json()["detail"]["code"] == "TOO_MANY_PAGES"


def test_content_length_besar_ditolak_dini(env):
    client, app = env(max_total_bytes=1024 * 1024)
    big = b"%PDF-" + b"0" * (7 * 1024 * 1024)
    r = client.post("/api/merge", files=upload(("besar.pdf", big), A), headers=h())
    assert r.status_code == 413 and r.json()["detail"]["code"] == "REQUEST_TOO_LARGE"
    row, _ = fetch(app, r.headers["x-request-id"])[0]
    assert row["status"] == "REJECTED" and row["error_code"] == "REQUEST_TOO_LARGE"


# ----------------------------------------------------------------- mesin gagal (FAILED)
@pytest.mark.parametrize(
    "mesin,kode,status",
    [
        (Gagal("ENGINE_HTTP_500", "boom internal", 502), "ENGINE_HTTP_500", 502),
        (Gagal("ENGINE_UNAVAILABLE", "ConnectError", 503), "ENGINE_UNAVAILABLE", 503),
        (Gagal("ENGINE_TIMEOUT", "ReadTimeout", 504), "ENGINE_TIMEOUT", 504),
        (Sampah(), "ENGINE_BAD_OUTPUT", 502),
        (BuangHalaman(), "OUTPUT_MISMATCH", 502),
    ],
)
def test_mesin_gagal(env, mesin, kode, status):
    client, app = env(engine=mesin)
    r = client.post("/api/merge", files=upload(A, B), headers=h())
    assert r.status_code == status
    assert r.headers["content-type"].startswith("application/json")
    row, files = fetch(app, r.headers["x-request-id"])[0]
    assert row["status"] == "FAILED" and row["error_code"] == kode and len(files) == 2


def test_pesan_ramah_untuk_staf(env):
    client, _ = env(engine=Gagal("ENGINE_HTTP_500", "stacktrace rahasia internal", 502))
    msg = client.post("/api/merge", files=upload(A, B), headers=h()).json()["detail"]["message"]
    assert "stacktrace" not in msg and "tim IT" in msg  # detail teknis tidak bocor ke staf


# ----------------------------------------------------------------- gagal-aman
def test_gagal_aman_bila_audit_tidak_bisa_ditulis(env, monkeypatch):
    client, app = env()
    store = app.state.audit
    asli = store.write

    def tulis(ev):
        if ev.status == "SUCCESS":
            raise RuntimeError("database mati")
        return asli(ev)

    monkeypatch.setattr(store, "write", tulis)
    r = client.post("/api/merge", files=upload(A, B), headers=h())
    assert r.status_code == 503 and r.json()["detail"]["code"] == "AUDIT_UNAVAILABLE"
    assert not r.headers["content-type"].startswith("application/pdf")
    assert jumlah(app, USER) == 0  # dan fixture env memastikan tidak ada file sementara tertinggal