from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfWriter
from sqlalchemy import text

from app.config import Settings
from app.engine import PypdfEngine
from app.main import create_app

SECRET = "rahasia-uji-" + "x" * 30
ADMIN = "AD-LAB\\admin1"
USER = "AD-LAB\\user1"


def make_pdf(n=1):
    w = PdfWriter()
    for _ in range(n):
        w.add_blank_page(width=100, height=100)
    b = BytesIO()
    w.write(b)
    return b.getvalue()


A = ("a.pdf", make_pdf(2))
B = ("b.pdf", make_pdf(1))


def upload(*blobs):
    return [("files", (n, d, "application/pdf")) for n, d in blobs]


def h(user=USER):
    return {
        "X-Remote-User": user,
        "X-Gateway-Secret": SECRET,
        "X-Forwarded-For": "10.1.1.5",
    }


@pytest.fixture
def env(tmp_path):
    app = create_app(
        Settings(
            gateway_secret=SECRET,
            database_url=f"sqlite:///{tmp_path / 'audit.db'}",
            admin_users=(ADMIN,),
            tmp_dir=str(tmp_path / "tmp"),
            db_auto_create=True,
        ),
        engine=PypdfEngine(),
    )
    return TestClient(app), app


def fetch(app, rid):
    with app.state.audit.db.connect() as c:
        return [
            dict(r)
            for r in c.execute(
                text("SELECT * FROM audit_log WHERE request_id=:r"), {"r": rid}
            ).mappings()
        ]


def test_non_admin_ditolak_dan_dicatat(env):
    client, app = env
    r = client.get("/admin/audit", headers=h())
    assert r.status_code == 403
    assert client.get("/admin", headers=h()).status_code == 403
    assert client.get("/admin/verify", headers=h()).status_code == 403
    assert client.get("/admin/audit.csv", headers=h()).status_code == 403
    (row,) = fetch(app, r.headers["x-request-id"])
    assert (
        row["action"] == "ADMIN_DENIED"
        and row["status"] == "REJECTED"
        and row["username"] == USER
    )


def test_admin_melihat_audit_dan_pembacaan_tercatat(env):
    client, app = env
    for _ in range(3):
        assert (
            client.post("/api/merge", files=upload(A, B), headers=h()).status_code
            == 200
        )
    r = client.get(
        "/admin/audit", params={"username": USER, "limit": 2}, headers=h(ADMIN)
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3 and len(body["rows"]) == 2
    assert body["rows"][0]["files"][0]["file_name"] == "a.pdf"
    hal2 = client.get(
        "/admin/audit",
        params={"username": USER, "limit": 2, "offset": 2},
        headers=h(ADMIN),
    ).json()
    assert len(hal2["rows"]) == 1
    (view,) = fetch(app, r.headers["x-request-id"])
    assert (
        view["action"] == "AUDIT_VIEW"
        and view["username"] == ADMIN
        and USER in view["detail"]
    )


def test_filter_status_dan_validasi(env):
    client, _ = env
    client.post("/api/merge", files=upload(A, B), headers=h())
    client.post("/api/merge", files=upload(A), headers=h())  # ditolak
    ok = client.get(
        "/admin/audit",
        params={"username": USER, "status": "REJECTED"},
        headers=h(ADMIN),
    ).json()
    assert ok["total"] == 1 and ok["rows"][0]["error_code"] == "TOO_FEW_FILES"
    assert (
        client.get(
            "/admin/audit", params={"status": "HACK"}, headers=h(ADMIN)
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/admin/audit", params={"since": "kemarin"}, headers=h(ADMIN)
        ).status_code
        == 422
    )


def test_verifikasi_lewat_endpoint(env):
    client, app = env
    client.post("/api/merge", files=upload(A, B), headers=h())
    r = client.get("/admin/verify", headers=h(ADMIN))
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["head_hash"]
    (row,) = fetch(app, r.headers["x-request-id"])
    assert row["action"] == "AUDIT_VERIFY"


def test_csv_aman_dari_formula(env):
    client, app = env
    client.post("/api/merge", files=upload(("=1+1.pdf", b"bukan pdf"), A), headers=h())
    r = client.get("/admin/audit.csv", params={"username": USER}, headers=h(ADMIN))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    teks = r.content.decode("utf-8-sig")
    baris = teks.strip().splitlines()
    assert baris[0].startswith("id,ts_utc,username") and len(baris) == 2
    assert ",'=1+1.pdf" in baris[1]  # sel yang diawali '=' diberi awalan petik
    assert ",=1+1" not in baris[1]
    (export,) = fetch(app, r.headers["x-request-id"])
    assert export["action"] == "AUDIT_EXPORT"


def test_admin_tidak_peka_huruf_besar_kecil(env):
    client, _ = env
    assert client.get("/admin/audit", headers=h(ADMIN.upper())).status_code == 200


def test_gagal_aman_pembacaan_audit(env, monkeypatch):
    client, app = env
    monkeypatch.setattr(
        app.state.audit,
        "write",
        lambda ev: (_ for _ in ()).throw(RuntimeError("db mati")),
    )
    r = client.get("/admin/audit", headers=h(ADMIN))
    assert (
        r.status_code == 503 and r.json()["detail"]["code"] == "AUDIT_UNAVAILABLE"
    )  # tak ada data tanpa jejak
