import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.engine import PypdfEngine
from app.main import create_app

SECRET = "rahasia-uji-" + "x" * 30
ADMIN = "AD-LAB\\admin1"


def buat(tmp_path, **over):
    base = dict(
        gateway_secret=SECRET,
        database_url=f"sqlite:///{tmp_path / 'audit.db'}",
        admin_users=(ADMIN,),
        tmp_dir=str(tmp_path / "tmp"),
        db_auto_create=True,
    )
    base.update(over)
    return TestClient(create_app(Settings(**base), engine=PypdfEngine()))


def h(user="AD-LAB\\user1", secret=SECRET):
    out = {"X-Remote-User": user}
    if secret is not None:
        out["X-Gateway-Secret"] = secret
    return out


def test_health_tanpa_secret(tmp_path):
    r = buat(tmp_path).get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "db": True, "engine": True}


def test_header_keamanan(tmp_path):
    r = buat(tmp_path).get("/api/health")
    for k in ("content-security-policy", "x-content-type-options", "x-frame-options", "x-request-id"):
        assert k in r.headers
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("secret", [None, "salah", ""])
def test_tanpa_atau_salah_secret_ditolak(tmp_path, secret):
    c = buat(tmp_path)
    r = c.get("/api/me", headers=h(secret=secret))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "FORBIDDEN"


def test_header_user_palsu_tidak_dipercaya_tanpa_secret(tmp_path):
    assert buat(tmp_path).get("/api/me", headers=h(ADMIN, secret=None)).status_code == 403


@pytest.mark.parametrize("bad", ["", "user1", "AD-LAB/user1", "AD-LAB\\us er", "AD-LAB\\x;DROP", "a" * 80 + "\\u"])
def test_format_username_salah(tmp_path, bad):
    r = buat(tmp_path).get("/api/me", headers=h(bad))
    assert r.status_code == 401 and r.json()["detail"]["code"] == "NO_USER"


def test_me_user_biasa_dan_admin(tmp_path):
    c = buat(tmp_path)
    biasa = c.get("/api/me", headers=h()).json()
    assert biasa["username"] == "AD-LAB\\user1" and biasa["is_admin"] is False
    assert biasa["limits"]["max_files"] == 20 and biasa["limits"]["max_file_mb"] == 50
    assert c.get("/api/me", headers=h(ADMIN.upper())).json()["is_admin"] is True  # tidak peka huruf besar/kecil


def test_hanya_proxy_tepercaya(tmp_path):
    c = buat(tmp_path, trusted_proxy_ips=("203.0.113.9",))  # TestClient datang dari host lain
    assert c.get("/api/me", headers=h()).status_code == 403


def test_konfigurasi_buruk_menolak_start(tmp_path):
    with pytest.raises(Exception):
        create_app(Settings(gateway_secret="pendek", database_url="sqlite://", admin_users=(ADMIN,)))

def test_parameter_salah_format_rumah(tmp_path):
    r = buat(tmp_path).get("/admin/audit?limit=0", headers=h(ADMIN))
    assert r.status_code == 422
    assert r.json()["detail"]["code"] == "BAD_REQUEST" and "x-request-id" in r.headers


def test_mesin_ditutup_saat_aplikasi_berhenti(tmp_path):
    class MesinTutup(PypdfEngine):
        ditutup = False

        def close(self):
            MesinTutup.ditutup = True

    app = create_app(
        Settings(
            gateway_secret=SECRET,
            database_url=f"sqlite:///{tmp_path / 'audit.db'}",
            admin_users=(ADMIN,),
            tmp_dir=str(tmp_path / "tmp"),
            db_auto_create=True,
        ),
        engine=MesinTutup(),
    )
    with TestClient(app):
        assert MesinTutup.ditutup is False
    assert MesinTutup.ditutup is True
