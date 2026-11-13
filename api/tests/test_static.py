"""Halaman statis: aman terhadap CSP ketat dan tidak memakai HTML mentah dari data."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.engine import PypdfEngine
from app.main import STATIC_DIR, create_app

SECRET = "rahasia-uji-" + "x" * 30
ADMIN = "AD-LAB\\admin1"
USER = "AD-LAB\\user1"

WAJIB = ["index.html", "admin.html", "common.js", "app.js", "admin.js", "style.css"]
JS_TERLARANG = [
    r"\.innerHTML\b", r"\.outerHTML\b", r"insertAdjacentHTML", r"\beval\s*\(",
    r"new\s+Function\b", r"document\.write", r"setTimeout\s*\(\s*['\"]", r"setInterval\s*\(\s*['\"]",
]


def h(user=USER):
    return {"X-Remote-User": user, "X-Gateway-Secret": SECRET}


@pytest.fixture
def client(tmp_path):
    s = Settings(
        gateway_secret=SECRET,
        database_url=f"sqlite:///{tmp_path / 'audit.db'}",
        admin_users=(ADMIN,),
        tmp_dir=str(tmp_path / "tmp"),
        db_auto_create=True,
    )
    return TestClient(create_app(s, engine=PypdfEngine()))


@pytest.mark.parametrize("nama", WAJIB)
def test_file_statis_ada(nama):
    assert (STATIC_DIR / nama).is_file()


@pytest.mark.parametrize("js", sorted(p.name for p in STATIC_DIR.glob("*.js")))
def test_js_tanpa_html_mentah_atau_eval(js):
    isi = (STATIC_DIR / js).read_text("utf-8")
    for pola in JS_TERLARANG:
        assert not re.search(pola, isi), f"{js}: pola terlarang {pola}"


@pytest.mark.parametrize("html", sorted(p.name for p in STATIC_DIR.glob("*.html")))
def test_html_tanpa_skrip_atau_gaya_inline(html):
    isi = (STATIC_DIR / html).read_text("utf-8")
    for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", isi, re.S):
        assert tag.strip() == "", f"{html}: skrip inline"
    assert all("src=" in t for t in re.findall(r"<script\b[^>]*>", isi)), f"{html}: <script> tanpa src"
    assert "<style" not in isi, f"{html}: <style> inline"
    assert not re.search(r"\sstyle\s*=", isi), f"{html}: atribut style"
    assert not re.search(r"\son[a-z]+\s*=", isi), f"{html}: handler event inline"
    assert not re.search(r"(src|href)\s*=\s*\"(https?:)?//", isi), f"{html}: sumber eksternal"


def test_halaman_staf(client):
    r = client.get("/", headers=h())
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert '/static/app.js' in r.text


def test_halaman_admin_hanya_untuk_admin(client):
    assert client.get("/admin", headers=h()).status_code == 403
    r = client.get("/admin", headers=h(ADMIN))
    assert r.status_code == 200 and '/static/admin.js' in r.text


def test_aset_statis_butuh_secret(client):
    assert client.get("/static/app.js").status_code == 403
    r = client.get("/static/app.js", headers=h())
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
