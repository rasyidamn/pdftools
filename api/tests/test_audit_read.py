import sqlite3
import uuid

import pytest

from app.audit import AuditEvent, AuditStore, FileEntry


def event(i=0, user=r"AD-LAB\user1", status="SUCCESS", action="MERGE"):
    return AuditEvent(
        request_id=f"t-{uuid.uuid4().hex}",
        username=user,
        client_ip="10.0.0.1",
        user_agent="uji",
        action=action,
        status=status,
        files=[
            FileEntry(1, f"f{i}.pdf", 10, "0" * 64, 1),
            FileEntry(2, "b.pdf", 20, "1" * 64, 2),
        ],
        total_bytes_in=30,
        duration_ms=5,
        engine="stirling",
        engine_version="v1",
        app_version="0.1.0",
    )


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "audit.db"


@pytest.fixture
def store(db_path):
    return AuditStore(f"sqlite:///{db_path}", auto_create=True)


def seed(store, n=4):
    for i in range(n):
        store.write(event(i))
    assert store.verify_chain().ok


def tipe(res):
    return {p["type"] for p in res.problems}


def sql(db_path, *stmts):
    with sqlite3.connect(db_path) as c:
        for s in stmts:
            c.execute(s)


# ---------------------------------------------------------------- baca
def test_query_filter_dan_halaman(store):
    store.write(event(1, user=r"AD-LAB\a"))
    store.write(event(2, user=r"AD-LAB\b", status="FAILED"))
    store.write(event(3, user=r"AD-LAB\a", status="REJECTED"))
    total, rows = store.query(username=r"ad-lab\A")  # tidak peka huruf besar/kecil
    assert total == 2 and [r["id"] for r in rows] == [3, 1]  # terbaru dulu
    assert rows[0]["files"][0]["file_name"] == "f3.pdf"
    assert store.query(status="FAILED")[0] == 1
    total, rows = store.query(limit=2, offset=2)
    assert total == 3 and len(rows) == 1


def test_iter_rows_urut_dan_batas(store):
    seed(store, 5)
    ids = [r["id"] for r in store.iter_rows(batch=2)]
    assert ids == [1, 2, 3, 4, 5]
    assert len(list(store.iter_rows(max_rows=3))) == 3


# ---------------------------------------------------------------- verifikasi
def test_rantai_utuh(store):
    seed(store)
    res = store.verify_chain()
    assert res.ok and res.rows_checked == 4 and res.head_id == 4 and res.head_hash
    assert res.as_dict()["problem_count"] == 0


def test_ubah_kolom_terdeteksi(store, db_path):
    seed(store)
    sql(db_path, "UPDATE audit_log SET username = 'AD-LAB\\evil' WHERE id = 2")
    res = store.verify_chain()
    assert not res.ok and "COLUMN_MISMATCH" in tipe(res)


def test_ubah_payload_terdeteksi(store, db_path):
    seed(store)
    sql(
        db_path,
        "UPDATE audit_log SET payload_json = replace(payload_json, 'SUCCESS', 'FAILED') WHERE id = 3",
    )
    assert "BAD_HASH" in tipe(store.verify_chain())


def test_hapus_baris_tengah_terdeteksi(store, db_path):
    seed(store)
    sql(
        db_path,
        "DELETE FROM audit_file WHERE audit_id = 2",
        "DELETE FROM audit_log WHERE id = 2",
    )
    assert "BROKEN_LINK" in tipe(store.verify_chain())


def test_ubah_tabel_file_terdeteksi(store, db_path):
    seed(store)
    sql(
        db_path,
        "UPDATE audit_file SET sha256 = 'f' || substr(sha256, 2) WHERE audit_id = 1",
    )
    assert "FILES_MISMATCH" in tipe(store.verify_chain())


def test_hapus_baris_terakhir_tidak_terdeteksi_rantai_saja(store, db_path):
    """Batas yang diketahui: butuh head_hash yang disimpan di luar. Tes ini mendokumentasikannya."""
    seed(store)
    sebelum = store.verify_chain().head_hash
    sql(
        db_path,
        "DELETE FROM audit_file WHERE audit_id = 4",
        "DELETE FROM audit_log WHERE id = 4",
    )
    res = store.verify_chain()
    assert (
        res.ok and res.head_hash != sebelum
    )  # hanya terlihat bila dibandingkan dengan salinan luar
