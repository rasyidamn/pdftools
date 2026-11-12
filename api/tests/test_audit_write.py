import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text

from app.audit import GENESIS, AuditEvent, AuditStore, FileEntry, chain_hash


def event(i=0, **over):
    base = dict(
        request_id=f"t-{uuid.uuid4().hex}", username=r"AD-LAB\user1", client_ip="10.0.0.1",
        user_agent="uji", action="MERGE", status="SUCCESS",
        files=[FileEntry(1, f"f{i}.pdf", 10, "0" * 64, 1), FileEntry(2, "b.pdf", 20, "1" * 64, 2)],
        total_bytes_in=30, duration_ms=5, engine="stirling", engine_version="v1", app_version="0.1.0",
    )
    base.update(over)
    return AuditEvent(**base)


@pytest.fixture
def store(tmp_path):
    return AuditStore(f"sqlite:///{tmp_path / 'audit.db'}", auto_create=True)


def rows(store):
    with store.db.connect() as c:
        return c.execute(text("SELECT * FROM audit_log ORDER BY id")).mappings().all()


def test_tulis_dan_ping(store):
    assert store.ping()
    new_id = store.write(event())
    r = rows(store)
    assert len(r) == 1 and r[0]["id"] == new_id
    assert r[0]["username"] == r"AD-LAB\user1" and r[0]["file_count"] == 2
    with store.db.connect() as c:
        files = c.execute(text("SELECT file_name, position FROM audit_file ORDER BY position")).all()
    assert [f[0] for f in files] == ["f0.pdf", "b.pdf"]


def test_rantai_hash_tersambung(store):
    for i in range(4):
        store.write(event(i))
    r = rows(store)
    assert r[0]["prev_hash"] == GENESIS
    for a, b in zip(r, r[1:]):
        assert b["prev_hash"] == a["row_hash"]
    for x in r:
        assert x["row_hash"] == chain_hash(x["prev_hash"], x["payload_json"])


def test_teks_dibersihkan_sebelum_disimpan(store):
    store.write(event(files=[FileEntry(1, "a\u202ebc\x07.pdf", 1, "0" * 64, 1)], user_agent="ua\x00\x1b[31m"))
    with store.db.connect() as c:
        name = c.execute(text("SELECT file_name FROM audit_file")).scalar_one()
    assert name == "abc.pdf"
    assert "\x00" not in rows(store)[0]["user_agent"]


def test_penulisan_paralel_tidak_memutus_rantai(store):
    with ThreadPoolExecutor(16) as pool:
        ids = list(pool.map(lambda i: store.write(event(i)), range(40)))
    assert len(set(ids)) == 40
    r = rows(store)
    assert len(r) == 40
    for a, b in zip(r, r[1:]):
        assert b["prev_hash"] == a["row_hash"]