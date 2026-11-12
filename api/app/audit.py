"""Audit log berantai hash (append-only).

Setiap baris menyimpan hash baris sebelumnya. Baris yang diubah atau dihapus di tengah
rantai terdeteksi oleh `verify_chain()`. Penghapusan baris PALING AKHIR tidak terdeteksi
oleh rantai saja; karena itu `head_hash` perlu disalin ke tempat lain secara berkala.
"""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .util import clean_text

GENESIS = "0" * 64
PG_LOCK_KEY = (
    0x5044465F41554454  # kunci advisory lock untuk menyerialkan penulisan rantai
)
_ID = BigInteger().with_variant(Integer, "sqlite")

# Daftar kolom yang ikut di-hash (di luar 'files'). Urutan tidak penting; JSON dikanonkan.
COLUMNS = [
    "ts_utc",
    "request_id",
    "username",
    "client_ip",
    "user_agent",
    "action",
    "status",
    "error_code",
    "error_message",
    "detail",
    "file_count",
    "total_bytes_in",
    "output_bytes",
    "output_sha256",
    "output_pages",
    "duration_ms",
    "engine",
    "engine_version",
    "app_version",
]


class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(_ID, primary_key=True, autoincrement=True)
    ts_utc: Mapped[str] = mapped_column(String(32), index=True)
    request_id: Mapped[str] = mapped_column(String(64))
    username: Mapped[str] = mapped_column(String(160), index=True)
    client_ip: Mapped[str] = mapped_column(String(64))
    user_agent: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_count: Mapped[int] = mapped_column(Integer)
    total_bytes_in: Mapped[int] = mapped_column(BigInteger)
    output_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_pages: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer)
    engine: Mapped[str | None] = mapped_column(String(32), nullable=True)
    engine_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    app_version: Mapped[str] = mapped_column(String(32))
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[str] = mapped_column(Text)


class AuditFile(Base):
    __tablename__ = "audit_file"
    id: Mapped[int] = mapped_column(_ID, primary_key=True, autoincrement=True)
    audit_id: Mapped[int] = mapped_column(_ID, ForeignKey("audit_log.id"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    file_name: Mapped[str] = mapped_column(String(255))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    pages: Mapped[int | None] = mapped_column(Integer, nullable=True)


@dataclass
class FileEntry:
    position: int
    file_name: str
    size_bytes: int
    sha256: str
    pages: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "file_name": self.file_name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "pages": self.pages,
        }


@dataclass
class AuditEvent:
    request_id: str
    username: str
    client_ip: str
    user_agent: str
    action: str
    status: str  # SUCCESS | FAILED | REJECTED
    error_code: str | None = None
    error_message: str | None = None
    detail: str | None = None
    files: list[FileEntry] = field(default_factory=list)
    total_bytes_in: int = 0
    output_bytes: int | None = None
    output_sha256: str | None = None
    output_pages: int | None = None
    duration_ms: int = 0
    engine: str | None = None
    engine_version: str | None = None
    app_version: str = ""


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def chain_hash(prev_hash: str, payload_json: str) -> str:
    return hashlib.sha256(f"{prev_hash}\n{payload_json}".encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class VerifyResult:
    ok: bool
    rows_checked: int
    problems: list[dict[str, Any]]
    head_id: int | None
    head_hash: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rows_checked": self.rows_checked,
            "problems": self.problems[:100],
            "problem_count": len(self.problems),
            "head_id": self.head_id,
            "head_hash": self.head_hash,
        }


class AuditStore:
    def __init__(self, database_url: str, auto_create: bool = False):
        self._sqlite = database_url.startswith("sqlite")
        kwargs: dict[str, Any] = {"pool_pre_ping": True}
        if self._sqlite:
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        self.db = create_engine(database_url, **kwargs)
        self._sessions = sessionmaker(self.db, expire_on_commit=False)
        self._sqlite_lock = threading.Lock()
        if auto_create:
            Base.metadata.create_all(self.db)

    # ------------------------------------------------------------------ tulis
    def write(self, ev: AuditEvent) -> int:
        files = [f.as_dict() for f in ev.files]
        for f in files:
            f["file_name"] = clean_text(f["file_name"], 255)
        fields: dict[str, Any] = {
            "request_id": clean_text(ev.request_id, 64),
            "username": clean_text(ev.username, 160),
            "client_ip": clean_text(ev.client_ip, 64),
            "user_agent": clean_text(ev.user_agent, 200),
            "action": ev.action,
            "status": ev.status,
            "error_code": clean_text(ev.error_code, 48) or None,
            "error_message": clean_text(ev.error_message, 500) or None,
            "detail": clean_text(ev.detail, 500) or None,
            "file_count": len(files),
            "total_bytes_in": int(ev.total_bytes_in),
            "output_bytes": ev.output_bytes,
            "output_sha256": ev.output_sha256,
            "output_pages": ev.output_pages,
            "duration_ms": int(ev.duration_ms),
            "engine": ev.engine,
            "engine_version": clean_text(ev.engine_version, 64) or None,
            "app_version": ev.app_version,
        }
        guard = self._sqlite_lock if self._sqlite else nullcontext()
        with guard:
            with self._sessions() as s:
                with s.begin():
                    if not self._sqlite:
                        s.execute(
                            text("SELECT pg_advisory_xact_lock(:k)"), {"k": PG_LOCK_KEY}
                        )
                    prev = (
                        s.execute(
                            select(AuditLog.row_hash)
                            .order_by(AuditLog.id.desc())
                            .limit(1)
                        ).scalar_one_or_none()
                        or GENESIS
                    )
                    ts = _now()
                    payload = {"ts_utc": ts, **fields, "files": files}
                    payload_json = canonical(payload)
                    row = AuditLog(
                        ts_utc=ts,
                        **fields,
                        prev_hash=prev,
                        row_hash=chain_hash(prev, payload_json),
                        payload_json=payload_json,
                    )
                    s.add(row)
                    s.flush()
                    for f in files:
                        s.add(AuditFile(audit_id=row.id, **f))
                    return row.id

    # ------------------------------------------------------------------ baca
    def ping(self) -> bool:
        try:
            with self.db.connect() as c:
                c.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
