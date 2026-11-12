"""Gateway merge PDF: identitas dari IIS, validasi, mesin (Stirling), audit lengkap."""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from fastapi import Depends, FastAPI, File, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from .audit import AuditEvent, AuditStore, FileEntry
from .auth import USER_RE, Identity, secret_matches
from .config import APP_VERSION, MB, Settings, load_settings
from .engine import EngineError, MergeEngine, build_engine
from .errors import ApiError
from .pdfcheck import inspect_pdf, verify_output
from .util import clean_text, client_ip_from, safe_filename

log = logging.getLogger("pdftool")
STATIC_DIR = Path(__file__).parent / "static"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
DATE_RE = r"^\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?$"
STATUSES = "^(SUCCESS|FAILED|REJECTED)$"
ACTIONS = "^(MERGE|AUDIT_VIEW|AUDIT_EXPORT|AUDIT_VERIFY|ADMIN_DENIED)$"

ENGINE_MESSAGES = {
    "ENGINE_TIMEOUT": "Proses terlalu lama. Coba lagi dengan file yang lebih sedikit atau lebih kecil.",
    "ENGINE_UNAVAILABLE": "Mesin PDF sedang tidak tersedia. Hubungi tim IT.",
}


class Reject(Exception):
    def __init__(self, code: str, message: str, status: int = 422):
        self.code, self.message, self.status = code, message, status


def create_app(
    settings: Settings | None = None,
    engine: MergeEngine | None = None,
    audit: AuditStore | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    settings.validate()
    engine = engine or build_engine(settings)
    audit = audit or AuditStore(settings.database_url, auto_create=settings.db_auto_create)
    admins = {u.lower() for u in settings.admin_users}
    tmp = Path(settings.tmp_dir)
    tmp.mkdir(parents=True, exist_ok=True)
    for leftover in tmp.glob("*.pdf"):
        leftover.unlink(missing_ok=True)
    limiter = asyncio.Semaphore(settings.max_concurrent)

    app = FastAPI(title="PDF Tool", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.audit = audit
    app.state.engine = engine

    # ------------------------------------------------------------ pembantu
    def identity_from(request: Request) -> Identity:
        user = request.headers.get("x-remote-user", "")
        if not USER_RE.match(user):
            raise ApiError(401, "NO_USER", "Identitas pengguna tidak terbaca. Hubungi tim IT.")
        peer = request.client.host if request.client else None
        return Identity(
            user,
            client_ip_from(request.headers.get("x-forwarded-for"), peer),
            clean_text(request.headers.get("user-agent", ""), 200),
        )

    def get_identity(request: Request) -> Identity:
        return identity_from(request)

    def make_event(ident: Identity, rid: str, action: str, status: str, started: float, **kw) -> AuditEvent:
        return AuditEvent(
            request_id=rid,
            username=ident.username,
            client_ip=ident.client_ip,
            user_agent=ident.user_agent,
            action=action,
            status=status,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine=engine.name,
            engine_version=engine.version(),
            app_version=APP_VERSION,
            **kw,
        )

    async def audit_best_effort(ev: AuditEvent) -> None:
        """Untuk kejadian penolakan/kegagalan: tidak ada hasil yang diserahkan, jadi gagal-tulis hanya dicatat di log."""
        try:
            await run_in_threadpool(audit.write, ev)
        except Exception:
            log.exception(
                "AUDIT GAGAL DITULIS action=%s status=%s code=%s user=%s req=%s",
                ev.action, ev.status, ev.error_code, ev.username, ev.request_id,
            )

    async def audit_required(ev: AuditEvent) -> None:
        """Gagal-aman: bila audit tidak bisa ditulis, operasi dibatalkan."""
        try:
            await run_in_threadpool(audit.write, ev)
        except Exception as exc:
            log.exception("AUDIT WAJIB GAGAL action=%s user=%s req=%s", ev.action, ev.username, ev.request_id)
            raise ApiError(
                503, "AUDIT_UNAVAILABLE",
                "Pencatatan audit sedang bermasalah, jadi permintaan dibatalkan. Hubungi tim IT.",
            ) from exc

    def error_json(status: int, code: str, message: str, rid: str) -> JSONResponse:
        return JSONResponse(
            {"detail": {"code": code, "message": message}, "request_id": rid}, status_code=status
        )

    def decorate(response, rid: str):
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = CSP
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    def sweep_tmp(max_age_s: int = 3600) -> None:
        now = time.time()
        for p in tmp.glob("*.pdf"):
            try:
                if now - p.stat().st_mtime > max_age_s:
                    p.unlink(missing_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def gateway_guard(request: Request, call_next):
        rid = uuid.uuid4().hex
        request.state.request_id = rid
        path = request.url.path
        if path != "/api/health":
            peer = request.client.host if request.client else ""
            secret_ok = secret_matches(request.headers.get("x-gateway-secret", ""), settings.gateway_secret)
            proxy_ok = (not settings.trusted_proxy_ips) or peer in settings.trusted_proxy_ips
            if not (secret_ok and proxy_ok):
                log.warning("Permintaan ditolak (bukan dari gateway) peer=%s path=%s req=%s", peer, path, rid)
                return decorate(error_json(403, "FORBIDDEN", "Akses ditolak.", rid), rid)
            if request.method == "POST" and path == "/api/merge":
                cl = request.headers.get("content-length", "")
                if cl.isdigit() and int(cl) > settings.max_total_bytes + 5 * MB:
                    try:
                        ident = identity_from(request)
                        await audit_best_effort(
                            make_event(
                                ident, rid, "MERGE", "REJECTED", time.perf_counter(),
                                error_code="REQUEST_TOO_LARGE",
                                error_message=f"Content-Length {cl} melebihi batas",
                            )
                        )
                    except ApiError:
                        pass
                    return decorate(
                        error_json(
                            413, "REQUEST_TOO_LARGE",
                            f"Total ukuran file melebihi batas {settings.max_total_bytes // MB} MB.", rid,
                        ),
                        rid,
                    )
        response = await call_next(request)
        return decorate(response, rid)

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, exc: ApiError):
        rid = getattr(request.state, "request_id", "-")
        return error_json(exc.status, exc.code, exc.message, rid)

    # ------------------------------------------------------------ halaman
    @app.get("/api/health")
    async def health():
        db_ok = await run_in_threadpool(audit.ping)
        eng_ok = await run_in_threadpool(engine.health)
        ok = db_ok and eng_ok
        return JSONResponse(
            {"status": "ok" if ok else "degraded", "db": db_ok, "engine": eng_ok},
            status_code=200 if ok else 503,
        )

    @app.get("/api/me")
    async def me(ident: Identity = Depends(get_identity)):
        return {
            "username": ident.username,
            "is_admin": ident.username.lower() in admins,
            "limits": {
                "min_files": settings.min_files,
                "max_files": settings.max_files,
                "max_file_mb": settings.max_file_bytes // MB,
                "max_total_mb": settings.max_total_bytes // MB,
                "max_pages": settings.max_pages,
            },
        }

    @app.get("/", response_class=HTMLResponse)
    async def index(ident: Identity = Depends(get_identity)):
        return (STATIC_DIR / "index.html").read_text("utf-8")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def factory() -> FastAPI:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return create_app()