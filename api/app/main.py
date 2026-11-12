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

        # ------------------------------------------------------------ merge
    @app.post("/api/merge")
    async def merge(
        request: Request,
        ident: Identity = Depends(get_identity),
        files: list[UploadFile] | None = File(None),
    ):
        started = time.perf_counter()
        rid = request.state.request_id
        await run_in_threadpool(sweep_tmp)
        entries: list[FileEntry] = []
        uploads: list[tuple[str, UploadFile]] = []
        total_bytes = 0

        # 1) Validasi masukan -> REJECTED bila ada masalah
        try:
            if not files or len(files) < settings.min_files:
                raise Reject("TOO_FEW_FILES", f"Pilih minimal {settings.min_files} file PDF.")
            if len(files) > settings.max_files:
                raise Reject("TOO_MANY_FILES", f"Maksimal {settings.max_files} file per proses.", 413)
            problems: list[tuple[str, tuple[str, str, int]]] = []
            for i, f in enumerate(files, 1):
                name = safe_filename(f.filename)
                info = await run_in_threadpool(inspect_pdf, f.file, settings.max_file_bytes, settings.max_pages)
                entries.append(FileEntry(i, name, info.size, info.sha256, info.pages))
                uploads.append((name, f))
                total_bytes += info.size
                if info.problem:
                    problems.append((name, info.problem))
            if problems:
                name, (code, msg, status) = problems[0]
                extra = f" (+{len(problems) - 1} file bermasalah lain)" if len(problems) > 1 else ""
                raise Reject(code, f"{name}: {msg}{extra}", status)
            if total_bytes > settings.max_total_bytes:
                raise Reject("TOTAL_TOO_LARGE", f"Total ukuran melebihi {settings.max_total_bytes // MB} MB.", 413)
            total_pages = sum(e.pages or 0 for e in entries)
            if total_pages > settings.max_pages:
                raise Reject("TOO_MANY_PAGES", f"Total halaman melebihi {settings.max_pages}.")
        except Reject as r:
            await audit_best_effort(
                make_event(
                    ident, rid, "MERGE", "REJECTED", started,
                    error_code=r.code, error_message=r.message, files=entries, total_bytes_in=total_bytes,
                )
            )
            raise ApiError(r.status, r.code, r.message)

        # 2) Panggil mesin
        out_path = tmp / f"{rid}.pdf"

        def drop_output() -> None:
            out_path.unlink(missing_ok=True)

        async def fail(code: str, detail: str, status: int, message: str):
            drop_output()
            await audit_best_effort(
                make_event(
                    ident, rid, "MERGE", "FAILED", started,
                    error_code=code, error_message=detail, files=entries, total_bytes_in=total_bytes,
                )
            )
            raise ApiError(status, code, message)

        generic = f"Penggabungan gagal. Pastikan semua file PDF tidak rusak. Jika berulang, hubungi tim IT (kode {rid[:8]})."
        try:
            for _, f in uploads:
                f.file.seek(0)
            async with limiter:
                await run_in_threadpool(engine.merge, [(n, f.file) for n, f in uploads], out_path)
            out_size, out_sha, out_pages = await run_in_threadpool(verify_output, out_path, total_pages)
        except EngineError as e:
            await fail(e.code, e.detail, e.http_status, ENGINE_MESSAGES.get(e.code, generic))
        except ApiError:
            raise
        except Exception as e:  # kesalahan tak terduga
            log.exception("Kesalahan tak terduga saat merge req=%s", rid)
            await fail("INTERNAL_ERROR", f"{type(e).__name__}", 500, generic)

        # 3) Audit WAJIB berhasil sebelum hasil diserahkan (gagal-aman)
        try:
            await audit_required(
                make_event(
                    ident, rid, "MERGE", "SUCCESS", started,
                    files=entries, total_bytes_in=total_bytes,
                    output_bytes=out_size, output_sha256=out_sha, output_pages=out_pages,
                )
            )
        except ApiError:
            drop_output()
            raise

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return FileResponse(
            out_path,
            media_type="application/pdf",
            filename=f"gabungan-{stamp}.pdf",
            background=BackgroundTask(drop_output),
        )

        # ------------------------------------------------------------ admin
    async def require_admin(request: Request, ident: Identity = Depends(get_identity)) -> Identity:
        if ident.username.lower() not in admins:
            await audit_best_effort(
                make_event(
                    ident, request.state.request_id, "ADMIN_DENIED", "REJECTED", time.perf_counter(),
                    error_code="NOT_ADMIN", detail=request.url.path,
                )
            )
            raise ApiError(403, "FORBIDDEN", "Halaman ini khusus admin.")
        return ident

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(ident: Identity = Depends(require_admin)):
        return (STATIC_DIR / "admin.html").read_text("utf-8")

    # ------------------------------------------------------------ admin audit
    def filters(
        username: str | None, status: str | None, action: str | None, since: str | None, until: str | None
    ) -> dict:
        return {"username": username, "status": status, "action": action, "since": since, "until": until}

    def describe(f: dict) -> str:
        parts = [f"{k}={v}" for k, v in f.items() if v]
        return ("filter: " + ", ".join(parts)) if parts else "tanpa filter"

    @app.get("/admin/audit")
    async def admin_audit(
        request: Request,
        ident: Identity = Depends(require_admin),
        username: str | None = Query(None, max_length=160),
        status: str | None = Query(None, pattern=STATUSES),
        action: str | None = Query(None, pattern=ACTIONS),
        since: str | None = Query(None, pattern=DATE_RE),
        until: str | None = Query(None, pattern=DATE_RE),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        f = filters(username, status, action, since, until)
        await audit_required(
            make_event(
                ident, request.state.request_id, "AUDIT_VIEW", "SUCCESS", time.perf_counter(),
                detail=f"{describe(f)}, limit={limit}, offset={offset}",
            )
        )
        total, rows = await run_in_threadpool(lambda: audit.query(**f, limit=limit, offset=offset))
        return {"total": total, "limit": limit, "offset": offset, "rows": rows}

    def csv_cell(v) -> str:
        s = "" if v is None else str(v)
        return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

    CSV_HEADER = [
        "id", "ts_utc", "username", "client_ip", "action", "status", "error_code", "error_message",
        "file_count", "total_bytes_in", "output_pages", "output_bytes", "output_sha256",
        "duration_ms", "engine", "engine_version", "request_id", "files",
    ]

    def csv_stream(rows: Iterator[dict]) -> Iterator[str]:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_HEADER)
        yield "\ufeff" + buf.getvalue()
        for r in rows:
            buf.seek(0)
            buf.truncate(0)
            r = dict(r)
            r["files"] = " ; ".join(
                f"{x['position']}. {x['file_name']} | {x['size_bytes']}B | {x['sha256']}" for x in r["files"]
            )
            w.writerow([csv_cell(r.get(c)) for c in CSV_HEADER])
            yield buf.getvalue()

    @app.get("/admin/audit.csv")
    async def admin_audit_csv(
        request: Request,
        ident: Identity = Depends(require_admin),
        username: str | None = Query(None, max_length=160),
        status: str | None = Query(None, pattern=STATUSES),
        action: str | None = Query(None, pattern=ACTIONS),
        since: str | None = Query(None, pattern=DATE_RE),
        until: str | None = Query(None, pattern=DATE_RE),
    ):
        f = filters(username, status, action, since, until)
        await audit_required(
            make_event(
                ident, request.state.request_id, "AUDIT_EXPORT", "SUCCESS", time.perf_counter(),
                detail=describe(f),
            )
        )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return StreamingResponse(
            csv_stream(audit.iter_rows(**f)),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'},
        )

    @app.get("/admin/verify")
    async def admin_verify(request: Request, ident: Identity = Depends(require_admin)):
        await audit_required(
            make_event(ident, request.state.request_id, "AUDIT_VERIFY", "SUCCESS", time.perf_counter())
        )
        result = await run_in_threadpool(audit.verify_chain)
        return result.as_dict()

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def factory() -> FastAPI:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return create_app()