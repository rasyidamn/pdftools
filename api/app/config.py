"""Konfigurasi dari environment. Semua nilai rahasia datang dari .env, bukan dari kode."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

APP_VERSION = "0.1.0"
MB = 1024 * 1024

ADMIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._$-]{1,64}$")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    gateway_secret: str
    database_url: str
    admin_users: tuple[str, ...]
    engine: str = "stirling"
    stirling_url: str = "http://stirling:8080"
    engine_version_label: str = "unknown"
    engine_timeout_s: float = 300.0
    trusted_proxy_ips: tuple[str, ...] = ()
    min_files: int = 2
    max_files: int = 20
    max_file_bytes: int = 50 * MB
    max_total_bytes: int = 100 * MB
    max_pages: int = 2000
    max_concurrent: int = 2
    tmp_dir: str = "/tmp/pdftool"
    db_auto_create: bool = False

    def validate(self) -> None:
        if len(self.gateway_secret) < 24 or self.gateway_secret.lower().startswith(
            "change"
        ):
            raise ConfigError(
                "GATEWAY_SECRET wajib diisi (minimal 24 karakter acak, bukan nilai contoh)."
            )
        if not self.database_url:
            raise ConfigError("DATABASE_URL wajib diisi.")
        if not self.admin_users:
            raise ConfigError(
                "ADMIN_USERS wajib diisi, contoh: AD-LAB\\user2 (pisahkan dengan koma)."
            )
        for u in self.admin_users:
            if not ADMIN_RE.match(u):
                raise ConfigError(
                    f"Format ADMIN_USERS salah: {u!r} (harus DOMAIN\\user)."
                )
        if self.engine not in ("stirling", "pypdf"):
            raise ConfigError("ENGINE harus 'stirling' atau 'pypdf'.")
        if self.min_files < 2 or self.max_files < self.min_files:
            raise ConfigError("MIN_FILES minimal 2 dan MAX_FILES >= MIN_FILES.")
        if self.max_concurrent < 1:
            raise ConfigError("MAX_CONCURRENT minimal 1.")


def _csv(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in value.split(",") if x.strip())


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load_settings(env: dict[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env
    s = Settings(
        gateway_secret=e.get("GATEWAY_SECRET", ""),
        database_url=e.get("DATABASE_URL", ""),
        admin_users=_csv(e.get("ADMIN_USERS", "")),
        engine=e.get("ENGINE", "stirling").strip().lower(),
        stirling_url=e.get("STIRLING_URL", "http://stirling:8080").rstrip("/"),
        engine_version_label=e.get("ENGINE_VERSION_LABEL", "unknown"),
        engine_timeout_s=float(e.get("ENGINE_TIMEOUT_S", "300")),
        trusted_proxy_ips=_csv(e.get("TRUSTED_PROXY_IPS", "")),
        min_files=int(e.get("MIN_FILES", "2")),
        max_files=int(e.get("MAX_FILES", "20")),
        max_file_bytes=int(e.get("MAX_FILE_MB", "50")) * MB,
        max_total_bytes=int(e.get("MAX_TOTAL_MB", "100")) * MB,
        max_pages=int(e.get("MAX_PAGES", "2000")),
        max_concurrent=int(e.get("MAX_CONCURRENT", "2")),
        tmp_dir=e.get("TMP_DIR", "/tmp/pdftool"),
        db_auto_create=_bool(e.get("DB_AUTO_CREATE"), False),
    )
    s.validate()
    return s
