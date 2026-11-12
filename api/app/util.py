"""Pembersih teks dan pengurai IP. Dipakai agar isi audit tidak bisa dipalsukan lewat nama file."""

from __future__ import annotations

import ipaddress
import re

# Karakter kontrol dan karakter pembalik arah teks (bidi) dibuang dari nama file,
# user-agent, dan pesan error sebelum masuk audit.
_BAD = dict.fromkeys(
    list(range(0, 32))
    + [127, 0x85, 0x061C, 0x200E, 0x200F, 0x2028, 0x2029]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A)),
    None,
)


def clean_text(value: str | None, limit: int) -> str:
    if not value:
        return ""
    return value.translate(_BAD)[:limit]


def safe_filename(raw: str | None) -> str:
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = clean_text(name, 255).strip()
    return name or "tanpa-nama.pdf"


_V4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$")
_V6_PORT = re.compile(r"^\[([0-9a-fA-F:]+)\]:\d{1,5}$")


def parse_ip(candidate: str | None) -> str | None:
    if not candidate:
        return None
    c = candidate.strip()
    for attempt in (c, c.strip("[]")):
        try:
            return str(ipaddress.ip_address(attempt))
        except ValueError:
            pass
    for rx in (_V4_PORT, _V6_PORT):
        m = rx.match(c)
        if m:
            try:
                return str(ipaddress.ip_address(m.group(1)))
            except ValueError:
                return None
    return None


def client_ip_from(xff: str | None, peer: str | None) -> str:
    """Ambil IP klien dari entri TERKANAN X-Forwarded-For (yang ditambahkan proxy tepercaya).

    Entri sebelah kiri bisa dipalsukan klien, jadi tidak dipakai.
    """
    if xff:
        parts = [p for p in xff.split(",") if p.strip()]
        if parts:
            ip = parse_ip(parts[-1])
            if ip:
                return ip
    return parse_ip(peer) or "unknown"
