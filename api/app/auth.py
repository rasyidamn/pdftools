"""Identitas pengguna. FastAPI TIDAK mengautentikasi: IIS yang melakukannya (Windows Auth).

FastAPI hanya mempercayai header dari IIS bila X-Gateway-Secret cocok (dicek di middleware).
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass

# Contoh yang sah: AD-LAB\user1. Selain format ini ditolak (mencegah header aneh masuk audit).
USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._$-]{1,64}$")


@dataclass(frozen=True)
class Identity:
    username: str
    client_ip: str
    user_agent: str


def secret_matches(provided: str, expected: str) -> bool:
    return hmac.compare_digest(
        provided.encode("latin-1", "replace"), expected.encode("latin-1", "replace")
    )