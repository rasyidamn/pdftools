from __future__ import annotations


class ApiError(Exception):
    """Error yang dikembalikan ke pengguna sebagai JSON {detail:{code,message}}."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.status = status
        self.code = code
        self.message = message