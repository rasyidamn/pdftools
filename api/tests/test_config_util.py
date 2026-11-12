import pytest

from app.config import MB, ConfigError, load_settings
from app.util import client_ip_from, safe_filename

OK = {
    "GATEWAY_SECRET": "x" * 30,
    "DATABASE_URL": "sqlite://",
    "ADMIN_USERS": r"AD-LAB\user2, AD-LAB\user3",
}


def test_config_default_dan_admin():
    s = load_settings(OK)
    assert s.admin_users == (r"AD-LAB\user2", r"AD-LAB\user3")
    assert s.max_file_bytes == 50 * MB and s.engine == "stirling"


@pytest.mark.parametrize(
    "ubah",
    [
        {"GATEWAY_SECRET": "pendek"},
        {"GATEWAY_SECRET": "change-me-" + "x" * 30},
        {"ADMIN_USERS": ""},
        {"ADMIN_USERS": "user2"},
        {"ENGINE": "lain"},
        {"MIN_FILES": "1"},
    ],
)
def test_config_salah_ditolak(ubah):
    with pytest.raises(ConfigError):
        load_settings({**OK, **ubah})


def test_nama_file_dibersihkan():
    assert safe_filename("C:\\fakepath\\..\\..\\evil.pdf") == "evil.pdf"
    assert safe_filename("/etc/passwd") == "passwd"
    assert safe_filename("a\u202eb\x07c.pdf") == "abc.pdf"
    assert safe_filename("\x00\x01") == "tanpa-nama.pdf"
    assert safe_filename(None) == "tanpa-nama.pdf"
    assert len(safe_filename("x" * 1000)) == 255


@pytest.mark.parametrize(
    "xff,peer,expected",
    [
        ("1.2.3.4, 10.1.1.5", "9.9.9.9", "10.1.1.5"),
        ("10.1.1.5:51234", "9.9.9.9", "10.1.1.5"),
        ("[2001:db8::1]:443", "9.9.9.9", "2001:db8::1"),
        ("bukan-ip", "9.9.9.9", "9.9.9.9"),
        (None, "9.9.9.9", "9.9.9.9"),
        (None, None, "unknown"),
        ("1.2.3.4,", "9.9.9.9", "1.2.3.4"),
    ],
)
def test_ip_klien(xff, peer, expected):
    assert client_ip_from(xff, peer) == expected
