"""
config.py - Central configuration.

All settings come from environment variables (loaded from the .env file by
python-dotenv). Secrets such as API keys are NEVER hard-coded in source code.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


# HIBP publishes this all-zero key for integration testing. It only returns
# data for addresses on the hibp-integration-tests.com domain.
HIBP_TEST_KEY = "00000000000000000000000000000000"
HIBP_TEST_DOMAIN = "hibp-integration-tests.com"


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or os.urandom(32).hex()

    ALLOW_LIVE_MODE = _bool("ALLOW_LIVE_MODE", True)

    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    AUTHORIZED_EMAIL_DOMAINS = _list("AUTHORIZED_EMAIL_DOMAINS")

    USER_AGENT = os.getenv(
        "OSINT_USER_AGENT", "OSINT-Footprint-Dashboard/1.0 (academic project)"
    )
    HTTP_TIMEOUT = _int("HTTP_TIMEOUT", 10)
    CRTSH_TIMEOUT = _int("CRTSH_TIMEOUT", 25)
    DNS_TIMEOUT = _int("DNS_TIMEOUT", 5)

    SCAN_RATE_LIMIT = os.getenv("SCAN_RATE_LIMIT", "10 per minute")
    # Pages and read-only API calls (one overview page load = 5 requests)
    DEFAULT_RATE_LIMIT = os.getenv("DEFAULT_RATE_LIMIT", "1000 per hour")
    RETENTION_DAYS = _int("RETENTION_DAYS", 30)

    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "osint.db"))
    LOG_DIR = BASE_DIR / "logs"

    # Reject request bodies larger than 16 KB (inputs are tiny)
    MAX_CONTENT_LENGTH = 16 * 1024
    JSON_SORT_KEYS = False


def get_config() -> dict:
    """Return the Config attributes as a plain dict (used by Flask)."""
    return {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
