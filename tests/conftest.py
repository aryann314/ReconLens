"""Shared pytest fixtures: a fresh app + temporary database for every test."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from extensions import limiter  # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "DATABASE_PATH": str(tmp_path / "test.db"),
        "SCAN_RATE_LIMIT": "1000 per minute",
        "ALLOW_LIVE_MODE": True,
        "HIBP_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
        "AUTHORIZED_EMAIL_DOMAINS": [],
    })
    with application.app_context():
        limiter.reset()
    yield application


@pytest.fixture
def client(app):
    return app.test_client()


class FakeResponse:
    """Minimal stand-in for requests.Response used by collector tests."""

    def __init__(self, status_code=200, json_data=None, text="", headers=None):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.headers = headers or {}
        self.ok = 200 <= status_code < 400

    def json(self):
        return self._json

    def raise_for_status(self):
        if not self.ok:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")
