"""
collectors/username_collector.py - Username footprint across public platforms.

For each platform in sites.json we request the public profile URL (or the
platform's public API) for the username and classify the HTTP response:

    confirmed     the platform positively indicates a profile exists
    not_found     the platform clearly reports no such user (e.g. HTTP 404)
    inconclusive  blocked (403), rate-limited (429), CAPTCHA/bot wall,
                  redirect to a login page, server error, or timeout

The key rule from the project brief: an error or a blocked request is NEVER
treated as proof that an account exists. We also never try to get around
CAPTCHAs, logins or platform restrictions.

Requests run in a small thread pool (6 at a time) with a short timeout, so a
full check finishes in a few seconds without hammering any single site.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

from .base import BaseCollector, Finding

SITES_FILE = Path(__file__).resolve().parent / "sites.json"
MAX_WORKERS = 6
SITE_TIMEOUT = 8
MAX_BODY = 200_000
REUSE_THRESHOLD = 5

BOT_WALL_MARKERS = (
    "cf-chl", "just a moment...", "attention required! | cloudflare",
    "verify you are human", "unusual traffic", "are you a robot",
)
LOGIN_MARKERS = ("/login", "/signin", "/sign-in", "/accounts/login", "/challenge")


def load_sites() -> list[dict]:
    with open(SITES_FILE, encoding="utf-8") as fh:
        return [s for s in json.load(fh)["sites"] if s.get("enabled", True)]


def classify(site: dict, http_status: int, body: str, final_url: str) -> tuple[str, str]:
    """Pure function: decide confirmed / not_found / inconclusive. Unit-tested."""
    found_codes = site.get("found_codes", [200])
    not_found_codes = site.get("not_found_codes", [404, 410])
    lower = (body or "")[:MAX_BODY].lower()

    if http_status == 429:
        return "inconclusive", "Rate-limited by the platform (HTTP 429)"
    if http_status in (401, 403):
        return "inconclusive", f"Request blocked by the platform (HTTP {http_status})"
    if http_status >= 500:
        return "inconclusive", f"Platform server error (HTTP {http_status})"
    if any(m in (final_url or "").lower() for m in LOGIN_MARKERS):
        return "inconclusive", "Redirected to a login page - profile visibility unknown"
    if http_status in not_found_codes:
        return "not_found", f"Platform reported no such user (HTTP {http_status})"
    if any(m in lower for m in BOT_WALL_MARKERS):
        return "inconclusive", "Bot-protection page returned - not bypassed by design"

    if site.get("method") == "message":
        if http_status != 200:
            return "inconclusive", f"Unexpected response (HTTP {http_status})"
        absent = site["absent_text"]
        absent_hit = (body.strip() == absent) if site.get("absent_exact") else \
            (absent.lower() in lower)
        if absent_hit:
            return "not_found", "Platform response indicates no such user"
        return "confirmed", "Platform response contains profile data"

    if http_status in found_codes:
        return "confirmed", f"Public profile responded (HTTP {http_status})"
    return "inconclusive", f"Unexpected response (HTTP {http_status})"


class UsernameCollector(BaseCollector):
    module = "username"
    source = "Public platform profiles"

    def __init__(self, config: dict, sites: list[dict] | None = None):
        super().__init__(config)
        self.sites = sites if sites is not None else load_sites()
        self.session.headers["Accept"] = "text/html,application/json;q=0.9,*/*;q=0.8"

    def check_site(self, site: dict, username: str) -> Finding:
        safe = quote(username, safe="")
        url = site["url"].format(safe)
        profile = site.get("profile_url", site["url"]).format(safe)
        details = {"platform": site["name"], "category": site.get("category", "")}
        try:
            # requests.get (not the shared Session) keeps each worker thread independent
            resp = requests.get(url, headers=dict(self.session.headers), timeout=SITE_TIMEOUT,
                                allow_redirects=True, stream=True)
            body = resp.raw.read(MAX_BODY, decode_content=True).decode(
                resp.encoding or "utf-8", errors="replace")
            resp.close()
            status, reason = classify(site, resp.status_code, body, resp.url)
            details["http_status"] = resp.status_code
        except requests.Timeout:
            status, reason = "inconclusive", f"No response within {SITE_TIMEOUT}s"
        except requests.RequestException as exc:
            status, reason = "inconclusive", f"Connection failed ({exc.__class__.__name__})"
        details["reason"] = reason

        code = {"confirmed": "USERNAME_FOUND", "not_found": "USERNAME_NOT_FOUND"}.get(
            status, "USERNAME_INCONCLUSIVE")
        return self.finding(
            code=code, title=site["name"],
            value=profile if status == "confirmed" else reason,
            status=status,
            severity="low" if status == "confirmed" else "info",
            source_url=profile, details=details)

    def collect(self, username: str) -> list[Finding]:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            findings = list(pool.map(lambda s: self.check_site(s, username), self.sites))

        found = [f for f in findings if f.status == "confirmed"]
        if len(found) >= REUSE_THRESHOLD:
            findings.insert(0, self.finding(
                code="USERNAME_REUSE",
                title="Same username reused across many platforms",
                value=f"'{username}' was found on {len(found)} platforms. Reusing one handle "
                      "makes it easy to link accounts and build a profile for social engineering.",
                severity="medium",
                details={"platforms": [f.title for f in found]}))
        return findings
