"""
collectors/hibp_collector.py - Breach exposure via the Have I Been Pwned API v3.

Endpoint: GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
          header  hibp-api-key: <key>      (required, paid subscription)
          header  user-agent: <descriptive> (required by HIBP)

Without a paid key we use HIBP's official TEST key
(00000000000000000000000000000000). It only returns data for addresses on
hibp-integration-tests.com, e.g.:
    account-exists@hibp-integration-tests.com    -> one breach
    multiple-breaches@hibp-integration-tests.com -> several breaches
    not-active-and-active-breach@hibp-integration-tests.com
    spam-list-only@hibp-integration-tests.com    -> spam-list breach only
    opt-out@hibp-integration-tests.com           -> 404 (no data)

Ethics: only check addresses you own or are authorised to assess. We never
attempt logins, password resets or account recovery. The full address is sent
only to HIBP over HTTPS; elsewhere in the app it is stored masked.
"""
from __future__ import annotations

import html
import re
from urllib.parse import quote

from config import HIBP_TEST_DOMAIN, HIBP_TEST_KEY
from .base import BaseCollector, CollectorError, Finding

API = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
BREACH_PAGE = "https://haveibeenpwned.com/PwnedWebsites#{}"


def strip_html(text: str | None) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text or "")).strip()


def classify_breach(breach: dict) -> tuple[str, str]:
    classes = [c.lower() for c in breach.get("DataClasses", [])]
    if breach.get("IsSpamList"):
        return "HIBP_BREACH_SPAMLIST", "low"
    if "passwords" in classes:
        return "HIBP_BREACH_PASSWORDS", "high"
    return "HIBP_BREACH", "medium"


class HibpCollector(BaseCollector):
    module = "hibp"
    source = "Have I Been Pwned"

    def api_key_for(self, email: str) -> tuple[str, bool]:
        key = self.config.get("HIBP_API_KEY")
        if key:
            return key, False
        if email.endswith("@" + HIBP_TEST_DOMAIN):
            return HIBP_TEST_KEY, True
        raise CollectorError(
            "No HIBP API key configured. Without a paid key only test addresses "
            f"@{HIBP_TEST_DOMAIN} can be checked.", skipped=True)

    def collect(self, email: str) -> list[Finding]:
        key, is_test = self.api_key_for(email)
        resp = self.http_get(
            API.format(quote(email, safe="")),  # "@" is sent as %40, as in HIBP's docs
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "Accept": "application/json"},
        )
        source = self.source + (" (official test key)" if is_test else "")

        if resp.status_code == 404:
            return [self.finding(
                source=source, code="HIBP_NO_BREACH",
                title="Not found in any known breach",
                value="HIBP has no breach records for this address. This does not guarantee "
                      "the address was never exposed - only that HIBP holds no record of it.",
                status="not_found", source_url="https://haveibeenpwned.com/")]
        if resp.status_code == 401:
            raise CollectorError("HIBP rejected the API key (HTTP 401). Check HIBP_API_KEY in .env.")
        if resp.status_code == 403:
            raise CollectorError("HIBP refused the request (HTTP 403). A user-agent is required.")
        if resp.status_code == 429:
            wait = resp.headers.get("retry-after", "a few")
            raise CollectorError(f"HIBP rate limit reached - retry after {wait} seconds.")
        if resp.status_code == 400:
            raise CollectorError("HIBP considers the address invalid (HTTP 400).")
        resp.raise_for_status()

        breaches = resp.json()
        out: list[Finding] = []
        all_classes: set[str] = set()
        rows = []
        for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True):
            code, severity = classify_breach(b)
            all_classes.update(b.get("DataClasses", []))
            flags = []
            if not b.get("IsVerified", True):
                flags.append("unverified")
            if b.get("IsFabricated"):
                flags.append("fabricated")
            if b.get("IsSensitive"):
                flags.append("sensitive")
            title = b.get("Title") or b.get("Name", "Unknown breach")
            rows.append([title, b.get("BreachDate", ""), ", ".join(b.get("DataClasses", [])),
                         ", ".join(flags) or "verified"])
            out.append(self.finding(
                source=source, code=code,
                title=f"Breach: {title}" + (f" ({', '.join(flags)})" if flags else ""),
                value=f"Breached {b.get('BreachDate', 'unknown date')}. Data exposed: "
                      f"{', '.join(b.get('DataClasses', [])) or 'not specified'}",
                severity=severity,
                source_url=BREACH_PAGE.format(quote(b.get("Name", ""))),
                details={
                    "breach_date": b.get("BreachDate"),
                    "added_date": b.get("AddedDate"),
                    "domain": b.get("Domain"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "verified": b.get("IsVerified"),
                    "description": strip_html(b.get("Description"))[:600],
                }))

        out.insert(0, self.finding(
            source=source, code="HIBP_SUMMARY",
            title=f"Address appears in {len(breaches)} known breach(es)",
            value="Exposed data types: " + (", ".join(sorted(all_classes)) or "none listed"),
            source_url="https://haveibeenpwned.com/",
            details={"table": {"columns": ["Breach", "Date", "Data classes", "Flags"],
                               "rows": rows}}))
        return out
