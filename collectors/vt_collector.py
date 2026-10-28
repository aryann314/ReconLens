"""
collectors/vt_collector.py - Domain / IP / URL reputation from VirusTotal API v3.

    GET https://www.virustotal.com/api/v3/domains/{domain}
    GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
    GET https://www.virustotal.com/api/v3/urls/{url_id}   (url_id = base64url(url), no padding)
    header  x-apikey: <key>

Free "Public API": 4 requests/minute, 500/day, non-commercial use only.
We enforce the per-minute limit locally so the app never exceeds it.

Two deliberate design choices worth explaining in a viva:
1. We only READ existing VirusTotal reports. We never SUBMIT a URL for
   scanning, because submissions are shared with the VirusTotal community and
   could leak a private URL.
2. Reputation is a signal, not proof. "3 engines flagged this" means three
   vendors' classifiers think so - it is not confirmed malicious activity.
"""
from __future__ import annotations

import base64
import threading
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import quote

from .base import BaseCollector, CollectorError, Finding

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
PER_MINUTE = 4

_calls: deque = deque()
_lock = threading.Lock()


def reserve_quota(now: float | None = None) -> float:
    """Return 0 if a call is allowed now, else seconds to wait."""
    now = now or time.time()
    with _lock:
        while _calls and now - _calls[0] >= 60:
            _calls.popleft()
        if len(_calls) >= PER_MINUTE:
            return 60 - (now - _calls[0])
        _calls.append(now)
        return 0.0


def target_kind(target: str) -> str:
    import ipaddress
    if target.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalCollector(BaseCollector):
    module = "virustotal"
    source = "VirusTotal"

    def collect(self, target: str) -> list[Finding]:
        key = self.config.get("VIRUSTOTAL_API_KEY")
        if not key:
            raise CollectorError("VirusTotal API key not configured (VIRUSTOTAL_API_KEY in .env).",
                                 skipped=True)
        wait = reserve_quota()
        if wait:
            raise CollectorError(
                f"Local quota guard: the free VirusTotal API allows {PER_MINUTE} requests per "
                f"minute. Try again in {int(wait) + 1} s.")

        kind = target_kind(target)
        if kind == "url":
            endpoint, gui = f"{API}/urls/{url_id(target)}", f"{GUI}/url/{url_id(target)}"
        elif kind == "ip":
            endpoint, gui = f"{API}/ip_addresses/{target}", f"{GUI}/ip-address/{target}"
        else:
            endpoint, gui = f"{API}/domains/{quote(target)}", f"{GUI}/domain/{target}"

        resp = self.http_get(endpoint, headers={"x-apikey": key, "Accept": "application/json"})
        if resp.status_code == 404:
            return [self.finding(
                code="VT_NOT_FOUND", title="No VirusTotal report exists",
                value="VirusTotal has never analysed this target. (We do not submit it, "
                      "because submissions are shared publicly.)",
                status="not_found", source_url=gui)]
        if resp.status_code == 401:
            raise CollectorError("VirusTotal rejected the API key (HTTP 401).")
        if resp.status_code == 429:
            raise CollectorError("VirusTotal quota exceeded (HTTP 429). Free tier: 4/min, 500/day.")
        resp.raise_for_status()
        return self.build_findings(resp.json().get("data", {}).get("attributes", {}), gui, kind)

    def build_findings(self, attrs: dict, gui: str, kind: str) -> list[Finding]:
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        engines = sum(v for v in stats.values() if isinstance(v, int))
        ts = attrs.get("last_analysis_date")
        analysed = (datetime.fromtimestamp(ts, timezone.utc).date().isoformat()
                    if isinstance(ts, (int, float)) else "unknown")
        note = "Reputation data from security vendors - a signal, not confirmed malicious activity."
        out: list[Finding] = []

        if malicious:
            out.append(self.finding(
                code="VT_MALICIOUS", title=f"Flagged as malicious by {malicious} of {engines} engines",
                value=f"Last analysed {analysed}. {note}", severity="high", source_url=gui))
        if suspicious:
            out.append(self.finding(
                code="VT_SUSPICIOUS",
                title=f"Flagged as suspicious by {suspicious} of {engines} engines",
                value=f"Last analysed {analysed}. {note}", severity="medium", source_url=gui))
        if not malicious and not suspicious:
            out.append(self.finding(
                code="VT_CLEAN", title="No engine flagged this target",
                value=f"0 of {engines} engines reported it as malicious or suspicious "
                      f"(last analysed {analysed}).", source_url=gui))

        out.append(self.finding(
            code="VT_STATS", title="Engine verdict breakdown",
            value=", ".join(f"{k}: {v}" for k, v in stats.items()), source_url=gui,
            details={"chart": {k: v for k, v in stats.items() if isinstance(v, int)},
                     "table": {"columns": ["Verdict", "Engines"],
                               "rows": [[k, v] for k, v in stats.items()]}}))

        if "reputation" in attrs:
            rep = attrs["reputation"]
            out.append(self.finding(
                code="VT_COMMUNITY_SCORE", title="Community reputation score",
                value=f"{rep} (negative values mean the community voted it harmful)",
                severity="low" if isinstance(rep, int) and rep < 0 else "info", source_url=gui))

        cats = attrs.get("categories") or {}
        if cats:
            out.append(self.finding(
                code="VT_CATEGORIES", title="Vendor categories",
                value=", ".join(sorted(set(cats.values()))), source_url=gui))
        if kind == "ip" and (attrs.get("as_owner") or attrs.get("country")):
            out.append(self.finding(
                code="VT_NETWORK", title="Network owner",
                value=f"{attrs.get('as_owner', 'unknown')} ({attrs.get('country', '??')})",
                source_url=gui))
        return out
