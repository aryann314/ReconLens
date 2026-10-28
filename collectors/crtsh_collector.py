"""
collectors/crtsh_collector.py - Certificate Transparency (CT) via crt.sh.

Every publicly trusted TLS certificate must be logged in public, append-only
CT logs (RFC 6962). crt.sh indexes those logs. Because certificates list the
hostnames they protect, CT logs reveal subdomains an organisation may have
forgotten about - e.g. dev., staging., vpn. or old-admin.

Important limitation: a hostname in a certificate is NOT proof that the host
is still online. We label these as "observed in CT logs".
"""
from __future__ import annotations

import json
import re
from collections import Counter

from .base import BaseCollector, CollectorError, Finding

CRTSH_URL = "https://crt.sh/"
MAX_BYTES = 15 * 1024 * 1024     # stop reading huge responses (very large domains)
MAX_ROWS = 300

SENSITIVE_KEYWORDS = (
    "dev", "test", "stage", "staging", "uat", "qa", "admin", "internal", "intranet",
    "vpn", "old", "backup", "beta", "jenkins", "git", "gitlab", "grafana", "kibana",
    "phpmyadmin", "cpanel", "remote", "db", "sql", "debug", "demo", "legacy", "sandbox",
)


def is_sensitive(hostname: str, domain: str) -> str | None:
    """Return the matching keyword if a subdomain label looks sensitive."""
    sub = hostname[: -len(domain)].rstrip(".")
    for label in re.split(r"[.\-]", sub):
        for kw in SENSITIVE_KEYWORDS:
            if label == kw or (label.startswith(kw) and label[len(kw):].isdigit()):
                return kw
    return None


def parse_crtsh(entries: list[dict], domain: str) -> dict:
    hosts: dict[str, dict] = {}
    issuers: Counter = Counter()
    wildcard = False
    for e in entries:
        m = re.search(r"O=([^,]+)", e.get("issuer_name") or "")
        if m:
            issuers[m.group(1).strip().strip('"')] += 1
        for name in (e.get("name_value") or "").lower().splitlines():
            name = name.strip()
            if name.startswith("*."):
                wildcard = True
                name = name[2:]
            if not (name == domain or name.endswith("." + domain)):
                continue
            first, last = e.get("not_before", "")[:10], e.get("not_after", "")[:10]
            h = hosts.setdefault(name, {"first_seen": first, "last_expiry": last, "certs": 0})
            h["certs"] += 1
            if first and (not h["first_seen"] or first < h["first_seen"]):
                h["first_seen"] = first
            if last and last > h["last_expiry"]:
                h["last_expiry"] = last
    return {"hosts": hosts, "issuers": issuers, "wildcard": wildcard,
            "certificate_count": len({e.get("id") for e in entries})}


class CrtshCollector(BaseCollector):
    module = "crtsh"
    source = "crt.sh Certificate Transparency"

    def collect(self, domain: str) -> list[Finding]:
        page = f"https://crt.sh/?q=%25.{domain}"
        resp = self.http_get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"},
                             timeout=self.config.get("CRTSH_TIMEOUT", 25), stream=True)
        if resp.status_code in (429, 502, 503, 504):
            raise CollectorError(
                f"crt.sh is busy or unavailable (HTTP {resp.status_code}). "
                "This is common - please retry in a minute.")
        resp.raise_for_status()

        body = bytearray()
        for chunk in resp.iter_content(65536):
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                resp.close()
                return [self.finding(
                    code="CRTSH_TOO_LARGE", title="Too many certificates to analyse",
                    value="This domain has more CT entries than the prototype processes. "
                          "Open crt.sh directly to browse them.",
                    status="inconclusive", source_url=page)]
        try:
            entries = json.loads(body.decode("utf-8") or "[]")
        except ValueError:
            raise CollectorError("crt.sh returned a non-JSON response (service degraded)")

        if not entries:
            return [self.finding(
                code="CRTSH_NONE", title="No certificates found in CT logs",
                value="crt.sh has no certificates for this domain.",
                status="not_found", source_url=page)]

        data = parse_crtsh(entries, domain)
        hosts = data["hosts"]
        out: list[Finding] = []
        rows = [[h, v["first_seen"], v["last_expiry"], v["certs"]]
                for h, v in sorted(hosts.items())]
        out.append(self.finding(
            code="CRTSH_SUBDOMAINS",
            title="Hostnames observed in certificate logs",
            value=f"{len(hosts)} unique hostnames in {data['certificate_count']} certificates",
            source_url=page,
            details={"table": {"columns": ["Hostname", "First seen", "Latest expiry", "Certs"],
                               "rows": rows[:MAX_ROWS]},
                     "truncated": len(rows) > MAX_ROWS,
                     "note": "Observed in CT logs; a hostname may no longer be active."}))

        sensitive = [[h, kw] for h in sorted(hosts)
                     if (kw := is_sensitive(h, domain))]
        if sensitive:
            out.append(self.finding(
                code="CRTSH_SENSITIVE_SUBDOMAINS",
                title="Sensitive-looking subdomains are publicly discoverable",
                value=f"{len(sensitive)} hostnames suggest dev/test/admin/remote-access systems",
                severity="medium", source_url=page,
                details={"table": {"columns": ["Hostname", "Keyword"], "rows": sensitive[:100]},
                         "note": "Names alone do not prove a system is exposed - verify each."}))

        if data["wildcard"]:
            out.append(self.finding(
                code="CRTSH_WILDCARD", title="Wildcard certificates in use",
                value="At least one *. certificate exists; hostnames behind it are hidden "
                      "from CT logs.", source_url=page))

        if data["issuers"]:
            out.append(self.finding(
                code="CRTSH_ISSUERS", title="Certificate authorities used",
                value=", ".join(f"{k} ({v})" for k, v in data["issuers"].most_common(5)),
                source_url=page))
        return out
