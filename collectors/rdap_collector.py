"""
collectors/rdap_collector.py - Domain registration data (RDAP, WHOIS fallback).

RDAP (Registration Data Access Protocol, RFC 9082/9083) is the JSON-based
successor of WHOIS. Since 28 January 2025 ICANN treats RDAP as the
authoritative source for gTLD registration data (.com, .org, .net ...).

How a lookup works:
1. Download IANA's "bootstrap" file (data.iana.org/rdap/dns.json), which maps
   each TLD to the RDAP server of its registry. It is cached in memory.
2. Query  <rdap-server>/domain/<domain>.
3. If the registry response links to the registrar's own RDAP server, follow
   that link once - it usually carries the (often redacted) registrant data.
4. Many country-code TLDs still have no RDAP service, so fall back to the
   classic WHOIS protocol on TCP port 43.

Privacy: we only extract the fields we need (registrar, dates, nameservers,
statuses, DNSSEC, whether the registrant is redacted). Raw WHOIS text, which
can contain personal data, is never stored.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from datetime import datetime, timezone

from .base import BaseCollector, CollectorError, Finding

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
ICANN_LOOKUP_URL = "https://lookup.icann.org/en/lookup"

_bootstrap_cache: dict = {"loaded_at": 0.0, "map": {}}
_bootstrap_lock = threading.Lock()
BOOTSTRAP_TTL = 24 * 3600

REDACTION_MARKERS = ("redacted", "privacy", "data protected", "not disclosed",
                     "withheld", "gdpr", "proxy", "contact privacy")


# --------------------------------------------------------------- helpers
def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
                "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def vcard_field(entity: dict, name: str) -> str | None:
    """Read a field (fn, org, email...) from an RDAP jCard (RFC 7095)."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == name:
            value = prop[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            return str(value) if value else None
    return None


def iter_entities(entities: list | None):
    """Yield entities recursively (registrars nest abuse contacts, etc.)."""
    for ent in entities or []:
        if isinstance(ent, dict):
            yield ent
            yield from iter_entities(ent.get("entities"))


def is_redacted(text: str | None) -> bool:
    return text is None or any(m in text.lower() for m in REDACTION_MARKERS)


def parse_rdap(data: dict) -> dict:
    """Extract the fields we need from an RDAP domain object."""
    events = {}
    for ev in data.get("events", []) or []:
        action = (ev.get("eventAction") or "").lower()
        if action and ev.get("eventDate"):
            events[action] = ev["eventDate"]

    registrar = None
    registrant = None
    for ent in iter_entities(data.get("entities")):
        roles = [r.lower() for r in ent.get("roles", []) or []]
        if "registrar" in roles and registrar is None:
            registrar = vcard_field(ent, "fn")
        if "registrant" in roles and registrant is None:
            registrant = {
                "name": vcard_field(ent, "fn"),
                "org": vcard_field(ent, "org"),
                "email": vcard_field(ent, "email"),
                "remarks": " ".join(
                    " ".join(r.get("description", []) or []) + " " + (r.get("title") or "")
                    for r in ent.get("remarks", []) or []
                ),
            }

    secure = data.get("secureDNS") or {}
    related = None
    for link in data.get("links", []) or []:
        if link.get("rel") == "related" and "rdap" in (link.get("type") or "") \
                and "/domain/" in (link.get("href") or ""):
            related = link["href"]
            break

    return {
        "domain": (data.get("ldhName") or "").lower(),
        "status": [s.lower() for s in data.get("status", []) or []],
        "registration": events.get("registration"),
        "expiration": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "registrant": registrant,
        "nameservers": sorted(
            (ns.get("ldhName") or "").lower() for ns in data.get("nameservers", []) or []
            if ns.get("ldhName")
        ),
        "dnssec": secure.get("delegationSigned"),
        "has_redacted_extension": bool(data.get("redacted")),
        "related_link": related,
    }


WHOIS_PATTERNS = {
    "registrar": r"^\s*(?:registrar|sponsoring registrar|registrar name)\s*:\s*(.+)$",
    "registration": r"^\s*(?:creation date|created|created on|registered on|registration date|"
                    r"registration time|domain registration date)\s*:\s*(.+)$",
    "expiration": r"^\s*(?:registry expiry date|registrar registration expiration date|"
                  r"expiry date|expiration date|expires|expires on|paid-till|"
                  r"expiration time)\s*:\s*(.+)$",
    "nameserver": r"^\s*(?:name server|nserver|nameserver)s?\s*:\s*(\S+)",
}


def parse_whois(text: str) -> dict:
    """Pull a few well-known fields out of free-form WHOIS text."""
    out: dict = {"nameservers": []}
    for line in text.splitlines():
        for key, pattern in WHOIS_PATTERNS.items():
            m = re.match(pattern, line, re.IGNORECASE)
            if not m:
                continue
            value = m.group(1).strip()
            if key == "nameserver":
                ns = value.lower().rstrip(".")
                if ns not in out["nameservers"]:
                    out["nameservers"].append(ns)
            elif key not in out:
                out[key] = value
    not_found = re.search(r"no match|not found|no data found|no entries found|"
                          r"status:\s*free|domain not found", text, re.IGNORECASE)
    out["not_found"] = bool(not_found) and "registration" not in out
    return out


class RdapCollector(BaseCollector):
    module = "rdap"
    source = "RDAP / WHOIS registration data"

    # -------------------------------------------------------------- RDAP
    def _bootstrap(self) -> dict:
        with _bootstrap_lock:
            if _bootstrap_cache["map"] and time.time() - _bootstrap_cache["loaded_at"] < BOOTSTRAP_TTL:
                return _bootstrap_cache["map"]
            resp = self.http_get(IANA_BOOTSTRAP_URL)
            resp.raise_for_status()
            mapping = {}
            for tlds, urls in resp.json().get("services", []):
                https = [u for u in urls if u.startswith("https://")] or urls
                for tld in tlds:
                    mapping[tld.lower()] = https[0].rstrip("/") + "/"
            _bootstrap_cache.update(map=mapping, loaded_at=time.time())
            return mapping

    def _rdap_base_for(self, domain: str) -> str | None:
        labels = domain.split(".")
        mapping = self._bootstrap()
        # longest suffix first, e.g. "co.uk" before "uk"
        for i in range(len(labels) - 1):
            suffix = ".".join(labels[i + 1:])
            if suffix in mapping:
                return mapping[suffix]
        return None

    # ------------------------------------------------------------- WHOIS
    @staticmethod
    def _whois_query(server: str, query: str, timeout: int) -> str:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # the domain is already IDNA/ASCII-encoded by the validator
            sock.sendall((query + "\r\n").encode("ascii"))
            chunks, total = [], 0
            while total < 200_000:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def _whois_lookup(self, domain: str) -> dict:
        timeout = self.config.get("HTTP_TIMEOUT", 10)
        iana = self._whois_query("whois.iana.org", domain, timeout)
        m = re.search(r"^\s*(?:refer|whois):\s*(\S+)", iana, re.IGNORECASE | re.MULTILINE)
        if not m:
            raise CollectorError("No WHOIS server is published for this TLD")
        server = m.group(1).strip()
        text = self._whois_query(server, domain, timeout)
        parsed = parse_whois(text)
        parsed["server"] = server
        return parsed

    # ----------------------------------------------------------- collect
    def collect(self, domain: str) -> list[Finding]:
        try:
            base = self._rdap_base_for(domain)
        except Exception:
            base = None  # bootstrap unreachable -> try WHOIS

        if base:
            url = f"{base}domain/{domain}"
            resp = self.http_get(url, headers={"Accept": "application/rdap+json"})
            if resp.status_code == 404:
                return [self.finding(
                    code="RDAP_NOT_REGISTERED",
                    title="Domain not found in the registry",
                    value="The registry's RDAP server has no record of this domain. "
                          "It may be unregistered.",
                    status="not_found", source_url=url)]
            if resp.status_code == 429:
                raise CollectorError("The RDAP server rate-limited this request. Try again later.")
            resp.raise_for_status()
            info = parse_rdap(resp.json())
            info["protocol"] = "RDAP"
            info["query_url"] = url

            # Follow the registrar's RDAP link once (thin registries like .com).
            # The link comes from a third party, so only plain https:// URLs are followed.
            related = info.get("related_link") or ""
            if related.lower().startswith("https://") and not info.get("registrant"):
                try:
                    rel = self.http_get(info["related_link"],
                                        headers={"Accept": "application/rdap+json"})
                    if rel.ok:
                        extra = parse_rdap(rel.json())
                        info["registrant"] = extra.get("registrant")
                        info["registrar"] = info["registrar"] or extra.get("registrar")
                        info["has_redacted_extension"] |= extra["has_redacted_extension"]
                except Exception:
                    pass  # registrar data is optional
            return self.build_findings(domain, info)

        # ------------- WHOIS fallback (ccTLDs without RDAP)
        try:
            info = self._whois_lookup(domain)
        except (OSError, socket.timeout) as exc:
            raise CollectorError(
                f"Neither RDAP nor WHOIS could be reached for this TLD ({exc.__class__.__name__})")
        if info.get("not_found"):
            return [self.finding(
                code="RDAP_NOT_REGISTERED", title="Domain not found in WHOIS",
                value=f"WHOIS server {info['server']} reports no match.",
                status="not_found", source_url=ICANN_LOOKUP_URL)]
        info.update(protocol="WHOIS", query_url=f"whois://{info['server']}",
                    status=[], dnssec=None, registrant=None, has_redacted_extension=False)
        return self.build_findings(domain, info)

    # ----------------------------------------------------- interpretation
    def build_findings(self, domain: str, info: dict) -> list[Finding]:
        src = f"{self.source} ({info['protocol']})"
        url = info["query_url"] if info["protocol"] == "RDAP" else ICANN_LOOKUP_URL
        out: list[Finding] = []
        now = datetime.now(timezone.utc)

        out.append(self.finding(
            source=src, code="RDAP_REGISTRAR", title="Registrar",
            value=info.get("registrar") or "Not published",
            status="confirmed" if info.get("registrar") else "inconclusive",
            source_url=url, details={"protocol": info["protocol"]}))

        created = parse_date(info.get("registration"))
        if created:
            age_days = (now - created).days
            out.append(self.finding(
                source=src, code="RDAP_REGISTRATION_DATE", title="Registration date",
                value=f"{created.date().isoformat()} (domain age: {age_days // 365} years, "
                      f"{age_days % 365} days)",
                source_url=url, details={"registered": created.isoformat(), "age_days": age_days}))
            if age_days < 90:
                out.append(self.finding(
                    source=src, code="RDAP_RECENTLY_REGISTERED",
                    title="Recently registered domain",
                    value=f"Registered {age_days} days ago. New domains are a common phishing "
                          "indicator when they imitate an established brand.",
                    severity="low", source_url=url))
        else:
            # Domain age is only reported when the source gives a reliable date.
            out.append(self.finding(
                source=src, code="RDAP_REGISTRATION_DATE", title="Registration date",
                value="Not published by the registry - domain age cannot be determined reliably",
                status="inconclusive", source_url=url))

        expires = parse_date(info.get("expiration"))
        if expires:
            days_left = (expires - now).days
            if days_left < 0:
                out.append(self.finding(
                    source=src, code="RDAP_EXPIRED", title="Registration appears expired",
                    value=f"Expiry date {expires.date().isoformat()} is in the past",
                    severity="high", source_url=url))
            elif days_left <= 30:
                out.append(self.finding(
                    source=src, code="RDAP_EXPIRY_SOON", title="Registration expires soon",
                    value=f"Expires {expires.date().isoformat()} ({days_left} days left)",
                    severity="medium", source_url=url))
            else:
                out.append(self.finding(
                    source=src, code="RDAP_EXPIRY", title="Expiry date",
                    value=f"{expires.date().isoformat()} ({days_left} days left)", source_url=url))

        if info.get("nameservers"):
            out.append(self.finding(
                source=src, code="RDAP_NAMESERVERS", title="Registered nameservers",
                value=", ".join(info["nameservers"]), source_url=url,
                details={"table": {"columns": ["Nameserver"],
                                   "rows": [[n] for n in info["nameservers"]]}}))

        statuses = info.get("status") or []
        if statuses:
            compact = [s.replace(" ", "").replace("_", "") for s in statuses]
            locked = any("transferprohibited" in s for s in compact)
            out.append(self.finding(
                source=src, code="RDAP_STATUS", title="Registry status codes",
                value=", ".join(statuses), source_url=url))
            if not locked:
                out.append(self.finding(
                    source=src, code="RDAP_NO_TRANSFER_LOCK",
                    title="No transfer lock on the domain",
                    value="No 'transfer prohibited' status was found. A transfer lock helps "
                          "prevent domain hijacking.", severity="low", source_url=url))

        if info.get("dnssec") is True:
            out.append(self.finding(source=src, code="RDAP_DNSSEC_ON", title="DNSSEC",
                                    value="Delegation is signed (DNSSEC enabled)", source_url=url))
        elif info.get("dnssec") is False:
            out.append(self.finding(
                source=src, code="RDAP_DNSSEC_OFF", title="DNSSEC not enabled",
                value="Delegation is unsigned; DNS answers cannot be cryptographically verified.",
                severity="low", source_url=url))

        reg = info.get("registrant")
        if reg:
            # Only personal fields count; an organisation name is not personal data.
            visible = {k: v for k, v in reg.items()
                       if k in ("name", "email") and v and not is_redacted(v)}
            remarks = (reg.get("remarks") or "").strip()
            remarks_redacted = bool(remarks) and is_redacted(remarks)
            if visible and not remarks_redacted and not info["has_redacted_extension"]:
                out.append(self.finding(
                    source=src, code="RDAP_REGISTRANT_PUBLIC",
                    title="Registrant contact details are public",
                    value="Registrant fields published: " + ", ".join(sorted(visible)),
                    severity="low", source_url=url,
                    details={"fields_visible": sorted(visible)}))
            else:
                out.append(self.finding(
                    source=src, code="RDAP_REGISTRANT_REDACTED",
                    title="Registrant contact details are redacted",
                    value="Personal contact data is withheld (privacy/GDPR redaction).",
                    source_url=url))
        return out
