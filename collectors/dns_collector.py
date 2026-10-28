"""
collectors/dns_collector.py - Public DNS records and email-security checks.

DNS is public by design: anyone can ask for a domain's records. They reveal
where a domain is hosted, which mail provider it uses, which third-party
SaaS services it has verified (TXT tokens) and whether its email is protected
against spoofing (SPF and DMARC).

Uses dnspython with the operating system's configured resolver. Only normal
DNS queries are sent - no zone transfers (AXFR) or brute-forcing.
"""
from __future__ import annotations

import dns.exception
import dns.resolver

from .base import BaseCollector, CollectorError, Finding

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]

# Patterns that reveal which third-party services a domain uses
TXT_SERVICE_HINTS = {
    "google-site-verification": "Google (Search Console / Workspace)",
    "ms=": "Microsoft 365",
    "facebook-domain-verification": "Meta / Facebook",
    "apple-domain-verification": "Apple",
    "atlassian-domain-verification": "Atlassian",
    "docusign": "DocuSign",
    "adobe-idp-site-verification": "Adobe",
    "zoom-verification": "Zoom",
    "stripe-verification": "Stripe",
    "hubspot": "HubSpot",
    "slack-domain-verification": "Slack",
    "github-verification": "GitHub",
    "_github-challenge": "GitHub",
    "globalsign": "GlobalSign",
    "amazonses": "Amazon SES",
    "mailchimp": "Mailchimp",
    "zoho-verification": "Zoho",
}

MX_PROVIDER_HINTS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "zoho": "Zoho Mail",
    "pphosted.com": "Proofpoint",
    "mimecast": "Mimecast",
    "secureserver.net": "GoDaddy",
    "protonmail": "Proton Mail",
    "yandex": "Yandex",
    "amazonaws.com": "Amazon",
    "mailgun": "Mailgun",
}


def rdata_to_text(rtype: str, rdata) -> str:
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype == "CAA":
        tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag
        val = rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
        return f'{rdata.flags} {tag} "{val}"'
    return rdata.to_text().rstrip(".")


def analyse_spf(txt_records: list[str]) -> tuple[str, str, str]:
    """Return (code, severity, explanation) for the SPF policy."""
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf:
        return ("DNS_SPF_MISSING", "medium",
                "No SPF record. Anyone can send email that claims to come from this domain.")
    if len(spf) > 1:
        return ("DNS_SPF_MULTIPLE", "medium",
                "More than one SPF record exists; RFC 7208 treats this as an error, "
                "so receivers may ignore SPF entirely.")
    record = spf[0].lower().split()
    if "+all" in record or "all" in record:
        return ("DNS_SPF_PERMISSIVE", "high",
                f"SPF ends in '+all', which authorises every server on the internet: {spf[0]}")
    if "?all" in record:
        return ("DNS_SPF_NEUTRAL", "low",
                f"SPF ends in '?all' (neutral), which gives receivers no guidance: {spf[0]}")
    if "~all" in record or "-all" in record:
        return ("DNS_SPF_OK", "info", f"SPF policy present: {spf[0]}")
    return ("DNS_SPF_NEUTRAL", "low", f"SPF record has no 'all' mechanism: {spf[0]}")


def analyse_dmarc(txt_records: list[str]) -> tuple[str, str, str]:
    dmarc = [t for t in txt_records if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not dmarc:
        return ("DNS_DMARC_MISSING", "medium",
                "No DMARC record at _dmarc. Receivers are not told what to do with "
                "spoofed mail.")
    tags = {}
    for part in dmarc[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    policy = tags.get("p", "")
    if policy == "none":
        return ("DNS_DMARC_MONITOR", "low",
                f"DMARC is in monitoring mode (p=none); spoofed mail is still delivered: {dmarc[0]}")
    if policy in ("quarantine", "reject"):
        return ("DNS_DMARC_OK", "info", f"DMARC enforcement policy p={policy}: {dmarc[0]}")
    return ("DNS_DMARC_MISSING", "medium", f"DMARC record has no valid policy: {dmarc[0]}")


class DnsCollector(BaseCollector):
    module = "dns"
    source = "DNS (public resolver)"

    def __init__(self, config: dict, resolver: dns.resolver.Resolver | None = None):
        super().__init__(config)
        if resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = config.get("DNS_TIMEOUT", 5)
            resolver.timeout = min(3, resolver.lifetime)
        self.resolver = resolver

    def query(self, name: str, rtype: str):
        """Return (records, ttl, error). records is a list of strings."""
        try:
            answer = self.resolver.resolve(name, rtype)
            return [rdata_to_text(rtype, r) for r in answer], answer.rrset.ttl, None
        except dns.resolver.NXDOMAIN:
            return None, None, "NXDOMAIN"
        except (dns.resolver.NoAnswer, dns.resolver.NoMetaqueries):
            return [], None, None
        except dns.resolver.NoNameservers:
            return [], None, "SERVFAIL"
        except dns.exception.Timeout:
            return [], None, "TIMEOUT"

    def collect(self, domain: str) -> list[Finding]:
        url = f"https://dns.google/query?name={domain}"
        out: list[Finding] = []
        rows, records, failed = [], {}, []

        for rtype in RECORD_TYPES:
            values, ttl, err = self.query(domain, rtype)
            if err == "NXDOMAIN":
                return [self.finding(
                    code="DNS_NXDOMAIN", title="Domain does not exist in DNS",
                    value="The resolver returned NXDOMAIN (no such domain).",
                    status="not_found", source_url=url)]
            if err:
                failed.append(f"{rtype} ({err})")
                continue
            records[rtype] = values
            rows.extend([rtype, v, ttl] for v in values)

        if len(failed) == len(RECORD_TYPES):
            raise CollectorError(
                "DNS resolution failed for every record type (" + ", ".join(failed) +
                "). Check your internet connection or DNS server.")
        if failed:
            out.append(self.finding(
                code="DNS_PARTIAL", title="Some record types could not be resolved",
                value=", ".join(failed), status="inconclusive", source_url=url))

        out.append(self.finding(
            code="DNS_RECORDS", title="Public DNS records",
            value=f"{len(rows)} records across {len([t for t in records if records[t]])} types",
            source_url=url,
            details={"table": {"columns": ["Type", "Value", "TTL"], "rows": rows}}))

        # ---- hosting / IP exposure
        ips = records.get("A", []) + records.get("AAAA", [])
        if ips:
            out.append(self.finding(
                code="DNS_HOST_IPS", title="Hosting IP addresses",
                value=", ".join(ips), source_url=url))

        # ---- mail provider
        mx = records.get("MX", [])
        if mx:
            providers = sorted({p for rec in mx for k, p in MX_PROVIDER_HINTS.items()
                                if k in rec.lower()})
            out.append(self.finding(
                code="DNS_MX", title="Mail servers (MX)",
                value=", ".join(r.split(" ", 1)[-1] for r in mx)
                      + (f" - provider: {', '.join(providers)}" if providers else ""),
                source_url=url))
        else:
            out.append(self.finding(
                code="DNS_NO_MX", title="No MX records",
                value="This domain does not advertise mail servers (it does not receive email).",
                source_url=url))

        # ---- SaaS footprint from TXT verification tokens
        txt = records.get("TXT", [])
        services = sorted({svc for t in txt for k, svc in TXT_SERVICE_HINTS.items()
                           if k in t.lower()})
        if services:
            out.append(self.finding(
                code="DNS_TXT_SERVICES", title="Third-party services revealed by TXT records",
                value=", ".join(services), source_url=url,
                details={"note": "Verification tokens show which SaaS platforms the "
                                 "organisation uses - useful context for phishing pretexts."}))

        # ---- SPF
        if "TXT" in records:
            code, sev, text = analyse_spf(txt)
            out.append(self.finding(
                code=code, title="SPF (Sender Policy Framework)", value=text,
                severity=sev, source_url=url))

        # ---- DMARC
        dmarc_values, _, err = self.query(f"_dmarc.{domain}", "TXT")
        if err in (None, "NXDOMAIN"):
            code, sev, text = analyse_dmarc(dmarc_values or [])
            out.append(self.finding(
                code=code, title="DMARC (Domain-based Message Authentication)", value=text,
                severity=sev, source_url=f"https://dns.google/query?name=_dmarc.{domain}&type=TXT"))
        else:
            out.append(self.finding(
                code="DNS_DMARC_UNKNOWN", title="DMARC (Domain-based Message Authentication)",
                value=f"Could not query _dmarc record ({err})", status="inconclusive",
                source_url=url))

        # ---- CAA
        if "CAA" in records and not records["CAA"]:
            out.append(self.finding(
                code="DNS_CAA_MISSING", title="No CAA record",
                value="Any certificate authority may issue certificates for this domain.",
                source_url=url))
        elif records.get("CAA"):
            out.append(self.finding(
                code="DNS_CAA_OK", title="CAA record present",
                value="; ".join(records["CAA"]), source_url=url))
        return out
