
"""
collectors/dns_collector.py

Google Public DNS-over-HTTPS collector for ReconLens.

Queries public DNS records using Google's JSON API.
No API key is required.
"""

from __future__ import annotations

import requests
from urllib.parse import urlencode

from .base import BaseCollector, CollectorError, Finding


GOOGLE_DNS_URL = "https://dns.google/resolve"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]

# DNS numeric type codes returned by Google's JSON API
DNS_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}

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


def clean_dns_value(rtype: str, value: str) -> str:
    """Convert Google's DNS JSON data into readable record values."""

    value = str(value).strip()

    if rtype == "TXT":
        # Google's JSON API wraps TXT values in quotation marks.
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        value = value.replace('\\"', '"').replace("\\\\", "\\")
        return value

    if rtype in ("A", "AAAA"):
        return value

    return value.rstrip(".")


def analyse_spf(txt_records: list[str]) -> tuple[str, str, str]:
    """Return (code, severity, explanation) for SPF."""

    spf = [
        record for record in txt_records
        if record.lower().startswith("v=spf1")
    ]

    if not spf:
        return (
            "DNS_SPF_MISSING",
            "medium",
            "No SPF record. Anyone can send email claiming to come from this domain."
        )

    if len(spf) > 1:
        return (
            "DNS_SPF_MULTIPLE",
            "medium",
            "More than one SPF record exists. This can cause SPF validation errors."
        )

    record = spf[0].lower().split()

    if "+all" in record:
        return (
            "DNS_SPF_PERMISSIVE",
            "high",
            f"SPF ends in '+all', which authorises every server: {spf[0]}"
        )

    if "?all" in record:
        return (
            "DNS_SPF_NEUTRAL",
            "low",
            f"SPF ends in '?all' (neutral): {spf[0]}"
        )

    if "~all" in record or "-all" in record:
        return (
            "DNS_SPF_OK",
            "info",
            f"SPF policy present: {spf[0]}"
        )

    return (
        "DNS_SPF_NEUTRAL",
        "low",
        f"SPF record has no clear all mechanism: {spf[0]}"
    )


def analyse_dmarc(txt_records: list[str]) -> tuple[str, str, str]:
    """Return (code, severity, explanation) for DMARC."""

    dmarc = [
        record for record in txt_records
        if record.lower().replace(" ", "").startswith("v=dmarc1")
    ]

    if not dmarc:
        return (
            "DNS_DMARC_MISSING",
            "medium",
            "No DMARC record found at _dmarc."
        )

    tags = {}

    for part in dmarc[0].split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip().lower()

    policy = tags.get("p", "")

    if policy == "none":
        return (
            "DNS_DMARC_MONITOR",
            "low",
            f"DMARC is in monitoring mode (p=none): {dmarc[0]}"
        )

    if policy in ("quarantine", "reject"):
        return (
            "DNS_DMARC_OK",
            "info",
            f"DMARC enforcement policy p={policy}: {dmarc[0]}"
        )

    return (
        "DNS_DMARC_MISSING",
        "medium",
        f"DMARC record has no valid policy: {dmarc[0]}"
    )


class DnsCollector(BaseCollector):

    module = "dns"
    source = "Google Public DNS (DNS-over-HTTPS)"

    def __init__(self, config: dict):
        super().__init__(config)
        self.timeout = config.get("DNS_TIMEOUT", 10)

    def source_url(self, name: str, rtype: str | None = None) -> str:
        """Build a link to the Google DNS query."""

        params = {"name": name}

        if rtype:
            params["type"] = rtype

        return f"{GOOGLE_DNS_URL}?{urlencode(params)}"

    def query(self, name: str, rtype: str):
        """
        Query Google Public DNS.

        Returns:
            records: list of DNS record strings
            ttl: record TTL or None
            error: error code or None
        """

        if rtype not in DNS_TYPE_CODES:
            return [], None, "UNSUPPORTED_RECORD_TYPE"

        try:
            response = self.http_get(
                GOOGLE_DNS_URL,
                params={
                    "name": name,
                    "type": rtype,
                },
                headers={
                    "Accept": "application/dns-json"
                },
                timeout=self.timeout,
            )

            response.raise_for_status()
            payload = response.json()

        except requests.Timeout:
            return [], None, "TIMEOUT"

        except requests.RequestException:
            return [], None, "HTTP_ERROR"

        except ValueError:
            return [], None, "INVALID_JSON"

        status = payload.get("Status")

        # DNS response status 3 means NXDOMAIN.
        if status == 3:
            return None, None, "NXDOMAIN"

        if status != 0:
            error_names = {
                1: "FORMERR",
                2: "SERVFAIL",
                4: "NOTIMP",
                5: "REFUSED",
            }
            return [], None, error_names.get(
                status, f"DNS_STATUS_{status}"
            )

        answers = payload.get("Answer", [])
        expected_type = DNS_TYPE_CODES[rtype]

        # Ignore unrelated records, such as CNAME records returned
        # alongside an A-record lookup.
        matching = [
            answer for answer in answers
            if answer.get("type") == expected_type
        ]

        if not matching:
            return [], None, None

        records = [
            clean_dns_value(rtype, answer.get("data", ""))
            for answer in matching
        ]

        ttls = [
            answer.get("TTL")
            for answer in matching
            if isinstance(answer.get("TTL"), int)
        ]

        ttl = min(ttls) if ttls else None

        return records, ttl, None

    def collect(self, domain: str) -> list[Finding]:

        url = self.source_url(domain)

        out: list[Finding] = []
        rows = []
        records = {}
        failed = []

        # -----------------------------------
        # 1. Retrieve DNS records from Google
        # -----------------------------------

        for rtype in RECORD_TYPES:

            values, ttl, err = self.query(domain, rtype)

            if err == "NXDOMAIN":
                return [
                    self.finding(
                        code="DNS_NXDOMAIN",
                        title="Domain does not exist in DNS",
                        value="Google DNS returned NXDOMAIN.",
                        status="not_found",
                        source_url=url,
                    )
                ]

            if err:
                failed.append(f"{rtype} ({err})")
                continue

            records[rtype] = values

            for value in values:
                rows.append([rtype, value, ttl])

        if len(failed) == len(RECORD_TYPES):
            raise CollectorError(
                "Google DNS could not resolve any record types: "
                + ", ".join(failed)
            )

        if failed:
            out.append(
                self.finding(
                    code="DNS_PARTIAL",
                    title="Some record types could not be resolved",
                    value=", ".join(failed),
                    status="inconclusive",
                    source_url=url,
                )
            )

        # -----------------------------------
        # 2. Display all DNS records
        # -----------------------------------

        out.append(
            self.finding(
                code="DNS_RECORDS",
                title="Public DNS records",
                value=(
                    f"{len(rows)} records across "
                    f"{len([t for t in records if records[t]])} types"
                ),
                source_url=url,
                details={
                    "table": {
                        "columns": ["Type", "Value", "TTL"],
                        "rows": rows,
                    }
                },
            )
        )

        # -----------------------------------
        # 3. Hosting IP addresses
        # -----------------------------------

        ips = records.get("A", []) + records.get("AAAA", [])

        if ips:
            out.append(
                self.finding(
                    code="DNS_HOST_IPS",
                    title="Hosting IP addresses",
                    value=", ".join(ips),
                    source_url=url,
                )
            )

        # -----------------------------------
        # 4. Mail server information
        # -----------------------------------

        mx = records.get("MX", [])

        if mx:

            providers = sorted({
                provider
                for record in mx
                for keyword, provider in MX_PROVIDER_HINTS.items()
                if keyword in record.lower()
            })

            out.append(
                self.finding(
                    code="DNS_MX",
                    title="Mail servers (MX)",
                    value=(
                        ", ".join(
                            record.split(" ", 1)[-1]
                            for record in mx
                        )
                        + (
                            f" - provider: {', '.join(providers)}"
                            if providers else ""
                        )
                    ),
                    source_url=url,
                )
            )

        else:
            out.append(
                self.finding(
                    code="DNS_NO_MX",
                    title="No MX records",
                    value="This domain does not advertise mail servers.",
                    source_url=url,
                )
            )

        # -----------------------------------
        # 5. Third-party services from TXT
        # -----------------------------------

        txt = records.get("TXT", [])

        services = sorted({
            service
            for record in txt
            for keyword, service in TXT_SERVICE_HINTS.items()
            if keyword in record.lower()
        })

        if services:
            out.append(
                self.finding(
                    code="DNS_TXT_SERVICES",
                    title="Third-party services revealed by TXT records",
                    value=", ".join(services),
                    source_url=url,
                    details={
                        "note": (
                            "TXT verification records can reveal third-party "
                            "services used by the organisation."
                        )
                    },
                )
            )

        # -----------------------------------
        # 6. SPF security analysis
        # -----------------------------------

        if "TXT" in records:

            code, severity, explanation = analyse_spf(txt)

            out.append(
                self.finding(
                    code=code,
                    title="SPF (Sender Policy Framework)",
                    value=explanation,
                    severity=severity,
                    source_url=url,
                )
            )

        # -----------------------------------
        # 7. DMARC security analysis
        # -----------------------------------

        dmarc_domain = f"_dmarc.{domain}"

        dmarc_values, _, err = self.query(dmarc_domain, "TXT")

        if err in (None, "NXDOMAIN"):

            code, severity, explanation = analyse_dmarc(
                dmarc_values or []
            )

            out.append(
                self.finding(
                    code=code,
                    title="DMARC (Domain-based Message Authentication)",
                    value=explanation,
                    severity=severity,
                    source_url=self.source_url(dmarc_domain, "TXT"),
                )
            )

        else:
            out.append(
                self.finding(
                    code="DNS_DMARC_UNKNOWN",
                    title="DMARC (Domain-based Message Authentication)",
                    value=f"Could not query DMARC record ({err}).",
                    status="inconclusive",
                    source_url=self.source_url(dmarc_domain, "TXT"),
                )
            )

        # -----------------------------------
        # 8. CAA security analysis
        # -----------------------------------

        caa = records.get("CAA", [])

        if "CAA" in records and not caa:

            out.append(
                self.finding(
                    code="DNS_CAA_MISSING",
                    title="No CAA record",
                    value=(
                        "No CAA record was found. This does not restrict "
                        "certificate authorities through DNS CAA."
                    ),
                    source_url=url,
                )
            )

        elif caa:

            out.append(
                self.finding(
                    code="DNS_CAA_OK",
                    title="CAA record present",
                    value="; ".join(caa),
                    source_url=url,
                )
            )

        return out
