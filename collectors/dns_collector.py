
"""
collectors/dns_collector.py

Google + Cloudflare DNS-over-HTTPS collector for ReconLens.

Queries public DNS records using two independent DNS providers.
No API keys are required.
"""

from __future__ import annotations

import requests
from urllib.parse import urlencode

from .base import BaseCollector, CollectorError, Finding


GOOGLE_DNS_URL = "https://dns.google/resolve"
CLOUDFLARE_DNS_URL = "https://cloudflare-dns.com/dns-query"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]

DNS_TYPE_CODES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    257: "CAA",
}

DNS_TYPE_NUMBERS = {
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
    """Convert DNS JSON data into readable record values."""

    value = str(value).strip()

    if rtype == "TXT":
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        value = value.replace('\\"', '"').replace("\\\\", "\\")

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
    source = "Google + Cloudflare Public DNS"

    def __init__(self, config: dict):
        super().__init__(config)
        self.timeout = config.get("DNS_TIMEOUT", 10)

    def source_url(
        self,
        name: str,
        rtype: str | None = None,
        provider: str = "google"
    ) -> str:
        """Build a public DNS query URL."""

        params = {"name": name}

        if rtype:
            params["type"] = rtype

        if provider == "cloudflare":
            return f"{CLOUDFLARE_DNS_URL}?{urlencode(params)}"

        return f"{GOOGLE_DNS_URL}?{urlencode(params)}"

    def query_provider(
        self,
        name: str,
        rtype: str,
        provider: str
    ):
        """
        Query a DNS provider.

        Returns:
            records: list of DNS record strings
            ttl: record TTL or None
            error: error code or None
        """

        if rtype not in DNS_TYPE_NUMBERS:
            return [], None, "UNSUPPORTED_RECORD_TYPE"

        if provider == "google":
            endpoint = GOOGLE_DNS_URL
            headers = {
                "Accept": "application/dns-json"
            }

        elif provider == "cloudflare":
            endpoint = CLOUDFLARE_DNS_URL
            headers = {
                "Accept": "application/dns-json"
            }

        else:
            return [], None, "UNKNOWN_PROVIDER"

        try:
            response = self.http_get(
                endpoint,
                params={
                    "name": name,
                    "type": rtype
                },
                headers=headers,
                timeout=self.timeout
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
        expected_type = DNS_TYPE_NUMBERS[rtype]

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

    def query(self, name: str, rtype: str):
        """Keep the existing query interface using Google DNS."""

        return self.query_provider(name, rtype, "google")

    def compare_providers(self, domain: str):
        """
        Query both providers and compare their DNS records.

        Google results remain the primary results used by the
        existing ReconLens security checks.
        """

        comparison_rows = []
        differences = []
        cloudflare_errors = []

        for rtype in RECORD_TYPES:

            google_records, _, google_error = self.query_provider(
                domain, rtype, "google"
            )

            cloudflare_records, _, cloudflare_error = self.query_provider(
                domain, rtype, "cloudflare"
            )

            google_records = google_records or []
            cloudflare_records = cloudflare_records or []

            if google_error:
                google_status = google_error
            else:
                google_status = (
                    f"{len(google_records)} record(s)"
                    if google_records else "No records"
                )

            if cloudflare_error:
                cloudflare_status = cloudflare_error
                cloudflare_errors.append(
                    f"{rtype} ({cloudflare_error})"
                )
            else:
                cloudflare_status = (
                    f"{len(cloudflare_records)} record(s)"
                    if cloudflare_records else "No records"
                )

            comparison_rows.append([
                "Google DNS",
                rtype,
                ", ".join(google_records) or "-",
                google_status
            ])

            comparison_rows.append([
                "Cloudflare DNS",
                rtype,
                ", ".join(cloudflare_records) or "-",
                cloudflare_status
            ])

            if not google_error and not cloudflare_error:

                google_set = set(google_records)
                cloudflare_set = set(cloudflare_records)

                if google_set != cloudflare_set:
                    differences.append(
                        f"{rtype}: Google={sorted(google_set)}; "
                        f"Cloudflare={sorted(cloudflare_set)}"
                    )

        return comparison_rows, differences, cloudflare_errors

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
                        source_url=url
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
                    source_url=url
                )
            )

        # -----------------------------------
        # 2. Display Google DNS records
        # -----------------------------------

        out.append(
            self.finding(
                code="DNS_RECORDS",
                title="Public DNS records (Google)",
                value=(
                    f"{len(rows)} records across "
                    f"{len([t for t in records if records[t]])} types"
                ),
                source_url=url,
                details={
                    "table": {
                        "columns": ["Type", "Value", "TTL"],
                        "rows": rows
                    }
                }
            )
        )

        # -----------------------------------
        # 3. Compare Google and Cloudflare
        # -----------------------------------

        comparison_rows, differences, cloudflare_errors = (
            self.compare_providers(domain)
        )

        out.append(
            self.finding(
                code="DNS_PROVIDER_COMPARISON",
                title="DNS provider comparison",
                value=(
                    f"Compared Google DNS and Cloudflare DNS "
                    f"for {len(RECORD_TYPES)} record types."
                ),
                source_url=url,
                details={
                    "table": {
                        "columns": [
                            "Provider",
                            "Type",
                            "Records",
                            "Status"
                        ],
                        "rows": comparison_rows
                    }
                }
            )
        )

        if differences:
            out.append(
                self.finding(
                    code="DNS_PROVIDER_DIFFERENCE",
                    title="DNS provider responses differ",
                    value=(
                        "The providers returned different DNS answers: "
                        + " | ".join(differences)
                    ),
                    severity="low",
                    status="inconclusive",
                    source_url=url
                )
            )

        if cloudflare_errors:
            out.append(
                self.finding(
                    code="DNS_CLOUDFLARE_PARTIAL",
                    title="Cloudflare DNS partial response",
                    value=", ".join(cloudflare_errors),
                    status="inconclusive",
                    source_url=self.source_url(
                        domain, provider="cloudflare"
                    )
                )
            )

        # -----------------------------------
        # 4. Hosting IP addresses
        # -----------------------------------

        ips = records.get("A", []) + records.get("AAAA", [])

        if ips:
            out.append(
                self.finding(
                    code="DNS_HOST_IPS",
                    title="Hosting IP addresses",
                    value=", ".join(ips),
                    source_url=url
                )
            )

        # -----------------------------------
        # 5. Mail server information
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
                    source_url=url
                )
            )

        else:
            out.append(
                self.finding(
                    code="DNS_NO_MX",
                    title="No MX records",
                    value="This domain does not advertise mail servers.",
                    source_url=url
                )
            )

        # -----------------------------------
        # 6. Third-party services from TXT
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
                    }
                )
            )

        # -----------------------------------
        # 7. SPF security analysis
        # -----------------------------------

        if "TXT" in records:

            code, severity, explanation = analyse_spf(txt)

            out.append(
                self.finding(
                    code=code,
                    title="SPF (Sender Policy Framework)",
                    value=explanation,
                    severity=severity,
                    source_url=url
                )
            )

        # -----------------------------------
        # 8. DMARC security analysis
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
                    source_url=self.source_url(dmarc_domain, "TXT")
                )
            )

        else:
            out.append(
                self.finding(
                    code="DNS_DMARC_UNKNOWN",
                    title="DMARC (Domain-based Message Authentication)",
                    value=f"Could not query DMARC record ({err}).",
                    status="inconclusive",
                    source_url=self.source_url(dmarc_domain, "TXT")
                )
            )

        # -----------------------------------
        # 9. CAA security analysis
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
                    source_url=url
                )
            )

        elif caa:

            out.append(
                self.finding(
                    code="DNS_CAA_OK",
                    title="CAA record present",
                    value="; ".join(caa),
                    source_url=url
                )
            )

        return out
