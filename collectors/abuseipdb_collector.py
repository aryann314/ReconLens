"""Public IP reputation lookups using AbuseIPDB API v2."""
from __future__ import annotations

import ipaddress

from .base import BaseCollector, CollectorError, Finding

API = "https://api.abuseipdb.com/api/v2/check"
GUI = "https://www.abuseipdb.com/check/"


class AbuseIPDBCollector(BaseCollector):
    module = "abuseipdb"
    source = "AbuseIPDB"

    def collect(self, target: str) -> list[Finding]:
        key = self.config.get("ABUSEIPDB_API_KEY")
        if not key:
            raise CollectorError("AbuseIPDB API key not configured (ABUSEIPDB_API_KEY in .env).", skipped=True)
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            raise CollectorError("AbuseIPDB checks public IP addresses only.", skipped=True)
        if not address.is_global:
            raise CollectorError("AbuseIPDB checks public IP addresses only.", skipped=True)

        resp = self.http_get(
            API,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": str(address), "maxAgeInDays": 90},
        )
        if resp.status_code == 401:
            raise CollectorError("AbuseIPDB rejected the API key (HTTP 401).")
        if resp.status_code == 429:
            raise CollectorError("AbuseIPDB daily request limit reached (HTTP 429).")
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return self.build_findings(data, str(address))

    def build_findings(self, data: dict, address: str) -> list[Finding]:
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        severity = "high" if score >= 75 else "medium" if score >= 25 else \
            "low" if score > 0 else "info"
        common = {
            "source_url": f"{GUI}{address}",
            "details": {k: data.get(k) for k in (
                "ipAddress", "countryCode", "usageType", "isp", "domain",
                "totalReports", "numDistinctUsers", "lastReportedAt",
            ) if data.get(k) is not None},
        }
        if reports:
            return [self.finding(
                code="ABUSEIPDB_REPORTED",
                title=f"AbuseIPDB confidence score: {score}%",
                value=(f"{reports} reports in the last 90 days; {data.get('numDistinctUsers', 0)} "
                       "distinct reporters. Reputation is a signal, not proof of malicious activity."),
                severity=severity,
                **common,
            )]
        return [self.finding(
            code="ABUSEIPDB_NO_REPORTS",
            title="No recent AbuseIPDB reports",
            value="No abuse reports were returned for the last 90 days. This does not prove the IP is safe.",
            status="not_found",
            **common,
        )]
