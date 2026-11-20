"""
URLhaus collector - checks whether a URL is listed as a malware-distribution URL.
Uses the official URLhaus Community API.
"""
from __future__ import annotations

from .base import BaseCollector, CollectorError, Finding

API = "https://urlhaus-api.abuse.ch/v1/url/"


class URLhausCollector(BaseCollector):
    module = "urlhaus"
    source = "URLhaus"

    def collect(self, target: str) -> list[Finding]:
        # URLhaus looks up URLs, not bare domains or IP addresses.
        if not target.lower().startswith(("http://", "https://")):
            raise CollectorError(
                "URLhaus checks full URLs. Enter a URL beginning with "
                "http:// or https:// to use this source.",
                skipped=True,
            )

        key = self.config.get("URLHAUS_AUTH_KEY")
        if not key:
            raise CollectorError(
                "URLhaus Auth-Key is not configured. Add URLHAUS_AUTH_KEY "
                "to your environment variables.",
                skipped=True,
            )

        response = self.session.post(
            API,
            headers={
                "Auth-Key": key,
                "Accept": "application/json",
            },
            data={"url": target},
            timeout=self.config.get("HTTP_TIMEOUT", 10),
        )

        if response.status_code == 401:
            raise CollectorError("URLhaus rejected the Auth-Key (HTTP 401).")
        if response.status_code == 429:
            raise CollectorError("URLhaus rate limit reached. Try again later.")

        response.raise_for_status()
        result = response.json()
        query_status = result.get("query_status", "")

        if query_status == "no_results":
            return [self.finding(
                code="URLHAUS_NOT_LISTED",
                title="URL not found in URLhaus",
                value=(
                    "URLhaus has no matching record for this URL. "
                    "This does not guarantee that the URL is safe."
                ),
                status="not_found",
                source_url="https://urlhaus.abuse.ch/",
            )]

        if query_status != "ok":
            raise CollectorError(
                f"URLhaus returned query status: {query_status or 'unknown'}"
            )

        url_status = result.get("url_status", "unknown")
        threat = result.get("threat", "unknown")
        tags = result.get("tags") or []
        date_added = result.get("date_added", "Not provided")
        last_online = result.get("last_online") or "Not reported"
        url_id = result.get("id", "Not provided")

        tag_text = ", ".join(str(tag) for tag in tags) or "No tags provided"

        return [
            self.finding(
                code="URLHAUS_LISTED",
                title="URL found in URLhaus malware database",
                value=(
                    f"URLhaus lists this URL as a malware-distribution URL. "
                    f"Status: {url_status}. Threat: {threat}. "
                    f"Tags: {tag_text}."
                ),
                status="confirmed",
                severity="high",
                source_url="https://urlhaus.abuse.ch/",
                details={
                    "url_id": url_id,
                    "url_status": url_status,
                    "threat": threat,
                    "tags": tags,
                    "date_added": date_added,
                    "last_online": last_online,
                    "reporter": result.get("reporter"),
                    "payloads": result.get("payloads") or [],
                    "table": {
                        "columns": ["Field", "Value"],
                        "rows": [
                            ["URL status", url_status],
                            ["Threat", threat],
                            ["Tags", tag_text],
                            ["Date added", date_added],
                            ["Last online", last_online],
                            ["URLhaus ID", url_id],
                        ],
                    },
                },
            )
        ]
