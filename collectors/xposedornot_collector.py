
"""
XposedOrNot email breach collector.

Uses the public XposedOrNot API.
No API key is required for basic email checks.
"""

from urllib.parse import quote

from collectors.base import BaseCollector, CollectorError

API_URL = "https://api.xposedornot.com/v1/check-email/{}"


class XposedOrNotCollector(BaseCollector):
    module = "xposedornot"
    source = "XposedOrNot"

    def collect(self, email: str):
        url = API_URL.format(quote(email, safe=""))

        response = self.http_get(
            url,
            headers={"Accept": "application/json"},
        )

        if response.status_code == 429:
            raise CollectorError(
                "XposedOrNot rate limit reached. Please try again later."
            )

        if response.status_code == 400:
            raise CollectorError(
                "XposedOrNot rejected the email address."
            )

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            raise CollectorError(
                "XposedOrNot returned an invalid response."
            )

        if data.get("Error") == "Not found":
            return [
                self.finding(
                    code="XON_NO_BREACH",
                    title="No known breach found",
                    value=(
                        "XposedOrNot did not find this email in its "
                        "indexed breach records. This does not guarantee "
                        "that the email has never been exposed."
                    ),
                    status="not_found",
                    severity="info",
                    source_url="https://xposedornot.com/",
                )
            ]

        if data.get("status") != "success":
            raise CollectorError(
                "XposedOrNot returned an unexpected response."
            )

        # The API returns breach names inside a nested list.
        raw_breaches = data.get("breaches", [])

        breaches = []
        for item in raw_breaches:
            if isinstance(item, list):
                breaches.extend(item)
            elif isinstance(item, str):
                breaches.append(item)

        breaches = sorted(set(
            name.strip()
            for name in breaches
            if isinstance(name, str) and name.strip()
        ))

        if not breaches:
            return [
                self.finding(
                    code="XON_NO_BREACH",
                    title="No known breach found",
                    value="No breach names were returned by XposedOrNot.",
                    status="not_found",
                    severity="info",
                    source_url="https://xposedornot.com/",
                )
            ]

        findings = [
            self.finding(
                code="XON_BREACH_SUMMARY",
                title=f"Email found in {len(breaches)} breach(es)",
                value=", ".join(breaches),
                severity="medium",
                source_url="https://xposedornot.com/",
                details={"breach_count": len(breaches)},
            )
        ]

        for breach in breaches:
            findings.append(
                self.finding(
                    code="XON_BREACH",
                    title=f"Exposure reported: {breach}",
                    value=(
                        f"XposedOrNot reports this email in the "
                        f"{breach} breach."
                    ),
                    severity="low",
                    source_url="https://xposedornot.com/",
                    details={"breach_name": breach},
                )
            )

        return findings
