"""
collectors/base.py - The common contract every OSINT source follows.

Why this matters: every collector (RDAP, DNS, crt.sh, usernames, HIBP,
VirusTotal) returns findings in ONE shared format. The rest of the app
(scoring, recommendations, database, reports, UI) only understands this
format, so adding a new OSINT source means writing one new collector class -
nothing else has to change.

Finding.status - how sure we are:
    confirmed     the source positively reported this observation
    not_found     the source answered and definitively reported "nothing"
    inconclusive  we could not tell (blocked, rate-limited, ambiguous, redacted)
    error         the source failed (timeout, network, bad response)

Finding.severity - how much it contributes to exposure:
    info < low < medium < high
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import requests

STATUSES = ("confirmed", "not_found", "inconclusive", "error")
SEVERITIES = ("info", "low", "medium", "high")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    module: str
    source: str
    code: str
    title: str
    value: str | None = None
    status: str = "confirmed"
    severity: str = "info"
    source_url: str | None = None
    details: dict = field(default_factory=dict)
    collected_at: str = field(default_factory=utc_now)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"invalid status {self.status!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CollectorResult:
    module: str
    source: str
    findings: list[Finding] = field(default_factory=list)
    status: str = "ok"          # ok | partial | error | skipped
    error: str | None = None
    duration_ms: int = 0

    def summary(self) -> dict:
        return {
            "module": self.module,
            "source": self.source,
            "status": self.status,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "finding_count": len(self.findings),
        }


class CollectorError(Exception):
    """A known, explainable failure (rate limit, missing key, source down)."""

    def __init__(self, message: str, skipped: bool = False):
        super().__init__(message)
        self.skipped = skipped


class BaseCollector:
    module = "base"
    source = "Base collector"

    def __init__(self, config: dict):
        # config is a plain dict copy of Flask's config, because collectors
        # run in worker threads that have no Flask application context.
        self.config = config
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.get("USER_AGENT", "OSINT-Dashboard")

    # ---------------------------------------------------------------- API
    def collect(self, target: str) -> list[Finding]:
        raise NotImplementedError

    def run(self, target: str) -> CollectorResult:
        """Run collect() with timing and uniform error handling."""
        result = CollectorResult(module=self.module, source=self.source)
        start = time.perf_counter()
        try:
            result.findings = self.collect(target)
            statuses = {f.status for f in result.findings}
            if statuses == {"error"}:
                result.status = "error"
                result.error = result.findings[0].value
            elif "error" in statuses:
                result.status = "partial"
        except CollectorError as exc:
            result.status = "skipped" if exc.skipped else "error"
            result.error = str(exc)
            result.findings = [self.error_finding(str(exc))]
        except requests.Timeout:
            result.status = "error"
            result.error = f"{self.source} did not respond within the timeout"
            result.findings = [self.error_finding(result.error)]
        except requests.RequestException as exc:
            result.status = "error"
            result.error = f"Network error contacting {self.source}: {exc.__class__.__name__}"
            result.findings = [self.error_finding(result.error)]
        except Exception as exc:  # never let one source crash the whole scan
            result.status = "error"
            result.error = f"Unexpected error in {self.source}: {exc.__class__.__name__}"
            result.findings = [self.error_finding(result.error)]
        result.duration_ms = int((time.perf_counter() - start) * 1000)
        return result

    # ------------------------------------------------------------ helpers
    def finding(self, **kwargs) -> Finding:
        kwargs.setdefault("module", self.module)
        kwargs.setdefault("source", self.source)
        return Finding(**kwargs)

    def error_finding(self, message: str) -> Finding:
        return self.finding(
            code=f"{self.module.upper()}_ERROR",
            title=f"{self.source} could not be queried",
            value=message,
            status="error",
            severity="info",
        )

    def http_get(self, url: str, *, timeout: int | None = None, **kwargs) -> requests.Response:
        return self.session.get(
            url, timeout=timeout or self.config.get("HTTP_TIMEOUT", 10), **kwargs
        )
