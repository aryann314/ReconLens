
"""
services/scan_service.py - Orchestrates a scan.

    input -> choose collectors -> run them in parallel
    -> merge findings -> score -> recommendations -> limitations

The result is a plain dict; the route layer stores it in SQLite.
To add a new OSINT source, write a collector and add it to COLLECTORS.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from collectors import demo_data
from collectors.base import utc_now
from collectors.crtsh_collector import CrtshCollector
from collectors.dns_collector import DnsCollector
from collectors.rdap_collector import RdapCollector
from collectors.tls_collector import TlsCollector
from collectors.username_collector import UsernameCollector
from collectors.vt_collector import VirusTotalCollector
from collectors.urlhaus_collector import URLhausCollector
from collectors.xposedornot_collector import XposedOrNotCollector

from .recommendations import build_recommendations
from .scoring import compute_score
from .validation import mask_email


COLLECTORS = {
    "domain": [
        RdapCollector,
        DnsCollector,
        CrtshCollector,
        TlsCollector,
    ],

    "username": [
        UsernameCollector,
    ],

    "email": [
        XposedOrNotCollector,
    ],

    "reputation": [
        VirusTotalCollector,
        URLhausCollector,
    ],
}


LIMITATIONS = {
    "domain": [
        "RDAP/WHOIS data may be redacted for privacy; missing fields are labelled, not guessed.",
        "Domain age is shown only when the registry publishes a registration date.",
        "Hostnames from certificate-transparency logs may belong to systems that are no longer online. They indicate past certificate issuance, not current exposure.",
        "DNS answers reflect the resolver used at scan time and may be cached.",
        "The TLS check performs one standard HTTPS handshake on port 443 to read the certificate.",
        "No active scanning (ports or vulnerabilities) is performed. This is passive OSINT only.",
    ],

    "username": [
        "Only the platforms listed in collectors/sites.json are checked.",
        "A matching username does not prove the accounts belong to the same person.",
        "Platforms may block or rate-limit automated requests. Such results are labelled inconclusive and are never counted as found.",
        "Platforms that require login (e.g. Instagram, LinkedIn, X) are excluded by design.",
    ],

    "email": [
        "Email breach results are based on records indexed by XposedOrNot.",
        "A not-found result does not guarantee that an email has never been exposed.",
        "The free API has hourly and daily request limits.",
        "Only check email addresses you own or are authorised to assess.",
    ],

    "reputation": [
        "Reputation is aggregated vendor opinion, not confirmed malicious activity.",
        "Targets never analysed by VirusTotal return no data; we do not submit them.",
        "The free VirusTotal API is limited to 4 requests per minute and 500 per day.",
        "URLhaus checks full URLs, not bare domains or IP addresses.",
        "A URL not found in URLhaus is not guaranteed to be safe.",
    ],
}


def run_collectors(scan_type: str, target: str, config: dict):
    collector_classes = COLLECTORS.get(scan_type)

    if not collector_classes:
        raise ValueError(
            f"No live collectors are configured for scan type: {scan_type}"
        )

    collectors = [
        collector_class(config)
        for collector_class in collector_classes
    ]

    with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
        return list(
            pool.map(lambda collector: collector.run(target), collectors)
        )


def run_scan(
    scan_type: str,
    target: str,
    mode: str,
    config: dict,
    authorization: str | None = None,
) -> dict:

    if scan_type not in ("domain", "username", "email", "reputation"):
        raise ValueError(f"Unsupported scan type: {scan_type}")

    started = utc_now()
    t0 = time.perf_counter()

    if mode == "demo":
        results = demo_data.get_demo_results(scan_type, target)

    elif mode == "live":
        results = run_collectors(scan_type, target, config)

    else:
        raise ValueError(f"Unsupported scan mode: {mode}")

    findings = [
        finding.to_dict()
        for result in results
        for finding in result.findings
    ]

    scoring = compute_score(findings)

    module_states = {
        result.status
        for result in results
    }

    if not module_states or module_states <= {"error", "skipped"}:
        status = "failed"

    elif module_states & {"error", "skipped", "partial"}:
        status = "partial"

    else:
        status = "completed"

    limitations = list(LIMITATIONS[scan_type])

    if mode == "demo":
        limitations.insert(
            0,
            "DEMO MODE: all data in this report is fictional and was not collected from any real source."
        )

    return {
        "scan_type": scan_type,
        "target": mask_email(target) if scan_type == "email" else target,
        "mode": mode,
        "status": status,
        "exposure_score": scoring["score"],
        "exposure_level": scoring["level"],
        "authorization": authorization,
        "started_at": started,
        "completed_at": utc_now(),
        "duration_ms": int(
            (time.perf_counter() - t0) * 1000
        ),
        "modules": [
            result.summary()
            for result in results
        ],
        "findings": findings,
        "scoring": scoring,
        "recommendations": build_recommendations(
            scan_type,
            findings
        ),
        "limitations": limitations,
    }
