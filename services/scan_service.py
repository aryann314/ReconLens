"""
services/scan_service.py - Orchestrates a scan.

    input -> choose collectors -> run them in parallel (each with its own
    timeout) -> merge findings -> score -> recommendations -> limitations

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
from collectors.hibp_collector import HibpCollector
from collectors.rdap_collector import RdapCollector
from collectors.tls_collector import TlsCollector
from collectors.username_collector import UsernameCollector
from collectors.vt_collector import VirusTotalCollector

from .recommendations import build_recommendations
from .scoring import compute_score
from .validation import mask_email

COLLECTORS = {
    "domain": [RdapCollector, DnsCollector, CrtshCollector, TlsCollector],
    "username": [UsernameCollector],
    "email": [HibpCollector],
    "reputation": [VirusTotalCollector],
}

LIMITATIONS = {
    "domain": [
        "RDAP/WHOIS data may be redacted for privacy; missing fields are labelled, not guessed.",
        "Domain age is shown only when the registry publishes a registration date.",
        "Hostnames from certificate-transparency logs may belong to systems that are no "
        "longer online. They indicate past certificate issuance, not current exposure.",
        "DNS answers reflect the resolver used at scan time and may be cached.",
        "The TLS check performs one standard HTTPS handshake on port 443 (what any browser "
        "does) to read the certificate. No other contact with the target is made.",
        "No active scanning (ports, vulnerabilities) is performed - this is passive OSINT only.",
    ],
    "username": [
        "Only the platforms listed in collectors/sites.json are checked.",
        "A matching username does not prove the accounts belong to the same person.",
        "Platforms may block or rate-limit automated requests; such results are labelled "
        "inconclusive and are never counted as found.",
        "Platforms that require login (e.g. Instagram, LinkedIn, X) are excluded by design.",
    ],
    "email": [
        "Results cover only breaches loaded into Have I Been Pwned.",
        "'Not found' means HIBP holds no record - not that the address was never exposed.",
        "Only check addresses you own or are authorised to assess.",
    ],
    "reputation": [
        "Reputation is aggregated vendor opinion, not confirmed malicious activity.",
        "Targets never analysed by VirusTotal return no data; we do not submit them.",
        "The free VirusTotal API is limited to 4 requests per minute and 500 per day.",
    ],
}


def run_collectors(scan_type: str, target: str, config: dict):
    collectors = [cls(config) for cls in COLLECTORS[scan_type]]
    with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
        return list(pool.map(lambda c: c.run(target), collectors))


def run_scan(scan_type: str, target: str, mode: str, config: dict,
             authorization: str | None = None) -> dict:
    started = utc_now()
    t0 = time.perf_counter()

    if mode == "demo":
        results = demo_data.get_demo_results(scan_type, target)
    else:
        results = run_collectors(scan_type, target, config)

    findings = [f.to_dict() for r in results for f in r.findings]
    scoring = compute_score(findings)
    module_states = {r.status for r in results}
    if module_states <= {"error", "skipped"}:
        status = "failed"
    elif module_states & {"error", "skipped", "partial"}:
        status = "partial"
    else:
        status = "completed"

    limitations = list(LIMITATIONS[scan_type])
    if mode == "demo":
        limitations.insert(0, "DEMO MODE: all data in this report is fictional and was not "
                              "collected from any real source.")

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
        "duration_ms": int((time.perf_counter() - t0) * 1000),
        "modules": [r.summary() for r in results],
        "findings": findings,
        "scoring": scoring,
        "recommendations": build_recommendations(scan_type, findings),
        "limitations": limitations,
    }
