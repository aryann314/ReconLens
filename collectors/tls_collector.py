"""
collectors/tls_collector.py - SSL/TLS certificate analysis.

What it does: opens ONE standard HTTPS (TLS) handshake to port 443 of the
domain - exactly what a web browser does when you visit the site - and reads
the certificate the server presents. No pages are requested, nothing is
probed, and the connection is closed immediately.

Findings:
    TLS_CERT          certificate subject, issuer, validity, SAN count, protocol
    TLS_EXPIRED       certificate already expired                       (high)
    TLS_EXPIRY_SOON   certificate expires within 14 days                (medium)
    TLS_UNTRUSTED     browser-style verification failed (self-signed,
                      wrong host name, unknown CA ...)                  (high)
    TLS_HANDSHAKE_FAILED  port 443 answered but no TLS 1.2+ session     (inconclusive)
    TLS_NO_HTTPS      nothing answered on port 443                      (not found)

Safety: the host name is resolved first and private, loopback or link-local
addresses are refused, so the collector cannot be used to reach internal
systems (SSRF protection).
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from .base import BaseCollector, CollectorError, Finding

EXPIRY_WARNING_DAYS = 14
CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _name(parts) -> dict:
    """Turn ssl's nested ((('commonName', 'x'),),) tuples into a flat dict."""
    out = {}
    for rdn in parts or ():
        for key, value in rdn:
            out[key] = value
    return out


def parse_cert(cert: dict, now: datetime | None = None) -> dict:
    """Extract the fields we report from ssl.getpeercert() output."""
    now = now or datetime.now(timezone.utc)
    subject, issuer = _name(cert.get("subject")), _name(cert.get("issuer"))
    not_before = datetime.strptime(cert["notBefore"], CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return {
        "subject": subject.get("commonName", "(no common name)"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", "unknown"),
        "issuer_cn": issuer.get("commonName", ""),
        "valid_from": not_before.date().isoformat(),
        "valid_until": not_after.date().isoformat(),
        "days_left": (not_after - now).days,
        "san_count": len(sans),
        "sans": sans[:50],
    }


def cert_findings(info: dict, protocol: str, cipher: str, finding) -> list[Finding]:
    """Turn parsed certificate data into findings (pure function, easy to test)."""
    url = f"https://crt.sh/?q={info['subject']}"
    rows = [["Subject (CN)", info["subject"]], ["Issuer", info["issuer"]],
            ["Valid from", info["valid_from"]], ["Valid until", info["valid_until"]],
            ["Days left", info["days_left"]], ["Names covered (SAN)", info["san_count"]],
            ["Protocol", protocol], ["Cipher", cipher]]
    out = [finding(code="TLS_CERT", title="TLS certificate",
                   value=f"Issued by {info['issuer']}, valid until {info['valid_until']} "
                         f"({info['days_left']} days left), negotiated {protocol}",
                   source_url=url,
                   details={"table": {"columns": ["Field", "Value"], "rows": rows},
                            "issuer": info["issuer"], "valid_until": info["valid_until"],
                            "days_left": info["days_left"], "protocol": protocol})]
    if info["days_left"] < 0:
        out.append(finding(code="TLS_EXPIRED", title="TLS certificate has expired",
                           value=f"Expired on {info['valid_until']}. Browsers show a full-page "
                                 "security warning to every visitor.",
                           severity="high", source_url=url))
    elif info["days_left"] <= EXPIRY_WARNING_DAYS:
        out.append(finding(code="TLS_EXPIRY_SOON", title="TLS certificate expires soon",
                           value=f"Expires {info['valid_until']} ({info['days_left']} days left).",
                           severity="medium", source_url=url))
    return out


class TlsCollector(BaseCollector):
    module = "tls"
    source = "TLS certificate (HTTPS handshake)"

    def _public_address(self, domain: str) -> str:
        """Resolve once and return the address to connect to.

        Every address must be public. We then connect to that exact address
        (not the name again), so a second DNS answer pointing at an internal
        host cannot slip through (DNS rebinding).
        """
        try:
            infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise CollectorError("The domain does not resolve, so no certificate can be read.")
        addresses = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if getattr(ip, "ipv4_mapped", None):
                ip = ip.ipv4_mapped
            if not ip.is_global or ip.is_multicast:
                raise CollectorError("The domain resolves to a private/internal address; "
                                     "it was not contacted.", skipped=True)
            addresses.append(info[4][0])
        if not addresses:
            raise CollectorError("The domain does not resolve, so no certificate can be read.")
        return addresses[0]

    def collect(self, domain: str) -> list[Finding]:
        address = self._public_address(domain)
        timeout = self.config.get("HTTP_TIMEOUT", 10)
        context = ssl.create_default_context()
        try:
            # SNI and certificate checks still use the domain name
            with socket.create_connection((address, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
                    protocol = tls.version() or "unknown"
                    cipher = (tls.cipher() or ("unknown",))[0]
        except ssl.SSLCertVerificationError as exc:
            reason = getattr(exc, "verify_message", None) or str(exc)
            return [self.finding(
                code="TLS_UNTRUSTED", title="TLS certificate is not trusted",
                value=f"Browser-style verification failed: {reason}. Visitors see a "
                      "security warning.", severity="high")]
        except ssl.SSLError as exc:
            # Something answered on 443 but no modern TLS session could be set up.
            # We cannot tell why for certain, so this is inconclusive (0 points).
            return [self.finding(
                code="TLS_HANDSHAKE_FAILED", title="TLS handshake failed",
                value=f"A service answered on port 443 but the TLS handshake failed "
                      f"({getattr(exc, 'reason', None) or exc.__class__.__name__}). "
                      "The server may only offer "
                      "outdated protocols (TLS 1.0/1.1) or it is not a TLS service.",
                status="inconclusive")]
        except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError):
            return [self.finding(
                code="TLS_NO_HTTPS", title="No HTTPS service on port 443",
                value="Nothing answered a TLS handshake on port 443 (the domain may not host "
                      "a website, or it blocks the connection).", status="not_found")]
        return cert_findings(parse_cert(cert), protocol, cipher, self.finding)
