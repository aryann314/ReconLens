"""
collectors/demo_data.py - Safe demo mode with FICTIONAL data.

Demo mode lets you present the dashboard without querying any real person or
organisation and without internet access. Every target below is fictional:
  * domains use the reserved ".test" TLD (RFC 2606), which can never be
    registered, so they cannot belong to anyone;
  * the usernames/emails are invented for this project.

The fixtures produce exactly the same Finding objects (same codes, same
structure) as the live collectors, so scoring, recommendations, the database,
the UI and reports all behave identically in both modes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .base import CollectorResult, Finding
from .username_collector import load_sites

DEMO_SOURCE_SUFFIX = " [DEMO - fictional data]"

DEMO_TARGETS = {
    "domain": [
        {"target": "demo-corp.test", "label": "Weakly configured organisation"},
        {"target": "secure-shop.test", "label": "Well configured organisation"},
    ],
    "username": [
        {"target": "demo_analyst", "label": "Handle reused on many platforms"},
        {"target": "ghost_user_404", "label": "Handle with almost no footprint"},
    ],
    "email": [
        {"target": "alice@demo-corp.test", "label": "Address found in 3 breaches"},
        {"target": "bob@secure-shop.test", "label": "Address with no known breaches"},
    ],
    "reputation": [
        {"target": "phish-login.demo-corp.test", "label": "Domain flagged by engines"},
        {"target": "secure-shop.test", "label": "Domain with clean reputation"},
    ],
}


def demo_targets_for(scan_type: str) -> set[str]:
    return {t["target"] for t in DEMO_TARGETS.get(scan_type, [])}


def _f(module, source, code, title, value=None, status="confirmed", severity="info",
       url=None, details=None) -> Finding:
    return Finding(module=module, source=source + DEMO_SOURCE_SUFFIX, code=code, title=title,
                   value=value, status=status, severity=severity,
                   source_url=url, details=details or {})


def _result(module, source, findings, ms) -> CollectorResult:
    status = "partial" if any(f.status == "error" for f in findings) else "ok"
    return CollectorResult(module=module, source=source + DEMO_SOURCE_SUFFIX,
                           findings=findings, status=status, duration_ms=ms)


# ------------------------------------------------------------------ domain
def _domain(target: str) -> list[CollectorResult]:
    now = datetime.now(timezone.utc)
    weak = target == "demo-corp.test"
    rd, rs = "rdap", "RDAP / WHOIS registration data (RDAP)"
    url = f"https://rdap.example.invalid/domain/{target}"

    reg_date = now - timedelta(days=365 * (6 if weak else 9) + 40)
    exp_date = now + timedelta(days=21 if weak else 730)
    rdap = [
        _f(rd, rs, "RDAP_REGISTRAR", "Registrar", "Example Registrar Ltd (fictional)", url=url),
        _f(rd, rs, "RDAP_REGISTRATION_DATE", "Registration date",
           f"{reg_date.date()} (domain age: {(now - reg_date).days // 365} years, "
           f"{(now - reg_date).days % 365} days)", url=url,
           details={"registered": reg_date.isoformat(), "age_days": (now - reg_date).days}),
    ]
    if weak:
        rdap += [
            _f(rd, rs, "RDAP_EXPIRY_SOON", "Registration expires soon",
               f"Expires {exp_date.date()} (21 days left)", severity="medium", url=url),
            _f(rd, rs, "RDAP_NAMESERVERS", "Registered nameservers",
               "ns1.cheap-dns.test, ns2.cheap-dns.test", url=url,
               details={"table": {"columns": ["Nameserver"],
                                  "rows": [["ns1.cheap-dns.test"], ["ns2.cheap-dns.test"]]}}),
            _f(rd, rs, "RDAP_STATUS", "Registry status codes", "active", url=url),
            _f(rd, rs, "RDAP_NO_TRANSFER_LOCK", "No transfer lock on the domain",
               "No 'transfer prohibited' status was found. A transfer lock helps prevent "
               "domain hijacking.", severity="low", url=url),
            _f(rd, rs, "RDAP_DNSSEC_OFF", "DNSSEC not enabled",
               "Delegation is unsigned; DNS answers cannot be cryptographically verified.",
               severity="low", url=url),
            _f(rd, rs, "RDAP_REGISTRANT_PUBLIC", "Registrant contact details are public",
               "Registrant fields published: email, name", severity="low", url=url,
               details={"fields_visible": ["email", "name"]}),
        ]
    else:
        rdap += [
            _f(rd, rs, "RDAP_EXPIRY", "Expiry date", f"{exp_date.date()} (730 days left)", url=url),
            _f(rd, rs, "RDAP_NAMESERVERS", "Registered nameservers",
               "ns1.secure-dns.test, ns2.secure-dns.test", url=url,
               details={"table": {"columns": ["Nameserver"],
                                  "rows": [["ns1.secure-dns.test"], ["ns2.secure-dns.test"]]}}),
            _f(rd, rs, "RDAP_STATUS", "Registry status codes",
               "client transfer prohibited, client delete prohibited, client update prohibited",
               url=url),
            _f(rd, rs, "RDAP_DNSSEC_ON", "DNSSEC", "Delegation is signed (DNSSEC enabled)", url=url),
            _f(rd, rs, "RDAP_REGISTRANT_REDACTED", "Registrant contact details are redacted",
               "Personal contact data is withheld (privacy/GDPR redaction).", url=url),
        ]

    dm, ds = "dns", "DNS (public resolver)"
    durl = f"https://dns.google/query?name={target}"
    if weak:
        rows = [["A", "203.0.113.10", 300], ["A", "203.0.113.11", 300],
                ["MX", "1 aspmx.l.google.com", 3600], ["NS", "ns1.cheap-dns.test", 86400],
                ["NS", "ns2.cheap-dns.test", 86400],
                ["TXT", "v=spf1 include:_spf.google.com ?all", 3600],
                ["TXT", "google-site-verification=DEMO123", 3600],
                ["TXT", "MS=ms00000000", 3600],
                ["TXT", "atlassian-domain-verification=DEMO456", 3600]]
        dns = [
            _f(dm, ds, "DNS_RECORDS", "Public DNS records", f"{len(rows)} records across 4 types",
               url=durl, details={"table": {"columns": ["Type", "Value", "TTL"], "rows": rows}}),
            _f(dm, ds, "DNS_HOST_IPS", "Hosting IP addresses", "203.0.113.10, 203.0.113.11", url=durl),
            _f(dm, ds, "DNS_MX", "Mail servers (MX)",
               "aspmx.l.google.com - provider: Google Workspace", url=durl),
            _f(dm, ds, "DNS_TXT_SERVICES", "Third-party services revealed by TXT records",
               "Atlassian, Google (Search Console / Workspace), Microsoft 365", url=durl,
               details={"note": "Verification tokens show which SaaS platforms the organisation "
                                "uses - useful context for phishing pretexts."}),
            _f(dm, ds, "DNS_SPF_NEUTRAL", "SPF (Sender Policy Framework)",
               "SPF ends in '?all' (neutral), which gives receivers no guidance: "
               "v=spf1 include:_spf.google.com ?all", severity="low", url=durl),
            _f(dm, ds, "DNS_DMARC_MISSING", "DMARC (Domain-based Message Authentication)",
               "No DMARC record at _dmarc. Receivers are not told what to do with spoofed mail.",
               severity="medium", url=durl),
            _f(dm, ds, "DNS_CAA_MISSING", "No CAA record",
               "Any certificate authority may issue certificates for this domain.", url=durl),
        ]
    else:
        rows = [["A", "198.51.100.20", 300], ["AAAA", "2001:db8::20", 300],
                ["MX", "10 mx1.secure-mail.test", 3600], ["NS", "ns1.secure-dns.test", 86400],
                ["NS", "ns2.secure-dns.test", 86400], ["TXT", "v=spf1 mx -all", 3600],
                ["CAA", '0 issue "letsencrypt.org"', 3600]]
        dns = [
            _f(dm, ds, "DNS_RECORDS", "Public DNS records", f"{len(rows)} records across 6 types",
               url=durl, details={"table": {"columns": ["Type", "Value", "TTL"], "rows": rows}}),
            _f(dm, ds, "DNS_HOST_IPS", "Hosting IP addresses", "198.51.100.20, 2001:db8::20", url=durl),
            _f(dm, ds, "DNS_MX", "Mail servers (MX)", "mx1.secure-mail.test", url=durl),
            _f(dm, ds, "DNS_SPF_OK", "SPF (Sender Policy Framework)",
               "SPF policy present: v=spf1 mx -all", url=durl),
            _f(dm, ds, "DNS_DMARC_OK", "DMARC (Domain-based Message Authentication)",
               "DMARC enforcement policy p=reject: v=DMARC1; p=reject; rua=mailto:dmarc@secure-shop.test",
               url=durl),
            _f(dm, ds, "DNS_CAA_OK", "CAA record present", '0 issue "letsencrypt.org"', url=durl),
        ]

    cm, cs = "crtsh", "crt.sh Certificate Transparency"
    curl = f"https://crt.sh/?q=%25.{target}"
    if weak:
        hosts = ["demo-corp.test", "www.demo-corp.test", "mail.demo-corp.test",
                 "shop.demo-corp.test", "blog.demo-corp.test", "api.demo-corp.test",
                 "dev.demo-corp.test", "staging.demo-corp.test", "vpn.demo-corp.test",
                 "old-admin.demo-corp.test", "jenkins.demo-corp.test", "test2.demo-corp.test",
                 "cdn.demo-corp.test", "support.demo-corp.test"]
        sens = [["dev.demo-corp.test", "dev"], ["jenkins.demo-corp.test", "jenkins"],
                ["old-admin.demo-corp.test", "old"], ["staging.demo-corp.test", "staging"],
                ["test2.demo-corp.test", "test"], ["vpn.demo-corp.test", "vpn"]]
    else:
        hosts = ["secure-shop.test", "www.secure-shop.test", "api.secure-shop.test",
                 "status.secure-shop.test"]
        sens = []
    first = (now - timedelta(days=900)).date().isoformat()
    last = (now + timedelta(days=60)).date().isoformat()
    crt = [_f(cm, cs, "CRTSH_SUBDOMAINS", "Hostnames observed in certificate logs",
              f"{len(hosts)} unique hostnames in {len(hosts) * 3} certificates", url=curl,
              details={"table": {"columns": ["Hostname", "First seen", "Latest expiry", "Certs"],
                                 "rows": [[h, first, last, 3] for h in sorted(hosts)]},
                       "note": "Observed in CT logs; a hostname may no longer be active."})]
    if sens:
        crt.append(_f(cm, cs, "CRTSH_SENSITIVE_SUBDOMAINS",
                      "Sensitive-looking subdomains are publicly discoverable",
                      f"{len(sens)} hostnames suggest dev/test/admin/remote-access systems",
                      severity="medium", url=curl,
                      details={"table": {"columns": ["Hostname", "Keyword"], "rows": sens},
                               "note": "Names alone do not prove a system is exposed - verify each."}))
        crt.append(_f(cm, cs, "CRTSH_WILDCARD", "Wildcard certificates in use",
                      "At least one *. certificate exists; hostnames behind it are hidden from CT logs.",
                      url=curl))
    crt.append(_f(cm, cs, "CRTSH_ISSUERS", "Certificate authorities used",
                  "Let's Encrypt (" + str(len(hosts) * 3) + ")", url=curl))
    tm, ts = "tls", "TLS certificate (HTTPS handshake)"
    days = 9 if weak else 74
    valid_until = (now + timedelta(days=days)).date().isoformat()
    valid_from = (now - timedelta(days=90 - days)).date().isoformat()
    issuer = "Let's Encrypt"
    proto = "TLSv1.2" if weak else "TLSv1.3"
    cipher = "ECDHE-RSA-AES128-GCM-SHA256" if weak else "TLS_AES_256_GCM_SHA384"
    sans = 2 if weak else 3
    tls = [_f(tm, ts, "TLS_CERT", "TLS certificate",
              f"Issued by {issuer}, valid until {valid_until} ({days} days left), "
              f"negotiated {proto}", url=f"https://crt.sh/?q={target}",
              details={"table": {"columns": ["Field", "Value"], "rows": [
                  ["Subject (CN)", target], ["Issuer", issuer], ["Valid from", valid_from],
                  ["Valid until", valid_until], ["Days left", days],
                  ["Names covered (SAN)", sans], ["Protocol", proto], ["Cipher", cipher]]},
                  "issuer": issuer, "valid_until": valid_until, "days_left": days,
                  "protocol": proto})]
    if weak:
        tls.append(_f(tm, ts, "TLS_EXPIRY_SOON", "TLS certificate expires soon",
                      f"Expires {valid_until} ({days} days left).", severity="medium",
                      url=f"https://crt.sh/?q={target}"))
    return [_result(rd, rs.split(" (")[0], rdap, 640), _result(dm, ds, dns, 210),
            _result(cm, cs, crt, 2830), _result(tm, ts, tls, 180)]


# ---------------------------------------------------------------- username
def _username(target: str) -> list[CollectorResult]:
    m, s = "username", "Public platform profiles"
    if target == "demo_analyst":
        found = {"GitHub", "GitLab", "Docker Hub", "PyPI", "DEV Community", "Hacker News",
                 "Chess.com", "Codeforces"}
        inconclusive = {"Reddit": "Rate-limited by the platform (HTTP 429)",
                        "Steam Community": "Bot-protection page returned - not bypassed by design"}
    else:
        found = set()
        inconclusive = {"Reddit": "Request blocked by the platform (HTTP 403)",
                        "Pastebin": "Bot-protection page returned - not bypassed by design"}
    findings = []
    for site in load_sites():
        profile = site.get("profile_url", site["url"]).format(target)
        details = {"platform": site["name"], "category": site.get("category", "")}
        if site["name"] in found:
            details.update(http_status=200, reason="Public profile responded (HTTP 200)")
            findings.append(_f(m, s, "USERNAME_FOUND", site["name"], profile, "confirmed", "low",
                               profile, details))
        elif site["name"] in inconclusive:
            details["reason"] = inconclusive[site["name"]]
            findings.append(_f(m, s, "USERNAME_INCONCLUSIVE", site["name"], details["reason"],
                               "inconclusive", "info", profile, details))
        else:
            details.update(http_status=404, reason="Platform reported no such user (HTTP 404)")
            findings.append(_f(m, s, "USERNAME_NOT_FOUND", site["name"], details["reason"],
                               "not_found", "info", profile, details))
    if len(found) >= 5:
        findings.insert(0, _f(
            m, s, "USERNAME_REUSE", "Same username reused across many platforms",
            f"'{target}' was found on {len(found)} platforms. Reusing one handle makes it easy "
            "to link accounts and build a profile for social engineering.", severity="medium",
            details={"platforms": sorted(found)}))
    return [_result(m, s, findings, 3120)]


# ------------------------------------------------------------------- email
def _email(target: str) -> list[CollectorResult]:
    m, s = "hibp", "Have I Been Pwned"
    if target.startswith("bob@"):
        return [_result(m, s, [_f(
            m, s, "HIBP_NO_BREACH", "Not found in any known breach",
            "HIBP has no breach records for this address. This does not guarantee the address "
            "was never exposed - only that HIBP holds no record of it.", "not_found",
            url="https://haveibeenpwned.com/")], 480)]
    breaches = [
        ("DemoForum", "2021-06-14", ["Email addresses", "Passwords", "Usernames", "IP addresses"],
         "HIBP_BREACH_PASSWORDS", "high"),
        ("ShopSample", "2019-11-02", ["Email addresses", "Names", "Phone numbers",
                                      "Physical addresses"], "HIBP_BREACH", "medium"),
        ("MarketingList", "2018-03-20", ["Email addresses", "Names"],
         "HIBP_BREACH_SPAMLIST", "low"),
    ]
    rows, findings, classes = [], [], set()
    for name, date, dc, code, sev in breaches:
        classes.update(dc)
        rows.append([f"{name} (fictional)", date, ", ".join(dc),
                     "spam list" if code.endswith("SPAMLIST") else "verified"])
        findings.append(_f(m, s, code, f"Breach: {name} (fictional)",
                           f"Breached {date}. Data exposed: {', '.join(dc)}", severity=sev,
                           url="https://haveibeenpwned.com/",
                           details={"breach_date": date, "data_classes": dc, "verified": True,
                                    "description": "Fictional breach used for demonstration."}))
    findings.insert(0, _f(m, s, "HIBP_SUMMARY", "Address appears in 3 known breach(es)",
                          "Exposed data types: " + ", ".join(sorted(classes)),
                          url="https://haveibeenpwned.com/",
                          details={"table": {"columns": ["Breach", "Date", "Data classes", "Flags"],
                                             "rows": rows}}))
    return [_result(m, s, findings, 520)]


# -------------------------------------------------------------- reputation
def _reputation(target: str) -> list[CollectorResult]:
    m, s = "virustotal", "VirusTotal"
    gui = f"https://www.virustotal.com/gui/domain/{target}"
    note = "Reputation data from security vendors - a signal, not confirmed malicious activity."
    if target.startswith("phish-login"):
        stats = {"malicious": 7, "suspicious": 2, "undetected": 21, "harmless": 62, "timeout": 0}
        findings = [
            _f(m, s, "VT_MALICIOUS", "Flagged as malicious by 7 of 92 engines",
               f"Last analysed 2026-10-19. {note}", severity="high", url=gui),
            _f(m, s, "VT_SUSPICIOUS", "Flagged as suspicious by 2 of 92 engines",
               f"Last analysed 2026-10-19. {note}", severity="medium", url=gui),
        ]
        rep, cats = -15, "phishing, suspicious"
    else:
        stats = {"malicious": 0, "suspicious": 0, "undetected": 24, "harmless": 68, "timeout": 0}
        findings = [_f(m, s, "VT_CLEAN", "No engine flagged this target",
                       "0 of 92 engines reported it as malicious or suspicious "
                       "(last analysed 2026-10-18).", url=gui)]
        rep, cats = 4, "e-commerce, shopping"
    findings += [
        _f(m, s, "VT_STATS", "Engine verdict breakdown",
           ", ".join(f"{k}: {v}" for k, v in stats.items()), url=gui,
           details={"chart": stats,
                    "table": {"columns": ["Verdict", "Engines"],
                              "rows": [[k, v] for k, v in stats.items()]}}),
        _f(m, s, "VT_COMMUNITY_SCORE", "Community reputation score",
           f"{rep} (negative values mean the community voted it harmful)",
           severity="low" if rep < 0 else "info", url=gui),
        _f(m, s, "VT_CATEGORIES", "Vendor categories", cats, url=gui),
    ]
    return [_result(m, s, findings, 730)]


def get_demo_results(scan_type: str, target: str) -> list[CollectorResult]:
    return {"domain": _domain, "username": _username, "email": _email,
            "reputation": _reputation}[scan_type](target)
