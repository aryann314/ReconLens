"""
services/recommendations.py - Rule-based security recommendations.

Each finding carries a machine-readable `code`. This module maps codes to
concrete, defensive actions. Rules are plain data, so they are easy to read,
extend and justify in the report. Baseline advice is added for every scan
type regardless of findings.
"""
from __future__ import annotations

PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Baseline": 3}

RULES = {
    # ---------------- domain: registration
    "RDAP_EXPIRED": ("Renew the domain registration immediately",
                     "An expired domain can be re-registered by anyone and used to receive "
                     "your email or impersonate you. Renew it and enable auto-renew.", "High"),
    "RDAP_EXPIRY_SOON": ("Renew the domain and enable auto-renew",
                         "The registration expires within 30 days. Lapsed domains are a known "
                         "takeover risk.", "Medium"),
    "RDAP_NO_TRANSFER_LOCK": ("Enable a registrar transfer lock",
                              "Ask your registrar to set clientTransferProhibited to reduce the "
                              "risk of domain hijacking.", "Low"),
    "RDAP_DNSSEC_OFF": ("Consider enabling DNSSEC",
                        "DNSSEC signs DNS answers so resolvers can detect tampering "
                        "(cache poisoning). Most registrars offer one-click DNSSEC.", "Low"),
    "RDAP_REGISTRANT_PUBLIC": ("Turn on registration privacy / redaction",
                               "Your name or email is publicly listed in registration data. "
                               "Enable WHOIS/RDAP privacy with your registrar.", "Low"),
    "RDAP_RECENTLY_REGISTERED": ("Verify recently registered look-alike domains",
                                 "If this domain is NOT yours but resembles your brand, monitor "
                                 "it and report phishing to the registrar's abuse contact.", "Low"),
    # ---------------- domain: TLS certificate
    "TLS_EXPIRED": ("Replace the expired TLS certificate now",
                    "Visitors are shown a full-page browser warning. Issue a new certificate "
                    "and automate renewal (for example with an ACME client such as certbot).",
                    "High"),
    "TLS_EXPIRY_SOON": ("Renew the TLS certificate and automate renewal",
                        "The certificate expires within 14 days. Automated renewal (ACME / "
                        "Let's Encrypt, or your host's auto-renew) prevents outages.", "Medium"),
    "TLS_UNTRUSTED": ("Install a certificate from a trusted authority",
                      "Browsers do not trust the certificate (self-signed, wrong host name or "
                      "incomplete chain). Install a valid certificate covering this host name "
                      "with its full intermediate chain.", "High"),
    # ---------------- domain: DNS / email security
    "DNS_SPF_MISSING": ("Publish an SPF record",
                        "Add a TXT record such as 'v=spf1 include:<your-mail-provider> -all'. "
                        "If the domain sends no email at all, publish 'v=spf1 -all'.", "Medium"),
    "DNS_SPF_MULTIPLE": ("Merge multiple SPF records into one",
                         "RFC 7208 allows only one SPF record; multiple records cause a "
                         "permanent error.", "Medium"),
    "DNS_SPF_PERMISSIVE": ("Remove '+all' from SPF immediately",
                           "'+all' authorises every server to send as your domain. "
                           "Use '-all' or '~all'.", "High"),
    "DNS_SPF_NEUTRAL": ("Tighten the SPF policy to ~all or -all",
                        "A neutral ('?all') policy gives receiving servers no instruction about "
                        "unauthorised senders.", "Low"),
    "DNS_DMARC_MISSING": ("Publish a DMARC policy",
                          "Start with 'v=DMARC1; p=none; rua=mailto:dmarc@<domain>' to collect "
                          "reports, then move to p=quarantine and p=reject.", "Medium"),
    "DNS_DMARC_MONITOR": ("Move DMARC from p=none to enforcement",
                          "Monitoring mode does not stop spoofed mail. After reviewing reports, "
                          "change to p=quarantine and then p=reject.", "Low"),
    "DNS_CAA_MISSING": ("Add a CAA record",
                        "CAA records restrict which certificate authorities may issue "
                        "certificates for your domain.", "Low"),
    "DNS_TXT_SERVICES": ("Remove stale verification TXT records",
                         "Old verification tokens reveal which SaaS tools you use. Delete tokens "
                         "for services you no longer use.", "Low"),
    # ---------------- certificate transparency
    "CRTSH_SENSITIVE_SUBDOMAINS": ("Review publicly discoverable internal hosts",
                                   "Check every dev/test/admin/VPN hostname: decommission unused "
                                   "ones, put admin panels behind VPN/SSO, and require MFA.",
                                   "Medium"),
    "CRTSH_SUBDOMAINS": ("Maintain an inventory of all your hostnames",
                         "Compare CT-log hostnames with your asset inventory; unknown hosts are "
                         "often forgotten and unpatched.", "Low"),
    # ---------------- username footprint
    "USERNAME_REUSE": ("Reduce linkability of your online identities",
                       "Use different handles for professional and personal accounts, and "
                       "remove personal details (city, birthday, employer) from public bios.",
                       "Medium"),
    "USERNAME_FOUND": ("Review privacy settings on accounts you own",
                       "For each confirmed profile: check what is public, delete dormant "
                       "accounts, and enable multi-factor authentication.", "Low"),
    # ---------------- breaches
    "HIBP_BREACH_PASSWORDS": ("Change passwords exposed in breaches",
                              "Change the password on the breached service AND anywhere it was "
                              "reused. Use a password manager to give each site a unique "
                              "password.", "High"),
    "HIBP_BREACH": ("Watch for targeted phishing",
                    "Breached personal data (names, phone numbers, addresses) is used to craft "
                    "convincing phishing messages. Verify unexpected requests.", "Medium"),
    "HIBP_BREACH_SPAMLIST": ("Expect spam and filter aggressively",
                             "The address is on a spam list. Use filtering rules and consider "
                             "email aliases for sign-ups.", "Low"),
    # ---------------- reputation
    "VT_MALICIOUS": ("Investigate the flagged target before trusting it",
                     "Do not visit or enter credentials. If it is YOUR asset, check for "
                     "compromise, clean it, and request re-review from the flagging vendors.",
                     "High"),
    "VT_SUSPICIOUS": ("Treat the target with caution",
                      "Some vendors consider it suspicious. Corroborate with other sources "
                      "before taking action.", "Medium"),
}

BASELINE = {
    "domain": [
        ("Enable MFA on your registrar and DNS-hosting accounts",
         "Whoever controls the registrar account controls the domain."),
        ("Monitor certificate transparency for your domain",
         "Free CT monitoring alerts you when a certificate is issued for your domain."),
    ],
    "username": [
        ("Enable multi-factor authentication everywhere",
         "MFA stops most account takeovers even if a password leaks."),
        ("Search for yourself periodically",
         "Re-run this check every few months and after joining new platforms."),
    ],
    "email": [
        ("Use a password manager and unique passwords",
         "Unique passwords make a breach on one site useless on others."),
        ("Enable MFA on your email account first",
         "Your mailbox can reset every other account you own."),
        ("Subscribe to breach notifications",
         "HIBP offers free notifications for your own address."),
    ],
    "reputation": [
        ("Corroborate reputation with multiple sources",
         "A single vendor verdict can be a false positive or outdated."),
    ],
}


def build_recommendations(scan_type: str, findings: list[dict]) -> list[dict]:
    recs: dict[str, dict] = {}
    for f in findings:
        if f["status"] != "confirmed" or f["code"] not in RULES:
            continue
        title, action, priority = RULES[f["code"]]
        rec = recs.setdefault(f["code"], {"code": f["code"], "title": title, "action": action,
                                          "priority": priority, "triggered_by": []})
        if f["title"] not in rec["triggered_by"]:
            rec["triggered_by"].append(f["title"])
    result = sorted(recs.values(), key=lambda r: PRIORITY_ORDER[r["priority"]])
    for title, action in BASELINE.get(scan_type, []):
        result.append({"code": "BASELINE", "title": title, "action": action,
                       "priority": "Baseline", "triggered_by": []})
    return result
