"""
Collector tests. Real network calls are replaced by fake responses so the
tests are fast, repeatable and never query real people or organisations.
"""
from datetime import datetime, timedelta, timezone

import dns.resolver
import pytest
import requests

from collectors.base import BaseCollector
from collectors.crtsh_collector import is_sensitive, parse_crtsh
from collectors.dns_collector import DnsCollector, analyse_dmarc, analyse_spf
from collectors.hibp_collector import HibpCollector
from collectors.rdap_collector import RdapCollector, parse_rdap, parse_whois
from collectors.username_collector import classify, load_sites
from collectors import vt_collector
from collectors.vt_collector import VirusTotalCollector, url_id
from conftest import FakeResponse

CFG = {"USER_AGENT": "test", "HTTP_TIMEOUT": 2, "CRTSH_TIMEOUT": 2, "DNS_TIMEOUT": 2,
       "HIBP_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}


# ------------------------------------------------------------ base contract
def test_base_collector_never_crashes():
    class Boom(BaseCollector):
        module, source = "boom", "Boom source"

        def collect(self, target):
            raise requests.Timeout()

    result = Boom(CFG).run("x")
    assert result.status == "error"
    assert result.findings[0].status == "error"
    assert "timeout" in result.error


# ------------------------------------------------------------------ username
SITE_STATUS = {"name": "X", "url": "https://x/{}", "method": "status_code"}
SITE_MSG = {"name": "Y", "url": "https://y/{}", "method": "message", "absent_text": "null",
            "absent_exact": True}


@pytest.mark.parametrize("site, code, body, url, expected", [
    (SITE_STATUS, 200, "<html>profile</html>", "https://x/a", "confirmed"),
    (SITE_STATUS, 404, "", "https://x/a", "not_found"),
    (SITE_STATUS, 403, "", "https://x/a", "inconclusive"),
    (SITE_STATUS, 429, "", "https://x/a", "inconclusive"),
    (SITE_STATUS, 503, "", "https://x/a", "inconclusive"),
    (SITE_STATUS, 200, "<title>Just a moment...</title>", "https://x/a", "inconclusive"),
    (SITE_STATUS, 200, "please sign in", "https://x/login?next=a", "inconclusive"),
    (SITE_STATUS, 302, "", "https://x/a", "inconclusive"),
    (SITE_MSG, 200, "null", "https://y/a", "not_found"),
    (SITE_MSG, 200, '{"id":"a","karma":5}', "https://y/a", "confirmed"),
    (SITE_MSG, 500, "", "https://y/a", "inconclusive"),
])
def test_username_classification(site, code, body, url, expected):
    assert classify(site, code, body, url)[0] == expected


def test_sites_json_is_valid():
    sites = load_sites()
    assert len(sites) >= 15
    for s in sites:
        assert "{}" in s["url"] and s["method"] in ("status_code", "message")
        if s["method"] == "message":
            assert s["absent_text"]


# ---------------------------------------------------------------------- DNS
def test_spf_rules():
    assert analyse_spf([])[0] == "DNS_SPF_MISSING"
    assert analyse_spf(["v=spf1 -all", "v=spf1 ~all"])[0] == "DNS_SPF_MULTIPLE"
    assert analyse_spf(["v=spf1 +all"])[0] == "DNS_SPF_PERMISSIVE"
    assert analyse_spf(["v=spf1 a mx all"])[0] == "DNS_SPF_PERMISSIVE"
    assert analyse_spf(["v=spf1 include:x ?all"])[0] == "DNS_SPF_NEUTRAL"
    assert analyse_spf(["v=spf1 include:_spf.google.com ~all"])[0] == "DNS_SPF_OK"


def test_dmarc_rules():
    assert analyse_dmarc([])[0] == "DNS_DMARC_MISSING"
    assert analyse_dmarc(["v=DMARC1; p=none"])[0] == "DNS_DMARC_MONITOR"
    assert analyse_dmarc(["v=DMARC1; p=reject; rua=mailto:x@y"])[0] == "DNS_DMARC_OK"


class FakeRdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeTxt:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeAnswer(list):
    class rrset:
        ttl = 300


class FakeResolver:
    def __init__(self, data):
        self.data = data

    def resolve(self, name, rtype):
        if name == "missing.test":
            raise dns.resolver.NXDOMAIN()
        key = (name, rtype)
        if key not in self.data:
            raise dns.resolver.NoAnswer()
        return FakeAnswer(self.data[key])


def test_dns_collector_with_fake_resolver():
    resolver = FakeResolver({
        ("acme.test", "A"): [FakeRdata("203.0.113.5")],
        ("acme.test", "TXT"): [FakeTxt("v=spf1 +all"), FakeTxt("google-site-verification=abc")],
        ("_dmarc.acme.test", "TXT"): [FakeTxt("v=DMARC1; p=none")],
    })
    codes = {f.code: f for f in DnsCollector(CFG, resolver).collect("acme.test")}
    assert codes["DNS_SPF_PERMISSIVE"].severity == "high"
    assert codes["DNS_DMARC_MONITOR"].severity == "low"
    assert "Google" in codes["DNS_TXT_SERVICES"].value
    assert "DNS_NO_MX" in codes and "DNS_CAA_MISSING" in codes

    nx = DnsCollector(CFG, resolver).collect("missing.test")
    assert nx[0].code == "DNS_NXDOMAIN" and nx[0].status == "not_found"


# --------------------------------------------------------------------- RDAP
def rdap_sample(days_to_expiry=400, locked=True, dnssec=True, registrant_name="REDACTED FOR PRIVACY"):
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return {
        "objectClassName": "domain", "ldhName": "EXAMPLE.TEST",
        "status": ["active"] + (["client transfer prohibited"] if locked else []),
        "events": [
            {"eventAction": "registration", "eventDate": (now - timedelta(days=4000)).strftime(fmt)},
            {"eventAction": "expiration",
             "eventDate": (now + timedelta(days=days_to_expiry)).strftime(fmt)},
        ],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                              ["fn", {}, "text", "Test Registrar"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", registrant_name]]]},
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}, {"ldhName": "NS2.EXAMPLE.TEST"}],
        "secureDNS": {"delegationSigned": dnssec},
    }


def test_parse_rdap_fields():
    info = parse_rdap(rdap_sample())
    assert info["registrar"] == "Test Registrar"
    assert info["nameservers"] == ["ns1.example.test", "ns2.example.test"]
    assert info["dnssec"] is True


def test_rdap_findings_good_domain():
    info = parse_rdap(rdap_sample())
    info.update(protocol="RDAP", query_url="https://rdap.test/domain/example.test")
    codes = {f.code for f in RdapCollector(CFG).build_findings("example.test", info)}
    assert {"RDAP_REGISTRAR", "RDAP_REGISTRATION_DATE", "RDAP_EXPIRY", "RDAP_DNSSEC_ON",
            "RDAP_REGISTRANT_REDACTED"} <= codes
    assert "RDAP_NO_TRANSFER_LOCK" not in codes


def test_rdap_findings_weak_domain():
    info = parse_rdap(rdap_sample(days_to_expiry=10, locked=False, dnssec=False,
                                  registrant_name="Jane Example"))
    info.update(protocol="RDAP", query_url="https://rdap.test/domain/example.test")
    codes = {f.code: f for f in RdapCollector(CFG).build_findings("example.test", info)}
    assert codes["RDAP_EXPIRY_SOON"].severity == "medium"
    assert "RDAP_NO_TRANSFER_LOCK" in codes and "RDAP_DNSSEC_OFF" in codes
    assert "RDAP_REGISTRANT_PUBLIC" in codes


def test_rdap_without_registration_date_is_inconclusive():
    data = rdap_sample()
    data["events"] = []
    info = parse_rdap(data)
    info.update(protocol="RDAP", query_url="u")
    reg = [f for f in RdapCollector(CFG).build_findings("example.test", info)
           if f.code == "RDAP_REGISTRATION_DATE"][0]
    assert reg.status == "inconclusive"


def test_rdap_collector_end_to_end(monkeypatch):
    collector = RdapCollector(CFG)
    monkeypatch.setattr(collector, "_rdap_base_for", lambda d: "https://rdap.test/")
    monkeypatch.setattr(collector, "http_get",
                        lambda url, **kw: FakeResponse(200, rdap_sample()))
    result = collector.run("example.test")
    assert result.status == "ok"
    monkeypatch.setattr(collector, "http_get", lambda url, **kw: FakeResponse(404))
    assert collector.run("nope.test").findings[0].code == "RDAP_NOT_REGISTERED"


@pytest.mark.parametrize("href, followed", [
    ("https://rdap.registrar.test/domain/example.test", True),
    ("http://169.254.169.254/domain/latest", False),
    ("file:///etc/passwd/domain/x", False),
])
def test_rdap_follows_only_https_registrar_links(monkeypatch, href, followed):
    thin = rdap_sample()
    thin["entities"] = thin["entities"][:1]          # registry has no registrant data
    thin["links"] = [{"rel": "related", "type": "application/rdap+json", "href": href}]
    calls = []
    collector = RdapCollector(CFG)
    monkeypatch.setattr(collector, "_rdap_base_for", lambda d: "https://rdap.test/")
    monkeypatch.setattr(collector, "http_get",
                        lambda url, **kw: calls.append(url) or FakeResponse(200, thin))
    assert collector.run("example.test").status == "ok"
    assert (href in calls) is followed


def test_parse_whois_text():
    text = ("Domain Name: example.in\nRegistrar: Example Registrar\n"
            "Creation Date: 2010-05-01T10:00:00Z\nRegistry Expiry Date: 2030-05-01T10:00:00Z\n"
            "Name Server: ns1.example.in\nName Server: ns2.example.in\n")
    out = parse_whois(text)
    assert out["registrar"] == "Example Registrar"
    assert out["registration"].startswith("2010-05-01")
    assert out["nameservers"] == ["ns1.example.in", "ns2.example.in"]
    assert parse_whois("No match for domain")["not_found"] is True


# ------------------------------------------------------------------- crt.sh
def test_crtsh_parsing_and_sensitive_names():
    entries = [
        {"id": 1, "name_value": "acme.test\nwww.acme.test", "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
         "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00"},
        {"id": 2, "name_value": "*.acme.test\ndev.acme.test\nother.example",
         "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
         "not_before": "2025-01-01T00:00:00", "not_after": "2025-04-01T00:00:00"},
    ]
    data = parse_crtsh(entries, "acme.test")
    assert set(data["hosts"]) == {"acme.test", "www.acme.test", "dev.acme.test"}
    assert data["wildcard"] is True and data["certificate_count"] == 2
    assert is_sensitive("dev.acme.test", "acme.test") == "dev"
    assert is_sensitive("old-admin.acme.test", "acme.test") in ("old", "admin")
    assert is_sensitive("test2.acme.test", "acme.test") == "test"
    assert is_sensitive("developer.acme.test", "acme.test") is None
    assert is_sensitive("www.acme.test", "acme.test") is None


# --------------------------------------------------------------------- HIBP
def test_hibp_requires_key_for_real_addresses():
    result = HibpCollector(CFG).run("someone@example.com")
    assert result.status == "skipped"


def test_hibp_test_address_uses_test_key(monkeypatch):
    collector = HibpCollector(CFG)
    seen = {}

    def fake_get(url, **kw):
        seen["key"] = kw["headers"]["hibp-api-key"]
        return FakeResponse(200, [
            {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "IsVerified": True,
             "DataClasses": ["Email addresses", "Passwords"], "Description": "<a>x</a> breach"},
            {"Name": "Spam", "Title": "Spam list", "BreachDate": "2017-01-01", "IsSpamList": True,
             "DataClasses": ["Email addresses"]},
        ])

    monkeypatch.setattr(collector, "http_get", fake_get)
    result = collector.run("account-exists@hibp-integration-tests.com")
    assert seen["key"] == "0" * 32
    codes = [f.code for f in result.findings]
    assert codes[0] == "HIBP_SUMMARY"
    assert "HIBP_BREACH_PASSWORDS" in codes and "HIBP_BREACH_SPAMLIST" in codes
    adobe = next(f for f in result.findings if f.code == "HIBP_BREACH_PASSWORDS")
    assert adobe.details["description"] == "x breach"  # HTML stripped


def test_hibp_404_and_429(monkeypatch):
    collector = HibpCollector({**CFG, "HIBP_API_KEY": "k"})
    monkeypatch.setattr(collector, "http_get", lambda u, **k: FakeResponse(404))
    assert collector.run("a@b.test").findings[0].status == "not_found"
    monkeypatch.setattr(collector, "http_get",
                        lambda u, **k: FakeResponse(429, headers={"retry-after": "2"}))
    res = collector.run("a@b.test")
    assert res.status == "error" and "retry after 2" in res.error


# --------------------------------------------------------------- VirusTotal
def test_vt_without_key_is_skipped():
    assert VirusTotalCollector(CFG).run("example.com").status == "skipped"


def test_vt_findings_and_url_id():
    assert url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"
    attrs = {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60,
                                     "undetected": 20}, "reputation": -5,
             "last_analysis_date": 1700000000}
    codes = {f.code: f for f in VirusTotalCollector(CFG).build_findings(attrs, "gui", "domain")}
    assert codes["VT_MALICIOUS"].severity == "high"
    assert "not confirmed" in codes["VT_MALICIOUS"].value
    assert codes["VT_COMMUNITY_SCORE"].severity == "low"


def test_vt_local_quota_guard():
    vt_collector._calls.clear()
    now = 1000.0
    assert all(vt_collector.reserve_quota(now) == 0 for _ in range(4))
    assert vt_collector.reserve_quota(now + 1) > 0          # 5th call within a minute blocked
    assert vt_collector.reserve_quota(now + 61) == 0        # window has passed
    vt_collector._calls.clear()
