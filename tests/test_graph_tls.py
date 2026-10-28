"""Tests for the relationship graph and the TLS certificate collector."""
import ssl
from datetime import datetime, timezone

import pytest

from collectors import tls_collector
from collectors.tls_collector import TlsCollector, cert_findings, parse_cert
from services.graph import build_case_graph, build_graph, parent_domain
from services.scan_service import run_scan

CFG = {"USER_AGENT": "test", "HTTP_TIMEOUT": 2}
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
    "notBefore": "Aug  1 00:00:00 2026 GMT", "notAfter": "Oct 10 00:00:00 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}


def demo(scan_type, target, scan_id=1):
    s = run_scan(scan_type, target, "demo", {})
    s["id"] = scan_id
    return s


# ------------------------------------------------------------------ TLS
def test_parse_cert_fields():
    info = parse_cert(CERT, NOW)
    assert info["subject"] == "example.com"
    assert info["issuer"] == "Let's Encrypt"
    assert info["days_left"] == 9 and info["san_count"] == 2


def test_cert_expiry_rules():
    finder = TlsCollector(CFG).finding
    soon = cert_findings(parse_cert(CERT, NOW), "TLSv1.3", "X", finder)
    assert {f.code for f in soon} == {"TLS_CERT", "TLS_EXPIRY_SOON"}
    expired = cert_findings(parse_cert(CERT, datetime(2027, 1, 1, tzinfo=timezone.utc)),
                            "TLSv1.3", "X", finder)
    assert any(f.code == "TLS_EXPIRED" and f.severity == "high" for f in expired)
    fine = cert_findings(parse_cert(CERT, datetime(2026, 8, 2, tzinfo=timezone.utc)),
                         "TLSv1.3", "X", finder)
    assert [f.code for f in fine] == ["TLS_CERT"]


def test_tls_refuses_private_addresses(monkeypatch):
    monkeypatch.setattr(tls_collector.socket, "getaddrinfo",
                        lambda *a, **k: [(None, None, None, None, ("10.0.0.5", 443))])
    result = TlsCollector(CFG).run("intranet.example.com")
    assert result.status == "skipped"


def test_tls_untrusted_and_closed_port(monkeypatch):
    monkeypatch.setattr(tls_collector.socket, "getaddrinfo",
                        lambda *a, **k: [(None, None, None, None, ("93.184.216.34", 443))])

    def refuse(*a, **k):
        raise ConnectionRefusedError()
    monkeypatch.setattr(tls_collector.socket, "create_connection", refuse)
    assert TlsCollector(CFG).run("example.com").findings[0].code == "TLS_NO_HTTPS"

    def untrusted(*a, **k):
        err = ssl.SSLCertVerificationError("bad")
        err.verify_message = "self-signed certificate"
        raise err
    monkeypatch.setattr(tls_collector.socket, "create_connection", untrusted)
    f = TlsCollector(CFG).run("example.com").findings[0]
    assert f.code == "TLS_UNTRUSTED" and f.severity == "high"


@pytest.mark.parametrize("address", ["0.0.0.0", "100.64.0.1", "::ffff:10.0.0.1", "fe80::1%eth0",
                                     "224.0.0.1", "169.254.169.254"])
def test_tls_refuses_every_non_public_address(monkeypatch, address):
    monkeypatch.setattr(tls_collector.socket, "getaddrinfo",
                        lambda *a, **k: [(None, None, None, None, (address, 443))])
    assert TlsCollector(CFG).run("sneaky.example.com").status == "skipped"


def test_tls_connects_to_the_checked_address(monkeypatch):
    """The name is resolved once; the connection goes to that vetted IP (no DNS rebinding)."""
    monkeypatch.setattr(tls_collector.socket, "getaddrinfo",
                        lambda *a, **k: [(None, None, None, None, ("93.184.216.34", 443))])
    seen = []

    def connect(addr, **k):
        seen.append(addr)
        raise ConnectionRefusedError()
    monkeypatch.setattr(tls_collector.socket, "create_connection", connect)
    TlsCollector(CFG).run("example.com")
    assert seen == [("93.184.216.34", 443)]


def test_tls_handshake_failure_is_inconclusive(monkeypatch):
    monkeypatch.setattr(tls_collector.socket, "getaddrinfo",
                        lambda *a, **k: [(None, None, None, None, ("93.184.216.34", 443))])

    def old_server(*a, **k):
        raise ssl.SSLError(1, "[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")
    monkeypatch.setattr(tls_collector.socket, "create_connection", old_server)
    f = TlsCollector(CFG).run("legacy.example.com").findings[0]
    assert f.code == "TLS_HANDSHAKE_FAILED" and f.status == "inconclusive"


def test_demo_domain_includes_tls_module():
    s = demo("domain", "demo-corp.test")
    assert "tls" in {m["module"] for m in s["modules"]}
    assert any(r["title"].startswith("Renew the TLS") for r in s["recommendations"])


# ---------------------------------------------------------------- graph
def test_parent_domain():
    assert parent_domain("phish-login.demo-corp.test") == "demo-corp.test"
    assert parent_domain("shop.example.co.in") == "example.co.in"
    assert parent_domain("example.com") is None


def test_domain_graph_structure():
    g = build_graph(demo("domain", "demo-corp.test"))
    ids = {n["id"] for n in g["nodes"]}
    assert "domain:demo-corp.test" in ids
    assert "ip:203.0.113.10" in ids
    kinds = g["stats"]["by_kind"]
    assert kinds["subdomain"] >= 5 and kinds["issue"] >= 3 and kinds["cert"] == 1
    node_ids = ids
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in g["edges"])
    risky = [n for n in g["nodes"] if n["kind"] == "subdomain" and n["severity"] == "medium"]
    assert any("jenkins" in n["label"] for n in risky)


def test_clean_domain_graph_has_no_issue_nodes():
    g = build_graph(demo("domain", "secure-shop.test"))
    assert "issue" not in g["stats"]["by_kind"]


def test_case_graph_correlates_scans():
    scans = [demo("domain", "demo-corp.test", 1), demo("email", "alice@demo-corp.test", 2),
             demo("reputation", "phish-login.demo-corp.test", 3)]
    g = build_case_graph(scans)
    shared = {n["id"]: n["scans"] for n in g["nodes"] if len(n["targets"]) > 1}
    assert sorted(shared["domain:demo-corp.test"]) == [1, 2, 3]
    # scanning the same target twice is not a correlation
    again = build_case_graph([demo("domain", "demo-corp.test", 1), demo("domain", "demo-corp.test", 2)])
    assert again["stats"]["shared_nodes"] == 0
    assert g["stats"]["scans"] == 3 and g["stats"]["shared_nodes"] >= 1


def test_graph_api(client):
    sid = client.post("/api/scan/domain", json={"target": "demo-corp.test", "mode": "demo"}
                      ).get_json()["scan"]["id"]
    client.post("/api/scan/email", json={"target": "alice@demo-corp.test", "mode": "demo"})
    one = client.get(f"/api/scans/{sid}/graph").get_json()
    assert one["ok"] and one["graph"]["stats"]["nodes"] > 10
    detail = client.get(f"/api/scans/{sid}").get_json()["scan"]
    assert "graph" in detail
    case = client.get("/api/graph").get_json()["graph"]
    assert case["stats"]["scans"] == 2 and case["stats"]["shared_nodes"] >= 1
    assert client.get("/api/graph?ids=abc").status_code == 400
    assert client.get("/api/scans/9999/graph").status_code == 404
    assert client.get("/graph").status_code == 200
