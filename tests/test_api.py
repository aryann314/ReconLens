"""API, safeguards, database and report tests (Flask test client)."""
import csv
import io
import logging
from datetime import datetime, timedelta, timezone

import pytest

from app import MaskEmailFilter

from collectors.base import CollectorResult, Finding
from extensions import limiter
from services import scan_service
from services.report import safe_cell

DEMO = [("domain", "demo-corp.test"), ("domain", "secure-shop.test"),
        ("username", "demo_analyst"), ("username", "ghost_user_404"),
        ("email", "alice@demo-corp.test"), ("email", "bob@secure-shop.test"),
        ("reputation", "phish-login.demo-corp.test"), ("reputation", "secure-shop.test")]


def scan(client, scan_type, target, mode="demo", **extra):
    return client.post(f"/api/scan/{scan_type}", json={"target": target, "mode": mode, **extra})


@pytest.mark.parametrize("scan_type, target", DEMO)
def test_every_demo_target_works(client, scan_type, target):
    r = scan(client, scan_type, target)
    assert r.status_code == 201
    s = r.get_json()["scan"]
    assert s["mode"] == "demo" and s["status"] == "completed"
    assert 0 <= s["exposure_score"] <= 100
    assert all("DEMO" in f["source"] for f in s["findings"])
    assert s["limitations"][0].startswith("DEMO MODE")


def test_weak_and_strong_demo_domains_differ(client):
    weak = scan(client, "domain", "demo-corp.test").get_json()["scan"]
    strong = scan(client, "domain", "secure-shop.test").get_json()["scan"]
    assert weak["exposure_score"] > strong["exposure_score"]
    assert any(r["priority"] == "Medium" for r in weak["recommendations"])


def test_email_is_masked_everywhere(client):
    s = scan(client, "email", "alice@demo-corp.test").get_json()["scan"]
    assert s["target"] == "a***@demo-corp.test"
    pdf = client.get(f"/api/scans/{s['id']}/report.csv").get_data(as_text=True)
    assert "alice@" not in pdf


def test_demo_mode_rejects_real_targets(client):
    r = scan(client, "domain", "example.com")
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "not_a_demo_target"


def test_live_mode_requires_authorization(client):
    r = scan(client, "domain", "example.com", mode="live")
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "authorization_required"
    r = scan(client, "domain", "example.com", mode="live", authorized="yes")  # must be literal true
    assert r.status_code == 403


def test_live_mode_can_be_disabled(app, client):
    app.config["ALLOW_LIVE_MODE"] = False
    r = scan(client, "domain", "example.com", mode="live", authorized=True)
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "live_disabled"


def test_live_domain_scan_with_mocked_collectors(client, monkeypatch):
    def fake_run(scan_type, target, config):
        return [CollectorResult(module="dns", source="DNS", findings=[
            Finding(module="dns", source="DNS", code="DNS_DMARC_MISSING", title="DMARC",
                    value="missing", severity="medium")]),
            CollectorResult(module="crtsh", source="crt.sh", status="error", error="busy",
                            findings=[Finding(module="crtsh", source="crt.sh", code="CRTSH_ERROR",
                                              title="crt.sh failed", status="error")])]
    monkeypatch.setattr(scan_service, "run_collectors", fake_run)
    r = scan(client, "domain", "example.com", mode="live", authorized=True)
    s = r.get_json()["scan"]
    assert r.status_code == 201
    assert s["status"] == "partial" and s["exposure_score"] == 10
    assert "example.com" in s["authorization"]


def test_live_email_policies(app, client):
    r = scan(client, "email", "me@example.com", mode="live", authorized=True)
    assert r.get_json()["error"]["code"] == "hibp_key_missing"
    app.config["HIBP_API_KEY"] = "k"
    app.config["AUTHORIZED_EMAIL_DOMAINS"] = ["mycollege.edu"]
    r = scan(client, "email", "me@example.com", mode="live", authorized=True)
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "domain_not_authorised"


def test_live_reputation_needs_key(client):
    r = scan(client, "reputation", "example.com", mode="live", authorized=True)
    assert r.get_json()["error"]["code"] == "virustotal_key_missing"


@pytest.mark.parametrize("body, status, code", [
    ({"target": "", "mode": "demo"}, 400, "invalid_input"),
    ({"target": "demo-corp.test", "mode": "stealth"}, 400, "bad_mode"),
    ({"target": "<script>alert(1)</script>", "mode": "demo"}, 400, "invalid_input"),
])
def test_bad_requests(client, body, status, code):
    r = client.post("/api/scan/domain", json=body)
    assert r.status_code == status and r.get_json()["error"]["code"] == code


def test_non_json_is_rejected(client):
    r = client.post("/api/scan/domain", data={"target": "demo-corp.test"})
    assert r.status_code == 415


def test_rate_limit(app, client):
    app.config["SCAN_RATE_LIMIT"] = "3 per minute"
    with app.app_context():
        limiter.reset()
    codes = [scan(client, "domain", "demo-corp.test").status_code for _ in range(4)]
    assert codes == [201, 201, 201, 429]
    r = scan(client, "domain", "demo-corp.test")
    assert r.get_json()["error"]["code"] == "too_many_requests"


def test_history_get_delete(client):
    ids = [scan(client, t, v).get_json()["scan"]["id"] for t, v in DEMO[:3]]
    listing = client.get("/api/scans").get_json()["scans"]
    assert [s["id"] for s in listing] == sorted(ids, reverse=True)
    assert client.get("/api/scans?type=username").get_json()["scans"][0]["scan_type"] == "username"
    assert client.get(f"/api/scans/{ids[0]}").get_json()["scan"]["findings"]
    assert client.delete(f"/api/scans/{ids[0]}").status_code == 200
    assert client.get(f"/api/scans/{ids[0]}").status_code == 404
    assert client.get("/api/stats").get_json()["stats"]["total_scans"] == 2


def test_reports(client):
    sid = scan(client, "domain", "demo-corp.test").get_json()["scan"]["id"]
    pdf = client.get(f"/api/scans/{sid}/report.pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    assert "attachment" in pdf.headers["Content-Disposition"]
    text = client.get(f"/api/scans/{sid}/report.csv").get_data(as_text=True).lstrip("﻿")
    rows = list(csv.reader(io.StringIO(text)))
    flat = [c for r in rows for c in r]
    for section in ("SCAN SUMMARY", "FINDINGS", "RECOMMENDATIONS", "LIMITATIONS", "SOURCES"):
        assert section in flat
    assert client.get("/api/scans/999/report.pdf").status_code == 404


def test_csv_formula_injection_is_neutralised():
    assert safe_cell("=HYPERLINK(\"http://evil\")").startswith("'")
    assert safe_cell("+1") == "'+1" and safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert safe_cell("normal") == "normal"


def test_security_headers_and_json_errors(client):
    r = client.get("/")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.get_json()["ok"] is False
    assert client.get("/scan/12345").status_code == 404


def test_pages_render(client):
    for path in ("/", "/domain", "/username", "/email", "/reputation", "/history", "/about"):
        assert client.get(path).status_code == 200


# ----------------------------------------------------------- smart search
@pytest.mark.parametrize("scan_type, target", [
    ("domain", "demo-corp.test"), ("domain", "secure-shop.test"),
    ("username", "demo_analyst"), ("username", "@ghost_user_404"),
    ("email", "alice@demo-corp.test"), ("email", "bob@secure-shop.test"),
    ("reputation", "phish-login.demo-corp.test"),   # only a reputation demo target
])
def test_auto_scan_runs_the_detected_module(client, scan_type, target):
    r = client.post("/api/scan/auto", json={"target": target, "mode": "demo"})
    assert r.status_code == 201
    assert r.get_json()["scan"]["scan_type"] == scan_type


def test_auto_scan_keeps_every_safeguard(client):
    r = client.post("/api/scan/auto", json={"target": "example.com", "mode": "live"})
    assert r.get_json()["error"]["code"] == "authorization_required"
    r = client.post("/api/scan/auto", json={"target": "someone@gmail.com", "mode": "live",
                                            "authorized": True})
    assert r.get_json()["error"]["code"] == "hibp_key_missing"
    r = client.post("/api/scan/auto", json={"target": "8.8.8.8", "mode": "live",
                                            "authorized": True})
    assert r.get_json()["error"]["code"] == "virustotal_key_missing"
    r = client.post("/api/scan/auto", json={"target": "10.0.0.5", "mode": "demo"})
    assert r.get_json()["error"]["code"] == "invalid_input"
    r = client.post("/api/scan/auto", json={"target": "not valid!", "mode": "demo"})
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "undetectable_target"
    assert client.post("/api/scan/auto", data={"target": "x"}).status_code == 415


def test_detect_endpoint(client):
    r = client.post("/api/detect", json={"target": "https://www.Example.com/x"}).get_json()
    assert r["scan_type"] == "reputation" and r["valid"] is True
    assert r["endpoint"] == "/api/scan/reputation"
    r = client.post("/api/detect", json={"target": "Example.COM"}).get_json()
    assert r["scan_type"] == "domain" and r["normalised"] == "example.com"
    r = client.post("/api/detect", json={"target": "alice@demo-corp.test"}).get_json()
    assert r["scan_type"] == "email" and r["normalised"] is None   # never echoed back
    r = client.post("/api/detect", json={"target": "192.168.0.1"}).get_json()
    assert r["scan_type"] == "reputation" and r["valid"] is False
    r = client.post("/api/detect", json={"target": "??"}).get_json()
    assert r["scan_type"] is None and r["valid"] is False
    assert client.post("/api/detect", json=["x"]).status_code == 400


# ------------------------------------------------------- data minimisation
def test_retention_applies_on_every_save(app, client):
    from database.db import get_db
    days = app.config["RETENTION_DAYS"] + 1
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO scans (scan_type, target, mode, status, started_at) "
                   "VALUES ('domain', 'old.test', 'demo', 'completed', ?)", (old,))
        db.commit()
    assert any(s["target"] == "old.test" for s in client.get("/api/scans").get_json()["scans"])
    scan(client, "domain", "demo-corp.test")
    assert not any(s["target"] == "old.test"
                   for s in client.get("/api/scans").get_json()["scans"])


@pytest.mark.parametrize("line, expected", [
    ('"GET /email?target=alice%40demo-corp.test&run=1 HTTP/1.1" 200',
     '"GET /email?target=a***%40demo-corp.test&run=1 HTTP/1.1" 200'),
    ("contact bob.smith+x@mail.example.org now", "contact b***@mail.example.org now"),
    ("no address here", "no address here"),
])
def test_log_lines_mask_email_addresses(line, expected):
    record = logging.LogRecord("werkzeug", logging.INFO, __file__, 1, "%s", (line,), None)
    assert MaskEmailFilter().filter(record) is True
    assert record.getMessage() == expected


def test_default_rate_limit_is_configurable(app, client):
    app.config["DEFAULT_RATE_LIMIT"] = "2 per minute"
    with app.app_context():
        limiter.reset()
    codes = [client.get("/api/health").status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert client.get("/static/css/style.css").status_code == 200   # static is exempt
