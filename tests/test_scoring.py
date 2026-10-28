"""Scoring and recommendation rules."""
from services.recommendations import build_recommendations
from services.scoring import compute_score, level_for


def f(code, status="confirmed", severity="info", title=None):
    return {"code": code, "status": status, "severity": severity, "title": title or code}


def test_weights_and_only_confirmed_count():
    findings = [f("A", severity="high"), f("B", severity="medium"), f("C", severity="low"),
                f("D", severity="info"), f("E", status="inconclusive", severity="high"),
                f("G", status="error", severity="high"), f("H", status="not_found", severity="high")]
    result = compute_score(findings)
    assert result["score"] == 34
    assert result["level"] == "Moderate"
    assert [b["code"] for b in result["breakdown"]] == ["A", "B", "C"]
    assert result["status_counts"] == {"confirmed": 4, "not_found": 1, "inconclusive": 1, "error": 1}


def test_score_is_capped_at_100():
    result = compute_score([f(str(i), severity="high") for i in range(10)])
    assert result["score"] == 100 and result["raw_total"] == 200
    assert result["level"] == "Critical"


def test_level_thresholds():
    assert [level_for(s) for s in (0, 19, 20, 49, 50, 74, 75, 100)] == \
        ["Low", "Low", "Moderate", "Moderate", "High", "High", "Critical", "Critical"]


def test_recommendations_from_confirmed_findings_only():
    recs = build_recommendations("domain", [
        f("DNS_DMARC_MISSING", severity="medium", title="DMARC"),
        f("DNS_SPF_PERMISSIVE", severity="high", title="SPF"),
        f("RDAP_EXPIRED", status="inconclusive"),
    ])
    codes = [r["code"] for r in recs]
    assert codes[:2] == ["DNS_SPF_PERMISSIVE", "DNS_DMARC_MISSING"]  # sorted by priority
    assert "RDAP_EXPIRED" not in codes
    assert recs[-1]["priority"] == "Baseline"
    assert recs[0]["triggered_by"] == ["SPF"]
