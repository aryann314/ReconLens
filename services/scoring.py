"""
services/scoring.py - Transparent exposure score (0-100).

The method is deliberately simple so it can be explained and audited:

    score = min(100, sum of weights of CONFIRMED findings)

    severity weight:  high = 20, medium = 10, low = 4, info = 0

    level:  0-19 Low | 20-49 Moderate | 50-74 High | 75-100 Critical

Inconclusive, not-found and error results contribute 0 points - we never
raise the score based on data we could not verify. The full breakdown
(which finding added how many points) is stored with every scan and shown in
the UI and the PDF report.
"""
from __future__ import annotations

WEIGHTS = {"high": 20, "medium": 10, "low": 4, "info": 0}
LEVELS = [(75, "Critical"), (50, "High"), (20, "Moderate"), (0, "Low")]

METHOD = ("Score = sum of severity weights of CONFIRMED findings, capped at 100. "
          "Weights: high 20, medium 10, low 4, info 0. Inconclusive, not-found and failed "
          "lookups add 0 points. Levels: 0-19 Low, 20-49 Moderate, 50-74 High, 75-100 Critical.")


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def compute_score(findings: list[dict]) -> dict:
    breakdown = []
    total = 0
    for f in findings:
        if f["status"] != "confirmed":
            continue
        points = WEIGHTS.get(f["severity"], 0)
        if points:
            breakdown.append({"code": f["code"], "title": f["title"],
                              "severity": f["severity"], "points": points})
            total += points
    score = min(100, total)
    counts = {s: 0 for s in ("confirmed", "not_found", "inconclusive", "error")}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return {
        "score": score,
        "raw_total": total,
        "level": level_for(score),
        "method": METHOD,
        "weights": WEIGHTS,
        "breakdown": sorted(breakdown, key=lambda b: -b["points"]),
        "status_counts": counts,
    }
