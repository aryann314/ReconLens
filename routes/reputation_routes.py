"""
routes/reputation_routes.py - POST /api/scan/reputation

Looks up an existing VirusTotal report for a domain, public IP or URL.
"""
from flask import Blueprint, current_app

from extensions import limiter

from .common import ApiError, handle_scan

bp = Blueprint("reputation_api", __name__, url_prefix="/api/scan")


def reputation_policy(_target: str):
    if not current_app.config["VIRUSTOTAL_API_KEY"]:
        raise ApiError(400, "virustotal_key_missing",
                       "No VirusTotal API key is configured. Add VIRUSTOTAL_API_KEY to .env "
                       "(free community account) or use demo mode.")


@bp.post("/reputation")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_reputation():
    return handle_scan("reputation", live_policy=reputation_policy)
