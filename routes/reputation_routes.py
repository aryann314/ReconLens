"""
routes/reputation_routes.py - POST /api/scan/reputation

Looks up an existing VirusTotal report for a domain, public IP or URL.
"""
import ipaddress

from flask import Blueprint, current_app
from extensions import limiter
from .common import ApiError, handle_scan

bp = Blueprint("reputation_api", __name__, url_prefix="/api/scan")

def reputation_policy(target: str):
    try:
        is_public_ip = ipaddress.ip_address(target).is_global
    except ValueError:
        is_public_ip = False
    if is_public_ip and current_app.config["ABUSEIPDB_API_KEY"]:
        return
    if not current_app.config["VIRUSTOTAL_API_KEY"]:
        raise ApiError(400, "virustotal_key_missing",
                       "No reputation provider is configured for this target. Add "
                       "VIRUSTOTAL_API_KEY (domains, URLs and IPs) or, for public IPs, "
                       "ABUSEIPDB_API_KEY to .env, or use demo mode.")

@bp.post("/reputation")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_reputation():
    return handle_scan("reputation", live_policy=reputation_policy)
