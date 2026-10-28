"""
routes/domain_routes.py - POST /api/scan/domain

Runs RDAP/WHOIS + DNS + certificate-transparency collectors in parallel.
"""
from flask import Blueprint, current_app

from extensions import limiter

from .common import handle_scan

bp = Blueprint("domain_api", __name__, url_prefix="/api/scan")


@bp.post("/domain")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_domain():
    return handle_scan("domain")
