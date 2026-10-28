"""
routes/username_routes.py - POST /api/scan/username

Checks the username against the curated platform list in collectors/sites.json.
"""
from flask import Blueprint, current_app

from extensions import limiter

from .common import handle_scan

bp = Blueprint("username_api", __name__, url_prefix="/api/scan")


@bp.post("/username")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_username():
    return handle_scan("username")
