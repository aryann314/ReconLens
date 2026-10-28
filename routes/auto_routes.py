"""
routes/auto_routes.py - Smart search on the server.

    POST /api/detect      {"target": "..."}  -> which module the value belongs to
    POST /api/scan/auto   {"target": "...", "mode": ..., "authorized": ...}
                          -> detects the type, then runs that module's scan

Both take the value in a JSON body rather than the URL, so email addresses
never appear in URLs, browser history or the server's access log.
The auto scan applies exactly the same validation, authorisation and
per-module policies as the dedicated endpoints.
"""
from flask import Blueprint, current_app, jsonify

from collectors.demo_data import demo_targets_for
from extensions import limiter
from services.validation import VALIDATORS, ValidationError, detect_scan_type

from .common import ApiError, handle_scan, read_json_body
from .email_routes import email_policy
from .reputation_routes import reputation_policy

bp = Blueprint("auto_api", __name__, url_prefix="/api")

LIVE_POLICIES = {"email": email_policy, "reputation": reputation_policy}
UNDETECTABLE = "That doesn't look like a domain, email address, IP/URL or username."


@bp.post("/detect")
def detect():
    target = read_json_body().get("target")
    scan_type = detect_scan_type(target)
    if scan_type is None:
        return jsonify({"ok": True, "scan_type": None, "valid": False, "message": UNDETECTABLE})
    try:
        normalised = VALIDATORS[scan_type](target)
    except ValidationError as exc:
        return jsonify({"ok": True, "scan_type": scan_type, "valid": False, "message": str(exc)})
    return jsonify({"ok": True, "scan_type": scan_type, "valid": True,
                    "endpoint": f"/api/scan/{scan_type}",
                    # never echo a full email address back unmasked
                    "normalised": None if scan_type == "email" else normalised})


def resolve_demo_type(scan_type: str, target) -> str:
    """A domain name is also a valid reputation target. In demo mode, send it to
    reputation when only that module has it as a demo target
    (e.g. phish-login.demo-corp.test)."""
    if scan_type != "domain":
        return scan_type
    try:
        domain = VALIDATORS["domain"](target)
    except ValidationError:
        return scan_type
    if domain not in demo_targets_for("domain") and domain in demo_targets_for("reputation"):
        return "reputation"
    return scan_type


@bp.post("/scan/auto")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_auto():
    data = read_json_body()
    scan_type = detect_scan_type(data.get("target"))
    if scan_type is None:
        raise ApiError(400, "undetectable_target", UNDETECTABLE)
    if data.get("mode", "demo") == "demo":
        scan_type = resolve_demo_type(scan_type, data.get("target"))
    return handle_scan(scan_type, live_policy=LIVE_POLICIES.get(scan_type))
