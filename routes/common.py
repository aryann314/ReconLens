"""
routes/common.py - Shared request handling for every scan endpoint.

Request body (JSON):
    {"target": "...", "mode": "demo" | "live", "authorized": true}

Safeguards enforced on the SERVER (not just in the browser):
  1. Content-Type must be application/json. Browsers cannot send JSON
     cross-site without a CORS pre-flight, so this blocks CSRF-style abuse.
  2. Input is validated by services/validation.py.
  3. Demo mode only accepts the fictional demo targets.
  4. Live mode must be enabled in config AND the operator must confirm
     authorisation for this specific target ("authorized": true).
  5. Each module may add its own policy (e.g. API key present).
"""
from __future__ import annotations

from flask import current_app, jsonify, request

from collectors.demo_data import DEMO_TARGETS, demo_targets_for
from database.db import get_scan, save_scan
from services.graph import build_graph
from services.scan_service import run_scan
from services.validation import VALIDATORS, ValidationError, mask_email

AUTH_STATEMENT = ("Operator confirmed they own '{target}' or have explicit permission to "
                  "assess it, and will use results only for defensive purposes.")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}

    def response(self):
        body = {"ok": False, "error": {"code": self.code, "message": self.message, **self.extra}}
        return jsonify(body), self.status


def scan_config() -> dict:
    """Plain-dict copy of the settings collectors need (they run in threads)."""
    keys = ("USER_AGENT", "HTTP_TIMEOUT", "CRTSH_TIMEOUT", "DNS_TIMEOUT",
            "HIBP_API_KEY", "VIRUSTOTAL_API_KEY")
    return {k: current_app.config.get(k) for k in keys}


def read_json_body() -> dict:
    """Return the request body as a dict, or raise the matching ApiError."""
    if not request.is_json:
        raise ApiError(415, "unsupported_media_type", "Send the request as application/json.")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "bad_json", "Request body must be a JSON object.")
    return data


def handle_scan(scan_type: str, live_policy=None):
    data = read_json_body()

    mode = data.get("mode", "demo")
    if mode not in ("demo", "live"):
        raise ApiError(400, "bad_mode", "mode must be 'demo' or 'live'.")

    try:
        target = VALIDATORS[scan_type](data.get("target"))
    except ValidationError as exc:
        raise ApiError(400, "invalid_input", str(exc), {"field": exc.field})

    authorization = None
    if mode == "demo":
        if target not in demo_targets_for(scan_type):
            raise ApiError(400, "not_a_demo_target",
                           "Demo mode only works with the fictional demo targets.",
                           {"demo_targets": DEMO_TARGETS[scan_type]})
    else:
        if not current_app.config["ALLOW_LIVE_MODE"]:
            raise ApiError(403, "live_disabled",
                           "Live mode is disabled on this server (ALLOW_LIVE_MODE=false).")
        if data.get("authorized") is not True:
            raise ApiError(403, "authorization_required",
                           "Confirm that you own this asset or have permission to assess it.")
        if live_policy:
            live_policy(target)
        shown = mask_email(target) if scan_type == "email" else target
        authorization = AUTH_STATEMENT.format(target=shown)

    scan = run_scan(scan_type, target, mode, scan_config(), authorization)
    scan_id = save_scan(scan)
    current_app.logger.info(
        "scan id=%s type=%s mode=%s target=%s status=%s score=%s duration=%sms",
        scan_id, scan_type, mode, scan["target"], scan["status"],
        scan["exposure_score"], scan["duration_ms"])
    stored = get_scan(scan_id)
    stored["graph"] = build_graph(stored)
    return jsonify({"ok": True, "scan": stored}), 201
