"""
routes/email_routes.py - POST /api/scan/email

Extra live-mode policy for email checks (the most privacy-sensitive module):
  * without a paid HIBP key, only HIBP's official test addresses are allowed;
  * if AUTHORIZED_EMAIL_DOMAINS is set in .env, live checks are limited to
    those domains (e.g. your own organisation).
"""
from flask import Blueprint, current_app

from config import HIBP_TEST_DOMAIN
from extensions import limiter

from .common import ApiError, handle_scan

bp = Blueprint("email_api", __name__, url_prefix="/api/scan")


def email_policy(email: str):
    domain = email.rsplit("@", 1)[1]
    is_test = domain == HIBP_TEST_DOMAIN
    if not current_app.config["HIBP_API_KEY"] and not is_test:
        raise ApiError(
            400, "hibp_key_missing",
            f"No HIBP API key is configured. Use demo mode, or a test address such as "
            f"account-exists@{HIBP_TEST_DOMAIN} (HIBP's official test key).")
    allowed = current_app.config["AUTHORIZED_EMAIL_DOMAINS"]
    if allowed and not is_test and domain not in allowed:
        raise ApiError(403, "domain_not_authorised",
                       "This server only allows live email checks for: " + ", ".join(allowed))


@bp.post("/email")
@limiter.limit(lambda: current_app.config["SCAN_RATE_LIMIT"])
def scan_email():
    return handle_scan("email", live_policy=email_policy)
