"""
app.py - Flask entry point.

Run:  python app.py        then open http://127.0.0.1:5000

create_app() is an "application factory": it builds a fresh, fully configured
Flask app. The tests call it with a temporary database.
"""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from config import get_config
from database.db import init_db
from extensions import limiter
from routes import (auto_routes, domain_routes, email_routes, page_routes, report_routes,
                    reputation_routes, scan_routes, username_routes)
from routes.common import ApiError

# Content-Security-Policy: only our own scripts/styles may run. There are no
# inline scripts, so injected HTML from third-party data cannot execute.
# The one hash below allows the single fixed CSS rule that Cytoscape.js
# injects for its graph container (".__________cytoscape_container {position:relative}").
CYTOSCAPE_STYLE_HASH = "'sha256-pgvDUBa4IjFA2yuSJ2cqcyxmNYJMborsd0ORcRv9vw8='"
CSP = ("default-src 'self'; script-src 'self'; "
       f"style-src 'self' {CYTOSCAPE_STYLE_HASH}; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
       "form-action 'self'; frame-ancestors 'none'")


# An email address in plain or URL-encoded form (alice@x.com / alice%40x.com)
EMAIL_IN_TEXT = re.compile(
    r"([A-Za-z0-9])[A-Za-z0-9._%+-]*(@|%40)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


class MaskEmailFilter(logging.Filter):
    """Masks email addresses in log lines (alice@x.com -> a***@x.com).

    The console access log prints request URLs, and a page URL such as
    /email?target=alice%40example.com would otherwise reveal the full address.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        masked = EMAIL_IN_TEXT.sub(r"\1***\2\3", message)
        if masked != message:
            record.msg, record.args = masked, ()
        return True


def configure_logging(app: Flask):
    app.config["LOG_DIR"].mkdir(parents=True, exist_ok=True)
    # app.logger is shared by every app instance (the tests create many),
    # so attach the file handler only once.
    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        handler = RotatingFileHandler(app.config["LOG_DIR"] / "app.log",
                                      maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.setLevel(logging.INFO)
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    for logger in (app.logger, logging.getLogger("werkzeug")):
        if not any(isinstance(f, MaskEmailFilter) for f in logger.filters):
            logger.addFilter(MaskEmailFilter())


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(get_config())
    if test_config:
        app.config.update(test_config)

    configure_logging(app)
    limiter.init_app(app)
    init_db(app)

    for module in (page_routes, scan_routes, domain_routes, username_routes,
                   email_routes, reputation_routes, auto_routes, report_routes):
        app.register_blueprint(module.bp)

    @app.context_processor
    def inject_flags():
        return {
            "live_allowed": app.config["ALLOW_LIVE_MODE"],
            "hibp_configured": bool(app.config["HIBP_API_KEY"]),
            "vt_configured": bool(app.config["VIRUSTOTAL_API_KEY"]),
        }

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------ error handling
    @app.errorhandler(ApiError)
    def api_error(err: ApiError):
        return err.response()

    @app.errorhandler(HTTPException)
    def http_error(err: HTTPException):
        if request.path.startswith("/api/"):
            messages = {
                404: "Endpoint not found.", 405: "Method not allowed for this endpoint.",
                413: "Request body too large.",
                429: "Too many requests - rate limit exceeded. Please wait and try again.",
            }
            body = {"ok": False, "error": {"code": err.name.lower().replace(" ", "_"),
                                           "message": messages.get(err.code, err.description)}}
            return jsonify(body), err.code
        return render_template("error.html", page="", title=err.name,
                               code=err.code, message=err.description), err.code

    @app.errorhandler(Exception)
    def unhandled(err: Exception):
        app.logger.exception("Unhandled error on %s", request.path)
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": {
                "code": "internal_error",
                "message": "An unexpected error occurred. Details were written to the log."}}), 500
        return render_template("error.html", page="", title="Server error", code=500,
                               message="An unexpected error occurred."), 500

    return app


if __name__ == "__main__":
    import os
    import socket

    port = int(os.getenv("PORT", 5000))
    if "PORT" not in os.environ:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                port = 5001

    application = create_app()
    print(f"\n  OSINT Footprint Dashboard running at  http://127.0.0.1:{port}\n"
          "  Press CTRL+C to stop.\n")
    # host 127.0.0.1 = reachable only from this computer (safer for a demo)
    application.run(host="127.0.0.1", port=port, debug=False)
