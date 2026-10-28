"""
extensions.py - Shared Flask extensions.

The rate limiter lives here (instead of app.py) so that route modules can
import it without creating a circular import.
"""
from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# In-memory storage is fine for a single-process student prototype.
# The default limit covers pages and read-only API calls (static files are
# exempt); scan endpoints additionally use the stricter SCAN_RATE_LIMIT.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[lambda: current_app.config["DEFAULT_RATE_LIMIT"]],
    storage_uri="memory://",
    headers_enabled=True,
)
