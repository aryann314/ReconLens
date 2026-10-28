"""
routes/page_routes.py - HTML pages. Each page is a Jinja2 template; the data
is loaded by the page's JavaScript from the JSON API.
"""
from flask import Blueprint, abort, render_template

from database.db import get_scan

bp = Blueprint("pages", __name__)

PAGES = {
    "domain": "Domain Intelligence",
    "username": "Username Footprint",
    "email": "Email Exposure",
    "reputation": "IP / URL Reputation",
}


@bp.get("/")
def index():
    return render_template("index.html", page="dashboard", title="Overview")


@bp.get("/domain")
def domain():
    return render_template("domain.html", page="domain", title=PAGES["domain"])


@bp.get("/username")
def username():
    return render_template("username.html", page="username", title=PAGES["username"])


@bp.get("/email")
def email():
    return render_template("email.html", page="email", title=PAGES["email"])


@bp.get("/reputation")
def reputation():
    return render_template("reputation.html", page="reputation", title=PAGES["reputation"])


@bp.get("/history")
def history():
    return render_template("history.html", page="history", title="Scan History")


@bp.get("/scan/<int:scan_id>")
def scan_detail(scan_id: int):
    if get_scan(scan_id) is None:
        abort(404)
    return render_template("scan_detail.html", page="history",
                           title=f"Scan #{scan_id}", scan_id=scan_id)


@bp.get("/graph")
def graph():
    return render_template("graph.html", page="graph", title="Investigation Graph")


@bp.get("/about")
def about():
    return render_template("about.html", page="about", title="Method & Ethics")
