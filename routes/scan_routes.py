"""
routes/scan_routes.py - Read/delete stored scans, statistics, health.

    GET    /api/health              server status and which API keys are configured
    GET    /api/demo-targets        fictional targets usable in demo mode
    GET    /api/scans?limit=&type=  scan history (newest first)
    GET    /api/scans/<id>          one scan with all findings
    DELETE /api/scans/<id>          delete a scan (data minimisation)
    GET    /api/stats               aggregate numbers for the dashboard charts
    GET    /api/scans/<id>/graph    relationship graph of one scan
    GET    /api/graph?limit=&ids=   correlated investigation graph across stored scans
"""
from flask import Blueprint, current_app, jsonify, request

from collectors.demo_data import DEMO_TARGETS
from database.db import delete_scan, get_scan, get_stats, list_scans
from services.graph import build_case_graph, build_graph

from .common import ApiError

bp = Blueprint("scan_api", __name__, url_prefix="/api")


@bp.get("/health")
def health():
    cfg = current_app.config
    return jsonify({
        "ok": True,
        "live_mode_allowed": cfg["ALLOW_LIVE_MODE"],
        "hibp_key_configured": bool(cfg["HIBP_API_KEY"]),
        "virustotal_key_configured": bool(cfg["VIRUSTOTAL_API_KEY"]),
        "retention_days": cfg["RETENTION_DAYS"],
        "scan_rate_limit": cfg["SCAN_RATE_LIMIT"],
    })


@bp.get("/demo-targets")
def demo_targets():
    return jsonify({"ok": True, "demo_targets": DEMO_TARGETS})


@bp.get("/scans")
def scans():
    scan_type = request.args.get("type") or None
    if scan_type and scan_type not in DEMO_TARGETS:
        raise ApiError(400, "bad_type", "type must be domain, username, email or reputation.")
    try:
        limit = max(1, min(200, int(request.args.get("limit", 50))))
    except ValueError:
        raise ApiError(400, "bad_limit", "limit must be a number.")
    return jsonify({"ok": True, "scans": list_scans(limit, scan_type)})


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    scan["graph"] = build_graph(scan)
    return jsonify({"ok": True, "scan": scan})


@bp.get("/scans/<int:scan_id>/graph")
def scan_graph(scan_id: int):
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    return jsonify({"ok": True, "graph": build_graph(scan)})


@bp.get("/graph")
def case_graph():
    """Merge stored scans into one graph; shared entities link the scans together."""
    try:
        limit = max(1, min(50, int(request.args.get("limit", 20))))
    except ValueError:
        raise ApiError(400, "bad_limit", "limit must be a number.")
    raw_ids = request.args.get("ids", "").strip()
    if raw_ids:
        try:
            ids = [int(x) for x in raw_ids.split(",") if x.strip()][:50]
        except ValueError:
            raise ApiError(400, "bad_ids", "ids must be a comma-separated list of scan numbers.")
    else:
        ids = [s["id"] for s in list_scans(limit)]
    scans = [s for s in (get_scan(i) for i in ids) if s is not None]
    graph = build_case_graph(scans)
    graph["scans"] = [{"id": s["id"], "scan_type": s["scan_type"], "target": s["target"],
                       "exposure_score": s["exposure_score"],
                       "exposure_level": s["exposure_level"], "mode": s["mode"]} for s in scans]
    return jsonify({"ok": True, "graph": graph})


@bp.delete("/scans/<int:scan_id>")
def scan_delete(scan_id: int):
    if not delete_scan(scan_id):
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    current_app.logger.info("scan id=%s deleted by operator", scan_id)
    return jsonify({"ok": True, "deleted": scan_id})


@bp.get("/stats")
def stats():
    return jsonify({"ok": True, "stats": get_stats()})
