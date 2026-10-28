"""
routes/report_routes.py - Downloadable reports.

    GET /api/scans/<id>/report.pdf
    GET /api/scans/<id>/report.csv
"""
from flask import Blueprint, Response

from database.db import get_scan
from services.report import build_csv, build_pdf

from .common import ApiError

bp = Blueprint("report_api", __name__, url_prefix="/api/scans")


def _load(scan_id: int) -> dict:
    scan = get_scan(scan_id)
    if scan is None:
        raise ApiError(404, "not_found", f"Scan {scan_id} does not exist.")
    return scan


def _filename(scan: dict, ext: str) -> str:
    return f"osint_report_{scan['id']}_{scan['scan_type']}.{ext}"


@bp.get("/<int:scan_id>/report.pdf")
def report_pdf(scan_id: int):
    scan = _load(scan_id)
    return Response(build_pdf(scan), mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="{_filename(scan, "pdf")}"'})


@bp.get("/<int:scan_id>/report.csv")
def report_csv(scan_id: int):
    scan = _load(scan_id)
    # UTF-8 BOM so Excel on Windows shows non-ASCII characters correctly
    return Response("﻿" + build_csv(scan), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{_filename(scan, "csv")}"'})
