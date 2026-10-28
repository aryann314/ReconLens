"""
services/report.py - Export a scan as CSV or PDF.

Both formats contain: scan summary, exposure score and its method, per-source
status, every finding with its source and timestamp, recommendations and
limitations.

Security notes
* CSV formula injection: data from third parties (e.g. a DNS TXT record
  "=HYPERLINK(...)") could execute as a formula when opened in Excel. Every
  cell that starts with = + - @ (or tab/CR) is prefixed with an apostrophe.
* PDF text is XML-escaped before it is passed to ReportLab's Paragraph
  mini-markup, so third-party data cannot inject markup.
* Email targets are already masked before storage, so reports never contain
  the full address.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

STATUS_LABEL = {"confirmed": "Confirmed", "not_found": "Not found",
                "inconclusive": "Inconclusive", "error": "Error"}
SEV_COLOR = {"high": colors.HexColor("#b42318"), "medium": colors.HexColor("#b54708"),
             "low": colors.HexColor("#1d4ed8"), "info": colors.HexColor("#475467")}
LEVEL_COLOR = {"Low": "#067647", "Moderate": "#b54708", "High": "#c4320a", "Critical": "#b42318"}
TYPE_LABEL = {"domain": "Domain Intelligence", "username": "Username Footprint",
              "email": "Email Exposure", "reputation": "IP / URL Reputation"}


# ------------------------------------------------------------------- CSV
def safe_cell(value) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def build_csv(scan: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    row = lambda *cells: w.writerow([safe_cell(c) for c in cells])  # noqa: E731

    row("OSINT Digital Footprint Report")
    row("Generated (UTC)", datetime.now(timezone.utc).replace(microsecond=0).isoformat())
    row("Classification", "CONFIDENTIAL - for the authorised owner of the assessed asset")
    row()
    row("SCAN SUMMARY")
    for key, label in (("id", "Scan ID"), ("scan_type", "Scan type"), ("target", "Target"),
                       ("mode", "Mode"), ("status", "Status"), ("exposure_score", "Exposure score"),
                       ("exposure_level", "Exposure level"), ("started_at", "Started (UTC)"),
                       ("completed_at", "Completed (UTC)"), ("duration_ms", "Duration (ms)"),
                       ("authorization", "Authorisation statement")):
        row(label, scan.get(key))
    row("Scoring method", scan.get("scoring", {}).get("method"))
    row()
    row("SOURCES")
    row("Module", "Source", "Status", "Duration (ms)", "Error")
    for m in scan.get("modules", []):
        row(m["module"], m["source"], m["status"], m["duration_ms"], m.get("error") or "")
    row()
    row("FINDINGS")
    row("Module", "Source", "Code", "Title", "Value", "Status", "Severity", "Source URL",
        "Collected at (UTC)")
    for f in scan.get("findings", []):
        row(f["module"], f["source"], f["code"], f["title"], f.get("value"), f["status"],
            f["severity"], f.get("source_url"), f["collected_at"])
    row()
    row("RECOMMENDATIONS")
    row("Priority", "Recommendation", "Action", "Triggered by")
    for r in scan.get("recommendations", []):
        row(r["priority"], r["title"], r["action"], "; ".join(r.get("triggered_by", [])))
    row()
    row("LIMITATIONS")
    for lim in scan.get("limitations", []):
        row(lim)
    return buf.getvalue()


# ------------------------------------------------------------------- PDF
def _p(text, style) -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)), style)


def build_pdf(scan: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=18 * mm, bottomMargin=16 * mm,
                            title=f"OSINT report - scan {scan.get('id')}",
                            author="OSINT Footprint Dashboard")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5,
                           textColor=colors.HexColor("#475467"))
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=18, leading=22, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, leading=16,
                        spaceBefore=10, spaceAfter=5, textColor=colors.HexColor("#0b2540"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    cell_b = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")
    banner = ParagraphStyle("banner", parent=small, alignment=TA_CENTER,
                            textColor=colors.HexColor("#b42318"))

    grid = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ])
    story = []
    story.append(_p("CONFIDENTIAL - prepared for the authorised owner of the assessed asset",
                    banner))
    story.append(Spacer(1, 4))
    story.append(_p("OSINT Digital Footprint Report", h1))
    story.append(_p(f"{TYPE_LABEL.get(scan['scan_type'], scan['scan_type'])}  |  "
                    f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                    small))
    story.append(Spacer(1, 8))
    if scan.get("mode") == "demo":
        story.append(_p("DEMO MODE - every value in this report is fictional.", banner))
        story.append(Spacer(1, 6))

    # ---- summary
    level = scan.get("exposure_level", "Low")
    score_par = Paragraph(
        f'<font size="22" color="{LEVEL_COLOR.get(level, "#000")}"><b>'
        f'{int(scan.get("exposure_score", 0))}</b></font>'
        f'<font size="10"> / 100</font><br/><font size="11" '
        f'color="{LEVEL_COLOR.get(level, "#000")}"><b>{escape(level)} exposure</b></font>', body)
    meta = [
        ["Target", scan.get("target")], ["Scan ID", scan.get("id")],
        ["Mode", scan.get("mode")], ["Status", scan.get("status")],
        ["Started (UTC)", scan.get("started_at")],
        ["Duration", (f"{scan.get('duration_ms') or 0} ms" if (scan.get("duration_ms") or 0) < 1000
                      else f"{scan['duration_ms'] / 1000:.1f} s")],
    ]
    meta_tbl = Table([[_p(k, cell_b), _p(v, cell)] for k, v in meta],
                     colWidths=[28 * mm, 82 * mm])
    meta_tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
                                  ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    summary = Table([[score_par, meta_tbl]], colWidths=[64 * mm, 114 * mm])
    summary.setStyle(TableStyle([
        ("BOX", (0, 0), (0, 0), 0.8, colors.HexColor("#d0d5dd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (0, 0), (0, 0), "CENTER")]))
    story.append(summary)

    counts = scan.get("scoring", {}).get("status_counts", {})
    story.append(Spacer(1, 6))
    story.append(_p("Result reliability: " + ", ".join(
        f"{STATUS_LABEL[k]} {counts.get(k, 0)}" for k in STATUS_LABEL), body))
    story.append(_p("Scoring method: " + scan.get("scoring", {}).get("method", ""), small))
    if scan.get("authorization"):
        story.append(_p("Authorisation: " + scan["authorization"], small))

    # ---- score breakdown
    breakdown = scan.get("scoring", {}).get("breakdown", [])
    if breakdown:
        story.append(_p("Score breakdown", h2))
        t = Table([[_p("Finding", cell_b), _p("Severity", cell_b), _p("Points", cell_b)]] +
                  [[_p(b["title"], cell), _p(b["severity"], cell), _p(b["points"], cell)]
                   for b in breakdown], colWidths=[128 * mm, 25 * mm, 25 * mm], repeatRows=1)
        t.setStyle(grid)
        story.append(t)

    # ---- sources
    story.append(_p("Data sources queried", h2))
    t = Table([[_p(h, cell_b) for h in ("Source", "Status", "Time", "Note")]] +
              [[_p(m["source"], cell), _p(m["status"], cell),
                _p(f"{m['duration_ms']} ms", cell), _p(m.get("error") or "", cell)]
               for m in scan.get("modules", [])],
              colWidths=[62 * mm, 20 * mm, 18 * mm, 78 * mm], repeatRows=1)
    t.setStyle(grid)
    story.append(t)

    # ---- findings
    story.append(_p("Findings", h2))
    order = {"confirmed": 0, "inconclusive": 1, "error": 2, "not_found": 3}
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings = sorted(scan.get("findings", []),
                      key=lambda f: (order[f["status"]], sev_order[f["severity"]]))
    rows = [[_p(h, cell_b) for h in ("Status", "Severity", "Finding", "Source / time")]]
    for f in findings:
        sev = Paragraph(f'<font color="{SEV_COLOR[f["severity"]].hexval().replace("0x", "#")}">'
                        f'<b>{escape(f["severity"].upper())}</b></font>', cell)
        val = (f.get("value") or "")[:500]
        src = f"{escape(f['source'])}<br/>{escape(f['collected_at'])}"
        if f.get("source_url"):
            src += f"<br/><font color='#1d4ed8'>{escape(f['source_url'][:90])}</font>"
        rows.append([_p(STATUS_LABEL[f["status"]], cell), sev,
                     Paragraph(f"<b>{escape(f['title'])}</b><br/>{escape(val)}", cell),
                     Paragraph(src, small)])
    t = Table(rows, colWidths=[20 * mm, 17 * mm, 88 * mm, 53 * mm], repeatRows=1)
    t.setStyle(grid)
    story.append(t)

    # ---- recommendations
    recs = scan.get("recommendations", [])
    if recs:
        story.append(_p("Security recommendations", h2))
        t = Table([[_p(h, cell_b) for h in ("Priority", "Recommendation")]] +
                  [[_p(r["priority"], cell),
                    Paragraph(f"<b>{escape(r['title'])}</b><br/>{escape(r['action'])}", cell)]
                   for r in recs], colWidths=[22 * mm, 156 * mm], repeatRows=1)
        t.setStyle(grid)
        story.append(t)

    # ---- limitations
    story.append(KeepTogether([_p("Limitations", h2)] +
                              [_p("- " + lim, body) for lim in scan.get("limitations", [])]))

    # ---- appendix tables
    tables = [f for f in findings if isinstance(f.get("details"), dict)
              and f["details"].get("table") and f["details"]["table"].get("rows")]
    if tables:
        story.append(PageBreak())
        story.append(_p("Appendix - data tables", h2))
        for f in tables:
            tb = f["details"]["table"]
            cols = tb["columns"]
            width = 178 * mm / len(cols)
            data = [[_p(c, cell_b) for c in cols]] + \
                   [[_p(str(v)[:120], cell) for v in r] for r in tb["rows"][:60]]
            t = Table(data, colWidths=[width] * len(cols), repeatRows=1)
            t.setStyle(grid)
            more = len(tb["rows"]) - 60
            story.append(KeepTogether([_p(f["title"], cell_b), Spacer(1, 2)]))
            story.append(t)
            if more > 0:
                story.append(_p(f"... {more} more rows in the CSV export / dashboard.", small))
            story.append(Spacer(1, 8))

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(16 * mm, 9 * mm,
                          "OSINT Footprint Dashboard - passive, authorised OSINT only")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
