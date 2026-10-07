"""PDF incident report builder (reportlab). Pure function of already-loaded rows - the API layer
(app/api/reports.py) does the DB reads, so this stays easy to test and never touches the loop."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.config import settings

TIER_COLORS = {
    "Critical": colors.HexColor("#C62828"), "High": colors.HexColor("#E65100"),
    "Medium": colors.HexColor("#B8860B"), "Low": colors.HexColor("#2E7D32"),
}
NAVY = colors.HexColor("#0D2340")
GREY = colors.HexColor("#5F6B7A")


def _fmt(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "-"


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def build_incident_pdf(
    incident, alerts: list, notes: list, tickets: list, steps: list, emails: dict[str, str],
) -> bytes:
    """`emails` maps user id (str) -> email, to show analyst names instead of raw UUIDs."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Incident report {incident.id}", author=settings.app_name,
    )
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=GREY)
    h1 = ParagraphStyle("h1", parent=base["Heading1"], fontSize=18, textColor=NAVY, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, textColor=NAVY, spaceBefore=14, spaceAfter=6)
    head_cell = ParagraphStyle("hc", parent=body, textColor=colors.white, fontName="Helvetica-Bold", fontSize=8)

    tier_color = TIER_COLORS.get(incident.tier or "", GREY)
    story: list = [
        _p(f"{settings.app_name} - Incident Report", h1),
        _p(f"Incident {incident.id}  |  Generated {_fmt(datetime.now(timezone.utc))}", small),
        Spacer(1, 8),
    ]

    # Summary table
    assignee = emails.get(str(incident.assigned_to), "Unassigned") if incident.assigned_to else "Unassigned"
    rows = [
        ["Severity", _p(incident.tier or "-", ParagraphStyle("t", parent=body, textColor=tier_color, fontName="Helvetica-Bold"))],
        ["Attack types", _p(", ".join(a.upper() for a in incident.attack_types), body)],
        ["Source IPs", _p(", ".join(incident.src_ips), body)],
        ["Interface", _p(incident.iface, body)],
        ["Combined impact", _p(f"{incident.combined_impact:.2f}  (correlation: {incident.correlation_confidence})", body)],
        ["First seen", _p(_fmt(incident.first_seen), body)],
        ["Last seen", _p(_fmt(incident.last_seen), body)],
        ["Workflow status", _p(incident.workflow_status, body)],
        ["Assigned to", _p(assignee, body)],
        ["Resolution", _p(incident.resolution or "-", body)],
        ["Resolved at", _p(_fmt(incident.resolved_at), body)],
    ]
    t = Table([[_p(k, small), v] for k, v in rows], colWidths=[38 * mm, 130 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5DBE3")),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)

    def table(header: list[str], data: list[list[object]], widths: list[float]) -> Table:
        tbl = Table([[Paragraph(escape(h), head_cell) for h in header]] + [[_p(c, body) for c in r] for r in data], colWidths=widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F6FA")]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D5DBE3")),
        ]))
        return tbl

    story.append(_p("Evidence", h2))
    if alerts:
        story.append(table(
            ["Time", "Type", "Source", "Destination", "Packets", "XGB", "DL", "Hybrid"],
            [[_fmt(a.created_at)[5:19], a.attack_type.upper(), a.src_ip, a.dst_ip, a.packets,
              f"{a.xgb_conf:.2f}", f"{a.dl_conf:.2f}", f"{a.hybrid_conf:.2f}"] for a in alerts[:40]],
            [27 * mm, 18 * mm, 28 * mm, 28 * mm, 16 * mm, 16 * mm, 16 * mm, 18 * mm],
        ))
        if len(alerts) > 40:
            story.append(_p(f"Showing the 40 most recent of {len(alerts)} alerts.", small))
    else:
        story.append(_p("No alert rows are linked to this incident.", body))

    story.append(_p("Response playbook", h2))
    if steps:
        done = sum(1 for s in steps if s.done)
        story.append(_p(f"{done} of {len(steps)} steps completed.", small))
        story.append(table(
            ["#", "Step", "Status", "Completed by"],
            [[i + 1, s.title, "Done" if s.done else "Open",
              f"{emails.get(str(s.done_by), 'analyst')} ({_fmt(s.done_at)[:16]})" if s.done else "-"] for i, s in enumerate(steps)],
            [8 * mm, 98 * mm, 16 * mm, 46 * mm],
        ))
    else:
        story.append(_p("No playbook was attached to this incident.", body))

    story.append(_p("Tickets", h2))
    if tickets:
        story.append(table(
            ["Reference", "Provider", "Status", "Created"],
            [[t.external_ref + (" (simulated)" if t.simulated else ""), t.provider, t.status or "-", _fmt(t.created_at)[:16]] for t in tickets],
            [38 * mm, 28 * mm, 40 * mm, 62 * mm],
        ))
    else:
        story.append(_p("No tickets were created.", body))

    story.append(_p("Analyst notes", h2))
    if notes:
        for n in notes:
            story.append(_p(f"{emails.get(str(n.author_id), 'analyst')} - {_fmt(n.created_at)[:16]}", small))
            story.append(_p(n.body, body))
            story.append(Spacer(1, 4))
    else:
        story.append(_p("No notes recorded.", body))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY)
        canvas.drawString(18 * mm, 9 * mm, f"{settings.app_name} - confidential incident report")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
