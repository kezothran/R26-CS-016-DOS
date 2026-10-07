"""HTML email templates (alert + summary). Table-based layout with inline CSS only - that is what
Gmail/Outlook/Apple Mail render reliably (no <style> blocks, flexbox or external images). Every
dynamic value is html-escaped before it is placed in the markup."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from app.config import settings

TIER_STYLE = {
    "Critical": {"bg": "#C62828", "soft": "#FDECEA", "icon": "&#9888;", "label": "CRITICAL INCIDENT DETECTED"},
    "High": {"bg": "#E65100", "soft": "#FFF0E3", "icon": "&#9888;", "label": "HIGH SEVERITY INCIDENT"},
    "Medium": {"bg": "#F9A825", "soft": "#FFF8E1", "icon": "&#9888;", "label": "MEDIUM SEVERITY INCIDENT"},
    "Low": {"bg": "#2E7D32", "soft": "#E8F5E9", "icon": "&#9432;", "label": "LOW SEVERITY NOTICE"},
}
NAVY = "#0D2340"
MUTED = "#5F6B7A"
LINE = "#E1E6ED"
FONT = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;"


def e(value: object) -> str:
    return escape(str(value))


def shell(banner_bg: str, banner_icon: str, banner_title: str, banner_sub: str, body: str, preheader: str = "") -> str:
    """Page chrome shared by every email: navy brand bar, coloured banner, white body, footer."""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#EEF1F6;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{e(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#EEF1F6;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:100%;max-width:600px;background:#ffffff;border-radius:10px;overflow:hidden;{FONT}">
  <tr><td style="background:{NAVY};padding:16px 24px;">
    <span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:2px;">SENTRIX</span>
    <span style="color:#8FB4E8;font-size:11px;letter-spacing:1px;margin-left:10px;">SECURITY OPERATIONS CONSOLE</span>
  </td></tr>
  <tr><td style="background:{banner_bg};padding:26px 24px;">
    <div style="color:#ffffff;font-size:13px;letter-spacing:1.5px;font-weight:600;">{banner_icon}&nbsp; {e(banner_title)}</div>
    <div style="color:#ffffff;font-size:22px;font-weight:700;line-height:1.3;margin-top:8px;">{banner_sub}</div>
  </td></tr>
  <tr><td style="padding:24px;color:{NAVY};font-size:14px;line-height:1.6;">{body}</td></tr>
  <tr><td style="background:#F6F8FB;padding:16px 24px;border-top:1px solid {LINE};color:{MUTED};font-size:11px;line-height:1.6;">
    You are receiving this because you are on the {e(settings.app_name)} alert list.<br>
    Sent automatically by the detection engine &middot; {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
  </td></tr>
</table>
</td></tr></table></body></html>"""


def button(label: str, url: str, color: str) -> str:
    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin:22px 0 4px;"><tr>'
        f'<td style="background:{color};border-radius:6px;"><a href="{e(url)}" style="display:inline-block;padding:12px 26px;'
        f'color:#ffffff;font-weight:700;font-size:14px;text-decoration:none;{FONT}">{e(label)} &rarr;</a></td></tr></table>'
    )


def stat_cell(value: str, label: str, color: str) -> str:
    return (
        f'<td align="center" style="padding:12px 6px;border:1px solid {LINE};border-radius:6px;">'
        f'<div style="font-size:22px;font-weight:700;color:{color};">{value}</div>'
        f'<div style="font-size:10px;letter-spacing:1px;color:{MUTED};text-transform:uppercase;">{e(label)}</div></td>'
    )


def alert_email(incident: dict, action: str, sample: bool = False) -> tuple[str, str, str]:
    """(subject, plain text, html) for a severity alert."""
    tier = str(incident.get("tier") or "Critical")
    st = TIER_STYLE.get(tier, TIER_STYLE["Critical"])
    types = ", ".join(t.upper() for t in incident.get("attack_types", [])) or "Unknown"
    ips = ", ".join(incident.get("src_ips", [])) or "Unknown"
    impact = incident.get("combined_impact", "n/a")
    iface = incident.get("interface") or incident.get("iface") or "-"
    inc_id = incident.get("id") or incident.get("incident_id") or ""
    link = f"{settings.dashboard_url.rstrip('/')}/dashboard/incidents" + (f"?open={inc_id}" if inc_id and not sample else "")
    detected = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    prefix = "[SAMPLE] " if sample else ""
    subject = f"{prefix}[SOC] {tier} incident: {types} from {ips}"

    sample_note = (
        f'<div style="background:#FFF8E1;border:1px solid #F9A825;border-radius:6px;padding:10px 14px;margin-bottom:18px;'
        f'color:#7A5800;font-size:12px;"><b>SAMPLE ALERT</b> &mdash; no real incident. This shows what a {e(tier)} alert looks like.</div>'
        if sample else ""
    )
    rows = [("Attack type", types), ("Source IPs", ips), ("Interface", iface), ("Detected", detected)]
    if inc_id and not sample:
        rows.append(("Incident ID", str(inc_id)))
    table = "".join(
        f'<tr><td style="padding:9px 0;border-bottom:1px solid {LINE};color:{MUTED};font-size:12px;width:120px;">{e(k)}</td>'
        f'<td style="padding:9px 0;border-bottom:1px solid {LINE};font-weight:600;">{e(v)}</td></tr>'
        for k, v in rows
    )
    body = f"""{sample_note}
<table role="presentation" width="100%" cellpadding="0" cellspacing="6" style="margin:-6px;margin-bottom:12px;"><tr>
  {stat_cell(e(impact), "Impact score", st["bg"])}
  {stat_cell(e(len(incident.get("attack_types", [])) or 1), "Attack types", NAVY)}
  {stat_cell(e(len(incident.get("src_ips", [])) or 1), "Source IPs", NAVY)}
</tr></table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:8px;">{table}</table>
<div style="margin-top:20px;background:{st["soft"]};border-left:4px solid {st["bg"]};border-radius:4px;padding:14px 16px;">
  <div style="font-size:11px;letter-spacing:1px;color:{MUTED};font-weight:700;">RECOMMENDED FIRST ACTION</div>
  <div style="margin-top:4px;">{e(action)}</div>
</div>
{button("Open incident in dashboard", link, st["bg"])}"""
    html = shell(st["bg"], st["icon"], st["label"], e(f"{types} flood from {ips}"), body, preheader=f"{tier}: {types} from {ips} - impact {impact}")

    text = (
        f"{'SAMPLE ALERT - no real incident' + chr(10) if sample else ''}{st['label']}\n\n"
        f"Attack type: {types}\nSource IPs: {ips}\nImpact score: {impact}\nInterface: {iface}\nDetected: {detected}\n\n"
        f"Recommended first action: {action}\n\nOpen the incident: {link}\n"
    )
    return subject, text, html
