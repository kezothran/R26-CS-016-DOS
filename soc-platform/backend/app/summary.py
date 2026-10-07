"""Daily / weekly management summary email. `build_summary` is a pure DB read; `send_summary`
does the (blocking) SMTP send via asyncio.to_thread; `run_summary_scheduler` is a fire-and-forget
startup task that wakes once a day at SUMMARY_HOUR (UTC) and sends when due. It never raises -
an SMTP or DB hiccup is logged and retried at the next scheduled slot.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

from sqlalchemy import select

from app.config import settings
from app.db.base import SessionLocal
from app.db.models import Incident

logger = logging.getLogger("soc")

TIERS = ("Critical", "High", "Medium", "Low")


def recipients() -> list[str]:
    raw = settings.summary_email_to or settings.alert_email_to or ""
    return [a.strip() for a in raw.split(",") if a.strip()]


def smtp_ready() -> bool:
    return bool(settings.smtp_host and settings.smtp_from and recipients())


async def build_summary(days: int) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    async with SessionLocal() as session:
        incidents = (await session.execute(select(Incident).where(Incident.first_seen >= since))).scalars().all()

    by_tier = Counter(i.tier for i in incidents)
    by_attack = Counter(a for i in incidents for a in i.attack_types)
    by_status = Counter(i.workflow_status for i in incidents)
    by_ip = Counter(ip for i in incidents for ip in i.src_ips)
    resolved = [i for i in incidents if i.resolved_at]
    mttr = (
        sum((i.resolved_at - i.first_seen).total_seconds() for i in resolved) / len(resolved) / 60 if resolved else None
    )
    return {
        "days": days, "since": since, "total": len(incidents),
        "by_tier": {t: by_tier.get(t, 0) for t in TIERS},
        "by_attack": dict(by_attack.most_common()),
        "by_status": dict(by_status),
        "top_sources": by_ip.most_common(5),
        "false_positives": sum(1 for i in incidents if i.resolution == "false_positive"),
        "mttr_minutes": mttr,
    }


def render(summary: dict) -> tuple[str, str, str]:
    label = "Daily" if summary["days"] == 1 else "Weekly" if summary["days"] == 7 else f"{summary['days']}-day"
    subject = f"[{settings.app_name}] {label} security summary - {summary['total']} incidents"
    mttr = f"{summary['mttr_minutes']:.0f} min" if summary["mttr_minutes"] is not None else "n/a"

    text = [f"{label} security summary (last {summary['days']} day(s))", "", f"Total incidents: {summary['total']}"]
    text += [f"  {t}: {n}" for t, n in summary["by_tier"].items()]
    text += ["", "Attack types: " + (", ".join(f"{k.upper()} {v}" for k, v in summary["by_attack"].items()) or "none"),
             f"Mean time to resolve: {mttr}", f"False positives: {summary['false_positives']}", "", "Top sources:"]
    text += [f"  {ip} ({n} incidents)" for ip, n in summary["top_sources"]] or ["  none"]

    tier_color = {"Critical": "#C62828", "High": "#E65100", "Medium": "#B8860B", "Low": "#2E7D32"}
    cards = "".join(
        f'<td style="padding:10px 16px;text-align:center;border:1px solid #D5DBE3">'
        f'<div style="font-size:22px;font-weight:700;color:{tier_color[t]}">{n}</div><div style="font-size:11px;color:#5F6B7A">{t}</div></td>'
        for t, n in summary["by_tier"].items()
    )
    attacks = "".join(f"<li>{escape(k.upper())}: {v}</li>" for k, v in summary["by_attack"].items()) or "<li>none</li>"
    sources = "".join(f"<li><code>{escape(ip)}</code> - {n} incident(s)</li>" for ip, n in summary["top_sources"]) or "<li>none</li>"
    from app.email_templates import MUTED, NAVY, button, shell

    body = f"""<div style="font-size:14px;margin-bottom:14px;"><b>{summary['total']}</b> incidents &middot; mean time to resolve <b>{mttr}</b> &middot; false positives <b>{summary['false_positives']}</b></div>
<table role="presentation" cellpadding="0" cellspacing="0" style="border-collapse:separate;border-spacing:6px;margin:-6px;"><tr>{cards}</tr></table>
<div style="margin-top:18px;font-size:11px;letter-spacing:1px;color:{MUTED};font-weight:700;">ATTACK TYPES</div><ul style="margin:6px 0 0;padding-left:20px;">{attacks}</ul>
<div style="margin-top:16px;font-size:11px;letter-spacing:1px;color:{MUTED};font-weight:700;">TOP SOURCE IPS</div><ul style="margin:6px 0 0;padding-left:20px;">{sources}</ul>
{button("Open the dashboard", settings.dashboard_url.rstrip("/") + "/dashboard/incidents", NAVY)}"""
    html = shell(NAVY, "&#128202;", f"{label.upper()} SECURITY SUMMARY", escape(f"Last {summary['days']} day(s)"), body, preheader=f"{summary['total']} incidents in the last {summary['days']} day(s)")
    return subject, "\n".join(text), html


def _send_blocking(subject: str, text: str, html: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = subject, settings.smtp_from, ", ".join(recipients())
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
        server.starttls()
        if settings.smtp_user and settings.smtp_password:
            server.login(settings.smtp_user, settings.smtp_password)
        server.sendmail(settings.smtp_from, recipients(), msg.as_string())


async def send_summary(days: int) -> int:
    """Sends one summary email now; returns the total incident count. Raises on SMTP failure
    (the manual-send endpoint reports it; the scheduler catches and logs it)."""
    summary = await build_summary(days)
    subject, text, html = render(summary)
    await asyncio.to_thread(_send_blocking, subject, text, html)
    return summary["total"]


def _next_run(now: datetime) -> datetime:
    run = now.replace(hour=settings.summary_hour % 24, minute=0, second=0, microsecond=0)
    if run <= now:
        run += timedelta(days=1)
    if settings.summary_schedule == "weekly":
        while run.weekday() != 0:  # Mondays
            run += timedelta(days=1)
    return run


async def run_summary_scheduler() -> None:
    if settings.summary_schedule not in ("daily", "weekly"):
        return
    if not smtp_ready():
        logger.warning("SUMMARY_SCHEDULE is set but SMTP / recipients are not configured - summary emails disabled.")
        return
    days = 1 if settings.summary_schedule == "daily" else 7
    logger.info(f"Summary email scheduler started ({settings.summary_schedule} at {settings.summary_hour:02d}:00 UTC).")
    while True:
        now = datetime.now(timezone.utc)
        await asyncio.sleep(max((_next_run(now) - now).total_seconds(), 1))
        try:
            total = await send_summary(days)
            logger.info(f"Summary email sent ({total} incidents).")
        except Exception as exc:
            logger.warning(f"Summary email failed: {exc}")
