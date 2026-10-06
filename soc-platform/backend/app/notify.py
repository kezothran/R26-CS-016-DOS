"""Critical-incident alerting - email and/or Slack webhook. Optional by design, same contract
as app/geoip.py: if neither SMTP nor a Slack webhook is configured, this no-ops with a one-time
startup warning rather than crashing the app. Both sends are blocking I/O (smtplib, requests),
so they're wrapped in asyncio.to_thread from the caller - never block the detection loop.
"""

from __future__ import annotations

import logging
import smtplib
import threading
from email.mime.text import MIMEText

from app.config import settings

logger = logging.getLogger("soc")

_warned = False
_lock = threading.Lock()


def _warn_once() -> None:
    global _warned
    with _lock:
        if not _warned:
            _warned = True
            logger.warning("No SMTP or Slack webhook configured - critical-incident alerting disabled.")


def _send_email(subject: str, body: str) -> None:
    if not (settings.smtp_host and settings.smtp_from and settings.alert_email_to):
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    to_addrs = [a.strip() for a in settings.alert_email_to.split(",") if a.strip()]
    msg["To"] = ", ".join(to_addrs)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls()
        if settings.smtp_user and settings.smtp_password:
            server.login(settings.smtp_user, settings.smtp_password)
        server.sendmail(settings.smtp_from, to_addrs, msg.as_string())


def _send_slack(text: str) -> None:
    if not settings.slack_webhook_url:
        return
    import requests

    requests.post(settings.slack_webhook_url, json={"text": text}, timeout=10)


def _build_message(incident: dict) -> tuple[str, str]:
    attack_types = ", ".join(incident.get("attack_types", []))
    src_ips = ", ".join(incident.get("src_ips", []))
    subject = f"[SOC] Critical incident: {attack_types} from {src_ips}"
    body = (
        f"Incident {incident.get('id')} reached Critical severity.\n\n"
        f"Attack types: {attack_types}\n"
        f"Source IP(s): {src_ips}\n"
        f"Combined impact: {incident.get('combined_impact')}\n"
        f"Interface: {incident.get('interface')}\n"
    )
    return subject, body


def notify_critical_sync(incident: dict) -> None:
    """Synchronous, blocking - call via asyncio.to_thread from async code."""
    if not (settings.smtp_host or settings.slack_webhook_url):
        _warn_once()
        return

    subject, body = _build_message(incident)
    try:
        _send_email(subject, body)
    except Exception as exc:
        logger.warning(f"Failed to send critical-incident email: {exc}")
    try:
        _send_slack(body)
    except Exception as exc:
        logger.warning(f"Failed to send critical-incident Slack notification: {exc}")
