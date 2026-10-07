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
            logger.warning("No alert channel (SMTP, Slack, Telegram, WhatsApp, Twilio) configured - critical-incident alerting disabled.")


def _send_email(subject: str, body: str, html: str | None = None) -> None:
    if not (settings.smtp_host and settings.smtp_from and settings.alert_email_to):
        return
    if html:
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
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


def twilio_configured() -> bool:
    return bool(
        settings.twilio_account_sid and settings.twilio_auth_token and settings.alert_phone_to
        and (settings.twilio_from or settings.twilio_whatsapp_from)
    )


def _send_twilio(text: str) -> None:
    """SMS (twilio_from) and/or WhatsApp (twilio_whatsapp_from) to every alert_phone_to number.
    One failed recipient never blocks the rest."""
    if not twilio_configured():
        return
    import requests

    url = f"https://api.twilio.com/2010-04-01/Accounts/{settings.twilio_account_sid}/Messages.json"
    auth = (settings.twilio_account_sid, settings.twilio_auth_token)
    numbers = [n.strip() for n in settings.alert_phone_to.split(",") if n.strip()]
    for number in numbers:
        channels = []
        if settings.twilio_from:
            channels.append((settings.twilio_from, number))
        if settings.twilio_whatsapp_from:
            channels.append((settings.twilio_whatsapp_from, f"whatsapp:{number}"))
        for sender, to in channels:
            try:
                resp = requests.post(url, data={"From": sender, "To": to, "Body": text[:1500]}, auth=auth, timeout=10)
                if resp.status_code >= 300:
                    logger.warning(f"Twilio rejected message to {to}: {resp.status_code} {resp.text[:200]}")
            except Exception as exc:
                logger.warning(f"Twilio send to {to} failed: {exc}")


def telegram_configured() -> bool:
    return bool(settings.telegram_bot_token and settings.telegram_chat_id)


def _send_telegram(text: str) -> list[str]:
    """One message per chat id. Returns a list of error strings (empty = all delivered)."""
    if not telegram_configured():
        return []
    import requests

    errors: list[str] = []
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    for chat_id in [c.strip() for c in settings.telegram_chat_id.split(",") if c.strip()]:
        try:
            resp = requests.post(url, json={"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": True}, timeout=10)
            if resp.status_code != 200:
                detail = resp.json().get("description", resp.text[:120]) if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:120]
                errors.append(f"Telegram chat {chat_id}: {detail}")
        except Exception as exc:
            errors.append(f"Telegram chat {chat_id}: {exc}")
    return errors


def callmebot_configured() -> bool:
    return bool(settings.callmebot_recipients and settings.callmebot_recipients.strip())


def _send_callmebot(text: str) -> list[str]:
    """Free WhatsApp via CallMeBot - one GET per "phone:apikey" recipient."""
    if not callmebot_configured():
        return []
    import requests

    errors: list[str] = []
    for pair in [p.strip() for p in settings.callmebot_recipients.split(",") if p.strip()]:
        phone, _, key = pair.partition(":")
        if not (phone and key):
            errors.append(f"WhatsApp recipient '{pair}' must look like +94771234567:apikey")
            continue
        try:
            resp = requests.get(
                "https://api.callmebot.com/whatsapp.php",
                params={"phone": phone, "text": text[:1000], "apikey": key}, timeout=15,
            )
            if resp.status_code != 200:
                errors.append(f"WhatsApp {phone}: HTTP {resp.status_code} {resp.text[:120]}")
        except Exception as exc:
            errors.append(f"WhatsApp {phone}: {exc}")
    return errors


def meta_wa_configured() -> bool:
    return bool(settings.meta_wa_token and settings.meta_wa_phone_number_id and settings.meta_wa_to)


def _meta_wa_error(resp) -> tuple[int | None, str]:
    try:
        err = resp.json().get("error", {})
        return err.get("code"), err.get("message", resp.text[:160])
    except ValueError:
        return None, resp.text[:160]


# Recommended first action per attack type - becomes variable {{4}} of the per-severity templates
# (mirrors the response playbooks). No newlines: template variables can't contain them.
ATTACK_ACTIONS = {
    "icmp": "Check the source against the whitelist, rate-limit ICMP on the edge and propose a block.",
    "syn": "Check the SYN backlog, enable SYN cookies and propose a block.",
    "fragmentation": "Verify it is not legitimate large traffic, check for teardrop patterns and limit fragment reassembly.",
    "udp": "Check for amplification, rate-limit the affected UDP port and propose a block.",
}


def _tier_template(incident: dict) -> tuple[str, list[str]] | None:
    """(template name, 4 body variables) for an incident when per-severity templates are enabled."""
    if not settings.meta_wa_template_prefix or not incident:
        return None
    tier = str(incident.get("tier") or "Critical").lower()
    types = list(incident.get("attack_types") or [])
    action = next((ATTACK_ACTIONS[t] for t in types if t in ATTACK_ACTIONS), "Review the evidence on the dashboard.")
    params = [
        ", ".join(t.upper() for t in types) or "Unknown",
        ", ".join(incident.get("src_ips") or []) or "Unknown",
        str(incident.get("combined_impact", "n/a")),
        action,
    ]
    return f"{settings.meta_wa_template_prefix}_{tier}", [" ".join(p.split())[:300] for p in params]


def meta_template_status() -> dict[str, str]:
    """Approval status of the per-severity templates (APPROVED / PENDING / REJECTED), or {} if unknown."""
    if not (settings.meta_wa_token and settings.meta_wa_waba_id):
        return {}
    import requests

    try:
        resp = requests.get(
            f"https://graph.facebook.com/{settings.meta_wa_api_version}/{settings.meta_wa_waba_id}/message_templates",
            headers={"Authorization": f"Bearer {settings.meta_wa_token}"},
            params={"fields": "name,status", "limit": 100}, timeout=15,
        )
        prefix = settings.meta_wa_template_prefix or "sentrix_alert"
        return {t["name"]: t["status"] for t in resp.json().get("data", []) if t["name"].startswith(prefix)}
    except Exception:
        return {}


def _send_meta_whatsapp(text: str, incident: dict | None = None) -> list[str]:
    """WhatsApp Cloud API. Meta answers HTTP 200 ("accepted") for a free-form text even when the
    recipient is outside the 24h customer-service window - it then fails later, asynchronously, so the
    reply can't be used to decide on a fallback. So delivery is made reliable with the template:
      * custom template configured (META_WA_TEMPLATE, one {{1}} body variable): send ONLY the template -
        it carries the alert text and is always deliverable to a verified recipient.
      * default hello_world: send the text (arrives only if the recipient messaged the number in the
        last 24h) AND the generic template, so something always arrives.
    Returns error strings (empty = every request was accepted by Meta)."""
    if not meta_wa_configured():
        return []
    import requests

    url = f"https://graph.facebook.com/{settings.meta_wa_api_version}/{settings.meta_wa_phone_number_id}/messages"
    headers = {"Authorization": f"Bearer {settings.meta_wa_token}"}
    flat = " ".join(text.split())[:900]  # template variables can't contain newlines/tabs
    tiered = _tier_template(incident or {})
    custom = tiered is not None or settings.meta_wa_template != "hello_world"
    template: dict = {"name": settings.meta_wa_template, "language": {"code": settings.meta_wa_template_lang}}
    if tiered:
        template["name"] = tiered[0]
        template["components"] = [{"type": "body", "parameters": [{"type": "text", "text": v} for v in tiered[1]]}]
    elif custom:
        template["components"] = [{"type": "body", "parameters": [{"type": "text", "text": flat}]}]

    errors: list[str] = []
    for number in [n.strip().lstrip("+") for n in settings.meta_wa_to.split(",") if n.strip()]:
        base = {"messaging_product": "whatsapp", "to": number}
        payloads = [{**base, "type": "template", "template": template}]
        if not custom:
            payloads.insert(0, {**base, "type": "text", "text": {"body": text[:3000]}})
        for payload in payloads:
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=15)
                if resp.status_code != 200:
                    _, msg = _meta_wa_error(resp)
                    errors.append(f"WhatsApp (Meta) {number}: {msg}")
            except Exception as exc:
                errors.append(f"WhatsApp (Meta) {number}: {exc}")
    return errors


def send_test_sync(channel: str) -> list[str]:
    """Sends a clearly-labelled test message on one channel; returns errors (empty = sent)."""
    text = f"[{settings.app_name}] Test message - alert delivery is working."
    if channel == "telegram":
        return _send_telegram(text) if telegram_configured() else ["Telegram is not configured"]
    if channel == "whatsapp":
        if not (callmebot_configured() or meta_wa_configured()):
            return ["WhatsApp is not configured (set META_WA_* or CALLMEBOT_RECIPIENTS)"]
        sample = {"tier": "Low", "attack_types": ["udp"], "src_ips": ["TEST - no real incident"], "combined_impact": 0}
        return _send_callmebot(text) + _send_meta_whatsapp(text, sample)
    if channel == "email":
        if not (settings.smtp_host and settings.smtp_from and settings.alert_email_to):
            return ["Email is not configured"]
        try:
            from app.email_templates import alert_email

            sample = {"tier": "Critical", "attack_types": ["udp", "syn"], "src_ips": ["203.0.113.50"], "combined_impact": 91.7, "interface": "Wi-Fi"}
            subject, body, html = alert_email(sample, ATTACK_ACTIONS["udp"], sample=True)
            _send_email(subject, body, html)
            return []
        except Exception as exc:
            return [f"Email: {exc}"]
    if channel == "slack":
        if not settings.slack_webhook_url:
            return ["Slack is not configured"]
        try:
            _send_slack(text)
            return []
        except Exception as exc:
            return [f"Slack: {exc}"]
    return [f"Unknown channel '{channel}'"]


def _short_message(incident: dict) -> str:
    attack_types = ", ".join(a.upper() for a in incident.get("attack_types", []))
    src_ips = ", ".join(incident.get("src_ips", []))
    return f"[{settings.app_name}] CRITICAL: {attack_types} flood from {src_ips} (impact {incident.get('combined_impact')}). Open the dashboard now."


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
    if not (settings.smtp_host or settings.slack_webhook_url or twilio_configured() or telegram_configured() or callmebot_configured() or meta_wa_configured()):
        _warn_once()
        return

    sends = (
        lambda: _send_telegram(_short_message(incident)),
        lambda: _send_callmebot(_short_message(incident)),
        lambda: _send_meta_whatsapp(_short_message(incident), {**incident, "tier": incident.get("tier", "Critical")}),
    )
    for send in sends:
        try:
            for err in send():
                logger.warning(f"Critical-incident alert failed: {err}")
        except Exception as exc:
            logger.warning(f"Critical-incident alert failed: {exc}")

    try:
        _send_twilio(_short_message(incident))
    except Exception as exc:
        logger.warning(f"Failed to send critical-incident SMS/WhatsApp: {exc}")

    from app.email_templates import alert_email

    action = next((ATTACK_ACTIONS[t] for t in incident.get("attack_types", []) if t in ATTACK_ACTIONS), "Review the evidence on the dashboard.")
    subject, body, html = alert_email({**incident, "tier": incident.get("tier", "Critical")}, action)
    try:
        _send_email(subject, body, html)
    except Exception as exc:
        logger.warning(f"Failed to send critical-incident email: {exc}")
    try:
        _send_slack(body)
    except Exception as exc:
        logger.warning(f"Failed to send critical-incident Slack notification: {exc}")
