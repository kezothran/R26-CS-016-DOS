"""PDF incident reports and the management summary email (manual send + status)."""

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit, summary as summary_mod
from app.api.playbooks import _incident_steps
from app.auth.security import get_current_user, require_role
from app.config import settings
from app.db.base import get_session
from app.db.models import Alert, Incident, IncidentNote, TicketLink, User
from app.reports import build_incident_pdf

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/incidents/{incident_id}/report.pdf")
async def incident_report(
    incident_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = (await session.execute(
        select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.created_at.desc())
    )).scalars().all()
    notes = (await session.execute(
        select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at)
    )).scalars().all()
    tickets = (await session.execute(
        select(TicketLink).where(TicketLink.incident_id == incident_id).order_by(TicketLink.created_at)
    )).scalars().all()
    steps = await _incident_steps(session, incident)
    emails = {str(u.id): u.email for u in (await session.execute(select(User))).scalars().all()}

    pdf = await asyncio.to_thread(build_incident_pdf, incident, list(alerts), list(notes), list(tickets), list(steps), emails)
    await audit.log(session, user.id, "incident.report_downloaded", "incident", str(incident_id), {})
    await session.commit()
    name = f"incident-{str(incident_id)[:8]}-{(incident.tier or 'report').lower()}.pdf"
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/summary/status")
async def summary_status(user: User = Depends(require_role("admin"))):
    from app import notify

    return {
        "schedule": settings.summary_schedule, "hour_utc": settings.summary_hour,
        "smtp_ready": summary_mod.smtp_ready(), "recipients": summary_mod.recipients(),
        # Critical-incident alert channels (app/notify.py) - which ones are configured.
        "channels": {
            "email": bool(settings.smtp_host and settings.smtp_from and settings.alert_email_to),
            "slack": bool(settings.slack_webhook_url),
            "telegram": notify.telegram_configured(),
            "whatsapp": notify.callmebot_configured() or notify.meta_wa_configured() or (notify.twilio_configured() and bool(settings.twilio_whatsapp_from)),
            "sms": notify.twilio_configured() and bool(settings.twilio_from),
        },
        "phone_count": len([n for n in (settings.alert_phone_to or "").split(",") if n.strip()]),
    }


@router.post("/notifications/test")
async def send_test_notification(
    channel: str,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    """Sends a labelled test message on one channel (telegram | whatsapp | email | slack)."""
    from app import notify

    errors = await asyncio.to_thread(notify.send_test_sync, channel)
    await audit.log(session, user.id, "notification.test", "channel", channel, {"ok": not errors})
    await session.commit()
    if errors:
        raise HTTPException(status_code=502, detail="; ".join(errors))
    return {"sent": True, "channel": channel}


@router.post("/summary/send")
async def send_summary_now(
    days: int = 1,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    if days not in (1, 7, 30):
        raise HTTPException(status_code=400, detail="days must be 1, 7 or 30")
    if not summary_mod.smtp_ready():
        raise HTTPException(status_code=400, detail="SMTP_HOST, SMTP_FROM and a recipient (SUMMARY_EMAIL_TO or ALERT_EMAIL_TO) must be set in backend/.env")
    try:
        total = await summary_mod.send_summary(days)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not send email: {exc}") from exc
    await audit.log(session, user.id, "summary.sent", "summary", f"{days}d", {"incidents": total})
    await session.commit()
    return {"sent_to": summary_mod.recipients(), "incidents": total}
