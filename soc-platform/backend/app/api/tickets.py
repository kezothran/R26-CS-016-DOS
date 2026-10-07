"""Cross-incident ticket list + live Jira card details. Creating a ticket stays on the incident
(app/api/scoring.py); this module is the read side for the Tickets page and ticket detail card."""

import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import get_current_user
from app.db.base import get_session
from app.db.models import Incident, TicketLink, User
from app.integrations import jira

router = APIRouter(prefix="/api/tickets", tags=["tickets"])

MAX_REFRESH = 25  # live Jira lookups per list call, so a long ticket list can't stall the request


@router.get("")
async def list_tickets(
    state: str = "all",
    refresh: bool = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """`state`: all | open | done. `refresh=true` re-reads live status for unfinished Jira tickets."""
    rows = (await session.execute(
        select(TicketLink, Incident).join(Incident, Incident.id == TicketLink.incident_id).order_by(TicketLink.created_at.desc()).limit(500)
    )).all()

    if refresh and jira.configured():
        stale = [t for t, _ in rows if not t.simulated and t.status_category != "done"][:MAX_REFRESH]
        for t in stale:
            try:
                t.status, t.status_category = await asyncio.to_thread(jira.get_status, t.external_ref)
                t.status_synced_at = datetime.now(timezone.utc)
            except jira.JiraError:
                continue  # one unreachable ticket shouldn't fail the list
        await session.commit()

    emails = {str(u.id): u.email for u in (await session.execute(select(User))).scalars().all()}
    out = []
    for t, inc in rows:
        done = t.status_category == "done"
        if (state == "open" and done) or (state == "done" and not done):
            continue
        out.append({
            "ticket_id": str(t.id), "external_ref": t.external_ref, "url": t.url, "simulated": t.simulated,
            "status": t.status, "status_category": t.status_category,
            "created_at": t.created_at.isoformat(), "created_by": emails.get(str(t.created_by), "unknown"),
            "status_synced_at": t.status_synced_at.isoformat() if t.status_synced_at else None,
            "incident_id": str(inc.id), "tier": inc.tier, "attack_types": inc.attack_types, "src_ips": inc.src_ips,
        })
    return {"jira_configured": jira.configured(), "tickets": out}


@router.get("/{ticket_id}/details")
async def ticket_details(
    ticket_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Live Jira card: status, assignee, priority, comments and status history. Also refreshes
    the stored status as a side effect."""
    t = await session.get(TicketLink, ticket_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if t.simulated or not jira.configured():
        raise HTTPException(status_code=400, detail="Live details are only available for real Jira tickets")
    try:
        details = await asyncio.to_thread(jira.get_details, t.external_ref)
    except jira.JiraError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    t.status, t.status_category = details["status"], details["status_category"]
    t.status_synced_at = datetime.now(timezone.utc)
    await session.commit()
    return details
