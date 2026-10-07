import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.api.query_utils import parse_range
from app.auth.security import get_current_user, require_role
from app.db.base import get_session
from app.integrations import jira
from app.db.models import Alert, FalsePositiveFeedback, Incident, IncidentNote, SecurityScore, TicketLink, User
from app.scoring import aggregate

router = APIRouter(prefix="/api", tags=["scoring"])

WORKFLOW_STATUSES = ("new", "investigating", "escalated", "resolved")
RESOLUTIONS = ("true_positive", "false_positive")


def _incident_out(i: Incident) -> dict:
    return {
        "incident_id": str(i.id),
        "attack_types": i.attack_types,
        "combined_impact": round(i.combined_impact, 2),
        "confidence": i.correlation_confidence,
        "tier": i.tier,
        "src_ips": i.src_ips,
        "interface": i.iface,
        "first_seen": i.first_seen.isoformat(),
        "last_seen": i.last_seen.isoformat(),
        "status": i.status,
        "workflow_status": i.workflow_status,
        "assigned_to": str(i.assigned_to) if i.assigned_to else None,
        "assigned_at": i.assigned_at.isoformat() if i.assigned_at else None,
        "resolution": i.resolution,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
    }


@router.get("/score/live")
async def score_live(user: User = Depends(get_current_user)):
    return aggregate.snapshot()


@router.get("/score/history")
async def score_history(
    range: str = "30m",
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.now(timezone.utc) - parse_range(range)
    result = await session.execute(
        select(SecurityScore)
        .where(SecurityScore.target == "aggregate", SecurityScore.created_at >= since)
        .order_by(SecurityScore.created_at)
    )
    rows = result.scalars().all()
    return [{"timestamp": r.created_at.isoformat(), "score": r.score} for r in rows]


@router.get("/incidents/active")
async def incidents_active(user: User = Depends(get_current_user)):
    return aggregate.snapshot()["active_incidents"]


@router.post("/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(
    incident_id: str,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    row.status = "acknowledged"
    row.acknowledged_by = user.id
    row.acknowledged_at = datetime.now(timezone.utc)
    await session.commit()
    aggregate.acknowledge(incident_id)
    return {"ok": True}


@router.get("/incidents")
async def list_incidents(
    range: str = "24h",
    tier: str | None = None,
    workflow_status: str | None = None,
    assigned_to: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Queryable incident queue - unlike /incidents/active (the in-memory live snapshot), this
    hits the DB table directly so resolved/historical incidents are visible too."""
    since = datetime.now(timezone.utc) - parse_range(range)
    query = select(Incident).where(Incident.first_seen >= since)
    if tier:
        query = query.where(Incident.tier == tier)
    if workflow_status:
        query = query.where(Incident.workflow_status == workflow_status)
    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)
    if attack_type:
        query = query.where(Incident.attack_types.any(attack_type))
    if src_ip:
        query = query.where(Incident.src_ips.any(src_ip))
    query = query.order_by(Incident.last_seen.desc()).limit(min(limit, 500)).offset(offset)

    result = await session.execute(query)
    return [_incident_out(i) for i in result.scalars().all()]


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
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
        select(TicketLink).where(TicketLink.incident_id == incident_id).order_by(TicketLink.created_at.desc())
    )).scalars().all()

    return {
        **_incident_out(incident),
        "evidence": [
            {
                "alert_id": str(a.id), "attack_type": a.attack_type, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
                "severity": a.severity, "xgb_conf": a.xgb_conf, "dl_conf": a.dl_conf, "hybrid_conf": a.hybrid_conf,
                "packets": a.packets, "iface": a.iface, "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "notes": [
            {"note_id": str(n.id), "author_id": str(n.author_id), "body": n.body, "created_at": n.created_at.isoformat()}
            for n in notes
        ],
        "tickets": [_ticket_out(t) for t in tickets],
    }


class IncidentPatch(BaseModel):
    workflow_status: str | None = None
    assigned_to: str | None = None
    resolution: str | None = None


@router.patch("/incidents/{incident_id}")
async def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    if body.assigned_to is not None and incident.assigned_to is None:
        incident.assigned_at = now
    if body.assigned_to is not None:
        incident.assigned_to = body.assigned_to
    if body.workflow_status is not None:
        if body.workflow_status not in WORKFLOW_STATUSES:
            raise HTTPException(status_code=400, detail=f"workflow_status must be one of {WORKFLOW_STATUSES}")
        incident.workflow_status = body.workflow_status
        if body.workflow_status == "resolved":
            incident.resolved_at = now
    if body.resolution is not None:
        if body.resolution not in RESOLUTIONS:
            raise HTTPException(status_code=400, detail=f"resolution must be one of {RESOLUTIONS}")
        incident.resolution = body.resolution

        # Collection-only dataset for a future retraining pass - snapshots the linked Alert
        # rows' already-persisted fields (raw per-flow features aren't retained after scoring).
        if body.resolution == "false_positive":
            linked_alerts = (await session.execute(select(Alert).where(Alert.incident_id == incident_id))).scalars().all()
            for a in linked_alerts:
                session.add(FalsePositiveFeedback(
                    incident_id=incident.id, alert_id=a.id, attack_type=a.attack_type, src_ip=a.src_ip,
                    dst_ip=a.dst_ip, packets=a.packets, xgb_conf=a.xgb_conf, dl_conf=a.dl_conf,
                    hybrid_conf=a.hybrid_conf, iface=a.iface, marked_by=user.id,
                ))

    await audit.log(session, user.id, "incident.updated", "incident", incident_id, body.model_dump(exclude_none=True))
    await session.commit()
    await session.refresh(incident)
    return _incident_out(incident)


class NoteBody(BaseModel):
    body: str


@router.get("/incidents/{incident_id}/notes")
async def list_notes(
    incident_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    notes = (await session.execute(
        select(IncidentNote).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at)
    )).scalars().all()
    return [
        {"note_id": str(n.id), "author_id": str(n.author_id), "body": n.body, "created_at": n.created_at.isoformat()}
        for n in notes
    ]


@router.post("/incidents/{incident_id}/notes")
async def add_note(
    incident_id: str,
    body: NoteBody,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = IncidentNote(incident_id=incident_id, author_id=user.id, body=body.body)
    session.add(note)
    await session.commit()
    await session.refresh(note)
    return {"note_id": str(note.id), "author_id": str(note.author_id), "body": note.body, "created_at": note.created_at.isoformat()}


def _ticket_out(t: TicketLink) -> dict:
    return {
        "ticket_id": str(t.id), "provider": t.provider, "external_ref": t.external_ref, "url": t.url,
        "created_at": t.created_at.isoformat(), "simulated": t.simulated, "status": t.status,
        "status_category": t.status_category,
        "status_synced_at": t.status_synced_at.isoformat() if t.status_synced_at else None,
    }


def _ticket_content(incident: Incident, alerts: list[Alert]) -> tuple[str, list[str], list[str]]:
    attacks = ", ".join(a.upper() for a in incident.attack_types)
    ips = ", ".join(incident.src_ips)
    summary = f"[{incident.tier}] {attacks} flood from {ips}"
    lines = [
        f"Sentrix incident {incident.id}",
        f"Severity: {incident.tier} (combined impact {incident.combined_impact:.1f}, correlation: {incident.correlation_confidence})",
        f"Attack types: {attacks}",
        f"Source IPs: {ips}",
        f"Interface: {incident.iface}",
        f"First seen: {incident.first_seen.isoformat()}  Last seen: {incident.last_seen.isoformat()}",
        f"Alerts recorded: {len(alerts)}; peak hybrid confidence: {max((a.hybrid_conf for a in alerts), default=0):.2f}",
    ]
    labels = ["sentrix", f"severity-{incident.tier}", *[f"attack-{a}" for a in incident.attack_types]]
    return summary, lines, labels


PRIORITIES = ("Highest", "High", "Medium", "Low")


class TicketBody(BaseModel):
    provider: str = "jira"
    # Optional analyst edits from the create-ticket form; defaults come from _ticket_content.
    summary: str | None = Field(default=None, max_length=250)
    description: str | None = Field(default=None, max_length=8000)
    priority: str | None = None


@router.get("/incidents/{incident_id}/ticket/preview")
async def ticket_preview(
    incident_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Pre-filled create-ticket form content, so the analyst can edit it before it is sent."""
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = (await session.execute(select(Alert).where(Alert.incident_id == incident_id))).scalars().all()
    summary, lines, labels = _ticket_content(incident, list(alerts))
    existing = (await session.execute(select(TicketLink).where(TicketLink.incident_id == incident_id))).scalars().all()
    open_ticket = next((t for t in existing if not t.simulated and t.status_category != "done"), None)
    return {
        "summary": summary, "description": "\n".join(lines), "labels": labels,
        "priority": jira.PRIORITY.get(incident.tier or "", "Medium"), "priorities": list(PRIORITIES),
        "jira_configured": jira.configured(), "project_key": jira.settings.jira_project_key,
        "open_ticket": open_ticket.external_ref if open_ticket else None,
    }


@router.post("/incidents/{incident_id}/ticket")
async def create_ticket(
    incident_id: str,
    body: TicketBody,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    """Creates a real Jira issue for the incident when JIRA_* is configured; otherwise records a
    simulated placeholder. One unfinished ticket per incident - a new one is allowed only after
    the previous one reaches a Jira 'done' status."""
    if body.provider != "jira":
        raise HTTPException(status_code=400, detail="Only the 'jira' provider is supported")
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    existing = (await session.execute(select(TicketLink).where(TicketLink.incident_id == incident_id))).scalars().all()
    open_ticket = next((t for t in existing if not t.simulated and t.status_category != "done"), None)
    if open_ticket is not None:
        raise HTTPException(status_code=409, detail=f"Incident already has an open ticket ({open_ticket.external_ref})")

    now = datetime.now(timezone.utc)
    if jira.configured():
        alerts = (await session.execute(select(Alert).where(Alert.incident_id == incident_id))).scalars().all()
        summary, lines, labels = _ticket_content(incident, list(alerts))
        if body.priority is not None and body.priority not in PRIORITIES:
            raise HTTPException(status_code=400, detail=f"priority must be one of {PRIORITIES}")
        if body.summary and body.summary.strip():
            summary = body.summary.strip()
        if body.description and body.description.strip():
            lines = body.description.strip().splitlines()
        try:
            key, url = await asyncio.to_thread(jira.create_issue, summary, lines, labels, incident.tier, body.priority)
            status, category = await asyncio.to_thread(jira.get_status, key)
        except jira.JiraError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e
        ticket = TicketLink(
            incident_id=incident_id, provider="jira", external_ref=key, url=url, created_by=user.id,
            simulated=False, status=status, status_category=category, status_synced_at=now,
        )
    else:
        total = len((await session.execute(select(TicketLink))).scalars().all())
        ticket = TicketLink(
            incident_id=incident_id, provider="jira", external_ref=f"SOC-{1000 + total}", created_by=user.id,
            simulated=True, status="Simulated", status_category="new",
        )

    session.add(ticket)
    await audit.log(session, user.id, "ticket.created", "incident", incident_id,
                    {"ref": ticket.external_ref, "simulated": ticket.simulated})
    await session.commit()
    await session.refresh(ticket)
    return _ticket_out(ticket)


@router.post("/incidents/{incident_id}/tickets/sync")
async def sync_tickets(
    incident_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Pulls the live Jira status for this incident's real tickets."""
    tickets = (await session.execute(select(TicketLink).where(TicketLink.incident_id == incident_id))).scalars().all()
    if jira.configured():
        for t in tickets:
            if t.simulated or (t.status_category == "done" and t.status_synced_at is not None):
                continue
            try:
                t.status, t.status_category = await asyncio.to_thread(jira.get_status, t.external_ref)
                t.status_synced_at = datetime.now(timezone.utc)
            except jira.JiraError as e:
                raise HTTPException(status_code=502, detail=str(e)) from e
        await session.commit()
    return [_ticket_out(t) for t in tickets]
