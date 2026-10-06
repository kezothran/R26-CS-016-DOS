"""Editable response playbooks + per-incident step checklists.

Admins manage playbooks (/api/playbooks); analysts tick steps on an incident
(/api/incidents/{id}/playbook). The first time an incident's playbook is opened, the matching
playbook steps are snapshotted onto the incident, so later edits don't rewrite history.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.auth.security import get_current_user, require_role
from app.db.base import SessionLocal, get_session
from app.db.models import BlockAction, Incident, IncidentPlaybookStep, Playbook, User

router = APIRouter(prefix="/api", tags=["playbooks"])

ATTACK_TYPES = ("icmp", "syn", "fragmentation", "udp")
TIERS = ("Low", "Medium", "High", "Critical")
ACTIONS = (None, "propose_block", "open_ticket")

# Seed content (used once, when the playbooks table is empty) - mirrors the old static list.
_SEED = {
    "icmp": [
        ("Confirm the flagged source IP(s) against the whitelist - legitimate monitoring tools (ping sweeps, uptime checks) can trigger ICMP volume alerts.", None),
        ("Check ICMP rate-limiting/throttling on the affected interface's edge device.", None),
        ("If confirmed malicious, propose a block for the source IP(s).", "propose_block"),
        ("Escalate to the network team if the source is internal (possible compromised host).", "open_ticket"),
    ],
    "syn": [
        ("Check SYN backlog/half-open connection count on the destination host - SYN floods exhaust the connection table.", None),
        ("Enable SYN cookies on the affected host/load balancer if not already active.", None),
        ("Correlate source IP(s) against known botnet/scanner threat intel if available.", None),
        ("Propose a block for sustained high-confidence sources.", "propose_block"),
    ],
    "fragmentation": [
        ("Verify this isn't legitimate large-payload traffic (some protocols fragment normally) before escalating.", None),
        ("Check for teardrop-style overlapping fragment patterns in the evidence panel, a stronger malicious signal than fragmentation alone.", None),
        ("Consider a fragment-reassembly timeout/limit on the edge firewall if not already configured.", None),
    ],
    "udp": [
        ("Check for UDP reflection/amplification signatures (small request, large unsolicited response) in the evidence panel.", None),
        ("Rate-limit or ACL the affected UDP service port(s) if externally reachable.", None),
        ("Propose a block for confirmed flood sources.", "propose_block"),
    ],
    None: [
        ("Review the evidence panel for the flagged flow features and confidence scores.", None),
        ("Cross-check the source IP(s) against the whitelist and any available threat intel.", None),
        ("Assign to an analyst and move to Investigating once triage begins.", None),
    ],
}


async def seed_default_playbooks() -> None:
    """Startup hook: inserts the default playbooks only if the table is completely empty."""
    async with SessionLocal() as session:
        if (await session.execute(select(func.count()).select_from(Playbook))).scalar_one() > 0:
            return
        for attack_type, steps in _SEED.items():
            name = f"{attack_type.upper()} flood response" if attack_type else "Default response"
            session.add(Playbook(
                name=name, attack_type=attack_type, tier=None,
                steps=[{"title": t, "action": a} for t, a in steps],
            ))
        await session.commit()


# ---------- admin CRUD ----------

class StepIn(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    action: str | None = None


class PlaybookIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    attack_type: str | None = None
    tier: str | None = None
    steps: list[StepIn] = Field(min_length=1, max_length=30)
    enabled: bool = True


def _validate(body: PlaybookIn) -> None:
    if body.attack_type is not None and body.attack_type not in ATTACK_TYPES:
        raise HTTPException(status_code=400, detail=f"attack_type must be null or one of {ATTACK_TYPES}")
    if body.tier is not None and body.tier not in TIERS:
        raise HTTPException(status_code=400, detail=f"tier must be null or one of {TIERS}")
    for s in body.steps:
        if s.action not in ACTIONS:
            raise HTTPException(status_code=400, detail="step action must be null, 'propose_block' or 'open_ticket'")


def _pb_out(p: Playbook) -> dict:
    return {
        "id": str(p.id), "name": p.name, "attack_type": p.attack_type, "tier": p.tier,
        "steps": p.steps, "enabled": p.enabled,
        "created_at": p.created_at.isoformat(), "updated_at": p.updated_at.isoformat(),
    }


@router.get("/playbooks")
async def list_playbooks(user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Playbook).order_by(Playbook.attack_type.nulls_last(), Playbook.tier.nulls_first(), Playbook.name)
    )).scalars().all()
    return [_pb_out(p) for p in rows]


@router.post("/playbooks")
async def create_playbook(
    body: PlaybookIn, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    _validate(body)
    pb = Playbook(
        name=body.name.strip(), attack_type=body.attack_type, tier=body.tier, enabled=body.enabled,
        steps=[s.model_dump() for s in body.steps], created_by=user.id,
    )
    session.add(pb)
    await session.flush()
    await audit.log(session, user.id, "playbook.created", "playbook", str(pb.id), {"name": pb.name})
    await session.commit()
    await session.refresh(pb)
    return _pb_out(pb)


@router.put("/playbooks/{playbook_id}")
async def update_playbook(
    playbook_id: uuid.UUID, body: PlaybookIn,
    user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    _validate(body)
    pb = await session.get(Playbook, playbook_id)
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    pb.name, pb.attack_type, pb.tier, pb.enabled = body.name.strip(), body.attack_type, body.tier, body.enabled
    pb.steps = [s.model_dump() for s in body.steps]
    pb.updated_at = datetime.now(timezone.utc)
    await audit.log(session, user.id, "playbook.updated", "playbook", str(pb.id), {"name": pb.name})
    await session.commit()
    await session.refresh(pb)
    return _pb_out(pb)


@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(
    playbook_id: uuid.UUID, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    pb = await session.get(Playbook, playbook_id)
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await audit.log(session, user.id, "playbook.deleted", "playbook", str(pb.id), {"name": pb.name})
    await session.delete(pb)
    await session.commit()
    return {"ok": True}


# ---------- per-incident checklist ----------

def _pick_playbooks(all_playbooks: list[Playbook], attack_types: list[str], tier: str | None) -> list[Playbook]:
    """For each attack type in the incident, the most specific enabled playbook wins
    (attack_type+tier > attack_type > tier > default). Distinct playbooks are all returned, so a
    multi-attack incident gets every relevant playbook, not just the first one."""
    enabled = [p for p in all_playbooks if p.enabled]
    picked: list[Playbook] = []

    def best(attack_type: str | None) -> Playbook | None:
        def score(p: Playbook) -> int | None:
            if p.attack_type not in (None, attack_type):
                return None
            if p.tier not in (None, tier):
                return None
            return (2 if p.attack_type is not None else 0) + (1 if p.tier is not None else 0)
        scored = [(s, p) for p in enabled if (s := score(p)) is not None]
        return max(scored, key=lambda sp: sp[0])[1] if scored else None

    for at in (attack_types or [None]):
        pb = best(at)
        if pb is not None and pb not in picked:
            picked.append(pb)
    return picked


def _step_out(s: IncidentPlaybookStep) -> dict:
    return {
        "id": str(s.id), "playbook_name": s.playbook_name, "step_index": s.step_index, "title": s.title,
        "action": s.action, "done": s.done,
        "done_by": str(s.done_by) if s.done_by else None,
        "done_at": s.done_at.isoformat() if s.done_at else None,
    }


async def _load_steps(session: AsyncSession, incident_id: uuid.UUID) -> list[IncidentPlaybookStep]:
    result = await session.execute(
        select(IncidentPlaybookStep)
        .where(IncidentPlaybookStep.incident_id == incident_id)
        .order_by(IncidentPlaybookStep.step_index)
    )
    return list(result.scalars().all())


async def _incident_steps(session: AsyncSession, incident: Incident) -> list[IncidentPlaybookStep]:
    steps = await _load_steps(session, incident.id)
    if steps:
        return steps
    all_pbs = (await session.execute(select(Playbook))).scalars().all()
    idx = 0
    for pb in _pick_playbooks(list(all_pbs), list(incident.attack_types), incident.tier):
        for s in pb.steps:
            session.add(IncidentPlaybookStep(
                incident_id=incident.id, playbook_id=pb.id, playbook_name=pb.name,
                step_index=idx, title=s["title"], action=s.get("action"),
            ))
            idx += 1
    await session.commit()
    return await _load_steps(session, incident.id)


@router.get("/incidents/{incident_id}/playbook")
async def get_incident_playbook(
    incident_id: uuid.UUID, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session),
):
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    steps = await _incident_steps(session, incident)
    return {"steps": [_step_out(s) for s in steps], "done": sum(1 for s in steps if s.done), "total": len(steps)}


class StepDone(BaseModel):
    done: bool


@router.post("/incidents/{incident_id}/playbook/steps/{step_id}")
async def set_step_done(
    incident_id: uuid.UUID, step_id: uuid.UUID, body: StepDone,
    user: User = Depends(require_role("admin", "analyst")), session: AsyncSession = Depends(get_session),
):
    step = await session.get(IncidentPlaybookStep, step_id)
    if step is None or step.incident_id != incident_id:
        raise HTTPException(status_code=404, detail="Step not found")
    step.done = body.done
    step.done_by = user.id if body.done else None
    step.done_at = datetime.now(timezone.utc) if body.done else None
    await audit.log(
        session, user.id, "playbook.step_done" if body.done else "playbook.step_undone",
        "incident", str(incident_id), {"step": step.title, "playbook": step.playbook_name},
    )
    await session.commit()
    await session.refresh(step)
    return _step_out(step)


@router.post("/incidents/{incident_id}/propose-block")
async def propose_block(
    incident_id: uuid.UUID, user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    """Playbook action: proposes a dry-run block for each of the incident's source IPs that
    doesn't already have a proposed/executed one. Never touches a real firewall."""
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    src_ips = list(incident.src_ips)
    existing: set[str] = set()
    if src_ips:
        existing = set((await session.execute(
            select(BlockAction.src_ip).where(
                BlockAction.src_ip.in_(src_ips), BlockAction.status.in_(["proposed", "executed_simulated"]),
            )
        )).scalars().all())
    created = [ip for ip in src_ips if ip not in existing]
    for ip in created:
        session.add(BlockAction(
            src_ip=ip, incident_id=incident.id, status="proposed", reason="Proposed by analyst via incident playbook",
        ))
    await audit.log(session, user.id, "block_action.proposed", "incident", str(incident_id), {"src_ips": created})
    await session.commit()
    return {"proposed": created, "already_proposed": [ip for ip in src_ips if ip in existing]}
