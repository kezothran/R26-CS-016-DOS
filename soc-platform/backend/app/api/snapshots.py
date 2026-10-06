from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import get_current_user, require_role
from app.db.base import get_session
from app.db.models import Snapshot, User
from app.detection import loop as detection_loop

router = APIRouter(prefix="/api/snapshots", tags=["snapshots"])


class SnapshotBody(BaseModel):
    label: str | None = None


def _summary_out(s: Snapshot) -> dict:
    source_ips = sorted({f["src"] for f in (s.live_flows or []) if f.get("src")})
    return {
        "id": str(s.id), "label": s.label, "trigger": s.trigger,
        "incident_id": str(s.incident_id) if s.incident_id else None,
        "security_score": s.security_score, "security_tier": s.security_tier,
        "active_incident_count": s.active_incident_count, "total_packets": s.total_packets,
        "source_ips": source_ips,
        "created_at": s.created_at.isoformat(),
    }


@router.get("")
async def list_snapshots(
    limit: int = 100,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Snapshot).order_by(Snapshot.created_at.desc()).limit(min(limit, 500)))
    return [_summary_out(s) for s in result.scalars().all()]


@router.get("/{snapshot_id}")
async def get_snapshot(
    snapshot_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(Snapshot, snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return {**_summary_out(row), "attacks": row.attacks, "live_flows": row.live_flows}


@router.post("")
async def create_snapshot(
    body: SnapshotBody,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    state = detection_loop.get_last_state()
    if state is None:
        raise HTTPException(status_code=409, detail="No detection cycle has completed yet - try again shortly")

    row = Snapshot(
        label=body.label,
        trigger="manual",
        security_score=state["security"]["score"],
        security_tier=state["security"]["tier"],
        active_incident_count=len(state["security"]["active_incidents"]),
        total_packets=state["total_packets"],
        attacks=state["attacks"],
        live_flows=state["live_flows"],
        created_by=user.id,
        created_at=datetime.now(timezone.utc),
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _summary_out(row)


@router.delete("/{snapshot_id}")
async def delete_snapshot(
    snapshot_id: str,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    await session.execute(delete(Snapshot).where(Snapshot.id == snapshot_id))
    await session.commit()
    return {"ok": True}
