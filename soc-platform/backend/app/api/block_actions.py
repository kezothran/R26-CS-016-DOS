"""Dry-run SIEM/SOAR block-action review. Rows are auto-proposed by
app/scoring/engine.py::_propose_block_actions when an incident reaches Critical tier.
Deliberately dry-run only per the user's explicit choice: "execute" never fires a real
firewall/network change, it only flips status and records who confirmed it, for audit purposes.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.auth.security import get_current_user, require_role
from app.db.base import get_session
from app.db.models import BlockAction, User

router = APIRouter(prefix="/api/block-actions", tags=["block-actions"])


def _out(b: BlockAction) -> dict:
    return {
        "id": str(b.id), "src_ip": b.src_ip, "incident_id": str(b.incident_id) if b.incident_id else None,
        "reason": b.reason, "status": b.status, "proposed_at": b.proposed_at.isoformat(),
        "decided_by": str(b.decided_by) if b.decided_by else None,
        "decided_at": b.decided_at.isoformat() if b.decided_at else None,
    }


@router.get("")
async def list_block_actions(
    status: str | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    query = select(BlockAction)
    if status:
        query = query.where(BlockAction.status == status)
    query = query.order_by(BlockAction.proposed_at.desc()).limit(200)
    result = await session.execute(query)
    return [_out(b) for b in result.scalars().all()]


@router.post("/{action_id}/execute")
async def execute_block_action(
    action_id: str,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(BlockAction, action_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Block action not found")
    if row.status != "proposed":
        raise HTTPException(status_code=400, detail=f"Block action is already '{row.status}'")
    row.status = "executed_simulated"
    row.decided_by = user.id
    row.decided_at = datetime.now(timezone.utc)
    await audit.log(session, user.id, "block_action.executed", "block_action", action_id, {"src_ip": row.src_ip})
    await session.commit()
    await session.refresh(row)
    return _out(row)


@router.post("/{action_id}/dismiss")
async def dismiss_block_action(
    action_id: str,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    row = await session.get(BlockAction, action_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Block action not found")
    if row.status != "proposed":
        raise HTTPException(status_code=400, detail=f"Block action is already '{row.status}'")
    row.status = "dismissed"
    row.decided_by = user.id
    row.decided_at = datetime.now(timezone.utc)
    await audit.log(session, user.id, "block_action.dismissed", "block_action", action_id, {"src_ip": row.src_ip})
    await session.commit()
    await session.refresh(row)
    return _out(row)
