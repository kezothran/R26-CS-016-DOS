from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.query_utils import parse_range
from app.auth.security import require_role
from app.db.base import get_session
from app.db.models import AuditLog, User

router = APIRouter(prefix="/api/audit-log", tags=["audit"])


@router.get("")
async def list_audit_log(
    range: str = "7d",
    action: str | None = None,
    limit: int = 100,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.now(timezone.utc) - parse_range(range)
    query = select(AuditLog).where(AuditLog.created_at >= since)
    if action:
        query = query.where(AuditLog.action == action)
    query = query.order_by(AuditLog.created_at.desc()).limit(min(limit, 500))

    result = await session.execute(query)
    return [
        {
            "id": str(row.id), "actor_id": str(row.actor_id), "action": row.action,
            "target_type": row.target_type, "target_id": row.target_id, "details": row.details,
            "created_at": row.created_at.isoformat(),
        }
        for row in result.scalars().all()
    ]
