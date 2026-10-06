"""Who-did-what trail. `log()` only stages the row (session.add) - it deliberately doesn't
commit, so the caller's own session.commit() makes the audit entry atomic with the actual
change it records (same transaction, both or neither).
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


async def log(
    session: AsyncSession, actor_id: uuid.UUID, action: str, target_type: str, target_id: str, details: dict | None = None,
) -> None:
    session.add(AuditLog(
        actor_id=actor_id, action=action, target_type=target_type, target_id=target_id, details=details or {},
    ))
