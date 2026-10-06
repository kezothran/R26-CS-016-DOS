"""Basic user & access management. Listing is open to any authenticated role (needed for the
Incidents queue's "assign to analyst" dropdown and "assigned to" display everywhere);
creating/editing users is admin-only. Also covers the "role-based views" part of the original
ask (role already existed, this adds the ability to manage it instead of only seeding one admin
via scripts/seed_admin.py).
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.auth.security import get_current_user, hash_password, require_role
from app.db.base import get_session
from app.db.models import (
    ROLES, AuditLog, BlockAction, FalsePositiveFeedback, Incident, IncidentNote, Snapshot,
    TicketLink, User, WhitelistEntry,
)

router = APIRouter(prefix="/api/users", tags=["users"])


def _out(u: User) -> dict:
    return {
        "id": str(u.id), "email": u.email, "role": u.role, "analyst_tier": u.analyst_tier,
        "must_change_password": u.must_change_password, "created_at": u.created_at.isoformat(),
    }


@router.get("")
async def list_users(
    # Any authenticated role can list users (no password data in the response) - the Incidents
    # queue's assignee dropdown and "assigned to" display need this for every role, not just
    # admins; only creating/editing users below is admin-only.
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    rows = (await session.execute(select(User).order_by(User.email))).scalars().all()
    return [_out(u) for u in rows]


class CreateUserBody(BaseModel):
    email: EmailStr
    password: str
    role: str = "viewer"
    analyst_tier: int | None = None


@router.post("")
async def create_user(
    body: CreateUserBody,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {ROLES}")
    if body.analyst_tier is not None and body.analyst_tier not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="analyst_tier must be 1, 2, or 3")

    existing = (await session.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="A user with that email already exists")

    new_user = User(
        email=body.email, password_hash=hash_password(body.password), role=body.role,
        analyst_tier=body.analyst_tier, must_change_password=True,
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return _out(new_user)


class PatchUserBody(BaseModel):
    role: str | None = None
    analyst_tier: int | None = None


@router.patch("/{user_id}")
async def patch_user(
    user_id: str,
    body: PatchUserBody,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    before = {"role": target.role, "analyst_tier": target.analyst_tier}
    if body.role is not None:
        if body.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {ROLES}")
        target.role = body.role
    if body.analyst_tier is not None:
        if body.analyst_tier not in (1, 2, 3):
            raise HTTPException(status_code=400, detail="analyst_tier must be 1, 2, or 3")
        target.analyst_tier = body.analyst_tier

    await audit.log(
        session, user.id, "user.updated", "user", user_id,
        {"before": before, "after": {"role": target.role, "analyst_tier": target.analyst_tier}},
    )
    await session.commit()
    await session.refresh(target)
    return _out(target)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    user: User = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_session),
):
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    if str(target.id) == str(user.id):
        raise HTTPException(status_code=400, detail="You cannot delete your own account")

    if target.role == "admin":
        admin_count = (await session.execute(select(func.count()).where(User.role == "admin"))).scalar_one()
        if admin_count <= 1:
            raise HTTPException(status_code=409, detail="Cannot delete the last remaining admin")

    # These have NOT NULL foreign keys to users - deleting the row would either violate that
    # constraint or (if ever changed to CASCADE) silently erase audit/case-management history.
    # Block instead, with a clear reason, rather than losing that trail.
    dependent_counts = {
        "audit log entries": (await session.execute(
            select(func.count()).where(AuditLog.actor_id == target.id)
        )).scalar_one(),
        "incident notes": (await session.execute(
            select(func.count()).where(IncidentNote.author_id == target.id)
        )).scalar_one(),
        "ticket links": (await session.execute(
            select(func.count()).where(TicketLink.created_by == target.id)
        )).scalar_one(),
        "false-positive feedback entries": (await session.execute(
            select(func.count()).where(FalsePositiveFeedback.marked_by == target.id)
        )).scalar_one(),
    }
    blocking = {label: n for label, n in dependent_counts.items() if n > 0}
    if blocking:
        detail = ", ".join(f"{n} {label}" for label, n in blocking.items())
        raise HTTPException(status_code=409, detail=f"Cannot delete: user has {detail} on record")

    # Nullable references - clear rather than block, this history stays intact either way.
    await session.execute(update(WhitelistEntry).where(WhitelistEntry.created_by == target.id).values(created_by=None))
    await session.execute(update(Incident).where(Incident.acknowledged_by == target.id).values(acknowledged_by=None))
    await session.execute(update(Incident).where(Incident.assigned_to == target.id).values(assigned_to=None))
    await session.execute(update(BlockAction).where(BlockAction.decided_by == target.id).values(decided_by=None))
    await session.execute(update(Snapshot).where(Snapshot.created_by == target.id).values(created_by=None))

    await audit.log(session, user.id, "user.deleted", "user", user_id, {"email": target.email, "role": target.role})
    await session.delete(target)
    await session.commit()
    return {"ok": True}
