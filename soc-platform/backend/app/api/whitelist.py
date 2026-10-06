from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import whitelist_cache
from app.auth.security import get_current_user, require_role
from app.db.base import get_session
from app.db.models import User, WhitelistEntry

router = APIRouter(prefix="/api/whitelist", tags=["whitelist"])

VALID_KINDS = {"ip", "network", "port"}


class WhitelistBody(BaseModel):
    value: str


@router.get("")
async def get_whitelist(user: User = Depends(get_current_user)):
    return whitelist_cache.snapshot()


@router.post("/{kind}/{action}")
async def mutate_whitelist(
    kind: str,
    action: str,
    body: WhitelistBody,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    if kind not in VALID_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {VALID_KINDS}")
    if action not in {"add", "remove"}:
        raise HTTPException(status_code=400, detail="action must be 'add' or 'remove'")

    if action == "add":
        exists = await session.execute(
            select(WhitelistEntry).where(WhitelistEntry.kind == kind, WhitelistEntry.value == body.value)
        )
        if exists.scalar_one_or_none() is None:
            session.add(WhitelistEntry(kind=kind, value=body.value, created_by=user.id))
            await session.commit()
    else:
        await session.execute(
            delete(WhitelistEntry).where(WhitelistEntry.kind == kind, WhitelistEntry.value == body.value)
        )
        await session.commit()

    await whitelist_cache.refresh_from_db(session)
    return {"ok": True}
