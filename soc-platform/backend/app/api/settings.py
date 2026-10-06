from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_cache
from app.auth.security import get_current_user, require_role
from app.capture.interfaces import list_interfaces
from app.db.base import get_session
from app.db.models import User

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(user: User = Depends(get_current_user)):
    return settings_cache.current()


@router.post("")
async def update_settings(
    updates: dict,
    user: User = Depends(require_role("admin", "analyst")),
    session: AsyncSession = Depends(get_session),
):
    allowed = set(settings_cache.DEFAULTS.keys())
    filtered = {k: v for k, v in updates.items() if k in allowed}
    await settings_cache.save_to_db(session, filtered)
    return {"ok": True}


@router.get("/interfaces")
async def get_interfaces(user: User = Depends(get_current_user)):
    return list_interfaces()
