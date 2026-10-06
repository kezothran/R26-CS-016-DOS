from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session
from app.db.models import Incident
from app.detection.loop import _started_at
from app.detection.registry import ACTIVE_ATTACKS, REGISTRY

router = APIRouter()


@router.get("/health")
async def health(session: AsyncSession = Depends(get_session)):
    today_start = datetime.combine(datetime.now(timezone.utc).date(), time.min, tzinfo=timezone.utc)
    incidents_today = (await session.execute(
        select(func.count()).select_from(Incident).where(Incident.first_seen >= today_start)
    )).scalar_one()
    high_severity_today = (await session.execute(
        select(func.count()).select_from(Incident).where(
            Incident.first_seen >= today_start, func.upper(Incident.tier).in_(["HIGH", "CRITICAL"])
        )
    )).scalar_one()

    return {
        "ok": True,
        "active_attacks": ACTIVE_ATTACKS,
        "trained": {key: mod.bundle.trained for key, mod in REGISTRY.items()},
        "uptime_seconds": round((datetime.now(timezone.utc) - _started_at).total_seconds(), 1),
        "model_status": {
            key: {"trained": mod.bundle.trained, "has_dl_model": mod.bundle.dl_model is not None}
            for key, mod in REGISTRY.items()
        },
        "incidents_today": incidents_today,
        "high_severity_today": high_severity_today,
        "detectors_total": len(REGISTRY),
    }
