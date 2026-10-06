import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.query_utils import parse_range
from app.auth.security import get_current_user
from app.db.base import get_session
from app.db.models import Alert, User

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _build_query(range_: str, severity: str | None, attack_type: str | None, src_ip: str | None, incident_id: str | None):
    since = datetime.now(timezone.utc) - parse_range(range_)
    query = select(Alert).where(Alert.created_at >= since)
    if severity:
        query = query.where(Alert.severity == severity)
    if attack_type:
        query = query.where(Alert.attack_type == attack_type)
    if src_ip:
        query = query.where(Alert.src_ip == src_ip)
    if incident_id:
        query = query.where(Alert.incident_id == incident_id)
    return query.order_by(Alert.created_at.desc())


def _alert_out(a: Alert) -> dict:
    return {
        "alert_id": str(a.id), "attack_type": a.attack_type, "src_ip": a.src_ip, "dst_ip": a.dst_ip,
        "severity": a.severity, "xgb_conf": a.xgb_conf, "dl_conf": a.dl_conf, "hybrid_conf": a.hybrid_conf,
        "packets": a.packets, "iface": a.iface, "incident_id": str(a.incident_id) if a.incident_id else None,
        "created_at": a.created_at.isoformat(),
    }


@router.get("")
async def list_alerts(
    range: str = "24h",
    severity: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    incident_id: str | None = None,
    limit: int = 200,
    offset: int = 0,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    query = _build_query(range, severity, attack_type, src_ip, incident_id).limit(min(limit, 1000)).offset(offset)
    result = await session.execute(query)
    return [_alert_out(a) for a in result.scalars().all()]


@router.get("/export")
async def export_alerts(
    range: str = "24h",
    severity: str | None = None,
    attack_type: str | None = None,
    src_ip: str | None = None,
    incident_id: str | None = None,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    query = _build_query(range, severity, attack_type, src_ip, incident_id).limit(10000)
    result = await session.execute(query)
    rows = result.scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["alert_id", "created_at", "attack_type", "src_ip", "dst_ip", "severity", "packets", "hybrid_conf", "iface", "incident_id"])
    for a in rows:
        writer.writerow([
            a.id, a.created_at.isoformat(), a.attack_type, a.src_ip, a.dst_ip,
            a.severity, a.packets, a.hybrid_conf, a.iface, a.incident_id or "",
        ])
    buf.seek(0)

    return StreamingResponse(
        buf, media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )
