"""Metrics & KPIs, computed from real Alert/Incident timestamps rather than a log-aggregation
pipeline (there isn't one) - see the "On MTTD" note in the plan for why Mean-Time-To-Detect
isn't reported here: this is real-time detection bounded by the capture window, not something
with a ground-truth "attack actually started at T0" to diff against. MTTA/MTTR are real.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import geoip, settings_cache
from app.api.query_utils import parse_range
from app.auth.security import get_current_user
from app.db.base import get_session
from app.db.models import Alert, FalsePositiveFeedback, Incident, User

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

TIER_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


@router.get("/summary")
async def metrics_summary(
    range: str = "24h",
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.now(timezone.utc) - parse_range(range)

    incidents = (await session.execute(select(Incident).where(Incident.first_seen >= since))).scalars().all()
    alerts_count = (await session.execute(select(Alert).where(Alert.created_at >= since))).scalars().all()

    mtta_samples = [
        (i.assigned_at - i.first_seen).total_seconds() for i in incidents if i.assigned_at is not None
    ]
    mttr_samples = [
        (i.resolved_at - i.first_seen).total_seconds() for i in incidents if i.resolved_at is not None
    ]
    resolved_with_verdict = [i for i in incidents if i.resolution is not None]
    false_positives = [i for i in resolved_with_verdict if i.resolution == "false_positive"]
    feedback_count = len((await session.execute(
        select(FalsePositiveFeedback).where(FalsePositiveFeedback.created_at >= since)
    )).scalars().all())

    return {
        "range": range,
        "total_alerts": len(alerts_count),
        "total_incidents": len(incidents),
        "mtta_seconds": round(sum(mtta_samples) / len(mtta_samples), 1) if mtta_samples else None,
        "mttr_seconds": round(sum(mttr_samples) / len(mttr_samples), 1) if mttr_samples else None,
        "false_positive_rate": (
            round(len(false_positives) / len(resolved_with_verdict), 3) if resolved_with_verdict else None
        ),
        "false_positive_feedback_count": feedback_count,
        "detection_window_secs": settings_cache.current().get("window_secs"),
    }


@router.get("/volume")
async def alert_volume(
    range: str = "24h",
    bucket: str = "1h",
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.now(timezone.utc) - parse_range(range)
    bucket_secs = int(parse_range(bucket).total_seconds())
    if bucket_secs <= 0:
        bucket_secs = 3600

    rows = (await session.execute(
        select(Alert.created_at).where(Alert.created_at >= since).order_by(Alert.created_at)
    )).scalars().all()

    counts: dict[int, int] = defaultdict(int)
    for ts in rows:
        bucket_key = int(ts.timestamp() // bucket_secs) * bucket_secs
        counts[bucket_key] += 1

    return [
        {"t": datetime.fromtimestamp(k, tz=timezone.utc).isoformat(), "value": v}
        for k, v in sorted(counts.items())
    ]


@router.get("/top-sources")
async def top_sources(
    range: str = "24h",
    limit: int = 10,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.now(timezone.utc) - parse_range(range)
    rows = (await session.execute(
        select(Alert.src_ip, Alert.severity).where(Alert.created_at >= since)
    )).all()

    grouped: dict[str, dict] = {}
    for src_ip, severity in rows:
        entry = grouped.setdefault(src_ip, {"src_ip": src_ip, "count": 0, "max_tier": "Low"})
        entry["count"] += 1
        if TIER_RANK.get(_normalize_tier(severity), 0) > TIER_RANK.get(entry["max_tier"], 0):
            entry["max_tier"] = _normalize_tier(severity)

    top = sorted(grouped.values(), key=lambda e: -e["count"])[: min(limit, 50)]
    for entry in top:
        geo = geoip.lookup(entry["src_ip"])
        entry["country"] = geo["country"] if geo else None
        entry["country_code"] = geo["country_code"] if geo else None
    return top


@router.get("/origins")
async def attack_origins(
    range: str = "24h",
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Country-grouped attack-origin counts (the Geo-IP panel) - a ranked list rather than a
    literal map, since this project has no mapping library and one panel doesn't justify adding
    one. Returns [] entries with country=None if no GEOIP_DB_PATH is configured."""
    since = datetime.now(timezone.utc) - parse_range(range)
    rows = (await session.execute(select(Alert.src_ip).where(Alert.created_at >= since))).scalars().all()

    by_country: dict[str, dict] = {}
    for src_ip in rows:
        geo = geoip.lookup(src_ip)
        key = geo["country_code"] if geo else "??"
        entry = by_country.setdefault(key, {
            "country": geo["country"] if geo else "Unknown",
            "country_code": key,
            "count": 0,
        })
        entry["count"] += 1

    return sorted(by_country.values(), key=lambda e: -e["count"])


@router.get("/live-origins")
async def live_origins(
    minutes: int = 15,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Recent attacker IPs for the live map. Public IPs get a map pin (GeoIP); private/loopback
    addresses can't be geolocated, so instead of being silently folded into a bare count they're
    grouped and listed the same way (IP, attack types, packet count, last seen) under
    `local_points` - the dashboard shows them as a text list next to the map rather than a pin."""
    import ipaddress

    since = datetime.now(timezone.utc) - timedelta(minutes=min(max(minutes, 1), 1440))
    rows = (await session.execute(
        select(Alert.src_ip, Alert.severity, Alert.attack_type, Alert.created_at, Alert.iface).where(Alert.created_at >= since)
    )).all()

    public_grouped: dict[str, dict] = {}
    local_grouped: dict[str, dict] = {}
    for src_ip, severity, attack_type, created_at, iface in rows:
        try:
            is_global = ipaddress.ip_address(src_ip).is_global
        except ValueError:
            continue
        bucket = public_grouped if is_global else local_grouped
        e = bucket.setdefault(src_ip, {
            "src_ip": src_ip, "count": 0, "max_tier": "Low", "attack_types": set(), "last_seen": created_at,
            "host": (iface or "").rsplit("@", 1)[1] if iface and "@" in iface else None,
        })
        e["count"] += 1
        e["attack_types"].add(attack_type)
        if created_at > e["last_seen"]:
            e["last_seen"] = created_at
        if TIER_RANK.get(_normalize_tier(severity), 0) > TIER_RANK.get(e["max_tier"], 0):
            e["max_tier"] = _normalize_tier(severity)

    def _out(e: dict, geo: dict | None) -> dict:
        return {
            "src_ip": e["src_ip"], "count": e["count"], "max_tier": e["max_tier"], "host": e["host"],
            "attack_types": sorted(e["attack_types"]), "last_seen": e["last_seen"].isoformat(),
            "country": geo["country"] if geo else None, "country_code": geo["country_code"] if geo else None,
            "city": geo["city"] if geo else None, "lat": geo["lat"] if geo else None, "lon": geo["lon"] if geo else None,
        }

    points = [_out(e, geoip.lookup(e["src_ip"])) for e in sorted(public_grouped.values(), key=lambda x: -x["count"])[:100]]
    local_points = [_out(e, None) for e in sorted(local_grouped.values(), key=lambda x: -x["count"])[:100]]
    return {
        "geoip_ready": geoip.ready(), "local_count": sum(e["count"] for e in local_grouped.values()),
        "points": points, "local_points": local_points,
    }


def _normalize_tier(severity: str) -> str:
    return {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}.get(severity, severity)
