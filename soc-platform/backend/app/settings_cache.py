"""In-memory detection-settings cache, same rationale as whitelist_cache.py: the detection loop
reads these every cycle and must not block on a DB round-trip. Backed by Supabase `settings`
table (attack_type="global" for this milestone - all active attack modules share one tunable
config, matching how both single-attack prototypes worked).
"""

from __future__ import annotations

import json
import threading

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as app_settings
from app.db.models import SettingEntry

GLOBAL = "global"

DEFAULTS = {
    "window_secs": app_settings.capture_window_secs,
    "threshold": 0.5,
    "min_pps": 10,
    "min_bps": 100,
    "xgb_weight": 0.6,
    "cnn_weight": 0.4,
    "capture_all": True,
    "selected_interfaces": [],
    # Severity Scoring Engine (app/scoring/) - generalizes the UDP WSM formula
    # (score = packet_count * weight) across all attack types. "udp" entries are kept
    # ready but dormant since UDP isn't in registry.ACTIVE_ATTACKS yet.
    "scoring_weights": {"icmp": 1.5, "syn": 3.0, "fragmentation": 2.0, "udp": 2.5},
    "scoring_normalization": {"icmp": 1200, "syn": 700, "fragmentation": 900, "udp": 1000},
    "scoring_impact_cap": {"icmp": 30, "syn": 40, "fragmentation": 35, "udp": 40},
    "scoring_tier_boundaries": {  # per-attack raw_score thresholds -> Low/Medium/High/Critical
        "icmp": {"low": 480, "medium": 1500, "high": 3000},
        "syn": {"low": 900, "medium": 2700, "high": 5400},
        "fragmentation": {"low": 640, "medium": 2000, "high": 4000},
        "udp": {"low": 800, "medium": 2500, "high": 5000},
    },
    "scoring_correlation_time_window_sec": 5,
    "scoring_beta_high": 0.65,
    "scoring_beta_medium": 0.35,
    # Flat combined_impact bonus per distinct attack type beyond the first in a correlated
    # incident (see incident_scorer.py) - escalates multi-vector attacks regardless of each
    # individual vector's raw volume.
    "scoring_multi_vector_bonus": 15,
    "scoring_decay_lambda": 0.01,
    "scoring_active_window_minutes": 10,
    "scoring_dashboard_tiers": {"normal": [90, 100], "elevated": [70, 89], "high": [40, 69], "critical": [0, 39]},
}

_lock = threading.Lock()
_current: dict = dict(DEFAULTS)


async def refresh_from_db(session: AsyncSession) -> None:
    result = await session.execute(select(SettingEntry).where(SettingEntry.attack_type == GLOBAL))
    rows = result.scalars().all()
    merged = dict(DEFAULTS)
    for row in rows:
        try:
            merged[row.key] = json.loads(row.value)
        except Exception:
            pass
    with _lock:
        _current.clear()
        _current.update(merged)


async def save_to_db(session: AsyncSession, updates: dict) -> None:
    for key, value in updates.items():
        result = await session.execute(
            select(SettingEntry).where(SettingEntry.attack_type == GLOBAL, SettingEntry.key == key)
        )
        row = result.scalar_one_or_none()
        encoded = json.dumps(value)
        if row is None:
            session.add(SettingEntry(attack_type=GLOBAL, key=key, value=encoded))
        else:
            row.value = encoded
    await session.commit()
    await refresh_from_db(session)


def current() -> dict:
    with _lock:
        return dict(_current)
