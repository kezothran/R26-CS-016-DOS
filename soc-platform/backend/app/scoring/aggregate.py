"""Stage 4 - aggregate security score engine. In-memory active-incident store (same pattern as
whitelist_cache.py/settings_cache.py: module-level state + threading.Lock, refreshed/read every
detection cycle rather than round-tripping the DB on the hot path) producing a time-decayed
0-100 live score.
"""

from __future__ import annotations

import math
import threading
import uuid
from datetime import datetime

_lock = threading.Lock()
_active: dict[str, dict] = {}
_snapshot: dict = {"score": 100.0, "tier": "Normal", "active_incidents": []}


def _serialize(incident: dict) -> dict:
    return {
        "incident_id": incident["id"],
        "attack_types": sorted(incident["attack_types"]),
        "combined_impact": round(incident["combined_impact"], 2),
        "confidence": incident["confidence"],
        "tier": incident["tier"],
        "src_ips": sorted(incident["src_ips"]),
        "interface": incident["interface"],
        "first_seen": incident["first_seen"].isoformat(),
        "last_seen": incident["last_seen"].isoformat(),
    }


def upsert_incident(
    group: list[dict], combined_impact: float, confidence: str, tier: str, now: datetime,
) -> tuple[dict, bool]:
    """Merges into an existing active incident sharing a src_ip, or creates a new one."""
    group_src_ips = {e["src_ip"] for e in group}
    group_attack_types = {e["attack_type"] for e in group}
    interface = group[0]["interface"]

    with _lock:
        for incident in _active.values():
            if incident["src_ips"] & group_src_ips:
                incident["attack_types"] |= group_attack_types
                incident["src_ips"] |= group_src_ips
                incident["combined_impact"] = max(incident["combined_impact"], combined_impact)
                incident["confidence"] = confidence
                incident["tier"] = tier
                incident["last_seen"] = now
                return dict(incident), False

        incident = {
            "id": str(uuid.uuid4()),
            "attack_types": group_attack_types,
            "src_ips": group_src_ips,
            "interface": interface,
            "combined_impact": combined_impact,
            "confidence": confidence,
            "tier": tier,
            "first_seen": now,
            "last_seen": now,
            "status": "active",
            # Whether app/notify.py's Critical-tier email/Slack alert has already fired for this
            # incident - tracked here (not via a DB fetch-and-check every cycle) so app/scoring/
            # engine.py can decide without a round-trip. See mark_notified below.
            "notified": False,
        }
        _active[incident["id"]] = incident
        return dict(incident), True


def mark_notified(incident_id: str) -> None:
    with _lock:
        if incident_id in _active:
            _active[incident_id]["notified"] = True


_INCIDENT_TIER_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_DASHBOARD_ORDER = ["Normal", "Elevated", "High", "Critical"]
# The lowest dashboard tier an active incident of a given rank allows: a Medium incident means the
# system is no longer "Normal", High means "High", Critical means "Critical".
_DASHBOARD_FLOOR = {1: "Elevated", 2: "High", 3: "Critical"}


def _dashboard_tier(score: float, cfg: dict) -> str:
    for tier_name, (low, high) in cfg["scoring_dashboard_tiers"].items():
        if low <= score <= high:
            return tier_name.capitalize()
    return "Critical"


def prune_and_score(cfg: dict, now: datetime) -> tuple[float, str, list[dict], list[str]]:
    """Drops idle incidents, computes the decayed aggregate score, and applies the
    single-critical-incident override so decay can't mask an ongoing severe attack."""
    active_window = cfg["scoring_active_window_minutes"] * 60
    lam = cfg["scoring_decay_lambda"]

    with _lock:
        resolved_ids = []
        for incident_id in list(_active.keys()):
            incident = _active[incident_id]
            if (now - incident["last_seen"]).total_seconds() > active_window:
                resolved_ids.append(incident_id)
                del _active[incident_id]

        total_impact = 0.0
        any_critical = False
        highest_rank = 0
        for incident in _active.values():
            # Decay by time since this incident was LAST seen, not since it started - a
            # sustained, still-ongoing attack keeps last_seen refreshed every cycle (see
            # upsert_incident above), so it stays near full weight for as long as it's actually
            # happening. Decaying by first_seen instead made a long-running attack's
            # contribution vanish after a few minutes purely because of its age, silently
            # dropping the score back to "Normal" while it was still active.
            age = (now - incident["last_seen"]).total_seconds()
            total_impact += incident["combined_impact"] * math.exp(-lam * age)
            if incident["tier"] == "Critical":
                any_critical = True
            highest_rank = max(highest_rank, _INCIDENT_TIER_RANK.get(incident["tier"], 0))

        score = round(max(0.0, min(100.0, 100.0 - total_impact)), 1)
        tier = "Critical" if any_critical else _dashboard_tier(score, cfg)
        if cfg.get("scoring_active_incident_floor", True) and highest_rank:
            floor_tier = _DASHBOARD_FLOOR[highest_rank]
            if _DASHBOARD_ORDER.index(floor_tier) > _DASHBOARD_ORDER.index(tier):
                tier = floor_tier
            if tier != "Normal":
                # keep the number and the label in agreement: clamp to the top of the tier's range
                upper = cfg["scoring_dashboard_tiers"].get(tier.lower(), [0, 100])[1]
                score = min(score, float(upper))
        active_list = [_serialize(i) for i in _active.values()]

        global _snapshot
        _snapshot = {"score": score, "tier": tier, "active_incidents": active_list}

        return score, tier, active_list, resolved_ids


def acknowledge(incident_id: str) -> bool:
    """Drops an incident from the active set immediately (called from the acknowledge API) so
    it stops contributing to the aggregate score/active list without waiting for it to idle
    out via prune_and_score."""
    with _lock:
        return _active.pop(incident_id, None) is not None


def snapshot() -> dict:
    with _lock:
        return dict(_snapshot)
