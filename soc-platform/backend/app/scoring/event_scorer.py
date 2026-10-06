"""Stage 1 - per-event severity calculator. Generalizes the UDP Flood WSM formula
(score = packet_count * weight) across all attack types, independently of the existing
packets-per-second tiering in app/detection/base.py::assign_tier_by_pps (that tier still
drives the existing Alert/tier_counts/attacker_ips contracts untouched; this is a separate,
downstream severity scale used only by the scoring engine's correlation/incident stages).
"""

from __future__ import annotations

TIER_ORDER = ["Low", "Medium", "High", "Critical"]


def classify_tier(attack_type: str, raw_score: float, cfg: dict) -> str:
    b = cfg["scoring_tier_boundaries"][attack_type]
    if raw_score <= b["low"]:
        return "Low"
    if raw_score <= b["medium"]:
        return "Medium"
    if raw_score <= b["high"]:
        return "High"
    return "Critical"


def score_event(attack_type: str, packet_count: float, cfg: dict) -> tuple[float, float, str]:
    """Returns (raw_score, normalized_impact, tier) for one detected flow."""
    weight = cfg["scoring_weights"][attack_type]
    normalization = cfg["scoring_normalization"][attack_type]
    impact_cap = cfg["scoring_impact_cap"][attack_type]

    raw_score = packet_count * weight
    normalized_impact = min(raw_score / normalization, impact_cap)
    tier = classify_tier(attack_type, raw_score, cfg)
    return raw_score, normalized_impact, tier
