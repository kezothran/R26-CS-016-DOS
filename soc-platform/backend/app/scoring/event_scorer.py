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


# Combined-impact points an event is lifted to when the detector's confidence (not its volume) sets
# its tier - kept equal to the boundaries in incident_scorer.classify_combined_tier so tier and
# impact stay consistent for the security score.
CONFIDENCE_IMPACT_FLOOR = {"Medium": 15.0, "High": 30.0}


def _higher(a: str, b: str) -> str:
    return a if TIER_ORDER.index(a) >= TIER_ORDER.index(b) else b


def score_event(attack_type: str, packet_count: float, cfg: dict, confidence: float | None = None) -> tuple[float, float, str]:
    """Returns (raw_score, normalized_impact, tier) for one detected flow.

    Volume (packet_count * weight) sets the base tier and impact. If the detector's own confidence
    is very high the tier is lifted to at least Medium/High (see scoring_confidence_floor), and the
    impact with it so the incident / security score reflect that too."""
    weight = cfg["scoring_weights"][attack_type]
    normalization = cfg["scoring_normalization"][attack_type]
    impact_cap = cfg["scoring_impact_cap"][attack_type]

    raw_score = packet_count * weight
    normalized_impact = min(raw_score / normalization, impact_cap)
    tier = classify_tier(attack_type, raw_score, cfg)

    floor_cfg = cfg.get("scoring_confidence_floor") or {}
    if confidence is not None:
        lifted = None
        if confidence >= floor_cfg.get("high", 2.0):
            lifted = "High"
        elif confidence >= floor_cfg.get("medium", 2.0):
            lifted = "Medium"
        if lifted and _higher(lifted, tier) == lifted and lifted != tier:
            tier = lifted
            normalized_impact = max(normalized_impact, CONFIDENCE_IMPACT_FLOOR[lifted])
    return raw_score, normalized_impact, tier
