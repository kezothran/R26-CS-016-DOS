"""Stage 3 - combined incident scorer. Merges a correlated group of events into one incident
score using max(impact) + beta * sum(remaining impacts) instead of a flat sum, so a
multi-vector attack from one source is flagged more severely than either vector alone without
naively double-counting.
"""

from __future__ import annotations

TIER_ORDER = ["Low", "Medium", "High", "Critical"]


def classify_combined_tier(score: float) -> str:
    if score < 15:
        return "Low"
    if score < 30:
        return "Medium"
    if score < 45:
        return "High"
    return "Critical"


def combined_incident_score(group: list[dict], cfg: dict) -> tuple[float, str, str]:
    """Returns (combined_impact, correlation_confidence, tier) for one correlated group."""
    if len(group) == 1:
        impact = group[0]["normalized_impact"]
        return impact, "single", group[0]["tier"]

    impacts = sorted((e["normalized_impact"] for e in group), reverse=True)
    same_source = all(e["src_ip"] == group[0]["src_ip"] for e in group)
    confidence = "high" if same_source else "medium"
    beta = cfg["scoring_beta_high"] if confidence == "high" else cfg["scoring_beta_medium"]

    # Multi-vector escalation - a coordinated attack running several distinct techniques at once
    # is inherently harder to defend against than the raw volume-weighted sum implies (each
    # individual vector can look moderate on its own while together they're a bigger problem).
    # Flat bonus per distinct attack type beyond the first, calibrated so 2 simultaneous types
    # typically reach High and 3+ typically reach Critical even at moderate per-type volume -
    # confirmed 2026-08-13: 3 real (but moderate-volume, VM-networking-capped) simultaneous
    # floods scored Medium under the volume-only formula, which undersold how serious a 3-vector
    # attack actually is.
    distinct_types = len({e["attack_type"] for e in group})
    multi_vector_bonus = cfg["scoring_multi_vector_bonus"] * max(0, distinct_types - 1)

    combined = impacts[0] + beta * sum(impacts[1:]) + multi_vector_bonus
    tier = classify_combined_tier(combined)
    return combined, confidence, tier
