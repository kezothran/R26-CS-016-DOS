"""Central place mapping an attack_type key to its extractor/scorer/model bundle/theme color.

Adding a fully-trained attack type later means adding one entry here - no other file needs to
change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.detection import fragmentation, icmp, syn, udp
from app.detection.base import ModelBundle, load_model_bundle


@dataclass
class AttackModule:
    key: str
    label: str
    color: str  # drives the frontend's attack-reactive theme (see frontend theme config)
    extract_features: Callable[[list[dict], dict], list[dict]]
    score: Callable[[list[dict], dict, ModelBundle], list[dict]]
    bundle: ModelBundle


# Attack types actually run by the live detection loop.
ACTIVE_ATTACKS = ["icmp", "syn", "fragmentation", "udp"]

REGISTRY: dict[str, AttackModule] = {
    "icmp": AttackModule(
        key="icmp", label="ICMP Flood", color="#f85149",
        extract_features=icmp.extract_features, score=icmp.score,
        bundle=load_model_bundle("icmp"),
    ),
    "syn": AttackModule(
        key="syn", label="SYN Flood", color="#bc8cff",
        extract_features=syn.extract_features, score=syn.score,
        bundle=load_model_bundle("syn"),
    ),
    "fragmentation": AttackModule(
        key="fragmentation", label="Fragmentation Flood", color="#e3b341",
        extract_features=fragmentation.extract_features, score=fragmentation.score,
        bundle=load_model_bundle("fragmentation"),
    ),
    "udp": AttackModule(
        key="udp", label="UDP Flood", color="#58a6ff",
        extract_features=udp.extract_features, score=udp.score,
        bundle=load_model_bundle("udp"),
    ),
}
