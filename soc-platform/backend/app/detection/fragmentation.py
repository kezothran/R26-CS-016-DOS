"""Fragmentation flood detection - feature extraction ported from the FragmentationAttackML
prototype's training notebook (Downloads/FragmentationAttackML/FragmentationAttackML/
fragmentation_model.ipynb). Its shipped `models/selected_features.json` (11 columns) is stale -
the actual fitted scaler/xgboost/CNN all have `n_features_in_ == 7` matching the notebook's
`selected_features` cell, so app/models/fragmentation/feature_names.json was written by hand
with that verified 7-feature list instead of copying the stale json.

Packets here are already pre-filtered by app/capture/engine.py to IP packets with the More
Fragments flag set or a non-zero fragment offset (the hallmark of a fragmentation/teardrop-style
flood). tcp.srcport/tcp.dstport are 0 on non-TCP packets and on later fragments that lack the L4
header - the same convention the training data used (tshark leaves those columns blank/0 there).
"""

from __future__ import annotations

import numpy as np

from app.detection.base import ModelBundle, assign_tier_by_pps, run_hybrid

FEATURES = [
    "frame.time_delta", "ip.proto", "frame.len", "ip.len", "ip.ttl",
    "tcp.srcport", "tcp.dstport",
]

MIN_FRAG_COUNT = 100  # below this, treat as normal (large legitimate payloads do fragment)


def extract_features(raw: list[dict], cfg: dict) -> list[dict]:
    if not raw:
        return []

    times = [p["time"] for p in raw]
    start_time = min(times)

    src_groups: dict[str, list[dict]] = {}
    for p in raw:
        src_groups.setdefault(p["src"], []).append(p)

    records = []
    for src, pkts in src_groups.items():
        pkts = sorted(pkts, key=lambda x: x["time"])
        src_times = [p["time"] for p in pkts]
        deltas = [src_times[j + 1] - src_times[j] for j in range(len(src_times) - 1)]
        mean_delta = float(np.mean(deltas)) if deltas else 0.0
        p = pkts[-1]

        records.append({
            "src": src,
            "dst": p["dst"],
            "n_packets": len(pkts),
            "iface": p.get("iface", "?"),
            "frame.len": float(p["length"]),
            "ip.proto": float(p.get("proto", 0)),
            "ip.len": float(p.get("ip_len", p["length"])),
            "ip.ttl": float(p.get("ttl", 64)),
            "tcp.srcport": float(p.get("tcp_sport", 0)),
            "tcp.dstport": float(p.get("tcp_dport", 0)),
            "src_packet_count": float(len(pkts)),
            "src_mean_delta": mean_delta,
            "frame.time_delta": deltas[-1] if deltas else 0.0,
            "frame.time_relative": p["time"] - start_time,
        })
    return records


def score(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    min_frag = cfg.get("min_frag_count", MIN_FRAG_COUNT)

    if bundle.trained:
        records = run_hybrid(records, cfg, bundle)
        thresh = cfg.get("threshold", 0.5)
        for r in records:
            is_flood = r["src_packet_count"] > min_frag
            # `or`, not `and`: same scaler-mismatch calibration issue as icmp.py (trained on
            # session-scale flows, live 5s-window features score as out-of-distribution) means hp
            # stays near 0 for genuine floods, which let `and` veto an obvious flood every cycle.
            # The rate rule alone is enough to flag one; ML confidence can only add a flag on top.
            r["attack"] = int(is_flood or r.get("hp", 0) > thresh)
            r["tier"] = assign_tier_by_pps(r["src_packet_count"]) if r["attack"] else "NORMAL"
        return records

    for r in records:
        is_flood = r["src_packet_count"] > min_frag
        conf = min(1.0, r["src_packet_count"] / (min_frag * 5)) if is_flood else 0.0
        r["xp"] = r["dp"] = r["hp"] = conf
        r["attack"] = int(is_flood)
        r["tier"] = assign_tier_by_pps(r["src_packet_count"]) if is_flood else "NORMAL"
    return records
