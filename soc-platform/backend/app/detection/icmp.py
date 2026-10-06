"""ICMP flood detection - feature extraction ported directly from the ICMP prototype's
`extract_features()`/`run_hybrid()` (Downloads/ICMP_flood final/ICMP_flood final/app.py).
"""

from __future__ import annotations

import numpy as np

from app.detection.base import ModelBundle, assign_tier_by_pps, run_hybrid

FEATURES = [
    "frame.len", "icmp.type", "icmp.code", "icmp.seq", "icmp.ident",
    "data.len", "ip.ttl_clean", "src_packet_count", "src_mean_delta",
    "frame.time_delta", "frame.time_relative",
]


def extract_features(raw: list[dict], cfg: dict) -> list[dict]:
    if not raw:
        return []

    times = [p["time"] for p in raw]
    start_time = min(times) if times else 0

    src_groups: dict[str, list[dict]] = {}
    for p in raw:
        src_groups.setdefault(p["src"], []).append(p)

    records = []
    for src, pkts in src_groups.items():
        pkts = sorted(pkts, key=lambda x: x["time"])
        src_times = [p["time"] for p in pkts]
        src_deltas = [src_times[j + 1] - src_times[j] for j in range(len(src_times) - 1)]
        src_mean_delta = float(np.mean(src_deltas)) if src_deltas else 0.0

        p = pkts[-1]
        i = raw.index(p)
        prev_time = raw[i - 1]["time"] if i > 0 else p["time"]
        time_delta = p["time"] - prev_time

        records.append({
            "src": src,
            "dst": p["dst"],
            "n_packets": len(pkts),
            "iface": p.get("iface", "?"),
            "frame.len": float(p["length"]),
            "icmp.type": float(p.get("icmp_type") or 8),
            "icmp.code": 0.0,
            "icmp.seq": float(p.get("icmp_seq", 0)),
            "icmp.ident": 0.0,
            "data.len": float(p["length"] - 28),
            "ip.ttl_clean": 64.0,
            "src_packet_count": float(len(pkts)),
            "src_mean_delta": src_mean_delta,
            "frame.time_delta": time_delta,
            "frame.time_relative": p["time"] - start_time,
        })
    return records


def score(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    records = run_hybrid(records, cfg, bundle)
    thresh = cfg.get("threshold", 0.5)
    for r in records:
        pkt_count = r["src_packet_count"]
        mean_delta = r["src_mean_delta"]
        is_flood = pkt_count > 100 and mean_delta < 0.01
        if bundle.trained:
            # `or`, not `and`: the trained scaler was fit on ~225K-packet flows (whole-session
            # scale from the original prototype's dataset), while a 5s live capture window can
            # realistically produce at most a few thousand - so hp stays near 0 for genuine
            # floods regardless of how obvious they are (confirmed 2026-08-12, see memory). The
            # rate rule alone is enough to flag a flood; ML confidence can still add a flag on
            # top of it (e.g. a slower-rate anomaly the rule misses) but never blocks one.
            r["attack"] = int(is_flood or r.get("hp", 0) > thresh)
        else:
            r["xp"] = r["dp"] = r["hp"] = 1.0 if is_flood else 0.0
            r["attack"] = int(is_flood)
        r["tier"] = assign_tier_by_pps(pkt_count) if r["attack"] else "NORMAL"
    return records
