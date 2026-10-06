"""UDP flood detection - feature extraction ported directly from the UDP prototype's
`extract_features()`/`run_detection()` (Desktop/R26-CS-016-DOS/udp_deshbord-/app_work.py).

Unlike ICMP/SYN/fragmentation, UDP floods (e.g. hping3 with randomized source ports) don't
group meaningfully into 5-tuple flows - grouping by (src, dst, sport, dport) yields ~1 packet
per "flow" when the source port changes every packet, so the model never sees a flood. The
prototype's fix (kept here): group by the 3-tuple (src, dst, dport) instead whenever the 5-tuple
grouping's average packets/flow looks like scattered single-packet noise, and suppress a flow if
its reverse direction carries much more traffic (a real two-way UDP service, not a one-way flood).
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from app.detection.base import ModelBundle, run_hybrid

FEATURES = [
    "Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Subflow Fwd Packets", "Subflow Bwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Bytes",
]

# Always-safe UDP service ports (DNS/NTP/mDNS/DHCP/NetBIOS/SSDP/LLMNR/HTTP(S)-over-UDP) - skipped
# the same way the prototype skipped them, so ordinary background chatter never gets grouped
# into a "flow". IP-level noise (CDNs, known-safe hosts) is handled upstream by the platform's
# whitelist_cache, same as every other attack type - not duplicated here.
WHITELIST_PORTS = {53, 123, 5353, 67, 68, 137, 138, 1900, 5355, 443, 80}

MIN_PPS = 50       # packets/sec
MIN_BPS = 50000    # bytes/sec

# Below this many packets, pps/bps aren't a meaningful rate measurement - two packets a few
# microseconds apart (e.g. a normal broadcast/multicast burst) divide out to an absurd
# instantaneous rate (sometimes millions of pps) purely from floating-point timing noise,
# trivially clearing MIN_PPS/MIN_BPS above without the flow being remotely flood-like. Confirmed
# 2026-08-13: every false-positive CRITICAL UDP alert in a 15-minute sample had 2-12 packets.
MIN_PACKETS = 20


def extract_features(raw: list[dict], cfg: dict) -> list[dict]:
    if not raw:
        return []

    min_pps = cfg.get("udp_min_pps", MIN_PPS)
    min_bps = cfg.get("udp_min_bps", MIN_BPS)
    min_packets = cfg.get("udp_min_packets", MIN_PACKETS)

    packets = [p for p in raw if p.get("dport") not in WHITELIST_PORTS and p.get("sport") not in WHITELIST_PORTS]

    flows_3: dict[tuple, list[dict]] = defaultdict(list)
    flows_5: dict[tuple, list[dict]] = defaultdict(list)
    for p in packets:
        flows_3[(p["src"], p["dst"], p["dport"])].append(p)
        flows_5[(p["src"], p["dst"], p.get("sport", 0), p["dport"])].append(p)

    avg_pkts_5 = sum(len(v) for v in flows_5.values()) / max(len(flows_5), 1)
    use_flows = flows_3 if avg_pkts_5 < 3 else flows_5

    records = []
    for key, pkts in use_flows.items():
        if len(pkts) < min_packets:
            continue
        if len(key) == 3:
            src, dst, dport = key
        else:
            src, dst, _sport, dport = key

        pkts = sorted(pkts, key=lambda x: x["time"])
        times = [p["time"] for p in pkts]
        lens = [p["length"] for p in pkts]
        dur_s = times[-1] - times[0]
        dur_us = dur_s * 1e6
        iats = [(times[i + 1] - times[i]) * 1e6 for i in range(len(times) - 1)]
        iat_mean = float(np.mean(iats)) if iats else 0.0
        iat_std = float(np.std(iats)) if iats else 0.0
        iat_max = float(np.max(iats)) if iats else 0.0
        iat_min = float(np.min(iats)) if iats else 0.0
        iat_total = float(sum(iats))
        n = len(pkts)
        total_len = sum(lens)
        bps = total_len / dur_s if dur_s > 0 else total_len * 1e6
        pps = n / dur_s if dur_s > 0 else n * 1e6

        # Rate gate - below this, treat as normal UDP traffic, not a flood candidate.
        if pps < min_pps and bps < min_bps:
            continue

        # Skip if the reverse direction carries much more traffic than this - a legitimate
        # two-way UDP service (e.g. a game server replying), not a one-way flood.
        rev_key = (dst, src, dport) if len(key) == 3 else (key[1], key[0], key[3], key[2])
        if rev_key in use_flows and len(use_flows[rev_key]) > n * 2:
            continue

        records.append({
            "src": src, "dst": dst, "n_packets": n,
            "iface": pkts[-1].get("iface", "?"),
            "dur_us": dur_us,
            "Flow Duration": dur_us,
            "Flow Bytes/s": bps, "Flow Packets/s": pps,
            "Fwd Packets/s": pps, "Bwd Packets/s": 0.0,
            "Flow IAT Mean": iat_mean, "Flow IAT Std": iat_std,
            "Flow IAT Max": iat_max, "Flow IAT Min": iat_min,
            "Fwd IAT Total": iat_total, "Fwd IAT Mean": iat_mean,
            "Fwd IAT Std": iat_std, "Fwd IAT Max": iat_max, "Fwd IAT Min": iat_min,
            "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0,
            "Total Fwd Packets": float(n), "Total Backward Packets": 0.0,
            "Total Length of Fwd Packets": float(total_len), "Total Length of Bwd Packets": 0.0,
            "Subflow Fwd Packets": float(n), "Subflow Bwd Packets": 0.0,
            "Subflow Fwd Bytes": float(total_len), "Subflow Bwd Bytes": 0.0,
        })
    return records


def _assign_tier(dur_us: float) -> str:
    # Thresholds ported from the prototype (calibrated against its training set's flow-duration
    # distribution, ~p99 = 986276us) - a flood's flow duration collapses toward zero as packet
    # rate rises, so shorter duration = more severe, unlike the pps-based tiering used elsewhere.
    if dur_us <= 1:
        return "CRITICAL"
    if dur_us <= 64:
        return "HIGH"
    if dur_us <= 109210:
        return "MEDIUM"
    return "LOW"


def score(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    if bundle.trained:
        records = run_hybrid(records, cfg, bundle)
        for r in records:
            # Every record here already cleared the pps/bps rate gate in extract_features - it's
            # already a flood candidate. `run_hybrid` sets r["attack"] purely from hp > threshold,
            # but hp doesn't reliably confirm what the rate gate already established (scaler-mismatch
            # calibration issue - see memory), which flickered attack on/off between cycles on live
            # traffic. Trust the rate gate like icmp.py/fragmentation.py do, not hp alone.
            r["attack"] = 1
            r["tier"] = _assign_tier(r["dur_us"])
        return records

    # Rule-based fallback (no trained model) - every record here already passed the rate gate
    # in extract_features, so treat it as a flood outright.
    for r in records:
        pps = r["Flow Packets/s"]
        conf = min(1.0, pps / (MIN_PPS * 5))
        r["xp"] = r["dp"] = r["hp"] = conf
        r["attack"] = 1
        r["tier"] = _assign_tier(r["dur_us"])
    return records
