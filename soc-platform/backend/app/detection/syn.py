"""SYN flood detection - bidirectional CICFlowMeter-style feature extraction, feeding a
5-class multi-output hybrid XGBoost + Conv1D/BiLSTM model (backend/app/models/syn/).

Unlike every other module here, this one isn't ported from a matching standalone prototype -
no training notebook was available, only the four trained artifacts (xgb_model.pkl, scaler.pkl,
feature_names.json, cnn_lstm_model.h5, dropped in from C:\\Users\\VICTUS\\Downloads\\trained\\).
Two things had to be reverse-engineered rather than confirmed against source:

1. Feature set: the shipped feature_names.json listed 78 columns, but the scaler/xgboost model
   both report `n_features_in_ == 81` - the true 81-name list was recovered from the fitted
   scaler's own `feature_names_in_` attribute (scikit-learn auto-captures this when fit on a
   named DataFrame), not from the stale json. It's the standard CICFlowMeter/CICIDS2017 column
   set, which needs full bidirectional flow stats (Fwd *and* Bwd packet/byte/IAT/flag
   statistics) - a materially bigger feature set than every other module's one-directional
   per-source counters. app/capture/engine.py now captures every TCP packet (not just bare
   SYNs) so both directions of a flow are available here.

2. Model semantics: both xgb_model.pkl and cnn_lstm_model.h5 are 5-class softmax classifiers
   (`multi:softprob`, output shape (None, 5)), not the binary attack/not-attack pair every other
   module's hybrid scorer (app/detection/base.py::run_hybrid) assumes. With no label mapping
   available, this assumes the standard convention - class 0 = benign, classes 1-4 = attack
   subtypes - so "attack probability" = 1 - P(class 0). That assumption is unverified.

Given both of the above are best-effort reconstructions, `score()` below deliberately never
lets this model's confidence be the sole trigger - the packet-rate rule (proven reliable for
every other module, including after ICMP's ML confidence turned out to be unreliable in both
directions) is always sufficient on its own; the model can only add a flag on top of it, never
block one.
"""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from app.detection.base import ModelBundle, assign_tier_by_pps

FEATURES = [
    " Source Port", " Destination Port", " Protocol", " Flow Duration",
    " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets",
    " Fwd Packet Length Max", " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std",
    "Flow Bytes/s", " Flow Packets/s",
    " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min",
    "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min",
    "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min",
    "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags",
    " Fwd Header Length", " Bwd Header Length",
    "Fwd Packets/s", " Bwd Packets/s",
    " Min Packet Length", " Max Packet Length", " Packet Length Mean", " Packet Length Std", " Packet Length Variance",
    "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count",
    " ACK Flag Count", " URG Flag Count", " CWE Flag Count", " ECE Flag Count",
    " Down/Up Ratio", " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size",
    " Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes",
    "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd", " min_seg_size_forward",
    "Active Mean", " Active Std", " Active Max", " Active Min",
    "Idle Mean", " Idle Std", " Idle Max", " Idle Min",
    " Inbound",
]

MIN_SYN_COUNT = 100  # below this, treat as normal connection attempts, not a flood

# TCP flag bits
_FIN, _SYN, _RST, _PSH, _ACK, _URG, _ECE, _CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

_IDLE_THRESHOLD_S = 1.0  # CICFlowMeter's default "activity timeout" - gaps beyond this split
                          # a flow into separate active/idle periods.


def _has_flag(pkt: dict, bit: int) -> bool:
    return bool(pkt["tcp_flags"] & bit)


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    """(max, min, mean, std), 0.0 for every field on an empty list."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=float)
    return float(arr.max()), float(arr.min()), float(arr.mean()), float(arr.std())


def _iats_us(times: list[float]) -> list[float]:
    return [(times[i + 1] - times[i]) * 1e6 for i in range(len(times) - 1)]


def _bulk_stats(pkts: list[dict]) -> tuple[float, float, float]:
    """(avg bytes/bulk, avg packets/bulk, avg bulk rate) - a "bulk" is a run of >=4
    same-direction, payload-carrying packets with <1s gaps, per CICFlowMeter's definition.
    SYN-flood-candidate flows are mostly bare control packets, so this is usually all zeros -
    expected, not a bug."""
    runs: list[list[dict]] = []
    current: list[dict] = []
    for p in pkts:
        if p["tcp_payload_len"] <= 0:
            if len(current) >= 4:
                runs.append(current)
            current = []
            continue
        if current and (p["time"] - current[-1]["time"]) > _IDLE_THRESHOLD_S:
            if len(current) >= 4:
                runs.append(current)
            current = []
        current.append(p)
    if len(current) >= 4:
        runs.append(current)

    if not runs:
        return 0.0, 0.0, 0.0
    avg_bytes = float(np.mean([sum(p["tcp_payload_len"] for p in r) for r in runs]))
    avg_pkts = float(np.mean([len(r) for r in runs]))
    total_bytes = sum(sum(p["tcp_payload_len"] for p in r) for r in runs)
    total_dur = sum(max(r[-1]["time"] - r[0]["time"], 1e-6) for r in runs)
    avg_rate = total_bytes / total_dur if total_dur > 0 else 0.0
    return avg_bytes, avg_pkts, avg_rate


def _active_idle_us(times: list[float]) -> tuple[list[float], list[float]]:
    """Splits a flow's sorted packet timestamps into active-period durations and the idle gaps
    between them (both in microseconds), per CICFlowMeter's 1s activity-timeout convention."""
    if len(times) < 2:
        return [], []
    active, idle = [], []
    seg_start = times[0]
    prev = times[0]
    for t in times[1:]:
        gap = t - prev
        if gap > _IDLE_THRESHOLD_S:
            active.append((prev - seg_start) * 1e6)
            idle.append(gap * 1e6)
            seg_start = t
        prev = t
    active.append((prev - seg_start) * 1e6)
    return active, idle


def extract_features(raw: list[dict], cfg: dict) -> list[dict]:
    if not raw:
        return []

    # Candidate attacker IPs = anyone seen sending a bare SYN (set, ACK unset) - the same
    # signal app/capture/engine.py used to filter this bucket before it captured every TCP
    # packet. Every packet either FROM or TO one of these IPs joins that IP's flow group -
    # grouped by attacker IP alone (not full 5-tuple), so a flood using randomized source ports
    # per packet (e.g. hping3 --flood) still accumulates into one flow instead of scattering
    # into hundreds of 1-packet "flows" (the same problem UDP's docstring describes solving).
    candidates = {p["src"] for p in raw if _has_flag(p, _SYN) and not _has_flag(p, _ACK)}
    if not candidates:
        return []

    groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for p in raw:
        if p["src"] in candidates:
            groups[p["src"]].append(("fwd", p))
        elif p["dst"] in candidates:
            groups[p["dst"]].append(("bwd", p))

    records = []
    for attacker_ip, tagged in groups.items():
        tagged.sort(key=lambda t: t[1]["time"])
        pkts = [p for _, p in tagged]
        fwd_pkts = [p for d, p in tagged if d == "fwd"]
        bwd_pkts = [p for d, p in tagged if d == "bwd"]
        if not fwd_pkts:
            continue

        times = [p["time"] for p in pkts]
        dur_s = times[-1] - times[0]
        dur_us = dur_s * 1e6
        n_total = len(pkts)

        fwd_lens = [float(p["length"]) for p in fwd_pkts]
        bwd_lens = [float(p["length"]) for p in bwd_pkts]
        all_lens = fwd_lens + bwd_lens
        total_fwd_bytes = sum(fwd_lens)
        total_bwd_bytes = sum(bwd_lens)
        total_bytes = total_fwd_bytes + total_bwd_bytes

        fwd_max, fwd_min, fwd_mean, fwd_std = _stats(fwd_lens)
        bwd_max, bwd_min, bwd_mean, bwd_std = _stats(bwd_lens)
        plen_max, plen_min, plen_mean, plen_std = _stats(all_lens)

        flow_iats = _iats_us(times)
        fwd_iats = _iats_us([p["time"] for p in fwd_pkts])
        bwd_iats = _iats_us([p["time"] for p in bwd_pkts])

        flow_bps = total_bytes / dur_s if dur_s > 0 else total_bytes * 1e6
        flow_pps = n_total / dur_s if dur_s > 0 else n_total * 1e6
        fwd_pps = len(fwd_pkts) / dur_s if dur_s > 0 else len(fwd_pkts) * 1e6
        bwd_pps = len(bwd_pkts) / dur_s if dur_s > 0 else len(bwd_pkts) * 1e6

        fwd_header_len = sum(p["tcp_header_len"] for p in fwd_pkts)
        bwd_header_len = sum(p["tcp_header_len"] for p in bwd_pkts)

        active_us, idle_us = _active_idle_us(times)
        fwd_bulk = _bulk_stats(fwd_pkts)
        bwd_bulk = _bulk_stats(bwd_pkts)

        first_fwd, first_bwd = fwd_pkts[0], (bwd_pkts[0] if bwd_pkts else None)

        try:
            import ipaddress
            inbound = 1.0 if ipaddress.ip_address(first_fwd["dst"]).is_private else 0.0
        except ValueError:
            inbound = 0.0

        feat = {
            " Source Port": float(first_fwd["sport"]),
            " Destination Port": float(first_fwd["dport"]),
            " Protocol": 6.0,
            " Flow Duration": dur_us,
            " Total Fwd Packets": float(len(fwd_pkts)),
            " Total Backward Packets": float(len(bwd_pkts)),
            "Total Length of Fwd Packets": total_fwd_bytes,
            " Total Length of Bwd Packets": total_bwd_bytes,
            " Fwd Packet Length Max": fwd_max, " Fwd Packet Length Min": fwd_min,
            " Fwd Packet Length Mean": fwd_mean, " Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max, " Bwd Packet Length Min": bwd_min,
            " Bwd Packet Length Mean": bwd_mean, " Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": flow_bps, " Flow Packets/s": flow_pps,
            " Flow IAT Mean": float(np.mean(flow_iats)) if flow_iats else 0.0,
            " Flow IAT Std": float(np.std(flow_iats)) if flow_iats else 0.0,
            " Flow IAT Max": float(np.max(flow_iats)) if flow_iats else 0.0,
            " Flow IAT Min": float(np.min(flow_iats)) if flow_iats else 0.0,
            "Fwd IAT Total": float(sum(fwd_iats)),
            " Fwd IAT Mean": float(np.mean(fwd_iats)) if fwd_iats else 0.0,
            " Fwd IAT Std": float(np.std(fwd_iats)) if fwd_iats else 0.0,
            " Fwd IAT Max": float(np.max(fwd_iats)) if fwd_iats else 0.0,
            " Fwd IAT Min": float(np.min(fwd_iats)) if fwd_iats else 0.0,
            "Bwd IAT Total": float(sum(bwd_iats)),
            " Bwd IAT Mean": float(np.mean(bwd_iats)) if bwd_iats else 0.0,
            " Bwd IAT Std": float(np.std(bwd_iats)) if bwd_iats else 0.0,
            " Bwd IAT Max": float(np.max(bwd_iats)) if bwd_iats else 0.0,
            " Bwd IAT Min": float(np.min(bwd_iats)) if bwd_iats else 0.0,
            "Fwd PSH Flags": float(sum(1 for p in fwd_pkts if _has_flag(p, _PSH))),
            " Bwd PSH Flags": float(sum(1 for p in bwd_pkts if _has_flag(p, _PSH))),
            " Fwd URG Flags": float(sum(1 for p in fwd_pkts if _has_flag(p, _URG))),
            " Bwd URG Flags": float(sum(1 for p in bwd_pkts if _has_flag(p, _URG))),
            " Fwd Header Length": float(fwd_header_len),
            " Bwd Header Length": float(bwd_header_len),
            "Fwd Packets/s": fwd_pps, " Bwd Packets/s": bwd_pps,
            " Min Packet Length": plen_min, " Max Packet Length": plen_max,
            " Packet Length Mean": plen_mean, " Packet Length Std": plen_std,
            " Packet Length Variance": plen_std ** 2,
            "FIN Flag Count": float(sum(1 for p in pkts if _has_flag(p, _FIN))),
            " SYN Flag Count": float(sum(1 for p in pkts if _has_flag(p, _SYN))),
            " RST Flag Count": float(sum(1 for p in pkts if _has_flag(p, _RST))),
            " PSH Flag Count": float(sum(1 for p in pkts if _has_flag(p, _PSH))),
            " ACK Flag Count": float(sum(1 for p in pkts if _has_flag(p, _ACK))),
            " URG Flag Count": float(sum(1 for p in pkts if _has_flag(p, _URG))),
            " CWE Flag Count": float(sum(1 for p in pkts if _has_flag(p, _CWR))),
            " ECE Flag Count": float(sum(1 for p in pkts if _has_flag(p, _ECE))),
            " Down/Up Ratio": float(len(bwd_pkts) / len(fwd_pkts)) if fwd_pkts else 0.0,
            " Average Packet Size": float(total_bytes / n_total) if n_total else 0.0,
            " Avg Fwd Segment Size": fwd_mean,
            " Avg Bwd Segment Size": bwd_mean,
            " Fwd Header Length.1": float(fwd_header_len),
            "Fwd Avg Bytes/Bulk": fwd_bulk[0], " Fwd Avg Packets/Bulk": fwd_bulk[1], " Fwd Avg Bulk Rate": fwd_bulk[2],
            " Bwd Avg Bytes/Bulk": bwd_bulk[0], " Bwd Avg Packets/Bulk": bwd_bulk[1], "Bwd Avg Bulk Rate": bwd_bulk[2],
            "Subflow Fwd Packets": float(len(fwd_pkts)), " Subflow Fwd Bytes": total_fwd_bytes,
            " Subflow Bwd Packets": float(len(bwd_pkts)), " Subflow Bwd Bytes": total_bwd_bytes,
            "Init_Win_bytes_forward": float(first_fwd["tcp_window"]),
            " Init_Win_bytes_backward": float(first_bwd["tcp_window"]) if first_bwd else 0.0,
            " act_data_pkt_fwd": float(sum(1 for p in fwd_pkts if p["tcp_payload_len"] > 0)),
            " min_seg_size_forward": float(min((p["tcp_header_len"] for p in fwd_pkts), default=0)),
            "Active Mean": float(np.mean(active_us)) if active_us else 0.0,
            " Active Std": float(np.std(active_us)) if active_us else 0.0,
            " Active Max": float(np.max(active_us)) if active_us else 0.0,
            " Active Min": float(np.min(active_us)) if active_us else 0.0,
            "Idle Mean": float(np.mean(idle_us)) if idle_us else 0.0,
            " Idle Std": float(np.std(idle_us)) if idle_us else 0.0,
            " Idle Max": float(np.max(idle_us)) if idle_us else 0.0,
            " Idle Min": float(np.min(idle_us)) if idle_us else 0.0,
            " Inbound": inbound,
        }

        feat.update({
            "src": attacker_ip,
            "dst": first_fwd["dst"],
            "n_packets": n_total,
            # Count of bare SYN packets specifically, not n_packets (every TCP packet involving
            # this source, both directions - includes all the ordinary ACK/data traffic of any
            # completed connection). A normal browsing session moves thousands of TCP packets a
            # minute with only a handful of real connection attempts; gating the flood rule on
            # n_packets flagged ordinary traffic to cloud/CDN IPs as a "flood" within minutes of
            # this model going live. syn_count restores the original rule-based version's
            # semantics (flood = high rate of *connection attempts*, not high data volume).
            "syn_count": float(feat[" SYN Flag Count"]),
            "iface": pkts[-1].get("iface", "?"),
            "dur_us": dur_us,
        })
        records.append(feat)

    return records


def _run_multiclass_hybrid(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    if not records or not bundle.trained:
        return records

    xw = cfg.get("xgb_weight", 0.6)
    cw = cfg.get("cnn_weight", 0.4)

    X = np.array([[r[f] for f in bundle.features] for r in records])
    X = np.nan_to_num(np.where(np.isinf(X), 0, X))
    Xsc = bundle.scaler.transform(X)

    # 5-class softmax on both sub-models (see module docstring) - "attack probability" is
    # 1 - P(class 0), assuming class 0 is benign. Unverified without the training source.
    xgb_all = bundle.xgb_model.predict_proba(Xsc)
    xprb = 1.0 - xgb_all[:, 0]

    dprb = np.zeros(len(records))
    if bundle.dl_model is not None:
        try:
            n_features = len(bundle.features)
            Xd = Xsc.reshape(-1, n_features, 1)
            dl_all = bundle.dl_model.predict(Xd, verbose=0)
            dprb = 1.0 - np.asarray(dl_all)[:, 0]
        except Exception:
            dprb = xprb.copy()

    hprb = xw * xprb + cw * dprb if bundle.dl_model is not None else xprb.copy()

    for i, r in enumerate(records):
        r["xp"] = float(xprb[i])
        r["dp"] = float(dprb[i])
        r["hp"] = float(hprb[i])

    return records


def score(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    min_syn = cfg.get("min_syn_count", MIN_SYN_COUNT)
    thresh = cfg.get("threshold", 0.5)

    if bundle.trained:
        records = _run_multiclass_hybrid(records, cfg, bundle)
        for r in records:
            is_flood = r["syn_count"] > min_syn
            # `or`, not `and` - see module docstring. The rate rule alone is always sufficient;
            # this unverified multi-class model can only add a flag on top of it.
            r["attack"] = int(is_flood or r.get("hp", 0) > thresh)
            r["tier"] = assign_tier_by_pps(r["syn_count"]) if r["attack"] else "NORMAL"
        return records

    for r in records:
        is_flood = r["syn_count"] > min_syn
        conf = min(1.0, r["syn_count"] / (min_syn * 5)) if is_flood else 0.0
        r["xp"] = r["dp"] = r["hp"] = conf
        r["attack"] = int(is_flood)
        r["tier"] = assign_tier_by_pps(r["syn_count"]) if is_flood else "NORMAL"
    return records
