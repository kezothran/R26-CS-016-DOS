"""Stage 2 - correlation engine. Groups this cycle's scored events (across all attack types,
since they already share one capture window) into single-vector vs multi-vector incidents:
same src_ip is a strong signal; same interface within the time window is a weaker one.
"""

from __future__ import annotations


def is_correlated(event_a: dict, event_b: dict, time_window_sec: float) -> bool:
    same_source = event_a["src_ip"] == event_b["src_ip"]
    same_target = event_a["interface"] == event_b["interface"]
    time_close = abs((event_a["detected_at"] - event_b["detected_at"]).total_seconds()) <= time_window_sec
    return same_source or (same_target and time_close)


def group_correlated_events(events: list[dict], time_window_sec: float) -> list[list[dict]]:
    groups: list[list[dict]] = []
    used: set[int] = set()

    for i, e1 in enumerate(events):
        if i in used:
            continue
        group = [e1]
        used.add(i)
        for j, e2 in enumerate(events):
            if j in used:
                continue
            if any(is_correlated(member, e2, time_window_sec) for member in group):
                group.append(e2)
                used.add(j)
        groups.append(group)

    return groups
