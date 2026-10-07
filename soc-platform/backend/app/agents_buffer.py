"""In-memory hand-off between the agent ingest endpoint and the detection loop.

Agents POST one capture window at a time (packet metadata only, no payload). The ingest endpoint
appends those rows here; each detection cycle drains the buffer and merges the rows with whatever
the local capture produced, so remote hosts run through exactly the same detectors, scoring and
dashboard as local traffic. Every row's `iface` is rewritten to "<iface>@<hostname>" so the host
is visible everywhere an interface already is (alerts, incidents, evidence, PDF reports).

Bounded on purpose: if the loop falls behind (or is stopped) the oldest rows are dropped instead of
growing without limit.
"""

from __future__ import annotations

import threading
from collections import defaultdict

MAX_ROWS_PER_BUCKET = 200_000

_lock = threading.Lock()
_buckets: dict[str, list[dict]] = defaultdict(list)


def push(hostname: str, buckets: dict[str, list[dict]]) -> int:
    """Adds one agent window; returns the number of rows accepted."""
    accepted = 0
    with _lock:
        for name, rows in buckets.items():
            dest = _buckets[name]
            for row in rows:
                row["iface"] = f"{row.get('iface') or '?'}@{hostname}"
                dest.append(row)
                accepted += 1
            if len(dest) > MAX_ROWS_PER_BUCKET:
                del dest[: len(dest) - MAX_ROWS_PER_BUCKET]
    return accepted


def drain() -> dict[str, list[dict]]:
    with _lock:
        out = {k: v for k, v in _buckets.items() if v}
        _buckets.clear()
    return out
