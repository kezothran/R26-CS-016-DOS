"""Shared helpers for the query/filter-heavy endpoints (scoring.py, alerts.py, metrics.py) -
range-string parsing ("30m"/"2h"/"90s") lifted out of scoring.py where it first appeared, since
alerts.py and metrics.py need the identical behavior rather than a near-copy.
"""

from __future__ import annotations

import re
from datetime import timedelta

from fastapi import HTTPException

_RANGE_RE = re.compile(r"^(\d+)([smhd])$")
_RANGE_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_range(range_: str) -> timedelta:
    match = _RANGE_RE.match(range_)
    if not match:
        raise HTTPException(status_code=400, detail="range must look like '30m', '2h', '7d', or '90s'")
    value, unit = match.groups()
    return timedelta(**{_RANGE_UNITS[unit]: int(value)})
