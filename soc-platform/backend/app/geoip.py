"""Thin wrapper around a local MaxMind GeoLite2-Country .mmdb file. Optional by design - the
app must work with zero GeoIP setup (no DB path configured, or the file missing), in which case
lookup() just returns None everywhere instead of raising, and callers (app/api/metrics.py)
degrade gracefully by omitting the country field.
"""

from __future__ import annotations

import logging
import threading

from app.config import settings

logger = logging.getLogger("soc")

_lock = threading.Lock()
_reader = None
_load_attempted = False


def _get_reader():
    global _reader, _load_attempted
    with _lock:
        if _load_attempted:
            return _reader
        _load_attempted = True

        if not settings.geoip_db_path:
            logger.warning("GEOIP_DB_PATH not set - Geo-IP attack-origin lookups disabled.")
            return None

        try:
            import geoip2.database

            _reader = geoip2.database.Reader(settings.geoip_db_path)
        except Exception as exc:
            logger.warning(f"Failed to load GeoIP database at {settings.geoip_db_path}: {exc}")
            _reader = None

        return _reader


def lookup(ip: str) -> dict | None:
    """Returns {"country": str, "country_code": str} or None if unavailable/not found."""
    reader = _get_reader()
    if reader is None:
        return None
    try:
        result = reader.country(ip)
        return {
            "country": result.country.name or "Unknown",
            "country_code": result.country.iso_code or "??",
        }
    except Exception:
        return None
