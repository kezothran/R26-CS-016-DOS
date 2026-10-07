"""Thin wrapper around a local MaxMind GeoLite2 .mmdb file (City preferred - it has coordinates for
the live attacker map; Country also works, pins then use country centroids). Optional by design - the
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


# Rough country centroids (lat, lon) - only used when the loaded DB is GeoLite2-Country (no coords).
_CENTROIDS = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "MX": (23.6, -102.5), "BR": (-14.2, -51.9), "AR": (-38.4, -63.6),
    "CL": (-35.7, -71.5), "CO": (4.6, -74.1), "PE": (-9.2, -75.0), "GB": (54.0, -2.0), "IE": (53.4, -8.2),
    "FR": (46.2, 2.2), "DE": (51.2, 10.5), "NL": (52.1, 5.3), "BE": (50.5, 4.5), "ES": (40.5, -3.7),
    "PT": (39.4, -8.2), "IT": (41.9, 12.6), "CH": (46.8, 8.2), "AT": (47.5, 14.6), "SE": (60.1, 18.6),
    "NO": (60.5, 8.5), "FI": (61.9, 25.7), "DK": (56.3, 9.5), "PL": (51.9, 19.1), "UA": (48.4, 31.2),
    "RU": (61.5, 105.3), "TR": (38.9, 35.2), "IL": (31.0, 34.9), "SA": (23.9, 45.1), "AE": (23.4, 53.8),
    "IR": (32.4, 53.7), "EG": (26.8, 30.8), "ZA": (-30.6, 22.9), "NG": (9.1, 8.7), "KE": (-0.0, 37.9),
    "IN": (20.6, 78.9), "PK": (30.4, 69.3), "BD": (23.7, 90.4), "LK": (7.9, 80.8), "CN": (35.9, 104.2),
    "JP": (36.2, 138.3), "KR": (35.9, 127.8), "TW": (23.7, 121.0), "HK": (22.4, 114.1), "SG": (1.35, 103.8),
    "MY": (4.2, 101.9), "TH": (15.9, 100.9), "VN": (14.1, 108.3), "ID": (-0.8, 113.9), "PH": (12.9, 121.8),
    "AU": (-25.3, 133.8), "NZ": (-40.9, 174.9),
}


def ready() -> bool:
    return _get_reader() is not None


def lookup(ip: str) -> dict | None:
    """Returns {"country", "country_code", "lat", "lon", "city"} or None if unavailable/not found.
    lat/lon are None when the DB is Country-only and the country isn't in the centroid table."""
    reader = _get_reader()
    if reader is None:
        return None
    try:
        if "City" in reader.metadata().database_type:
            r = reader.city(ip)
            return {
                "country": r.country.name or "Unknown", "country_code": r.country.iso_code or "??",
                "lat": r.location.latitude, "lon": r.location.longitude, "city": r.city.name,
            }
        r = reader.country(ip)
        code = r.country.iso_code or "??"
        lat, lon = _CENTROIDS.get(code, (None, None))
        return {"country": r.country.name or "Unknown", "country_code": code, "lat": lat, "lon": lon, "city": None}
    except Exception:
        return None
