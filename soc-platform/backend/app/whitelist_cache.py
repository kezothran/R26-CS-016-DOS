"""In-memory whitelist cache, refreshed from Supabase once per detection cycle so the capture
engine's per-packet whitelist check (called for every packet, on every interface thread) never
blocks on a DB round-trip. Mirrors the prototypes' `wl_ip()`/`wl_port()` helpers, backed by
Postgres instead of a flat whitelist.json.
"""

from __future__ import annotations

import ipaddress
import threading

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import WhitelistEntry

DEFAULT_PORTS = [53, 123, 5353, 67, 68, 137, 138, 1900, 5355]

_lock = threading.Lock()
_ips: set[str] = set()
_networks: list[str] = []
_ports: set[int] = set(DEFAULT_PORTS)


async def refresh_from_db(session: AsyncSession) -> None:
    result = await session.execute(select(WhitelistEntry))
    rows = result.scalars().all()
    ips, networks, ports = set(), [], set(DEFAULT_PORTS)
    for row in rows:
        if row.kind == "ip":
            ips.add(row.value)
        elif row.kind == "network":
            networks.append(row.value)
        elif row.kind == "port":
            ports.add(int(row.value))
    with _lock:
        _ips.clear()
        _ips.update(ips)
        _networks[:] = networks
        _ports.clear()
        _ports.update(ports)


def is_whitelisted(ip: str) -> bool:
    with _lock:
        ips, networks = set(_ips), list(_networks)
    if ip in ips:
        return True
    for net in networks:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False):
                return True
        except Exception:
            pass
    return False


def is_port_whitelisted(port: int) -> bool:
    with _lock:
        return port in _ports


def snapshot() -> dict:
    with _lock:
        return {"ips": sorted(_ips), "networks": list(_networks), "ports": sorted(_ports)}
