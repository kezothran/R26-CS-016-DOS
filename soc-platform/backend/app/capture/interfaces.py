"""Cross-platform interface enumeration.

The ICMP/UDP prototypes' `find_interface.py` was a Windows-only diagnostic script (it shelled
out to `ipconfig /all`). That approach doesn't work on Linux/macOS, so it isn't ported. Instead
this combines psutil (cross-platform IP/status info) with scapy's own interface list (already
used identically in both prototypes' detection loops) for human-readable descriptions.
"""

from __future__ import annotations

import psutil
from scapy.all import IFACES, get_if_addr, get_if_list


def list_interfaces() -> list[dict]:
    psutil_stats = psutil.net_if_stats()
    psutil_addrs = psutil.net_if_addrs()

    out = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "?"

        desc = iface
        try:
            for iv in IFACES.values():
                if iv.name == iface:
                    desc = getattr(iv, "description", iface) or iface
                    break
        except Exception:
            pass

        is_up = None
        for psutil_name, stats in psutil_stats.items():
            if psutil_name == iface or psutil_name in desc or desc in psutil_name:
                is_up = stats.isup
                break

        out.append({
            "name": iface,
            "description": (desc[:60] + "...") if len(desc) > 60 else desc,
            "ip": ip,
            "up": is_up if is_up is not None else True,
        })
    return out
