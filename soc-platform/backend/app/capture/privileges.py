"""Raw packet capture needs elevated privileges on every OS (Npcap-admin on Windows,
root/CAP_NET_RAW on Linux, root on macOS) - scapy abstracts the capture API but not the
privilege requirement. Fail fast at startup with a clear, platform-specific message instead of
silently capturing zero packets forever.
"""

from __future__ import annotations

import platform


def check_capture_privileges() -> None:
    from scapy.all import get_if_list, sniff

    ifaces = get_if_list()
    if not ifaces:
        raise RuntimeError("No network interfaces found by scapy - check Npcap/libpcap installation.")

    try:
        sniff(iface=ifaces[0], timeout=0.5, store=False)
    except Exception as exc:
        system = platform.system()
        hint = {
            "Windows": "Run this process as Administrator, and make sure Npcap is installed "
                       "with 'WinPcap API-compatible mode' checked (https://npcap.com).",
            "Linux": "Run this process as root, or grant it the capability: "
                     "sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)",
            "Darwin": "Run this process with sudo (macOS requires root for raw packet capture).",
        }.get(system, "Run this process with elevated/root privileges.")
        raise RuntimeError(f"Packet capture self-test failed on {system}: {exc}\n{hint}") from exc
