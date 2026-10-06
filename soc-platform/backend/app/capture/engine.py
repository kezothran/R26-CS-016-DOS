"""Shared packet capture engine.

Both prototypes ran one `scapy.sniff(filter="icmp"/"udp", ...)` thread per interface, per
attack type. Detecting 4 attack types at once that way would mean 4 concurrent sniff() calls
per NIC, which is wasteful and prone to Npcap/libpcap contention on Windows. Instead this
captures ALL IP traffic once per interface per window (fan-out/join pattern ported from the
prototypes' `_capture()`/`detection_loop()`), then classifies each packet into one or more
attack-type buckets so every `detection/*.py` module gets the packets it cares about from a
single capture pass.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Callable

WhitelistCheck = Callable[[str], bool]


def _classify(pkt) -> list[str]:
    from scapy.all import ICMP, IP, TCP, UDP

    if not pkt.haslayer(IP):
        return []

    buckets = []
    ip_layer = pkt[IP]

    # IP fragmentation flood: MF flag set, or a non-zero fragment offset.
    if (int(ip_layer.flags) & 0x1) or ip_layer.frag > 0:
        buckets.append("fragmentation")

    if pkt.haslayer(ICMP):
        buckets.append("icmp")
    elif pkt.haslayer(UDP):
        buckets.append("udp")
    elif pkt.haslayer(TCP):
        # Every TCP packet, not just bare SYNs - detection/syn.py now builds full bidirectional
        # CICFlowMeter-style flow statistics (needs both directions: the SYN plus any reply
        # traffic), then filters down to flows that actually started with a SYN itself.
        buckets.append("syn")

    return buckets


def _capture_iface(iface: str, window_secs: int, shared: dict, lock: threading.Lock, is_whitelisted: WhitelistCheck):
    try:
        from scapy.all import IP, sniff

        def handle(pkt):
            try:
                if not pkt.haslayer(IP):
                    return
                src, dst = pkt[IP].src, pkt[IP].dst
                if is_whitelisted(src) or is_whitelisted(dst):
                    return

                buckets = _classify(pkt)
                if not buckets:
                    return

                ip_layer = pkt[IP]
                raw = {
                    "time": float(pkt.time),
                    "src": src,
                    "dst": dst,
                    "length": len(pkt),
                    "iface": iface,
                    "icmp_type": int(pkt["ICMP"].type) if pkt.haslayer("ICMP") else None,
                    "icmp_seq": int(pkt["ICMP"].seq) if pkt.haslayer("ICMP") and pkt["ICMP"].seq else 0,
                    "dport": int(pkt["UDP"].dport) if pkt.haslayer("UDP") else (
                        int(pkt["TCP"].dport) if pkt.haslayer("TCP") else 0
                    ),
                    "sport": int(pkt["UDP"].sport) if pkt.haslayer("UDP") else (
                        int(pkt["TCP"].sport) if pkt.haslayer("TCP") else 0
                    ),
                    # ip.proto/ip.ttl/ip.len - the fragmentation model's raw IP-header features
                    # (later fragments carry these even when the L4 header is missing). tcp_sport/
                    # tcp_dport are kept TCP-only (unlike sport/dport above) because the fragmentation
                    # model was trained on tshark's tcp.srcport/tcp.dstport columns, which are 0/blank
                    # on non-TCP and headerless-fragment rows - reusing sport/dport would leak UDP
                    # ports into what the model expects to be a TCP-only field.
                    "proto": int(ip_layer.proto),
                    "ttl": int(ip_layer.ttl),
                    "ip_len": int(ip_layer.len),
                    "tcp_sport": int(pkt["TCP"].sport) if pkt.haslayer("TCP") else 0,
                    "tcp_dport": int(pkt["TCP"].dport) if pkt.haslayer("TCP") else 0,
                    # SYN-flow bidirectional feature set (detection/syn.py) - flags as a raw int
                    # (individual bits decoded downstream), window size, TCP header length (data
                    # offset is in 32-bit words, so *4 for bytes), and payload length (frame
                    # length minus every header scapy already parsed for us, more robust than
                    # hand-computing it from ip_len/dataofs here).
                    "tcp_flags": int(pkt["TCP"].flags) if pkt.haslayer("TCP") else 0,
                    "tcp_window": int(pkt["TCP"].window) if pkt.haslayer("TCP") else 0,
                    "tcp_header_len": int(pkt["TCP"].dataofs) * 4 if pkt.haslayer("TCP") else 0,
                    "tcp_payload_len": len(bytes(pkt["TCP"].payload)) if pkt.haslayer("TCP") else 0,
                }
                with lock:
                    for bucket in buckets:
                        shared[bucket].append(raw)
            except Exception:
                pass

        sniff(filter="ip", prn=handle, timeout=window_secs, store=False, iface=iface)
    except Exception:
        pass


def capture_window(ifaces: list[str], window_secs: int, is_whitelisted: WhitelistCheck) -> dict[str, list[dict]]:
    """Capture one window across all given interfaces, returns packets grouped by attack-type bucket."""
    shared: dict[str, list[dict]] = defaultdict(list)
    lock = threading.Lock()

    threads = [
        threading.Thread(target=_capture_iface, args=(iface, window_secs, shared, lock, is_whitelisted), daemon=True)
        for iface in ifaces
    ]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=window_secs + 2)

    return dict(shared)
