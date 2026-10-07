"""Shared packet capture engine.

Both prototypes ran one `scapy.sniff(filter="icmp"/"udp", ...)` thread per interface, per
attack type. Detecting 4 attack types at once that way would mean 4 concurrent sniff() calls
per NIC, which is wasteful and prone to Npcap/libpcap contention on Windows. Instead this
captures ALL IP traffic once per interface per window (fan-out/join pattern ported from the
prototypes' `_capture()`/`detection_loop()`), then classifies each packet into one or more
attack-type buckets so every `detection/*.py` module gets the packets it cares about from a
single capture pass.

Fragment handling: when an IP datagram is fragmented, only the FIRST fragment carries the
transport header (UDP/ICMP/TCP ports, ICMP type, TCP flags). Every later fragment is bare IP
payload, so a naive `haslayer(UDP)` check puts a fragmented UDP flood into the `fragmentation`
bucket only - the UDP detector never sees it. Two things fix that here:
  1. later fragments are bucketed by the IP header's protocol number (1/17/6), which every
     fragment carries, and
  2. they inherit the transport fields of their datagram's first fragment (matched on
     src, dst, IP id, protocol), so they join the same flow instead of forming port-0 noise.
A trailing fragment can arrive before its first fragment; those rows are held and back-filled
when the first fragment shows up. Any left over at the end of the window keep port 0.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Callable

WhitelistCheck = Callable[[str], bool]

PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17

# Transport-layer fields a first fragment carries and later fragments inherit.
_L4_FIELDS = ("icmp_type", "icmp_seq", "dport", "sport", "tcp_sport", "tcp_dport", "tcp_flags", "tcp_window", "tcp_header_len")

_MAX_FRAGMENT_CONTEXT = 50_000  # per interface per window - bounds memory under a fragment flood


def _classify(pkt) -> list[str]:
    from scapy.all import ICMP, IP, TCP, UDP

    if not pkt.haslayer(IP):
        return []

    buckets = []
    ip_layer = pkt[IP]
    proto = int(ip_layer.proto)
    # Offset > 0: a later fragment, so no transport header is visible - fall back to ip.proto.
    trailing = int(ip_layer.frag) > 0

    # IP fragmentation flood: MF flag set, or a non-zero fragment offset.
    if (int(ip_layer.flags) & 0x1) or trailing:
        buckets.append("fragmentation")

    if pkt.haslayer(ICMP) or (trailing and proto == PROTO_ICMP):
        buckets.append("icmp")
    elif pkt.haslayer(UDP) or (trailing and proto == PROTO_UDP):
        buckets.append("udp")
    elif pkt.haslayer(TCP) or (trailing and proto == PROTO_TCP):
        # Every TCP packet, not just bare SYNs - detection/syn.py now builds full bidirectional
        # CICFlowMeter-style flow statistics (needs both directions: the SYN plus any reply
        # traffic), then filters down to flows that actually started with a SYN itself.
        buckets.append("syn")

    return buckets


def build_row(pkt, iface: str) -> dict:
    """Packet metadata the detectors read (never payload)."""
    from scapy.all import IP

    ip_layer = pkt[IP]
    return {
        "time": float(pkt.time),
        "src": ip_layer.src,
        "dst": ip_layer.dst,
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


class FragmentContext:
    """Per-interface, per-window memory that lets later fragments inherit the transport fields of
    their datagram's first fragment. Not thread-shared: one instance per sniff thread."""

    def __init__(self) -> None:
        self.first: dict[tuple, dict] = {}
        self.waiting: dict[tuple, list[dict]] = defaultdict(list)

    def apply(self, pkt, row: dict) -> None:
        from scapy.all import IP

        ip_layer = pkt[IP]
        more_fragments = bool(int(ip_layer.flags) & 0x1)
        offset = int(ip_layer.frag)
        if not (more_fragments or offset):
            return  # not fragmented
        key = (row["src"], row["dst"], int(ip_layer.id), int(ip_layer.proto))

        if offset == 0:  # first fragment: remember its transport fields, back-fill any early arrivals
            if len(self.first) < _MAX_FRAGMENT_CONTEXT:
                fields = {f: row[f] for f in _L4_FIELDS}
                self.first[key] = fields
                for early in self.waiting.pop(key, []):
                    early.update(fields)
            return

        fields = self.first.get(key)
        if fields is not None:
            row.update(fields)
        elif len(self.waiting) < _MAX_FRAGMENT_CONTEXT:
            self.waiting[key].append(row)


def process_packet(pkt, iface: str, is_whitelisted: WhitelistCheck, ctx: FragmentContext) -> tuple[list[str], dict | None]:
    """(buckets, row) for one packet, or ([], None) if it should be ignored."""
    from scapy.all import IP

    if not pkt.haslayer(IP):
        return [], None
    src, dst = pkt[IP].src, pkt[IP].dst
    if is_whitelisted(src) or is_whitelisted(dst):
        return [], None
    buckets = _classify(pkt)
    if not buckets:
        return [], None
    row = build_row(pkt, iface)
    ctx.apply(pkt, row)
    return buckets, row


def _capture_iface(iface: str, window_secs: int, shared: dict, lock: threading.Lock, is_whitelisted: WhitelistCheck):
    try:
        from scapy.all import sniff

        ctx = FragmentContext()

        def handle(pkt):
            try:
                buckets, row = process_packet(pkt, iface, is_whitelisted, ctx)
                if not buckets:
                    return
                with lock:
                    # The same row object goes into every bucket it belongs to, so a later
                    # back-fill (a first fragment arriving after its followers) updates all of them.
                    for bucket in buckets:
                        shared[bucket].append(row)
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
