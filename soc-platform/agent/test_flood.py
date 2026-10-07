#!/usr/bin/env python3
"""Capped test-traffic generator (no hping3/VM needed - uses scapy, already installed for the backend).

Sends a FIXED, SMALL number of packets to one target, then stops. Not an open-ended flood.
Run as Administrator (Windows) / root (Linux).

    python test_flood.py icmp   <target-ip>
    python test_flood.py syn    <target-ip> [port]
    python test_flood.py udp    <target-ip> [port]
    python test_flood.py frag   <target-ip>

Only use this against a machine you own or have explicit permission to test.
"""
import random
import sys
import time

from scapy.all import IP, ICMP, TCP, UDP, Raw, send

COUNT = 3000       # packets sent, then it stops - not unlimited
DELAY = 0.002       # seconds between packets (~2ms, matches hping3 -i u2000)


def run(build):
    t0 = time.time()
    for i in range(COUNT):
        send(build(i), verbose=False)
        time.sleep(DELAY)
        if i % 500 == 0 and i:
            print(f"  {i}/{COUNT} sent...")
    print(f"Done: {COUNT} packets in {time.time() - t0:.1f}s")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    kind, target = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else (80 if kind == "syn" else 9999)

    print(f"Sending {COUNT} {kind.upper()} packets to {target} (capped test, not a sustained attack)")
    if kind == "icmp":
        run(lambda i: IP(dst=target) / ICMP())
    elif kind == "syn":
        run(lambda i: IP(dst=target) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S"))
    elif kind == "udp":
        run(lambda i: IP(dst=target) / UDP(sport=random.randint(1024, 65535), dport=port) / Raw(b"x" * 64))
    elif kind == "frag":
        run(lambda i: IP(dst=target, flags="MF", frag=0) / Raw(b"x" * 64))
    else:
        sys.exit(f"Unknown type '{kind}' - use icmp, syn, udp or frag")


if __name__ == "__main__":
    main()
