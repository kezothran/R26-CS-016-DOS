#!/usr/bin/env python3
"""Sentrix Agent - captures this machine's network traffic and ships packet METADATA (addresses,
ports, sizes, flags - never payload) to the Sentrix cloud server, which runs the detection models.

    python sentrix_agent.py enroll --server https://sentrix.example --token sxe_...
    python sentrix_agent.py run                  # normal operation (installed as a service)
    python sentrix_agent.py status [--quiet]     # --quiet: no output, exit code 0 = enrolled and key accepted
    python sentrix_agent.py test-capture         # sniff 3 s and print what was seen
    python sentrix_agent.py selftest             # send a tiny harmless window to the server

Needs raw-capture rights: Administrator (+ Npcap) on Windows, root / CAP_NET_RAW on Linux.
Connects OUTWARD only - no listening ports. It never gives up: if the server or VPN is down it keeps
retrying, queues windows on disk, and replays them when the connection returns. While running it
writes status.json (read by the Sentrix Agent desktop app) and agent.log next to its config.
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import os
import platform
import queue
import socket
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

import requests

VERSION = "1.2.0"
HEARTBEAT_SECS = 30
CONFIG_REFRESH_SECS = 60
STATUS_WRITE_SECS = 2
CONNECTED_GRACE_SECS = 45              # no successful server contact for this long = "reconnecting"
MAX_ROWS_PER_BUCKET = 50_000          # server cap per bucket per window
MAX_QUEUE_FILES = 600                  # ~50 min of 5 s windows kept while the server is unreachable
MAX_QUEUE_BYTES = 200 * 1024 * 1024
MAX_LOG_BYTES = 2 * 1024 * 1024
EXIT_REVOKED = 3                       # service managers are told not to restart on this code


# --------------------------------------------------------------------------- paths / config

def config_dir() -> Path:
    if os.environ.get("SENTRIX_AGENT_HOME"):
        base = Path(os.environ["SENTRIX_AGENT_HOME"])
    elif platform.system() == "Windows":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SentrixAgent"
    else:
        base = Path("/etc/sentrix-agent")
    try:
        base.mkdir(parents=True, exist_ok=True)
        (base / ".w").touch()
        (base / ".w").unlink()
    except OSError:
        base = Path.home() / ".sentrix-agent"
        base.mkdir(parents=True, exist_ok=True)
    return base


HOME = config_dir()
CFG_PATH = HOME / "agent.json"
QUEUE_DIR = HOME / "queue"
STATUS_PATH = HOME / "status.json"
LOG_PATH = HOME / "agent.log"
RECONNECT_FLAG = HOME / "reconnect.flag"   # the desktop app drops this file to ask for an immediate reconnect


def load_config() -> dict:
    if not CFG_PATH.exists():
        sys.exit(f"Not enrolled yet. Run:  python {Path(__file__).name} enroll --server <url> --token <token>")
    return json.loads(CFG_PATH.read_text())


def save_config(cfg: dict) -> None:
    CFG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CFG_PATH, 0o600)  # holds the agent key
    except OSError:
        pass


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > MAX_LOG_BYTES:
            LOG_PATH.replace(LOG_PATH.with_suffix(".log.1"))
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- live state for the desktop app

STATE_LOCK = threading.Lock()
STATE: dict = {
    "state": "starting", "version": VERSION, "name": "", "server": "", "pid": os.getpid(), "started": time.time(),
    "connected": False, "last_ok": 0.0, "last_error": "", "window_packets": 0, "windows_sent": 0,
    "interfaces": [], "window_secs": 5, "dashboard_url": "",
}


def set_state(**kw) -> None:
    with STATE_LOCK:
        STATE.update(kw)


def mark_ok() -> None:
    set_state(last_ok=time.time(), last_error="")


def mark_error(msg: str) -> None:
    set_state(last_error=msg[:160])


def write_status() -> None:
    with STATE_LOCK:
        snap = dict(STATE)
    snap["updated"] = time.time()
    snap["connected"] = snap["state"] == "running" and (time.time() - snap["last_ok"]) <= CONNECTED_GRACE_SECS
    try:
        snap["queued"] = len(list(QUEUE_DIR.glob("*.gz")))
    except OSError:
        snap["queued"] = 0
    try:
        tmp = STATUS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap))
        tmp.replace(STATUS_PATH)
    except OSError:
        pass


def status_loop() -> None:
    while True:
        write_status()
        time.sleep(STATUS_WRITE_SECS)


# --------------------------------------------------------------------------- capture

def _scapy():
    from scapy.all import ICMP, IFACES, IP, TCP, UDP, get_if_addr, get_if_list, sniff
    return ICMP, IFACES, IP, TCP, UDP, get_if_addr, get_if_list, sniff


def list_capture_interfaces() -> list[tuple[str, str]]:
    """(scapy name, friendly label) for every interface with a real, non-loopback IPv4 address."""
    ICMP, IFACES, IP, TCP, UDP, get_if_addr, get_if_list, sniff = _scapy()
    out = []
    for name in get_if_list():
        try:
            addr = get_if_addr(name)
        except Exception:
            continue
        if addr in ("0.0.0.0", "?", "") or addr.startswith("127."):
            continue
        label = name
        try:
            for iv in IFACES.values():
                if iv.name == name or getattr(iv, "network_name", None) == name:
                    label = getattr(iv, "name", None) or getattr(iv, "description", None) or name
                    break
        except Exception:
            pass
        if "loopback" in label.lower():
            continue
        out.append((name, str(label)[:40]))
    return out


PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17

# Transport-layer fields only a datagram's FIRST fragment carries; later fragments inherit them.
_L4_FIELDS = ("icmp_type", "icmp_seq", "dport", "sport", "tcp_sport", "tcp_dport", "tcp_flags", "tcp_window", "tcp_header_len")
_MAX_FRAGMENT_CONTEXT = 50_000


def classify(pkt) -> list[str]:
    """Attack-type buckets for a packet. A fragmented UDP/ICMP/TCP datagram has its transport header
    only in the first fragment, so later fragments (offset > 0) are bucketed by the IP header's
    protocol number instead - otherwise a fragmented UDP flood would reach only the fragmentation
    detector and never the UDP one."""
    ICMP, _, IP, TCP, UDP, *_ = _scapy()
    if not pkt.haslayer(IP):
        return []
    buckets = []
    ip = pkt[IP]
    proto = int(ip.proto)
    trailing = int(ip.frag) > 0
    if (int(ip.flags) & 0x1) or trailing:
        buckets.append("fragmentation")
    if pkt.haslayer(ICMP) or (trailing and proto == PROTO_ICMP):
        buckets.append("icmp")
    elif pkt.haslayer(UDP) or (trailing and proto == PROTO_UDP):
        buckets.append("udp")
    elif pkt.haslayer(TCP) or (trailing and proto == PROTO_TCP):
        buckets.append("syn")
    return buckets


def build_row(pkt, label: str) -> dict:
    """Packet metadata the server's detectors read (never payload)."""
    ICMP, _, IP, TCP, UDP, *_ = _scapy()
    ip = pkt[IP]
    tcp = pkt[TCP] if pkt.haslayer(TCP) else None
    udp = pkt[UDP] if pkt.haslayer(UDP) else None
    icmp = pkt[ICMP] if pkt.haslayer(ICMP) else None
    return {
        "time": float(pkt.time), "src": ip.src, "dst": ip.dst, "length": len(pkt), "iface": label,
        "icmp_type": int(icmp.type) if icmp else None,
        "icmp_seq": int(icmp.seq) if icmp and icmp.seq else 0,
        "dport": int(udp.dport) if udp else (int(tcp.dport) if tcp else 0),
        "sport": int(udp.sport) if udp else (int(tcp.sport) if tcp else 0),
        "proto": int(ip.proto), "ttl": int(ip.ttl), "ip_len": int(ip.len),
        "tcp_sport": int(tcp.sport) if tcp else 0, "tcp_dport": int(tcp.dport) if tcp else 0,
        "tcp_flags": int(tcp.flags) if tcp else 0, "tcp_window": int(tcp.window) if tcp else 0,
        "tcp_header_len": int(tcp.dataofs) * 4 if tcp else 0,
        "tcp_payload_len": len(bytes(tcp.payload)) if tcp else 0,
    }


class FragmentContext:
    """Lets later fragments inherit the transport fields (ports, ICMP type, TCP flags) of their
    datagram's first fragment, matched on (src, dst, IP id, protocol). A fragment that arrives
    before its first fragment is held and back-filled when that one shows up. One instance per
    sniff thread per window."""

    def __init__(self) -> None:
        self.first: dict = {}
        self.waiting: dict = defaultdict(list)

    def apply(self, pkt, row: dict) -> None:
        _, _, IP, *_ = _scapy()
        ip = pkt[IP]
        offset = int(ip.frag)
        if not ((int(ip.flags) & 0x1) or offset):
            return
        key = (row["src"], row["dst"], int(ip.id), int(ip.proto))
        if offset == 0:
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


class Whitelist:
    def __init__(self, data: dict | None = None):
        self.update(data or {})

    def update(self, data: dict) -> None:
        self.ips = set(data.get("ips", []))
        self.nets = []
        for n in data.get("networks", []):
            try:
                self.nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass

    def has(self, ip: str) -> bool:
        if ip in self.ips:
            return True
        if not self.nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.nets)


def process_packet(pkt, label: str, wl: "Whitelist", ctx: FragmentContext):
    """(buckets, row) for one packet, or ([], None) if it should be ignored."""
    _, _, IP, *_ = _scapy()
    if not pkt.haslayer(IP):
        return [], None
    if wl.has(pkt[IP].src) or wl.has(pkt[IP].dst):
        return [], None
    buckets = classify(pkt)
    if not buckets:
        return [], None
    row = build_row(pkt, label)
    ctx.apply(pkt, row)
    return buckets, row


def capture_window(ifaces: list[tuple[str, str]], secs: int, wl: Whitelist) -> dict[str, list[dict]]:
    ICMP, IFACES, IP, TCP, UDP, get_if_addr, get_if_list, sniff = _scapy()
    shared: dict[str, list[dict]] = defaultdict(list)
    lock = threading.Lock()

    def worker(name: str, label: str):
        ctx = FragmentContext()

        def handle(pkt):
            try:
                buckets, row = process_packet(pkt, label, wl, ctx)
                if not buckets:
                    return
                with lock:
                    # one shared row object per packet, so a late back-fill reaches every bucket
                    for b in buckets:
                        if len(shared[b]) < MAX_ROWS_PER_BUCKET:
                            shared[b].append(row)
            except Exception:
                pass
        try:
            sniff(filter="ip", prn=handle, timeout=secs, store=False, iface=name)
        except Exception as exc:
            log(f"capture on {label} failed: {exc}")

    threads = [threading.Thread(target=worker, args=i, daemon=True) for i in ifaces]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=secs + 3)
    return dict(shared)


# --------------------------------------------------------------------------- server I/O

class Server:
    def __init__(self, cfg: dict):
        self.base = cfg["server"].rstrip("/")
        self.s = requests.Session()
        self.s.headers["X-Agent-Key"] = cfg["agent_key"]
        self.s.headers["User-Agent"] = f"SentrixAgent/{VERSION}"

    def get(self, path: str, **kw):
        return self.s.get(self.base + path, timeout=15, **kw)

    def post(self, path: str, **kw):
        return self.s.post(self.base + path, timeout=30, **kw)


def die_if_revoked(resp: requests.Response) -> None:
    if resp.status_code in (401, 403):
        try:
            detail = resp.json().get("detail", "")
        except ValueError:
            detail = ""
        log(f"Server rejected this agent ({resp.status_code}: {detail}). It was revoked or deleted - stopping.")
        set_state(state="revoked", connected=False, last_error=f"Rejected by server: {detail}")
        write_status()
        os._exit(EXIT_REVOKED)


def pack(window_secs: int, buckets: dict) -> bytes:
    return gzip.compress(json.dumps({"window_secs": window_secs, "buckets": buckets}, separators=(",", ":")).encode(), 3)


class Sender(threading.Thread):
    """Posts windows to the server in order; failed ones are spooled to disk and replayed first."""

    def __init__(self, server: Server):
        super().__init__(daemon=True)
        self.server = server
        self.q: "queue.Queue[bytes]" = queue.Queue(maxsize=50)
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        self.sent = 0
        self.last_error = ""

    def submit(self, body: bytes) -> None:
        try:
            self.q.put_nowait(body)
        except queue.Full:
            self._spool(body)

    def _spool(self, body: bytes) -> None:
        files = sorted(QUEUE_DIR.glob("*.gz"))
        total = sum(f.stat().st_size for f in files)
        while files and (len(files) >= MAX_QUEUE_FILES or total + len(body) > MAX_QUEUE_BYTES):
            total -= files[0].stat().st_size
            files.pop(0).unlink(missing_ok=True)  # drop the oldest window first
        (QUEUE_DIR / f"{time.time_ns()}.gz").write_bytes(body)

    def _post(self, body: bytes) -> bool:
        try:
            r = self.server.post("/agent/v1/windows", data=body, headers={"Content-Encoding": "gzip", "Content-Type": "application/json"})
        except requests.RequestException as exc:
            self.last_error = str(exc)[:120]
            mark_error("Server unreachable - is the VPN connected?")
            return False
        die_if_revoked(r)
        if r.status_code >= 500 or r.status_code == 429:
            self.last_error = f"server {r.status_code}"
            mark_error(f"Server busy or restarting ({r.status_code})")
            return False
        if r.status_code >= 400:
            log(f"server refused a window ({r.status_code}): {r.text[:120]} - dropping it")
        self.sent += 1
        self.last_error = ""
        set_state(windows_sent=self.sent)
        mark_ok()
        return True

    def replay(self) -> None:
        for f in sorted(QUEUE_DIR.glob("*.gz"))[:20]:
            if not self._post(f.read_bytes()):
                return
            f.unlink(missing_ok=True)

    def run(self) -> None:
        while True:
            try:
                body = self.q.get(timeout=5)
            except queue.Empty:
                self.replay()
                continue
            self.replay()
            if not self._post(body):
                self._spool(body)


# --------------------------------------------------------------------------- commands

def cmd_enroll(args) -> None:
    ifaces = []
    try:
        ifaces = [label for _, label in list_capture_interfaces()]
    except Exception:
        pass
    host = args.name or socket.gethostname()
    try:
        r = requests.post(args.server.rstrip("/") + "/agent/v1/enroll", timeout=20, json={
            "token": args.token, "hostname": host, "os": f"{platform.system()} {platform.release()}",
            "version": VERSION, "interfaces": ifaces,
        })
    except requests.RequestException as exc:
        sys.exit(f"Cannot reach {args.server}: {exc}\nIs the VPN connected?")
    if r.status_code != 200:
        sys.exit(f"Enrolment failed ({r.status_code}): {r.json().get('detail', r.text)}")
    d = r.json()
    save_config({"server": args.server.rstrip("/"), "agent_id": d["agent_id"], "agent_key": d["agent_key"], "name": d["name"]})
    log(f"Enrolled as '{d['name']}' ({d['agent_id']}). Config saved to {CFG_PATH}")


def cmd_run(args) -> None:
    cfg = load_config()
    server = Server(cfg)
    wl = Whitelist()
    window = 5
    set_state(name=cfg["name"], server=cfg["server"], state="starting")
    threading.Thread(target=status_loop, daemon=True).start()

    def refresh_config():
        nonlocal window
        r = server.get("/agent/v1/config")
        die_if_revoked(r)
        if r.status_code == 200:
            d = r.json()
            window = int(d.get("window_secs", 5))
            wl.update(d.get("whitelist", {}))
            set_state(window_secs=window, dashboard_url=d.get("dashboard_url", ""))
            mark_ok()

    # Never give up on the first contact: keep retrying (the VPN may still be starting at boot).
    while True:
        try:
            refresh_config()
            break
        except requests.RequestException as exc:
            mark_error("Server unreachable - is the VPN connected?")
            log(f"Server not reachable yet ({str(exc)[:80]}); retrying in 10 s.")
            time.sleep(10)

    ifaces = []
    while not ifaces:
        try:
            ifaces = list_capture_interfaces()
        except Exception as exc:
            log(f"Cannot list interfaces ({exc}) - need Administrator/root and Npcap on Windows. Retrying in 30 s.")
            mark_error("Cannot capture: needs Administrator + Npcap")
        if not ifaces:
            time.sleep(30)
    set_state(state="running", interfaces=[l for _, l in ifaces])
    log(f"Agent {VERSION} '{cfg['name']}' capturing on: {', '.join(l for _, l in ifaces)} | window {window}s | server {cfg['server']}")

    sender = Sender(server)
    sender.start()

    def beat():
        while True:
            try:
                r = server.post("/agent/v1/heartbeat", json={"version": VERSION, "interfaces": [l for _, l in ifaces]})
                die_if_revoked(r)
                if r.status_code == 200:
                    mark_ok()
            except requests.RequestException:
                mark_error("Server unreachable - is the VPN connected?")
            for _ in range(HEARTBEAT_SECS):
                if RECONNECT_FLAG.exists():
                    break
                time.sleep(1)

    threading.Thread(target=beat, daemon=True).start()

    last_cfg = time.time()
    n = 0
    while True:
        started = time.time()
        buckets = capture_window(ifaces, window, wl)
        total = sum(len(v) for v in buckets.values())
        set_state(window_packets=total)
        sender.submit(pack(window, buckets))
        n += 1
        if n % 12 == 0:
            spooled = len(list(QUEUE_DIR.glob("*.gz")))
            log(f"window {n}: {total} packets this window | sent {sender.sent} | queued {spooled}" + (f" | last error: {sender.last_error}" if sender.last_error else ""))
        reconnect = RECONNECT_FLAG.exists()
        if reconnect:
            try:
                RECONNECT_FLAG.unlink()
            except OSError:
                pass
            log("Reconnect requested from the desktop app.")
        if reconnect or time.time() - last_cfg > CONFIG_REFRESH_SECS:
            try:
                refresh_config()
                if reconnect:
                    threading.Thread(target=sender.replay, daemon=True).start()
            except requests.RequestException:
                mark_error("Server unreachable - is the VPN connected?")
            last_cfg = time.time()
        # capture_window already took ~`window` seconds; guard against a failing interface returning instantly
        if time.time() - started < 0.5:
            time.sleep(window)


def cmd_status(args) -> None:
    quiet = getattr(args, "quiet", False)
    if not CFG_PATH.exists():
        if not quiet:
            print("not enrolled")
        sys.exit(1)
    cfg = json.loads(CFG_PATH.read_text())
    try:
        r = Server(cfg).get("/agent/v1/config")
    except requests.RequestException as exc:
        if not quiet:
            print(f"agent {cfg['name']} ({cfg['agent_id']}) -> {cfg['server']}\nserver NOT reachable: {exc}")
        sys.exit(2)
    ok = r.status_code == 200
    if not quiet:
        print(f"agent {cfg['name']} ({cfg['agent_id']}) -> {cfg['server']}")
        print("server reachable, key accepted" if ok else f"server answered {r.status_code}: {r.text[:120]}")
        print(f"spooled windows waiting to send: {len(list(QUEUE_DIR.glob('*.gz')))}")
    sys.exit(0 if ok else 3)


def cmd_test_capture(args) -> None:
    ifaces = list_capture_interfaces()
    print("interfaces:", ", ".join(l for _, l in ifaces) or "none found")
    b = capture_window(ifaces, 3, Whitelist())
    print({k: len(v) for k, v in b.items()} or "no IP traffic seen in 3 s")


def cmd_selftest(args) -> None:
    cfg = load_config()
    now = time.time()
    rows = [{
        "time": now + i * 0.5, "src": "192.0.2.10", "dst": "192.0.2.20", "length": 98, "iface": "selftest", "icmp_type": 8,
        "icmp_seq": i, "dport": 0, "sport": 0, "proto": 1, "ttl": 64, "ip_len": 84, "tcp_sport": 0, "tcp_dport": 0,
        "tcp_flags": 0, "tcp_window": 0, "tcp_header_len": 0, "tcp_payload_len": 0,
    } for i in range(3)]  # 3 echo requests - far below any flood threshold
    r = Server(cfg).post("/agent/v1/windows", data=pack(5, {"icmp": rows}), headers={"Content-Encoding": "gzip", "Content-Type": "application/json"})
    print(r.status_code, r.text)


def main() -> None:
    p = argparse.ArgumentParser(description="Sentrix Agent")
    p.add_argument("--version", action="version", version=f"sentrix-agent {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--server", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--name")
    s = sub.add_parser("status")
    s.add_argument("--quiet", action="store_true")
    for name in ("run", "test-capture", "selftest"):
        sub.add_parser(name)
    args = p.parse_args()
    {"enroll": cmd_enroll, "run": cmd_run, "status": cmd_status, "test-capture": cmd_test_capture, "selftest": cmd_selftest}[args.cmd](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
