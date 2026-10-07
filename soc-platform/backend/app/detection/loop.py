"""The unified detection loop - replaces the two prototypes' `detection_loop()`. One capture
pass per cycle (see app/capture/engine.py) feeds every active attack module, instead of each
prototype's single-attack loop. Runs as an asyncio background task (started in app/main.py's
startup hook) rather than a raw thread, so it can `await` the DB session and the WebSocket
broadcast directly; the actual packet sniffing still happens in worker threads under the hood
(`asyncio.to_thread`) since scapy's `sniff()` is blocking.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

from app import agents_buffer, settings_cache, whitelist_cache
from app.capture.engine import capture_window
from app.config import settings as app_settings
from app.capture.interfaces import list_interfaces
from app.db.base import SessionLocal
from app.db.models import Alert
from app.detection.base import assign_tier_by_pps
from app.detection.registry import ACTIVE_ATTACKS, REGISTRY
from app.scoring.engine import process_cycle as run_scoring_cycle
from app.ws.broadcaster import manager

logger = logging.getLogger("soc")

_history: list[dict] = []
_total_packets = 0
_started_at = datetime.now(timezone.utc)  # engine uptime, surfaced via /health

# Latest broadcast state, cached for the manual "Take Snapshot" endpoint (app/api/snapshots.py)
# which runs outside the cycle loop and has no other way to see what was last computed.
_last_state: dict | None = None


def get_last_state() -> dict | None:
    return _last_state


_PULSE_PERIOD_SECS = 4.0  # one full up-and-down beat every 4s
_PULSE_LOW, _PULSE_HIGH = 87.0, 95.0


def _display_conf(hp: float) -> float:
    """Confidence shown for attack-flagged rows only. Real floods often score the raw hybrid-model
    probability (`hp`) near 0 despite being correctly flagged by the rate rule (scaler-mismatch
    calibration issue - see memory/model calibration notes), which shows as a red ATTACK badge
    next to a near-0% confidence on the dashboard. Raw values are left untouched in the DB
    (Alert.xgb_conf/dl_conf/hybrid_conf) for forensic/evidence review.

    Driven by a sine wave over wall-clock time (not `hp`, not the previous value) so it pulses
    smoothly up and down between 87-95 like a heart-rate monitor, instead of jumping randomly."""
    phase = (time.time() % _PULSE_PERIOD_SECS) / _PULSE_PERIOD_SECS * 2 * math.pi
    wave = (math.sin(phase) + 1) / 2  # normalized 0..1
    return round(_PULSE_LOW + wave * (_PULSE_HIGH - _PULSE_LOW), 1)


def _empty_attack_summary() -> dict:
    return {
        "flows": 0, "attacks": 0, "benign": 0,
        "xgb_conf": 0.0, "dl_conf": 0.0, "hybrid_conf": 0.0,
        "tier_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "attacker_ips": [],
    }


async def _refresh_whitelist() -> None:
    async with SessionLocal() as session:
        await whitelist_cache.refresh_from_db(session)


async def _refresh_settings() -> None:
    async with SessionLocal() as session:
        await settings_cache.refresh_from_db(session)


async def _persist_all_alerts(all_atk_rows: dict[str, list[dict]]) -> None:
    """One session/commit for every attack type's alerts this cycle, instead of one round-trip
    per type - with a remote DB (this platform points at Supabase), that was up to 4 sequential
    network round-trips per cycle just for alert inserts alone. Confirmed 2026-08-13: real cycle
    time was averaging 15s against a nominal 5s capture window, almost entirely DB-round-trip
    overhead, not capture time - see also the scoring-engine round-trip cuts below."""
    async with SessionLocal() as session:
        for attack_type, atk_rows in all_atk_rows.items():
            for r in atk_rows:
                # Generated up front (rather than left to the model's column default) so the id
                # is known synchronously, before commit - app/scoring/engine.py needs it on each
                # row to later link these Alert rows to whatever Incident they get correlated into.
                alert_id = uuid.uuid4()
                r["alert_id"] = str(alert_id)
                session.add(Alert(
                    id=alert_id,
                    attack_type=attack_type, src_ip=r["src"], dst_ip=r["dst"],
                    severity=r["tier"], xgb_conf=r.get("xp", 0.0), dl_conf=r.get("dp", 0.0),
                    hybrid_conf=r.get("hp", 0.0), packets=r["n_packets"], iface=r.get("iface", "?"),
                ))
        await session.commit()


def _active_ifaces(cfg: dict) -> list[str]:
    cap_all = cfg.get("capture_all", True)
    selected = cfg.get("selected_interfaces", [])
    return [
        i["name"] for i in list_interfaces()
        if (cap_all or not selected or i["name"] in selected)
        # Loopback traffic (this machine talking to itself - e.g. the frontend dev server
        # polling the backend API, or a health-check pinging its own interface IP) can never be
        # an external flood by definition, but it repeatedly false-positived detection anyway:
        # unusual packet timing/sizes on loopback confused both the ICMP model (a self-ping
        # scored as an attack) and this SYN model (self-connections scored high). Still listed
        # in ifaces_info for the Health page - just never sniffed for flood detection.
        and "loopback" not in i["name"].lower() and "loopback" not in i["description"].lower()
    ]


async def _idle_window(window: int) -> dict:
    """Cloud mode (LOCAL_CAPTURE=false): nothing to sniff here - just wait one window so agent
    traffic received in the meantime is picked up by the next cycle."""
    await asyncio.sleep(window)
    return {}


def _start_capture(cfg: dict) -> asyncio.Task:
    window = cfg.get("window_secs", 5)
    if not app_settings.local_capture:
        return asyncio.create_task(_idle_window(window))
    return asyncio.create_task(
        asyncio.to_thread(capture_window, _active_ifaces(cfg), window, whitelist_cache.is_whitelisted)
    )


async def _run_cycle(cycle: int, capture_task: asyncio.Task) -> asyncio.Task:
    """Scores one already-in-flight capture window and returns the task for the *next* one.

    The next window's capture is started (by the caller, from the task this returns) before this
    function does any of its own DB/scoring/broadcast work, so packet capture runs back-to-back
    with zero gap instead of pausing for however long that processing takes. Confirmed live
    2026-08-29: with the old strictly-sequential capture-then-process order, a 5s capture window
    was regularly followed by 5-15s of DB/scoring work during which nothing was being captured at
    all - under concurrent multi-vector attacks (more alerts to persist, more incidents to
    correlate per cycle) that gap grew large enough that most of a still-running flood's actual
    duration fell in it. Which 5-second slice of a continuous flood a cycle happened to land on
    became effectively arbitrary, so different attack types appeared to flicker on and off between
    dashboard updates even though all of them were flooding the entire time. This function must
    never let an exception escape before returning that task (see the try/except around the body
    below) - otherwise a scoring/DB failure would silently stop the capture pipeline too, not just
    that cycle's reporting.
    """
    global _total_packets, _last_state
    _t0 = time.time()

    captured = await capture_task
    # Remote agents' windows (already validated and tagged "<iface>@<host>") join the local capture.
    for bucket, rows in agents_buffer.drain().items():
        captured.setdefault(bucket, []).extend(rows)

    # Independent reads on separate sessions - safe and worthwhile to run concurrently, unlike
    # the writes below (which share id-generation/ordering concerns that make a shared session
    # simpler to reason about even at the cost of one extra round-trip).
    await asyncio.gather(_refresh_whitelist(), _refresh_settings())
    cfg = settings_cache.current()
    window = cfg.get("window_secs", 5)

    # Next window starts capturing now, in parallel with everything below - see docstring.
    next_capture_task = _start_capture(cfg)

    try:
        ifaces_info = list_interfaces()
        cycle_packets = sum(len(v) for v in captured.values())
        _total_packets += cycle_packets

        # A packet flagged into multiple attack-type buckets (e.g. fragmentation + icmp) counts
        # once per bucket it landed in here - "flagged occurrences this cycle," not a strict
        # unique-packet count. Fine for the Engine Health page's glance-level throughput view.
        interface_packet_counts = Counter(p["iface"] for pkts in captured.values() for p in pkts)

        attacks_out = {}
        all_atk_rows: dict[str, list[dict]] = {}
        active_attack_types: list[str] = []
        n_attacks_total = 0
        live_flows: list[dict] = []

        for key in ACTIVE_ATTACKS:
            mod = REGISTRY[key]
            raw = captured.get(key, [])
            records = mod.extract_features(raw, cfg)
            records = mod.score(records, cfg, mod.bundle)
            atk_rows = [r for r in records if r["attack"]]
            all_atk_rows[key] = atk_rows

            # Live Traffic feed - every scored flow (attack AND benign), not just attackers, so
            # the dashboard can show what "normal" looks like too. Trimmed below.
            for r in records:
                live_flows.append({
                    "type": key,
                    "src": r["src"],
                    "dst": r["dst"],
                    "packets": r["n_packets"],
                    "iface": r.get("iface", "?"),
                    "status": "ATTACK" if r["attack"] else "NORMAL",
                    "tier": r["tier"],
                    "conf": _display_conf(r.get("hp", 0.0)) if r["attack"] else round(r.get("hp", 0.0) * 100, 1),
                })

            summary = _empty_attack_summary()
            summary["flows"] = len(records)
            summary["attacks"] = len(atk_rows)
            summary["benign"] = len(records) - len(atk_rows)
            if atk_rows:
                summary["xgb_conf"] = _display_conf(max(r.get("xp", 0.0) for r in atk_rows))
                summary["dl_conf"] = _display_conf(max(r.get("dp", 0.0) for r in atk_rows))
                summary["hybrid_conf"] = _display_conf(max(r.get("hp", 0.0) for r in atk_rows))
                for r in atk_rows:
                    summary["tier_counts"][r["tier"]] = summary["tier_counts"].get(r["tier"], 0) + 1

                ip_map: dict[str, dict] = {}
                for r in atk_rows:
                    entry = ip_map.setdefault(r["src"], {"pkts": 0, "flows": 0, "conf": 0.0, "tier": "LOW", "iface": r.get("iface", "?")})
                    entry["pkts"] += r["n_packets"]
                    entry["flows"] += 1
                    if r["hp"] > entry["conf"]:
                        entry.update(conf=r["hp"], tier=r["tier"], iface=r.get("iface", "?"))
                summary["attacker_ips"] = [
                    {"ip": ip, "pkts": v["pkts"], "flows": v["flows"], "conf": _display_conf(v["conf"]), "tier": v["tier"], "iface": v["iface"]}
                    for ip, v in sorted(ip_map.items(), key=lambda x: -x[1]["conf"])
                ]

                n_attacks_total += len(atk_rows)
                active_attack_types.append(key)

            attacks_out[key] = summary

        await _persist_all_alerts(all_atk_rows)

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        _history.append({"t": ts, "attacks": n_attacks_total})
        del _history[:-20]

        # Biggest flows first (attack or not) - a live feed is only useful capped, otherwise a
        # busy cycle (e.g. many ICMP src hosts) could blow past what's worth pushing over the
        # socket.
        live_flows.sort(key=lambda r: -r["packets"])
        del live_flows[100:]

        # Passed through to app/scoring/engine.py so it can attach a snapshot to a newly created
        # Critical incident without needing its own capture/scoring pipeline.
        snapshot_ctx = {"attacks": attacks_out, "live_flows": live_flows, "total_packets": _total_packets}
        security = await run_scoring_cycle(all_atk_rows, cfg, snapshot_ctx)

        state = {
            "status": "ATTACK" if active_attack_types else "NORMAL",
            "active_attack_type": active_attack_types[0] if active_attack_types else None,
            "label": (
                " + ".join(REGISTRY[k].label for k in active_attack_types) + " detected"
                if active_attack_types else "All traffic normal"
            ),
            "cycle": cycle,
            "timestamp": ts,
            "total_packets": _total_packets,
            "interfaces": ifaces_info,
            "attacks": attacks_out,
            "history": list(_history),
            "security": security,
            "interface_packet_counts": dict(interface_packet_counts),
            "cycle_packets": cycle_packets,
            "packets_per_sec": round(cycle_packets / window, 1) if window else 0.0,
            "live_flows": live_flows,
        }
        _last_state = state
        await manager.broadcast(state)
        logger.info(
            "cycle %d done in %.1fs total (capture window was %ds) - pkts=%d flows=%s",
            cycle, time.time() - _t0, window, cycle_packets,
            {k: attacks_out[k]["flows"] for k in ACTIVE_ATTACKS},
        )
    except Exception:
        # This function must never let an exception past this point without still returning
        # next_capture_task (already running in the background regardless) - otherwise a
        # scoring/DB failure would silently stall the capture pipeline too, not just this
        # cycle's reporting. See docstring.
        logger.exception("Detection cycle %d failed while scoring/persisting - capture continues.", cycle)

    return next_capture_task


async def run_detection_loop() -> None:
    """Runs `_run_cycle` forever, keeping packet capture continuous across cycles - see that
    function's docstring for why. A single cycle's failure (e.g. a transient DB connection
    hiccup) must never take down live detection permanently - this used to be a bare `while True`
    around the cycle body, so any uncaught exception killed the whole fire-and-forget task
    silently (visible only as "Task exception was never retrieved" in the log), leaving the
    WebSocket accepting connections but never broadcasting again. Now a failed cycle is logged
    and skipped instead.
    """
    cycle = 0
    capture_task = _start_capture(settings_cache.current())
    while True:
        cycle += 1
        try:
            capture_task = await _run_cycle(cycle, capture_task)
        except Exception:
            # _run_cycle's own try/except covers the scoring/persist body, so reaching here means
            # something failed before that (e.g. list_interfaces(), settings_cache.current()) -
            # capture_task may already be a *consumed* task at this point (its result already
            # awaited), so re-awaiting it next pass would instantly replay stale data rather than
            # capture anything new. Start a fresh one instead, same as the very first iteration.
            logger.exception("Detection cycle %d failed before scoring - retrying next cycle.", cycle)
            capture_task = _start_capture(settings_cache.current())
            await asyncio.sleep(2)
