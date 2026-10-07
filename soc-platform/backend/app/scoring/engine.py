"""Orchestrates Stages 1-4 of the Severity Scoring Engine once per detection cycle. Hooked
into app/detection/loop.py rather than run as a separate async loop, since that loop already
runs on a short window, already holds an open DB session pattern (see _persist_alerts), and
already has every attack type's flagged rows in memory for this cycle - a second independent
tick loop would just duplicate that.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update

from app.db.base import SessionLocal
from app.db.models import Alert, BlockAction, Incident, SecurityScore, Snapshot
from app.notify import notify_critical_sync
from app.scoring import aggregate, correlation, event_scorer, incident_scorer

logger = logging.getLogger("soc")

CRITICAL_BLOCK_REASON = "Incident reached Critical severity (auto-proposed, dry-run only)"


def _build_events(all_atk_rows: dict[str, list[dict]], cfg: dict, now: datetime) -> list[dict]:
    events = []
    for attack_type, rows in all_atk_rows.items():
        if attack_type not in cfg["scoring_weights"]:
            continue
        for r in rows:
            raw_score, normalized_impact, tier = event_scorer.score_event(attack_type, r["n_packets"], cfg, confidence=r.get("hp"))
            events.append({
                "attack_type": attack_type,
                "src_ip": r["src"],
                "interface": r.get("iface", "?"),
                "alert_id": r.get("alert_id"),
                "raw_score": raw_score,
                "normalized_impact": normalized_impact,
                "tier": tier,
                "detected_at": now,
            })
    return events


async def _propose_block_actions(session, incident: dict) -> None:
    """Auto-proposes a dry-run block for each src_ip in a Critical-tier incident, unless one is
    already proposed/executed for that IP. Never fires a real firewall/network change - see
    backend/app/api/block_actions.py for the (also dry-run) "execute" endpoint.

    One query for every src_ip at once (not one query per src_ip) - this runs every cycle for
    as long as an incident stays Critical, so a multi-source incident used to mean a
    round-trip per source per cycle.
    """
    if incident["tier"] != "Critical":
        return
    src_ips = list(incident["src_ips"])
    if not src_ips:
        return
    existing = await session.execute(
        select(BlockAction.src_ip).where(
            BlockAction.src_ip.in_(src_ips),
            BlockAction.status.in_(["proposed", "executed_simulated"]),
        )
    )
    already_proposed = {row[0] for row in existing.all()}
    for src_ip in src_ips:
        if src_ip in already_proposed:
            continue
        session.add(BlockAction(
            src_ip=src_ip, incident_id=incident["id"], reason=CRITICAL_BLOCK_REASON, status="proposed",
        ))


async def _persist(
    upserts: list[tuple[dict, bool, set[str]]], resolved_ids: list[str], score: float, tier: str, active_list: list[dict],
    snapshot_ctx: dict,
) -> None:
    async with SessionLocal() as session:
        for incident, is_new, group_alert_ids in upserts:
            if is_new:
                row = Incident(
                    id=incident["id"],
                    attack_types=sorted(incident["attack_types"]),
                    correlation_confidence=incident["confidence"],
                    combined_impact=incident["combined_impact"],
                    tier=incident["tier"],
                    src_ips=sorted(incident["src_ips"]),
                    iface=incident["interface"],
                    first_seen=incident["first_seen"],
                    last_seen=incident["last_seen"],
                    status="active",
                )
                session.add(row)

                # Auto-snapshot the live dashboard state the moment a Critical incident is born -
                # captures what the analyst would have seen at the time, for later reference even
                # after the incident decays out of the active list.
                if incident["tier"] == "Critical":
                    session.add(Snapshot(
                        label=f"Auto: Critical incident ({', '.join(sorted(incident['attack_types']))})",
                        trigger="auto_incident",
                        incident_id=incident["id"],
                        security_score=score,
                        security_tier=tier,
                        active_incident_count=len(active_list),
                        total_packets=snapshot_ctx["total_packets"],
                        attacks=snapshot_ctx["attacks"],
                        live_flows=snapshot_ctx["live_flows"],
                    ))
            else:
                # Direct bulk UPDATE, no fetch-then-mutate round-trip first - the in-memory
                # aggregate dict (app/scoring/aggregate.py) already carries every field this
                # cycle needs to write, so a SELECT here would only tell us what we already
                # know. This ran once per already-tracked active incident, every single cycle -
                # with 8+ active incidents (routine during a real attack) that's 8+ extra
                # round-trips per cycle to a remote DB, confirmed as the dominant contributor to
                # cycles averaging 15s against a nominal 5s capture window (2026-08-13).
                await session.execute(
                    update(Incident).where(Incident.id == incident["id"]).values(
                        attack_types=sorted(incident["attack_types"]),
                        correlation_confidence=incident["confidence"],
                        combined_impact=incident["combined_impact"],
                        tier=incident["tier"],
                        src_ips=sorted(incident["src_ips"]),
                        last_seen=incident["last_seen"],
                    )
                )

            if group_alert_ids:
                await session.execute(
                    update(Alert).where(Alert.id.in_(list(group_alert_ids))).values(incident_id=incident["id"])
                )

            await _propose_block_actions(session, incident)

            # Fires at most once per incident, guarded by the in-memory `notified` flag (see
            # aggregate.py::mark_notified) instead of a DB fetch-and-check - app/notify.py
            # no-ops if unconfigured; wrapped in to_thread since smtplib/requests are blocking
            # and this must never stall the detection loop.
            if incident["tier"] == "Critical" and not incident.get("notified", False):
                await asyncio.to_thread(notify_critical_sync, incident)
                aggregate.mark_notified(incident["id"])
                await session.execute(
                    update(Incident).where(Incident.id == incident["id"]).values(notified_at=datetime.now(timezone.utc))
                )

        if resolved_ids:
            # One statement for every incident that idled out this cycle, instead of a
            # fetch-then-mutate per incident.
            await session.execute(
                update(Incident)
                .where(Incident.id.in_(resolved_ids), Incident.status == "active")
                .values(status="resolved")
            )

        details = {
            "tier": tier,
            "active_incident_count": len(active_list),
            "contributing": [
                {"incident_id": i["incident_id"], "impact": i["combined_impact"], "attack_types": i["attack_types"]}
                for i in active_list
            ],
        }
        session.add(SecurityScore(target="aggregate", score=score, details=details))

        await session.commit()


async def process_cycle(all_atk_rows: dict[str, list[dict]], cfg: dict, snapshot_ctx: dict) -> dict:
    now = datetime.now(timezone.utc)

    events = _build_events(all_atk_rows, cfg, now)
    groups = correlation.group_correlated_events(events, cfg["scoring_correlation_time_window_sec"])

    upserts = []
    for group in groups:
        combined_impact, confidence, tier = incident_scorer.combined_incident_score(group, cfg)
        incident, is_new = aggregate.upsert_incident(group, combined_impact, confidence, tier, now)
        group_alert_ids = {e["alert_id"] for e in group if e.get("alert_id")}
        upserts.append((incident, is_new, group_alert_ids))

    score, tier, active_list, resolved_ids = aggregate.prune_and_score(cfg, now)
    await _persist(upserts, resolved_ids, score, tier, active_list, snapshot_ctx)

    return {"score": score, "tier": tier, "active_incidents": active_list}


async def resolve_orphaned_incidents() -> None:
    """Called once from app/main.py's startup hook. aggregate._active (the in-memory
    active-incident tracker) always starts empty on process start, so any Incident row still
    marked status="active" in the DB at this point is guaranteed orphaned - it belonged to a
    previous process lifetime that exited (e.g. a restart) before its incident naturally idled
    out via prune_and_score. Left alone, these sit at "active" forever since nothing will ever
    revisit that specific row again (a recurrence gets a fresh id, not this one).
    """
    async with SessionLocal() as session:
        result = await session.execute(select(Incident).where(Incident.status == "active"))
        rows = result.scalars().all()
        for row in rows:
            row.status = "resolved"
        if rows:
            await session.commit()
            logger.info("Resolved %d orphaned active incident(s) from a previous run.", len(rows))
