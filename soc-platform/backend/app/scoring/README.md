# Severity Scoring Engine

Runs once per detection cycle, hooked into `app/detection/loop.py` (see `engine.py::process_cycle`,
which is the entry point). Takes every attack module's flagged rows for the cycle and turns them
into a live 0–100 security score plus a queryable incident list. Four stages, each in its own
module:

```
Stage 1  event_scorer.py     per-flow raw score -> normalized impact -> tier
Stage 2  correlation.py      group this cycle's events into incidents (connected components)
Stage 3  incident_scorer.py  combine each group's impacts into one incident score/tier
Stage 4  aggregate.py        merge incidents into the active set, decay, produce 0-100 score
```

All tunables below live in `app/settings_cache.py::DEFAULTS` (keys prefixed `scoring_`),
overridable per-deployment via the `settings` table / admin settings UI — values shown are the
current defaults.

## Stage 1 — per-event score (`event_scorer.score_event`)

Generalizes the original UDP-flood WSM formula (`score = packet_count * weight`) to every attack
type. For one detected flow (`attack_type`, `packet_count`):

```
raw_score        = packet_count * weight[attack_type]
normalized_impact = min(raw_score / normalization[attack_type], impact_cap[attack_type])
tier              = classify_tier(attack_type, raw_score)   # Low / Medium / High / Critical
```

Default weights, normalization divisors, and impact caps:

| attack_type | weight | normalization | impact_cap |
|---|---|---|---|
| icmp | 1.5 | 1200 | 30 |
| syn | 3.0 | 700 | 40 |
| fragmentation | 2.0 | 900 | 35 |
| udp | 2.5 | 1000 | 40 |

`normalized_impact` is what every later stage operates on — it's `raw_score` rescaled to roughly
a 0–impact_cap range so attack types with very different packet-count profiles (e.g. SYN vs UDP)
contribute comparably to a combined/aggregate score instead of whichever type produces the
biggest raw packet counts dominating by construction.

`tier` here is a **per-event** classification against `scoring_tier_boundaries[attack_type]`
(raw_score thresholds, not normalized_impact):

| attack_type | Low ≤ | Medium ≤ | High ≤ | else |
|---|---|---|---|---|
| icmp | 480 | 1500 | 3000 | Critical |
| syn | 900 | 2700 | 5400 | Critical |
| fragmentation | 640 | 2000 | 4000 | Critical |
| udp | 800 | 2500 | 5000 | Critical |

This tier is only used as the tier of a *single-event* incident (Stage 3); it's independent of
the separate packets-per-second tiering in `app/detection/base.py::assign_tier_by_pps` that
already drives the plain Alert/tier_counts/attacker_ips contracts.

## Stage 2 — correlation (`correlation.group_correlated_events`)

Groups this cycle's scored events (across all attack types — they already share one capture
window) into incidents. Two events are correlated if:

```
same_source  = same src_ip
same_target  = same interface AND detected within scoring_correlation_time_window_sec (default 5s)
correlated   = same_source OR same_target
```

Grouping is a **connected-components** traversal (BFS) over this relation, so it's transitive: if
A↔B and B↔C are correlated but A and C aren't directly, all three still land in one incident.
This matters for multi-vector attacks — e.g. one attacker pivoting src_ip mid-attack, or
independent sources hitting the same interface within the time window — which would otherwise
silently split into several under-scored incidents depending on event ordering (fixed 2026-08-04,
previously a single non-transitive scan pass).

## Stage 3 — combined incident score (`incident_scorer.combined_incident_score`)

For a correlated group of events:

- **Single event**: incident score = that event's `normalized_impact`; confidence `"single"`;
  tier = the event's own Stage-1 tier.
- **Multiple events**: sort `normalized_impact` values descending, take the largest at full
  weight and the rest discounted by β, so a multi-vector attack scores higher than any one vector
  alone without naively summing (double-counting) every contributing flow:

  ```
  combined_impact = impact[0] + beta * sum(impact[1:])
  ```

  `confidence` = `"high"` if every event in the group shares the same src_ip, else `"medium"`.
  `beta` = `scoring_beta_high` (0.65) for high confidence, `scoring_beta_medium` (0.35) for
  medium — a same-source multi-vector attack is trusted more, so its secondary vectors count for
  more of their impact.

  Combined tier (independent scale from Stage 1's per-attack raw_score boundaries):

  | combined_impact | tier |
  |---|---|
  | < 15 | Low |
  | < 30 | Medium |
  | < 45 | High |
  | ≥ 45 | Critical |

## Stage 4 — aggregate score (`aggregate.py`)

In-memory active-incident store (module-level dict + lock, same pattern as
`whitelist_cache.py`/`settings_cache.py` — read/written every cycle, no DB round-trip on the hot
path; persisted to Postgres afterward by `engine.py::_persist`).

**Merge**: `upsert_incident` folds a newly-correlated group into an existing active incident if
they share any src_ip (union of attack_types/src_ips, `combined_impact` takes the max, tier/
confidence/last_seen replaced with the latest), otherwise creates a new incident (`first_seen` =
`last_seen` = now).

**Prune**: on every cycle, `prune_and_score` drops any active incident whose `last_seen` is older
than `scoring_active_window_minutes` (default 10 min) — these become `resolved_ids` and the
Postgres `Incident.status` flips to `"resolved"`.

**Decay + aggregate score**: for each still-active incident, age it exponentially from its
`first_seen` and sum:

```
total_impact = Σ combined_impact_i * exp(-lambda * age_seconds_i)     # lambda = scoring_decay_lambda (0.01)
score         = round(clamp(100 - total_impact, 0, 100), 1)
```

So the score starts at 100 (no active incidents) and drops as impact accumulates; older
incidents' contribution decays toward zero (half-life ≈ 69s at the default λ=0.01, i.e.
`ln(2)/0.01`), so a resolved-in-effect-but-not-yet-pruned attack stops dragging the score down
long before the 10-minute prune window elapses.

**Dashboard tier**: normally looked up from `score` via `scoring_dashboard_tiers`:

| score range | tier |
|---|---|
| 90–100 | Normal |
| 70–89 | Elevated |
| 40–69 | High |
| 0–39 | Critical |

**Single-Critical override**: if *any* active incident is individually tier `"Critical"`, the
dashboard tier is forced to `"Critical"` regardless of the numeric score — decay/dilution from
other low-impact incidents can't mask an ongoing severe attack.

**Acknowledge**: `acknowledge()` (called from `POST /api/incidents/{id}/acknowledge`) removes an
incident from the active set immediately, so it stops contributing to the score without waiting
for it to idle out.

## Side effects per cycle (`engine.py`)

- Every upserted/merged incident is written to the `incidents` table (`_persist`); alerts in the
  group get their `incident_id` set.
- A `Critical`-tier incident gets a dry-run block proposed per src_ip (`BlockAction`, status
  `"proposed"`) unless one's already proposed/executed for that IP — **never fires a real
  firewall change**, see `app/api/block_actions.py`.
- The first time an incident reaches `Critical`, `notify_critical_sync` fires (email/Slack, no-op
  if unconfigured) — gated by `Incident.notified_at` so it's at most once per incident.
- One `SecurityScore(target="aggregate", score=..., details=...)` row is written per cycle for
  the score-history chart.

## Outputs / API surface (`app/api/scoring.py`)

| Endpoint | Returns |
|---|---|
| `GET /api/score/live` | Current snapshot: `{score, tier, active_incidents}` — same shape `aggregate.snapshot()` holds in memory. |
| `GET /api/score/history?range=30m` | `[{timestamp, score}, ...]` time series from the `SecurityScore` table, for the score trend chart. |
| `GET /api/incidents/active` | Just `active_incidents` from the live snapshot. |
| `GET /api/incidents?range=24h&tier=&workflow_status=&assigned_to=&attack_type=&src_ip=` | Paginated DB-backed incident queue (includes resolved/historical, unlike `/active`), each row shaped by `_incident_out`. |
| `GET /api/incidents/{id}` | One incident + its linked alerts (evidence), analyst notes, and ticket links. |
| `PATCH /api/incidents/{id}` | Update `workflow_status` (new/investigating/escalated/resolved), `assigned_to`, or `resolution` (true_positive/false_positive — the latter snapshots linked alerts into `false_positive_feedback` for future retraining). |
| `POST /api/incidents/{id}/acknowledge` | Marks resolved in DB + drops from the live active set. |
| `POST /api/incidents/{id}/notes`, `GET .../notes` | Analyst case notes. |
| `POST /api/incidents/{id}/ticket` | Simulated Jira/ServiceNow ticket link (no real outbound call). |
-
### `active_incidents` / incident shape

```jsonc
{
  "incident_id": "uuid",
  "attack_types": ["syn", "udp"],
  "combined_impact": 27.4,
  "confidence": "high",           // "single" | "high" | "medium"
  "tier": "High",                 // Low | Medium | High | Critical
  "src_ips": ["203.0.113.7"],
  "interface": "eth0",
  "first_seen": "2026-08-04T09:12:03Z",
  "last_seen": "2026-08-04T09:12:41Z",
  // DB-backed /api/incidents and /api/nicidents/{id} additionally include:
  "status": "active",             // active | resolved | acknowledged
  "workflow_status": "new",       // new | investigating | escalated | resolved
  "assigned_to": null,
  "assigned_at": null,
  "resolution": null,             // true_positive | false_positive
  "resolved_at": null
}
```

## Worked example

Two SYN-flood flows and one ICMP-flood flow, all from the same src_ip, in one cycle:

1. **Stage 1**:
   - SYN flow A, 2000 packets → `raw = 2000*3.0 = 6000`, `normalized = min(6000/700, 40) = 40` (hits the cap), event tier `Critical` (6000 > 5400).
   - SYN flow B, 1800 packets → `raw = 5400`, `normalized = min(5400/700, 40) = 7.71`, event tier `Critical` (5400 > 5400 boundary is exclusive-below, so this lands exactly on it — treat as illustrative).
   - ICMP flow, 600 packets → `raw = 900`, `normalized = min(900/1200, 30) = 0.75`, event tier `Medium` (480 < 900 ≤ 1500).
2. **Stage 2**: all three share src_ip → one correlated group.
3. **Stage 3**: impacts sorted desc = `[40, 7.71, 0.75]`. Same src_ip → confidence `"high"`, β = 0.65:
   `combined_impact = 40 + 0.65*(7.71 + 0.75) = 40 + 5.50 = 45.50` → tier `Critical` (≥ 45).
4. **Stage 4**: at age 0 this incident's undecayed impact feeds `total_impact` directly, so that cycle's `score = round(100 - 45.50, 1) = 54.5`. Numerically that alone would map to dashboard tier `High` (40–69), but the single-Critical-incident override forces the dashboard tier to `"Critical"` regardless. A dry-run block gets proposed for that src_ip, and a Critical notification fires once (gated by `Incident.notified_at`).
