# SOC Flood Detection Platform

A full SOC (Security Operations Center) dashboard for DoS/flood detection, built as a FastAPI +
Next.js + Supabase (Postgres) application. Started as a vertical slice unifying the ICMP flood
prototype with SYN/fragmentation/UDP flood detectors; has since grown a severity-scoring engine,
an incident queue with case-management workflow, KPI metrics, critical-incident alerting, and
admin tooling on top of the live detection loop.

**All four attack types run live**: ICMP, SYN, Fragmentation (rule-based) and UDP (hybrid
XGBoost + DL, ported from its flow-based CICFlowMeter-style feature set). SYN and Fragmentation
fall back to a packet-rate heuristic until trained models are dropped into their `app/models/`
folders (see §6).

## Features

- **Live detection dashboard** (`/dashboard`) — per-attack-type confidence cards, attacker IP
  table, interface status, severity breakdown, and a live traffic banner that reacts to whichever
  attack type is currently firing.
- **Severity Scoring Engine** (`backend/app/scoring/`) — generalizes a weighted packet-count
  formula across attack types: per-event scoring → same-source/same-window correlation into
  incidents → combined incident severity (Low/Medium/High/Critical) → a decayed 0–100 aggregate
  security score with a single-Critical-incident override.
- **Incident queue & case management** (`/dashboard/incidents`) — workflow status
  (new/investigating/escalated/resolved), analyst assignment, evidence/notes/ticket tabs,
  dry-run auto-block proposals for Critical incidents, and stub Jira/ServiceNow ticket links
  (no real external API calls — this platform never fires real firewall or ticketing actions).
- **Metrics & KPIs** (`/dashboard/metrics`) — MTTA/MTTR, false-positive rate, alert/traffic
  volume trends, top talkers, and Geo-IP attack origins (needs `GEOIP_DB_PATH`, optional).
- **Engine health** (`/dashboard/health`) — uptime, per-attack-type model status
  (trained/rule-based, DL model loaded), and live per-interface packet throughput — operational
  status, distinct from the security-focused Metrics page.
- **Users & access management** (`/dashboard/users`, admin-only) — RBAC (`admin`/`analyst`/
  `viewer`), Tier 1/2/3 analyst routing labels, and an audit log of role/incident/block-action
  changes.
- **Critical-incident alerting** (`backend/app/notify.py`) — optional email/Slack notification
  the first time an incident reaches Critical severity. No-ops with a startup warning if SMTP and
  a Slack webhook are both unconfigured — never required, never crashes.
- **False-positive feedback** — resolving an incident as a false positive snapshots its linked
  alerts into `false_positive_feedback`, building a labeled dataset for future model retraining.
- **Whitelist & settings** — IP whitelisting and tunable detection thresholds, shared across all
  attack modules.

## 1. Prerequisites

| OS | Requirement |
|---|---|
| Windows | [Npcap](https://npcap.com) installed with "WinPcap API-compatible mode" checked. Run the backend as **Administrator**. |
| Linux | libpcap (usually preinstalled). Run as **root**, or `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`. |
| macOS | Run with **sudo** (raw capture requires root). |

Also needed: Python 3.11+, Node.js 18+, a free [Supabase](https://supabase.com) project.

## 2. Supabase setup

1. Create a project at supabase.com.
2. Project Settings → Database → Connection string (URI) → copy it.
3. Open the SQL Editor and run `supabase/schema.sql` from this repo.

> `CREATE POLICY` has no `IF NOT EXISTS` in Postgres, so re-running the full `schema.sql` after
> the first apply will fail on already-existing policies. If you need to re-apply after pulling
> schema changes, run it statement-by-statement and skip `DuplicateObjectError`/
> `DuplicateTableError`/`DuplicateColumnError` (the additive `create table if not exists` /
> `add column if not exists` statements are safe to re-run as-is).

## 3. Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # fill in DATABASE_URL and JWT_SECRET
python -m scripts.seed_admin                              # creates the default admin user
```

Run (as Administrator/root — see prerequisites table):

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

On startup the backend runs a capture self-test and fails fast with a platform-specific error
if it doesn't have raw-capture privileges (see `app/capture/privileges.py`). There is no
`--reload` in this setup — restart uvicorn manually after any backend code change, otherwise
you'll keep talking to the old process (check `GET /health` for `uptime_seconds` resetting to
confirm a restart actually took).

The detection loop runs as a fire-and-forget `asyncio.create_task` with no automatic restart —
if it ever throws (e.g. a transient DB connection blip), it silently stops broadcasting forever
and the Overview page will hang on "Waiting for first detection cycle..." even though the rest
of the API keeps working. Check the uvicorn log for a `Task exception was never retrieved`
traceback and restart the process.

## 4. Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local    # points at the backend URL, defaults to localhost:8000
npm run dev
```

Open http://localhost:3000, log in with `DEFAULT_ADMIN_EMAIL` / `DEFAULT_ADMIN_PASSWORD` from
`backend/.env`, and change the password when prompted.

## 5. Testing against a real attack (from Kali)

```bash
# ICMP flood
sudo hping3 --icmp --flood <target-ip>

# SYN flood
sudo hping3 -S -p 80 --flood <target-ip>

# Fragmentation flood
sudo hping3 --frag --flood <target-ip>

# UDP flood (randomized source port, so the platform groups it by the 3-tuple src/dst/dport)
sudo hping3 -2 --udp -p 9999 --flood <target-ip>
```

Watch the Overview page: the banner and accent color should switch to the attack type's color
within one detection window (default 5s), the attacker IP should appear in the table, and the
model confidence cards should update (ICMP/UDP show real hybrid ML+DL confidence; SYN/fragmentation
show a rate-based confidence until real models are added, see below).

To confirm whitelisting works: add the Kali VM's IP on the Whitelist page, re-run the same
`hping3` command, and confirm the dashboard stays NORMAL.

## 6. Adding the SYN / fragmentation models later

Drop these files into `backend/app/models/syn/` or `backend/app/models/fragmentation/`:

- `xgb_model.pkl`, `scaler.pkl`, `feature_names.json` (required)
- `dl_model.h5` (optional, for the hybrid XGBoost+DL score)

`app/detection/base.load_model_bundle()` picks them up automatically and `syn.py`/
`fragmentation.py` switch from the rate-based rule to the real hybrid score — no code changes
needed unless your feature engineering differs from the placeholder `FEATURES` list in those
files, in which case update their `extract_features()` to match.

## 7. Known simplifications

- **Block actions and ticket integration are dry-run/stub only, by design** — Critical incidents
  get an auto-proposed "block this IP" action and can be linked to a fake Jira/ServiceNow
  reference, but neither ever calls a real firewall or ticketing API. Executing a proposed block
  only logs a simulated decision.
- **JWT is kept in `localStorage`, not an httpOnly cookie** — the client-side WebSocket needs the
  raw token to connect, which isn't possible with an httpOnly cookie without a server-side WS
  proxy. Fine for this milestone; revisit if third-party scripts are ever added to the frontend.
- **RLS policies in `supabase/schema.sql` are defense-in-depth only** — the backend connects via
  a direct Postgres connection string (not Supabase's PostgREST/anon-key layer), so RBAC is
  actually enforced in `backend/app/auth/security.py:require_role`.
- **GeoIP and alerting are both optional, graceful no-ops** — leave `GEOIP_DB_PATH`/SMTP/Slack
  env vars unset and those features degrade to an empty state or a one-time startup warning
  instead of failing.
- **False-positive feedback collects `Alert` summary fields, not raw feature vectors** — full
  per-flow feature vectors aren't retained after scoring, so the collected dataset is
  (attack_type, confidence scores, packet count → false positive), not raw model input.
