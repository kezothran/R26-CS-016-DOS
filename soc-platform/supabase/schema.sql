-- Run this once in the Supabase project's SQL Editor (or `psql "$DATABASE_URL" -f schema.sql`).
--
-- Note on RLS: the FastAPI backend connects directly via SQLAlchemy/asyncpg using the
-- connection string in backend/.env (DATABASE_URL), not through Supabase's PostgREST/anon-key
-- layer - so RBAC is actually enforced in application code (see
-- backend/app/auth/security.py:require_role). The RLS policies below are a defense-in-depth
-- safety net in case anything ever queries these tables via the Supabase client/anon key
-- directly; they are not the primary access-control mechanism for this app.

create extension if not exists "pgcrypto";

create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text unique not null,
    password_hash text not null,
    role text not null default 'viewer' check (role in ('admin', 'analyst', 'viewer')),
    must_change_password boolean not null default true,
    analyst_tier smallint,  -- display/routing label (1/2/3), independent of `role`
    created_at timestamptz not null default now()
);
-- CREATE TABLE IF NOT EXISTS is a no-op on an existing table, so installs that already had
-- `users` before this column was added need the explicit ALTER too.
alter table users add column if not exists analyst_tier smallint;

create table if not exists alerts (
    id uuid primary key default gen_random_uuid(),
    attack_type text not null,
    src_ip text not null,
    dst_ip text not null,
    severity text not null,
    xgb_conf double precision not null default 0,
    dl_conf double precision not null default 0,
    hybrid_conf double precision not null default 0,
    packets integer not null default 0,
    iface text not null default '?',
    created_at timestamptz not null default now()
);
create index if not exists idx_alerts_attack_type on alerts (attack_type);
create index if not exists idx_alerts_src_ip on alerts (src_ip);
create index if not exists idx_alerts_created_at on alerts (created_at desc);

create table if not exists whitelist_entries (
    id uuid primary key default gen_random_uuid(),
    kind text not null check (kind in ('ip', 'network', 'port')),
    value text not null,
    created_by uuid references users(id),
    created_at timestamptz not null default now(),
    unique (kind, value)
);

create table if not exists settings (
    id uuid primary key default gen_random_uuid(),
    attack_type text not null,
    key text not null,
    value text not null,
    unique (attack_type, key)
);

-- Aggregate security-score history (app/scoring/), one row written per detection cycle.
create table if not exists security_scores (
    id uuid primary key default gen_random_uuid(),
    target text not null,
    score double precision not null default 0,
    details jsonb not null default '{}',
    created_at timestamptz not null default now()
);
create index if not exists idx_security_scores_created_at on security_scores (created_at desc);

-- Correlated/combined incidents (app/scoring/), Stage 2-3 output of the Severity Scoring
-- Engine. Upserted every detection cycle while an incident stays active.
create table if not exists incidents (
    id uuid primary key default gen_random_uuid(),
    attack_types text[] not null,
    correlation_confidence text not null check (correlation_confidence in ('high', 'medium', 'single')),
    combined_impact double precision not null default 0,
    tier text not null,
    src_ips text[] not null,
    iface text not null default '?',
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    status text not null default 'active' check (status in ('active', 'resolved', 'acknowledged')),
    acknowledged_by uuid references users(id),
    acknowledged_at timestamptz
);
create index if not exists idx_incidents_status on incidents (status);
create index if not exists idx_incidents_last_seen on incidents (last_seen desc);

-- Analyst triage workflow on incidents - kept separate from the engine-managed `status` above
-- (decay/acknowledgement) so the two lifecycles never fight.
alter table incidents add column if not exists workflow_status text not null default 'new'
    check (workflow_status in ('new', 'investigating', 'escalated', 'resolved'));
alter table incidents add column if not exists assigned_to uuid references users(id);
alter table incidents add column if not exists assigned_at timestamptz;
alter table incidents add column if not exists resolution text check (resolution in ('true_positive', 'false_positive'));
alter table incidents add column if not exists resolved_at timestamptz;
create index if not exists idx_incidents_workflow_status on incidents (workflow_status);
create index if not exists idx_incidents_assigned_to on incidents (assigned_to);

-- Set the first time a Critical incident triggers an email/Slack notification (app/notify.py),
-- so it only ever fires once per incident, not once per detection cycle.
alter table incidents add column if not exists notified_at timestamptz;

-- Traces each raw flagged-flow row back to the incident it was folded into (app/scoring/
-- engine.py) - powers the Incidents queue's Evidence Panel drill-down.
alter table alerts add column if not exists incident_id uuid references incidents(id);
create index if not exists idx_alerts_incident_id on alerts (incident_id);

-- Case-management annotations, append-only.
create table if not exists incident_notes (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references incidents(id),
    author_id uuid not null references users(id),
    body text not null,
    created_at timestamptz not null default now()
);
create index if not exists idx_incident_notes_incident_id on incident_notes (incident_id);

-- Simulated ticket-system links - no outbound HTTP call, no real Jira/ServiceNow account to
-- hit; external_ref is a generated placeholder, clearly labeled as simulated in the UI.
create table if not exists ticket_links (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references incidents(id),
    provider text not null check (provider in ('jira', 'servicenow')),
    external_ref text not null,
    url text,
    created_by uuid not null references users(id),
    created_at timestamptz not null default now()
);
create index if not exists idx_ticket_links_incident_id on ticket_links (incident_id);

-- Dry-run SIEM/SOAR block proposals - auto-created when an incident's tier is Critical.
-- "Executing" one only flips status/logs it; it never fires a real firewall/network change.
create table if not exists block_actions (
    id uuid primary key default gen_random_uuid(),
    src_ip text not null,
    incident_id uuid references incidents(id),
    reason text not null,
    status text not null default 'proposed' check (status in ('proposed', 'executed_simulated', 'dismissed')),
    proposed_at timestamptz not null default now(),
    decided_by uuid references users(id),
    decided_at timestamptz
);
create index if not exists idx_block_actions_status on block_actions (status);
create index if not exists idx_block_actions_src_ip on block_actions (src_ip);

-- Collection-only dataset for a future model-retraining pass, populated when an incident is
-- resolved as a false positive. Snapshots the linked Alert rows' already-persisted fields -
-- raw per-flow feature vectors aren't retained anywhere after scoring, so this is what's
-- actually available, not full features.
create table if not exists false_positive_feedback (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references incidents(id),
    alert_id uuid not null references alerts(id),
    attack_type text not null,
    src_ip text not null,
    dst_ip text not null,
    packets integer not null default 0,
    xgb_conf double precision not null default 0,
    dl_conf double precision not null default 0,
    hybrid_conf double precision not null default 0,
    iface text not null default '?',
    marked_by uuid not null references users(id),
    created_at timestamptz not null default now()
);
create index if not exists idx_fp_feedback_created_at on false_positive_feedback (created_at desc);

-- Point-in-time captures of the live dashboard state (aggregate score, per-attack-type
-- summaries, and the Live Traffic feed's flow list) - either taken manually from the UI or
-- fired automatically the moment a Critical-tier incident is first created (app/scoring/
-- engine.py). Read-only once written; there's no "update a snapshot" flow.
create table if not exists snapshots (
    id uuid primary key default gen_random_uuid(),
    label text,
    trigger text not null default 'manual' check (trigger in ('manual', 'auto_incident')),
    incident_id uuid references incidents(id),
    security_score double precision not null default 0,
    security_tier text not null default 'Normal',
    active_incident_count integer not null default 0,
    total_packets bigint not null default 0,
    attacks jsonb not null default '{}',
    live_flows jsonb not null default '[]',
    created_by uuid references users(id),
    created_at timestamptz not null default now()
);
create index if not exists idx_snapshots_created_at on snapshots (created_at desc);

-- Who-did-what trail, written in the same transaction as the action it records. Covers
-- role/tier changes, incident workflow updates, and block-action decisions.
create table if not exists audit_log (
    id uuid primary key default gen_random_uuid(),
    actor_id uuid not null references users(id),
    action text not null,
    target_type text not null,
    target_id text not null,
    details jsonb not null default '{}',
    created_at timestamptz not null default now()
);
create index if not exists idx_audit_log_created_at on audit_log (created_at desc);
create index if not exists idx_audit_log_action on audit_log (action);

alter table users enable row level security;
alter table alerts enable row level security;
alter table whitelist_entries enable row level security;
alter table settings enable row level security;
alter table security_scores enable row level security;
alter table incidents enable row level security;
alter table incident_notes enable row level security;
alter table ticket_links enable row level security;
alter table block_actions enable row level security;
alter table false_positive_feedback enable row level security;
alter table audit_log enable row level security;
alter table snapshots enable row level security;

-- Defense-in-depth only (see note above) - these key off a `request.jwt.claims` role claim,
-- which is only populated when going through Supabase's own PostgREST auth layer.
create policy alerts_read_all on alerts for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy alerts_write_admin_analyst on alerts for insert
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

create policy whitelist_read_all on whitelist_entries for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy whitelist_write_admin_analyst on whitelist_entries for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

create policy incidents_read_all on incidents for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy incidents_write_admin_analyst on incidents for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

create policy incident_notes_read_all on incident_notes for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy incident_notes_write_admin_analyst on incident_notes for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

create policy ticket_links_read_all on ticket_links for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy ticket_links_write_admin_analyst on ticket_links for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

create policy block_actions_read_all on block_actions for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy block_actions_write_admin_analyst on block_actions for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

-- Admin-only in both directions (unlike the tables above) - feedback data and the audit trail
-- itself are more sensitive than operational incident data.
create policy fp_feedback_admin_only on false_positive_feedback for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') = 'admin')
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') = 'admin');

create policy audit_log_admin_only on audit_log for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') = 'admin')
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') = 'admin');

create policy snapshots_read_all on snapshots for select
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', 'viewer') in ('admin', 'analyst', 'viewer'));
create policy snapshots_write_admin_analyst on snapshots for all
    using (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'))
    with check (coalesce(current_setting('request.jwt.claims', true)::json->>'role', '') in ('admin', 'analyst'));

-- Response playbooks: editable per attack type and/or severity tier. NULL attack_type/tier means
-- "any". `steps` is a JSON array of {title, action} where action is null, 'propose_block' or
-- 'open_ticket'.
create table if not exists playbooks (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    attack_type text,
    tier text,
    steps jsonb not null default '[]'::jsonb,
    enabled boolean not null default true,
    created_by uuid references users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
create index if not exists idx_playbooks_attack_type on playbooks (attack_type);

-- Per-incident checklist snapshot of the matching playbook(s), so later playbook edits don't
-- rewrite history on incidents already being worked.
create table if not exists incident_playbook_steps (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references incidents(id),
    playbook_id uuid references playbooks(id) on delete set null,
    playbook_name text not null,
    step_index integer not null,
    title text not null,
    action text,
    done boolean not null default false,
    done_by uuid references users(id),
    done_at timestamptz,
    unique (incident_id, step_index)
);
create index if not exists idx_incident_playbook_steps_incident_id on incident_playbook_steps (incident_id);

-- Real Jira tickets: live status + whether the row is a simulated placeholder (all pre-existing
-- rows are simulated).
alter table ticket_links add column if not exists simulated boolean not null default true;
alter table ticket_links add column if not exists status text;
alter table ticket_links add column if not exists status_category text;
alter table ticket_links add column if not exists status_synced_at timestamptz;
