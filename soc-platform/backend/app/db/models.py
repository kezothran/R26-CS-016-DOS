import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, SmallInteger, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

ROLES = ("admin", "analyst", "viewer")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="viewer")
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    # Display/routing label only (Tier 1/2/3 analyst), independent of the permission `role`.
    analyst_tier: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    # TOTP two-factor auth (app/api/auth.py). The secret is set at setup time but only enforced
    # at login once totp_enabled is true (i.e. after the user proved they can generate a code).
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_type: Mapped[str] = mapped_column(String, index=True)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    dst_ip: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    xgb_conf: Mapped[float] = mapped_column(Float, default=0.0)
    dl_conf: Mapped[float] = mapped_column(Float, default=0.0)
    hybrid_conf: Mapped[float] = mapped_column(Float, default=0.0)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    iface: Mapped[str] = mapped_column(String, default="?")
    # Set by app/scoring/engine.py once this flagged flow is folded into a correlated incident -
    # this is what the Evidence Panel drills into from the Incidents queue.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class WhitelistEntry(Base):
    __tablename__ = "whitelist_entries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String)  # "ip" | "network" | "port"
    value: Mapped[str] = mapped_column(String)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SettingEntry(Base):
    __tablename__ = "settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_type: Mapped[str] = mapped_column(String, index=True)  # "global" or an attack_type key
    key: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(String)  # stored as JSON-encoded scalar/string


class SecurityScore(Base):
    """Aggregate score history (app/scoring/), one row per detection cycle. target is always
    "aggregate" for this milestone; details is a jsonb snapshot (tier, active incident count,
    contributing incidents) for the trend chart/audit trail. Column type must match the
    `details jsonb` in supabase/schema.sql - JSONB (not String) so SQLAlchemy passes a dict,
    not a pre-serialized string, or asyncpg rejects it with a DatatypeMismatchError.
    """

    __tablename__ = "security_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target: Mapped[str] = mapped_column(String)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Incident(Base):
    """Correlated/combined incidents (app/scoring/), Stage 2-3 output. One row per
    incident tracked by app/scoring/aggregate.py's in-memory active-incident store, kept in
    sync (upserted) every detection cycle while the incident stays active.
    """

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_types: Mapped[list[str]] = mapped_column(ARRAY(String))
    correlation_confidence: Mapped[str] = mapped_column(String)  # 'high' | 'medium' | 'single'
    combined_impact: Mapped[float] = mapped_column(Float, default=0.0)
    tier: Mapped[str] = mapped_column(String)
    src_ips: Mapped[list[str]] = mapped_column(ARRAY(String))
    iface: Mapped[str] = mapped_column(String, default="?")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    status: Mapped[str] = mapped_column(String, default="active", index=True)  # active | resolved | acknowledged
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Analyst triage workflow - deliberately separate from the engine-managed `status` above
    # (which tracks decay/acknowledgement, not human triage) so the two lifecycles never fight.
    workflow_status: Mapped[str] = mapped_column(String, default="new", index=True)  # new | investigating | escalated | resolved
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution: Mapped[str | None] = mapped_column(String, nullable=True)  # true_positive | false_positive
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Set the first time app/notify.py::notify_critical_sync fires for this incident, so a
    # Critical incident only ever triggers one email/Slack notification, not one per cycle.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentNote(Base):
    """Case-management annotations, append-only - shown in the Incidents queue detail panel."""

    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    author_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class TicketLink(Base):
    """Ticket link for an incident. Real Jira issues (simulated=False) store the Jira key in
    `external_ref` plus its browse `url` and live status; simulated=True rows are placeholder
    references created when Jira isn't configured.
    """

    __tablename__ = "ticket_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    provider: Mapped[str] = mapped_column(String)  # 'jira' | 'servicenow'
    external_ref: Mapped[str] = mapped_column(String)
    url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Real Jira tickets carry the live Jira status; legacy/fallback rows are simulated placeholders.
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True)
    status_category: Mapped[str | None] = mapped_column(String, nullable=True)  # new | indeterminate | done
    status_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BlockAction(Base):
    """Dry-run SIEM/SOAR block proposal - auto-created by app/scoring/engine.py when an
    incident's tier is Critical. "Executing" one only flips status/logs it; it never fires a
    real firewall/network change (see backend/app/api/block_actions.py).
    """

    __tablename__ = "block_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="proposed", index=True)  # proposed | executed_simulated | dismissed
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FalsePositiveFeedback(Base):
    """Collection-only dataset for a future model-retraining pass, populated when an incident is
    resolved as a false positive (app/api/scoring.py::patch_incident). Snapshots the linked
    Alert rows' already-persisted summary fields - the raw per-flow feature vectors themselves
    aren't retained anywhere after scoring, so this is what's actually available, not full
    features.
    """

    __tablename__ = "false_positive_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    attack_type: Mapped[str] = mapped_column(String)
    src_ip: Mapped[str] = mapped_column(String)
    dst_ip: Mapped[str] = mapped_column(String)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    xgb_conf: Mapped[float] = mapped_column(Float, default=0.0)
    dl_conf: Mapped[float] = mapped_column(Float, default=0.0)
    hybrid_conf: Mapped[float] = mapped_column(Float, default=0.0)
    iface: Mapped[str] = mapped_column(String, default="?")
    marked_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Snapshot(Base):
    """Point-in-time capture of the live dashboard state - either taken manually from the UI
    (app/api/snapshots.py) or fired automatically the moment a Critical-tier incident is first
    created (app/scoring/engine.py::_persist). Read-only once written.
    """

    __tablename__ = "snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    trigger: Mapped[str] = mapped_column(String, default="manual")  # 'manual' | 'auto_incident'
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    security_score: Mapped[float] = mapped_column(Float, default=0.0)
    security_tier: Mapped[str] = mapped_column(String, default="Normal")
    active_incident_count: Mapped[int] = mapped_column(Integer, default=0)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    attacks: Mapped[dict] = mapped_column(JSONB, default=dict)
    live_flows: Mapped[list] = mapped_column(JSONB, default=list)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class AuditLog(Base):
    """Who-did-what trail (app/audit.py), written in the same transaction as the action it
    records so the log entry and the actual change are atomic. Covers role/tier changes,
    incident workflow updates, and block-action decisions - see app/audit.py for call sites.
    """

    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String, index=True)
    target_type: Mapped[str] = mapped_column(String)
    target_id: Mapped[str] = mapped_column(String)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Playbook(Base):
    """Editable response playbook. NULL attack_type / tier means "any" - the most specific
    enabled match wins (see app/api/playbooks.py::_pick_playbooks). `steps` is a list of
    {"title": str, "action": None | "propose_block" | "open_ticket"}.
    """

    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String)
    attack_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    tier: Mapped[str | None] = mapped_column(String, nullable=True)
    steps: Mapped[list] = mapped_column(JSONB, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentPlaybookStep(Base):
    """One checklist item of a playbook, snapshotted onto an incident the first time its
    playbook is opened. Ticking it records who/when (and is audited)."""

    __tablename__ = "incident_playbook_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    playbook_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True)
    playbook_name: Mapped[str] = mapped_column(String)
    step_index: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String)
    action: Mapped[str | None] = mapped_column(String, nullable=True)
    done: Mapped[bool] = mapped_column(Boolean, default=False)
    done_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Agent(Base):
    """A remote capture agent installed on another PC/server (see /agent and app/api/agents.py).
    Only a SHA-256 hash of its key is stored; the key itself is shown once at enrolment."""

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String)
    hostname: Mapped[str] = mapped_column(String)
    os: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String, nullable=True)
    remote_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    interfaces: Mapped[list] = mapped_column(JSONB, default=list)
    key_hash: Mapped[str] = mapped_column(String)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_window_packets: Mapped[int] = mapped_column(Integer, default=0)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)


class AgentToken(Base):
    """One-time enrolment token created by an admin; stored hashed, valid until expires_at, consumed on first use."""

    __tablename__ = "agent_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String, unique=True)
    note: Mapped[str | None] = mapped_column(String, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_agent: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True)
