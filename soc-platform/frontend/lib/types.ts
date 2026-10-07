export interface AttackerIp {
  ip: string;
  pkts: number;
  flows: number;
  conf: number;
  tier: string;
  iface: string;
}

export interface AttackSummary {
  flows: number;
  attacks: number;
  benign: number;
  xgb_conf: number;
  dl_conf: number;
  hybrid_conf: number;
  tier_counts: Record<string, number>;
  attacker_ips: AttackerIp[];
}

export interface InterfaceInfo {
  name: string;
  description: string;
  ip: string;
  up: boolean;
}

export interface ActiveIncident {
  incident_id: string;
  attack_types: string[];
  combined_impact: number;
  confidence: "high" | "medium" | "single";
  tier: "Low" | "Medium" | "High" | "Critical";
  src_ips: string[];
  interface: string;
  first_seen: string;
  last_seen: string;
}

export interface SecurityScoreState {
  score: number;
  tier: "Normal" | "Elevated" | "High" | "Critical";
  active_incidents: ActiveIncident[];
}

export interface LiveFlow {
  type: string;
  src: string;
  dst: string;
  packets: number;
  iface: string;
  status: "NORMAL" | "ATTACK";
  tier: string;
  conf: number;
}

export interface SocState {
  status: "NORMAL" | "ATTACK";
  active_attack_type: string | null;
  label: string;
  cycle: number;
  timestamp: string;
  total_packets: number;
  interfaces: InterfaceInfo[];
  attacks: Record<string, AttackSummary>;
  history: { t: string; attacks: number }[];
  security: SecurityScoreState;
  interface_packet_counts: Record<string, number>;
  cycle_packets: number;
  packets_per_sec: number;
  live_flows: LiveFlow[];
}

// --- Incident queue / case management -------------------------------------------------

export type WorkflowStatus = "new" | "investigating" | "escalated" | "resolved";
export type Resolution = "true_positive" | "false_positive";

export interface IncidentSummary {
  incident_id: string;
  attack_types: string[];
  combined_impact: number;
  confidence: "high" | "medium" | "single";
  tier: "Low" | "Medium" | "High" | "Critical";
  src_ips: string[];
  interface: string;
  first_seen: string;
  last_seen: string;
  status: "active" | "resolved" | "acknowledged";
  workflow_status: WorkflowStatus;
  assigned_to: string | null;
  assigned_at: string | null;
  resolution: Resolution | null;
  resolved_at: string | null;
}

export interface EvidenceRow {
  alert_id: string;
  attack_type: string;
  src_ip: string;
  dst_ip: string;
  severity: string;
  xgb_conf: number;
  dl_conf: number;
  hybrid_conf: number;
  packets: number;
  iface: string;
  created_at: string;
}

export interface IncidentNote {
  note_id: string;
  author_id: string;
  body: string;
  created_at: string;
}

export interface TicketLink {
  ticket_id: string;
  provider: "jira" | "servicenow";
  external_ref: string;
  url: string | null;
  created_at: string;
  simulated: boolean;
  status: string | null;
  status_category: "new" | "indeterminate" | "done" | null;
  status_synced_at: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  evidence: EvidenceRow[];
  notes: IncidentNote[];
  tickets: TicketLink[];
}

export interface BlockAction {
  id: string;
  src_ip: string;
  incident_id: string | null;
  reason: string;
  status: "proposed" | "executed_simulated" | "dismissed";
  proposed_at: string;
  decided_by: string | null;
  decided_at: string | null;
}

// --- Metrics & KPIs ---------------------------------------------------------------------

export interface MetricsSummary {
  range: string;
  total_alerts: number;
  total_incidents: number;
  mtta_seconds: number | null;
  mttr_seconds: number | null;
  false_positive_rate: number | null;
  false_positive_feedback_count: number;
  detection_window_secs: number;
}

export interface VolumePoint {
  t: string;
  value: number;
}

export interface TopSource {
  src_ip: string;
  count: number;
  max_tier: string;
  country: string | null;
  country_code: string | null;
}

export interface AttackOrigin {
  country: string;
  country_code: string;
  count: number;
}

// --- Users -------------------------------------------------------------------------------

export interface AdminUser {
  id: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  analyst_tier: 1 | 2 | 3 | null;
  must_change_password: boolean;
  created_at: string;
  two_factor?: boolean;
}

// --- Snapshots -----------------------------------------------------------------------------

export interface SnapshotSummary {
  id: string;
  label: string | null;
  trigger: "manual" | "auto_incident";
  incident_id: string | null;
  security_score: number;
  security_tier: string;
  active_incident_count: number;
  total_packets: number;
  source_ips: string[];
  created_at: string;
}

export interface SnapshotDetail extends SnapshotSummary {
  attacks: Record<string, AttackSummary>;
  live_flows: LiveFlow[];
}

// --- Audit log ---------------------------------------------------------------------------

export interface AuditLogEntry {
  id: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  details: Record<string, unknown>;
  created_at: string;
}

// --- Engine health -------------------------------------------------------------------------

export interface ModelStatus {
  trained: boolean;
  has_dl_model: boolean;
}

export interface HealthStatus {
  ok: boolean;
  active_attacks: string[];
  trained: Record<string, boolean>;
  uptime_seconds: number;
  model_status: Record<string, ModelStatus>;
}

export type PlaybookAction = "propose_block" | "open_ticket" | null;

export interface PlaybookStepDef {
  title: string;
  action: PlaybookAction;
}

export interface Playbook {
  id: string;
  name: string;
  attack_type: string | null;
  tier: string | null;
  steps: PlaybookStepDef[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface IncidentPlaybookStep {
  id: string;
  playbook_name: string;
  step_index: number;
  title: string;
  action: PlaybookAction;
  done: boolean;
  done_by: string | null;
  done_at: string | null;
}

export interface IncidentPlaybook {
  steps: IncidentPlaybookStep[];
  done: number;
  total: number;
}

export interface TicketRow {
  ticket_id: string;
  external_ref: string;
  url: string | null;
  simulated: boolean;
  status: string | null;
  status_category: "new" | "indeterminate" | "done" | null;
  created_at: string;
  created_by: string;
  status_synced_at: string | null;
  incident_id: string;
  tier: string;
  attack_types: string[];
  src_ips: string[];
}

export interface TicketDetails {
  key: string;
  summary: string | null;
  url: string;
  status: string;
  status_category: "new" | "indeterminate" | "done";
  assignee: string | null;
  priority: string | null;
  created: string | null;
  updated: string | null;
  comments: { author: string; at: string; body: string }[];
  history: { at: string; by: string; from: string | null; to: string | null }[];
}

export interface TicketPreview {
  summary: string;
  description: string;
  labels: string[];
  priority: string;
  priorities: string[];
  jira_configured: boolean;
  project_key: string | null;
  open_ticket: string | null;
}

export interface LiveOriginPoint {
  src_ip: string;
  count: number;
  max_tier: string;
  attack_types: string[];
  last_seen: string;
  host: string | null;
  country: string | null;
  country_code: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
}

export interface LiveOrigins {
  geoip_ready: boolean;
  local_count: number;
  points: LiveOriginPoint[];
  local_points: LiveOriginPoint[];
}

export interface AgentRow {
  id: string;
  name: string;
  hostname: string;
  os: string | null;
  agent_version: string | null;
  remote_ip: string | null;
  interfaces: string[];
  revoked: boolean;
  status: "online" | "offline" | "revoked";
  enrolled_at: string;
  last_seen_at: string | null;
  last_window_packets: number;
  total_packets: number;
  alerts_24h: number;
}

export interface AgentsResponse {
  online_window_secs: number;
  local_capture: boolean;
  summary: { total: number; online: number; offline: number; revoked: number };
  agents: AgentRow[];
}
