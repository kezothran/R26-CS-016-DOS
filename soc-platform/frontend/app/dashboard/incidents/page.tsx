"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch, downloadFile } from "@/lib/api";
import { canWrite, getRole } from "@/lib/auth";
import { useSocStream } from "@/lib/SocStreamContext";
import { severityColor, themeFor, tierTheme } from "@/lib/theme";
import type {
  AdminUser, BlockAction, IncidentDetail, IncidentPlaybook, IncidentSummary, Resolution, WorkflowStatus,
} from "@/lib/types";

const RANGES = ["1h", "24h", "7d", "30d"];
const RANGE_LABEL: Record<string, string> = { "1h": "1 Hour", "24h": "24 Hours", "7d": "7 Days", "30d": "30 Days" };
// ms equivalents of RANGES, kept in lockstep with query_utils.py's parse_range regex ("1h"/"24h"/"7d"/"30d")
const RANGE_MS: Record<string, number> = { "1h": 3.6e6, "24h": 8.64e7, "7d": 6.048e8, "30d": 2.592e9 };
const DOUBLED_RANGE: Record<string, string> = { "1h": "2h", "24h": "48h", "7d": "14d", "30d": "60d" };
const PAGE_SIZES = [10, 25, 50];
const TIERS = ["Critical", "High", "Medium", "Low"];
const WORKFLOW_STATUSES: WorkflowStatus[] = ["new", "investigating", "escalated", "resolved"];
const WORKFLOW_LABEL: Record<WorkflowStatus, string> = {
  new: "New", investigating: "Investigating", escalated: "Escalated", resolved: "Resolved",
};
const WORKFLOW_COLOR: Record<WorkflowStatus, string> = {
  new: "var(--blue)", investigating: "var(--amber)", escalated: "var(--red)", resolved: "var(--green)",
};
// All currently supported detectors (backend/app/detection/registry.py) are volumetric/DoS
// floods, so this holds as a flat label rather than a per-type lookup until other categories exist.
const ATTACK_CATEGORY = "Network Flood";

const ICON_PATHS: Record<string, string> = {
  file: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6ZM14 2v6h6M9 13h6M9 17h6",
  shield: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM9 12l2 2 4-4",
  alert: "M12 3 2 20h20L12 3ZM12 10v5M12 18v.01",
  check: "M20 6 9 17l-5-5",
  filter: "M4 5h16l-6 8v6l-4 2v-8L4 5Z",
  copy: "M9 9h11v11H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4 21c0-4 3.6-7 8-7s8 3 8 7",
  kebab: "M12 6v.01M12 12v.01M12 18v.01",
  chevronLeft: "m15 18-6-6 6-6",
  chevronRight: "m9 18 6-6-6-6",
  sort: "M7 3v14M7 17l-3-3M7 17l3-3M17 21V7M17 7l3 3M17 7l-3 3",
};

function Icon({ name, size = 14 }: { name: keyof typeof ICON_PATHS; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}

export default function IncidentsPage() {
  const { state, connected } = useSocStream(); // live tick - "something changed", used to trigger refetch
  const [range, setRange] = useState("24h");
  const [tier, setTier] = useState("");
  const [workflowStatus, setWorkflowStatus] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null);
  const [prevCounts, setPrevCounts] = useState<Record<string, number> | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const writable = canWrite(getRole());

  const load = useCallback(async () => {
    const params = new URLSearchParams({ range });
    if (tier) params.set("tier", tier);
    if (workflowStatus) params.set("workflow_status", workflowStatus);
    if (srcIp.trim()) params.set("src_ip", srcIp.trim());
    setIncidents(await apiFetch<IncidentSummary[]>(`/api/incidents?${params.toString()}`));
  }, [range, tier, workflowStatus, srcIp]);

  useEffect(() => { load(); }, [load]);
  // Re-fetch on each live detection cycle - the WS connection is already the "something
  // changed" signal, no separate polling interval needed.
  useEffect(() => { load(); }, [state?.cycle]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    apiFetch<AdminUser[]>("/api/users").then(setUsers).catch(() => {});
  }, []);

  // Comparison bucket for the stat-card trend arrows ("vs last <range>") - fetches a
  // doubled-length window and buckets by first_seen into current vs. previous half, since
  // /api/incidents only supports a single "since" cutoff (no "until").
  useEffect(() => {
    let cancelled = false;
    async function loadPrev() {
      const params = new URLSearchParams({ range: DOUBLED_RANGE[range], limit: "500" });
      if (tier) params.set("tier", tier);
      if (workflowStatus) params.set("workflow_status", workflowStatus);
      if (srcIp.trim()) params.set("src_ip", srcIp.trim());
      const all = await apiFetch<IncidentSummary[]>(`/api/incidents?${params.toString()}`);
      if (cancelled) return;
      const cutoff = Date.now() - RANGE_MS[range];
      const prevCutoff = cutoff - RANGE_MS[range];
      const counts: Record<string, number> = { total: 0, Critical: 0, High: 0, Medium: 0, Low: 0, Resolved: 0 };
      for (const inc of all) {
        const t = new Date(inc.first_seen).getTime();
        if (t < cutoff && t >= prevCutoff) {
          counts.total++;
          counts[inc.tier] = (counts[inc.tier] ?? 0) + 1;
          if (inc.workflow_status === "resolved") counts.Resolved++;
        }
      }
      setPrevCounts(counts);
    }
    loadPrev().catch(() => setPrevCounts(null));
    return () => { cancelled = true; };
  }, [range, tier, workflowStatus, srcIp, state?.cycle]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { setPage(1); }, [range, tier, workflowStatus, srcIp, pageSize]);

  const currCounts = useMemo(() => {
    const counts: Record<string, number> = { total: incidents?.length ?? 0, Critical: 0, High: 0, Medium: 0, Low: 0, Resolved: 0 };
    for (const inc of incidents ?? []) {
      counts[inc.tier] = (counts[inc.tier] ?? 0) + 1;
      if (inc.workflow_status === "resolved") counts.Resolved++;
    }
    return counts;
  }, [incidents]);

  const totalPages = Math.max(1, Math.ceil((incidents?.length ?? 0) / pageSize));
  const pageStart = (page - 1) * pageSize;
  const pageIncidents = (incidents ?? []).slice(pageStart, pageStart + pageSize);

  return (
    <div>
      <PageHeader connected={connected} />

      <div
        className="fade-in-up"
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 20 }}
      >
        <StatCard label="Total Incidents" value={currCounts.total} prev={prevCounts?.total} color="var(--accent)" icon="file" range={range} />
        <StatCard label="Critical" value={currCounts.Critical} prev={prevCounts?.Critical} color={severityColor("Critical")} icon="shield" range={range} />
        <StatCard label="High" value={currCounts.High} prev={prevCounts?.High} color={severityColor("High")} icon="alert" range={range} />
        <StatCard label="Medium" value={currCounts.Medium} prev={prevCounts?.Medium} color={severityColor("Medium")} icon="file" range={range} />
        <StatCard label="Low" value={currCounts.Low} prev={prevCounts?.Low} color={severityColor("Low")} icon="shield" range={range} />
        <StatCard label="Resolved" value={currCounts.Resolved} prev={prevCounts?.Resolved} color="var(--teal, #2dd4bf)" icon="check" range={range} />
      </div>

      <Box title="Filters" icon="filter">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "flex-end" }}>
          <Field label="Range">
            <select value={range} onChange={(e) => setRange(e.target.value)} style={selectStyle}>
              {RANGES.map((r) => <option key={r} value={r}>{RANGE_LABEL[r]}</option>)}
            </select>
          </Field>
          <Field label="Severity">
            <select value={tier} onChange={(e) => setTier(e.target.value)} style={selectStyle}>
              <option value="">All</option>
              {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="Status">
            <select value={workflowStatus} onChange={(e) => setWorkflowStatus(e.target.value)} style={selectStyle}>
              <option value="">All</option>
              {WORKFLOW_STATUSES.map((w) => <option key={w} value={w}>{WORKFLOW_LABEL[w]}</option>)}
            </select>
          </Field>
          <Field label="Source IP">
            <input value={srcIp} onChange={(e) => setSrcIp(e.target.value)} placeholder="e.g. 10.0.0.5" style={selectStyle} />
          </Field>
          <div style={{ flex: 1 }} />
          <button
            onClick={() => downloadFile(`/api/alerts/export?range=${range}${srcIp.trim() ? `&src_ip=${srcIp.trim()}` : ""}`, "alerts_export.csv")}
            style={btnStyle}
          >
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <DownloadIcon /> Export CSV
            </span>
          </button>
        </div>
      </Box>

      <Box title={`Incidents ${incidents ? `(${incidents.length})` : ""}`} icon="file">
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Severity", "Attack Type", "Source IP", "Impact", "Status", "Assigned", "Last Seen", ""].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {incidents === null ? (
                <tr><td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>Loading...</td></tr>
              ) : incidents.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>No incidents match these filters</td></tr>
              ) : (
                pageIncidents.map((inc) => {
                  const impactColor = severityColor(inc.tier);
                  return (
                    <tr
                      key={inc.incident_id} className="row-hover" onClick={() => setSelected(inc.incident_id)}
                      style={{ cursor: "pointer", background: selected === inc.incident_id ? "var(--raised)" : undefined }}
                    >
                      <td style={cellStyle}><SeverityPill tier={inc.tier} /></td>
                      <td style={cellStyle}>
                        <div style={{ fontWeight: 600, fontSize: 12.5 }}>{inc.attack_types.map((t) => themeFor(t).label).join(" + ")}</div>
                        <span
                          style={{
                            display: "inline-block", marginTop: 4, fontSize: 9.5, fontWeight: 600, color: "var(--blue)",
                            background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.25)",
                            borderRadius: 4, padding: "1px 6px", textTransform: "uppercase", letterSpacing: "0.03em",
                          }}
                        >
                          {ATTACK_CATEGORY}
                        </span>
                      </td>
                      <td style={cellStyle}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--mono)" }}>
                          {inc.src_ips.join(", ")}
                          <CopyButton text={inc.src_ips.join(", ")} />
                        </div>
                      </td>
                      <td style={cellStyle}>
                        <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                          <ImpactRing value={inc.combined_impact} color={impactColor} />
                          <span style={{ fontFamily: "var(--mono)" }}>{inc.combined_impact.toFixed(1)}</span>
                        </div>
                      </td>
                      <td style={cellStyle}>
                        <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: WORKFLOW_COLOR[inc.workflow_status], fontWeight: 600 }}>
                          <span style={{ width: 6, height: 6, borderRadius: "50%", background: WORKFLOW_COLOR[inc.workflow_status] }} />
                          {WORKFLOW_LABEL[inc.workflow_status]}
                        </span>
                      </td>
                      <td style={cellStyle}>
                        <AssignCell incident={inc} users={users} writable={writable} onChanged={load} />
                      </td>
                      <td style={cellStyle}>{new Date(inc.last_seen).toLocaleString()}</td>
                      <td style={{ ...cellStyle, textAlign: "right" }}>
                        <button
                          onClick={(e) => { e.stopPropagation(); setSelected(inc.incident_id); }}
                          title="View details"
                          style={{ background: "transparent", border: "none", cursor: "pointer", color: "var(--dim)", padding: 4, display: "inline-flex" }}
                        >
                          <Icon name="kebab" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {incidents !== null && incidents.length > 0 && (
          <PaginationFooter
            total={incidents.length} page={page} pageSize={pageSize}
            onPage={setPage} onPageSize={setPageSize} totalPages={totalPages}
          />
        )}
      </Box>

      {selected && (
        <IncidentDetailPanel
          incidentId={selected}
          users={users}
          writable={writable}
          onChanged={load}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function pctChange(curr: number, prev: number | undefined): { pct: number; dir: "up" | "down" | "flat" } {
  if (prev === undefined) return { pct: 0, dir: "flat" };
  if (prev === 0) return curr > 0 ? { pct: 100, dir: "up" } : { pct: 0, dir: "flat" };
  const diff = ((curr - prev) / prev) * 100;
  if (Math.round(diff) === 0) return { pct: 0, dir: "flat" };
  return { pct: Math.round(Math.abs(diff)), dir: diff > 0 ? "up" : "down" };
}

function StatCard({
  label, value, prev, color, icon, range,
}: {
  label: string;
  value: number;
  prev: number | undefined;
  color: string;
  icon: keyof typeof ICON_PATHS;
  range: string;
}) {
  const { pct, dir } = pctChange(value, prev);
  const trendColor = dir === "up" ? "var(--green)" : dir === "down" ? "var(--red)" : "var(--dim)";
  return (
    <div
      className="card-hover"
      style={{
        position: "relative", borderRadius: 10, padding: "14px 16px", background: "var(--surf)",
        borderTop: `2px solid ${color}`, borderInline: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
      }}
    >
      <span style={{ position: "absolute", top: 13, right: 13, color: "var(--dim)" }}><Icon name={icon} /></span>
      <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, maxWidth: "80%" }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>{value}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10, color: trendColor, marginTop: 6, fontWeight: 600 }}>
        <span>{dir === "up" ? "↑" : dir === "down" ? "↓" : "—"}</span>
        {pct}% vs last {range}
      </div>
    </div>
  );
}

function ImpactRing({ value, color, max = 60 }: { value: number; color: string; max?: number }) {
  const size = 22;
  const stroke = 3;
  const radius = size / 2 - stroke;
  const circ = 2 * Math.PI * radius;
  const frac = Math.max(0, Math.min(1, value / max));
  const dash = circ * frac;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="var(--raised)" strokeWidth={stroke} />
      <circle
        cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth={stroke}
        strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
    </svg>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      title="Copy"
      style={{ background: "transparent", border: "none", cursor: "pointer", color: copied ? "var(--green)" : "var(--dim)", display: "inline-flex", padding: 2 }}
    >
      <Icon name={copied ? "check" : "copy"} size={12} />
    </button>
  );
}

function AssignCell({
  incident, users, writable, onChanged,
}: {
  incident: IncidentSummary;
  users: AdminUser[];
  writable: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const assignedEmail = users.find((u) => u.id === incident.assigned_to)?.email ?? "Unassigned";

  if (!writable) {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--muted)" }}>
        <Icon name="user" size={12} /> {assignedEmail}
      </span>
    );
  }

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const value = e.target.value;
    if (!value || value === incident.assigned_to) return;
    setBusy(true);
    try {
      await apiFetch(`/api/incidents/${incident.incident_id}`, { method: "PATCH", body: JSON.stringify({ assigned_to: value }) });
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  return (
    <select
      value={incident.assigned_to ?? ""}
      disabled={busy}
      onClick={(e) => e.stopPropagation()}
      onChange={handleChange}
      style={{ ...selectStyle, padding: "4px 8px", fontSize: 11.5, color: incident.assigned_to ? "var(--text)" : "var(--muted)" }}
    >
      <option value="">Unassigned</option>
      {users.map((u) => <option key={u.id} value={u.id}>{u.email}{u.analyst_tier ? ` (T${u.analyst_tier})` : ""}</option>)}
    </select>
  );
}

function PaginationFooter({
  total, page, pageSize, totalPages, onPage, onPageSize,
}: {
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
  onPage: (p: number) => void;
  onPageSize: (n: number) => void;
}) {
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(total, page * pageSize);
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10, marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
      <div style={{ fontSize: 11, color: "var(--muted)" }}>Showing {start} to {end} of {total} incidents</div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button onClick={() => onPage(Math.max(1, page - 1))} disabled={page <= 1} style={pagerBtnStyle(page <= 1)}>
          <Icon name="chevronLeft" size={13} />
        </button>
        <span style={{ fontSize: 11, color: "var(--text)", minWidth: 26, textAlign: "center", background: "var(--accent)", borderRadius: 5, padding: "3px 8px", fontWeight: 700 }}>
          {page}
        </span>
        <button onClick={() => onPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages} style={pagerBtnStyle(page >= totalPages)}>
          <Icon name="chevronRight" size={13} />
        </button>
        <select value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))} style={{ ...selectStyle, padding: "4px 8px", fontSize: 11 }}>
          {PAGE_SIZES.map((n) => <option key={n} value={n}>{n} / page</option>)}
        </select>
      </div>
    </div>
  );
}

function DownloadIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3v12M7 10l5 5 5-5M4 21h16" />
    </svg>
  );
}

function IncidentDetailPanel({
  incidentId, users, writable, onChanged, onClose,
}: {
  incidentId: string;
  users: AdminUser[];
  writable: boolean;
  onChanged: () => void;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [tab, setTab] = useState<"evidence" | "notes" | "ticket" | "block" | "playbook">("evidence");
  const [noteBody, setNoteBody] = useState("");
  const [blockActions, setBlockActions] = useState<BlockAction[]>([]);
  const [busy, setBusy] = useState(false);
  const [playbook, setPlaybook] = useState<IncidentPlaybook | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [ticketError, setTicketError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setDetail(await apiFetch<IncidentDetail>(`/api/incidents/${incidentId}`));
    setPlaybook(await apiFetch<IncidentPlaybook>(`/api/incidents/${incidentId}/playbook`).catch(() => null));
  }, [incidentId]);

  async function toggleStep(stepId: string, done: boolean) {
    setBusy(true);
    try {
      await apiFetch(`/api/incidents/${incidentId}/playbook/steps/${stepId}`, { method: "POST", body: JSON.stringify({ done }) });
      setPlaybook(await apiFetch<IncidentPlaybook>(`/api/incidents/${incidentId}/playbook`));
    } finally {
      setBusy(false);
    }
  }

  async function runStepAction(action: "propose_block" | "open_ticket") {
    if (action === "open_ticket") { setTab("ticket"); return; }
    setBusy(true);
    try {
      const r = await apiFetch<{ proposed: string[]; already_proposed: string[] }>(
        `/api/incidents/${incidentId}/propose-block`, { method: "POST" },
      );
      setActionMsg(
        r.proposed.length
          ? `Proposed dry-run block for ${r.proposed.join(", ")} - review it in the Block Action tab.`
          : "Every source IP already has a proposed or executed block.",
      );
      setBlockActions(await apiFetch<BlockAction[]>("/api/block-actions?status=proposed"));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    apiFetch<BlockAction[]>("/api/block-actions?status=proposed").then(setBlockActions).catch(() => {});
  }, [detail]);

  if (!detail) return null;
  const t = tierTheme(detail.tier);
  const relevantBlocks = blockActions.filter((b) => detail.src_ips.includes(b.src_ip));

  async function patch(body: Partial<{ workflow_status: WorkflowStatus; assigned_to: string; resolution: Resolution }>) {
    setBusy(true);
    try {
      await apiFetch(`/api/incidents/${incidentId}`, { method: "PATCH", body: JSON.stringify(body) });
      await load();
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  async function addNote() {
    if (!noteBody.trim()) return;
    setBusy(true);
    try {
      await apiFetch(`/api/incidents/${incidentId}/notes`, { method: "POST", body: JSON.stringify({ body: noteBody.trim() }) });
      setNoteBody("");
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function createTicket() {
    setBusy(true);
    setTicketError(null);
    try {
      await apiFetch(`/api/incidents/${incidentId}/ticket`, { method: "POST", body: JSON.stringify({ provider: "jira" }) });
      await load();
    } catch (e) {
      setTicketError(e instanceof Error ? e.message : "Ticket creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function syncTickets() {
    setBusy(true);
    setTicketError(null);
    try {
      await apiFetch(`/api/incidents/${incidentId}/tickets/sync`, { method: "POST" });
      await load();
    } catch (e) {
      setTicketError(e instanceof Error ? e.message : "Status refresh failed");
    } finally {
      setBusy(false);
    }
  }

  async function decideBlock(id: string, action: "execute" | "dismiss") {
    setBusy(true);
    try {
      await apiFetch(`/api/block-actions/${id}/${action}`, { method: "POST" });
      setBlockActions(await apiFetch<BlockAction[]>("/api/block-actions?status=proposed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box title="Incident Detail">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
            <SeverityPill tier={detail.tier} />
            <span style={{ fontSize: 13, fontWeight: 600 }}>{detail.attack_types.map((t2) => themeFor(t2).label).join(" + ")}</span>
          </div>
          <div style={{ fontSize: 11, color: "var(--muted)", fontFamily: "var(--mono)" }}>{detail.src_ips.join(", ")} · {detail.interface}</div>
        </div>
        <button onClick={onClose} style={{ ...btnStyle, background: "transparent" }}>Close</button>
      </div>

      {writable && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 16, padding: 12, background: "var(--raised)", borderRadius: 8 }}>
          <Field label="Workflow Status">
            <select
              value={detail.workflow_status} disabled={busy}
              onChange={(e) => patch({ workflow_status: e.target.value as WorkflowStatus })}
              style={selectStyle}
            >
              {WORKFLOW_STATUSES.map((w) => <option key={w} value={w}>{WORKFLOW_LABEL[w]}</option>)}
            </select>
          </Field>
          <Field label="Assigned To">
            <select
              value={detail.assigned_to ?? ""} disabled={busy}
              onChange={(e) => e.target.value && patch({ assigned_to: e.target.value })}
              style={selectStyle}
            >
              <option value="">Unassigned</option>
              {users.map((u) => <option key={u.id} value={u.id}>{u.email}{u.analyst_tier ? ` (T${u.analyst_tier})` : ""}</option>)}
            </select>
          </Field>
          {detail.workflow_status === "resolved" && (
            <Field label="Resolution">
              <select
                value={detail.resolution ?? ""} disabled={busy}
                onChange={(e) => e.target.value && patch({ resolution: e.target.value as Resolution })}
                style={selectStyle}
              >
                <option value="">Not set</option>
                <option value="true_positive">True Positive</option>
                <option value="false_positive">False Positive</option>
              </select>
            </Field>
          )}
        </div>
      )}

      <div style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--border)", marginBottom: 14 }}>
        {(["evidence", "notes", "ticket", "block", "playbook"] as const).map((tb) => (
          <button
            key={tb}
            onClick={() => setTab(tb)}
            style={{
              background: "transparent", border: "none", borderBottom: `2px solid ${tab === tb ? "var(--accent)" : "transparent"}`,
              color: tab === tb ? "var(--text)" : "var(--muted)", padding: "8px 12px", fontSize: 12, fontWeight: 600,
              cursor: "pointer", textTransform: "capitalize",
            }}
          >
            {tb === "block" ? "Block Action" : tb === "playbook" && playbook && playbook.total > 0 ? `playbook ${playbook.done}/${playbook.total}` : tb}
          </button>
        ))}
      </div>

      {tab === "evidence" && (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Attack Type", "Src", "Dst", "Packets", "Hybrid %", "Severity", "Time"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "6px 8px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {detail.evidence.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: 16, textAlign: "center", color: "var(--dim)" }}>No linked evidence rows</td></tr>
              ) : detail.evidence.map((e) => (
                <tr key={e.alert_id}>
                  <td style={cellStyle}>{themeFor(e.attack_type).label}</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{e.src_ip}</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{e.dst_ip}</td>
                  <td style={cellStyle}>{e.packets}</td>
                  <td style={cellStyle}>{(e.hybrid_conf * 100).toFixed(1)}%</td>
                  <td style={cellStyle}><SeverityPill tier={e.severity} /></td>
                  <td style={cellStyle}>{new Date(e.created_at).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "notes" && (
        <div>
          {writable && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <input value={noteBody} onChange={(e) => setNoteBody(e.target.value)} placeholder="Add an analyst note..." style={{ ...selectStyle, flex: 1 }} />
              <button onClick={addNote} disabled={busy} style={btnStyle}>Add Note</button>
            </div>
          )}
          {detail.notes.length === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>No notes yet</div>
          ) : (
            detail.notes.map((n) => (
              <div key={n.note_id} style={{ padding: "8px 0", borderBottom: "1px solid var(--raised)" }}>
                <div style={{ fontSize: 12 }}>{n.body}</div>
                <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 3 }}>{new Date(n.created_at).toLocaleString()}</div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "ticket" && (
        <div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginBottom: 12 }}>
            Creates a Jira issue pre-filled with this incident&apos;s severity, source IPs and attack types. One open ticket per incident.
          </div>
          {writable && (
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <button onClick={createTicket} disabled={busy} style={btnStyle}>Create Jira Ticket</button>
              {detail.tickets.some((tk) => !tk.simulated) && (
                <button onClick={syncTickets} disabled={busy} style={{ ...btnStyle, background: "transparent" }}>Refresh status</button>
              )}
            </div>
          )}
          {ticketError && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 10 }}>{ticketError}</div>}
          {detail.tickets.length === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>No tickets created</div>
          ) : (
            detail.tickets.map((tk) => {
              const done = tk.status_category === "done";
              const color = done ? "var(--green)" : tk.status_category === "indeterminate" ? "var(--amber)" : "var(--blue)";
              return (
                <div key={tk.ticket_id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 0", fontSize: 12, borderBottom: "1px solid var(--raised)" }}>
                  <span>
                    {tk.url ? (
                      <a href={tk.url} target="_blank" rel="noreferrer" style={{ fontFamily: "var(--mono)", color: "var(--blue)" }}>{tk.external_ref}</a>
                    ) : (
                      <span style={{ fontFamily: "var(--mono)" }}>{tk.external_ref}</span>
                    )}
                    {tk.simulated && <em style={{ color: "var(--dim)", fontStyle: "normal", fontSize: 10 }}> (simulated)</em>}
                    {tk.status && !tk.simulated && (
                      <span style={{ marginLeft: 8, fontSize: 10, padding: "2px 8px", borderRadius: 10, border: `1px solid ${color}`, color }}>{tk.status}</span>
                    )}
                  </span>
                  <span style={{ color: "var(--muted)" }}>{new Date(tk.created_at).toLocaleString()}</span>
                </div>
              );
            })
          )}
        </div>
      )}

      {tab === "block" && (
        <div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginBottom: 12 }}>
            Dry-run only - "Execute" never fires a real firewall/network change, it just records the analyst's decision for audit purposes.
          </div>
          {relevantBlocks.length === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>No proposed block actions for this incident's source IPs</div>
          ) : (
            relevantBlocks.map((b) => (
              <div key={b.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid var(--raised)" }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{b.src_ip}</div>
                  <div style={{ fontSize: 10, color: "var(--dim)" }}>{b.reason}</div>
                </div>
                {writable && (
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={() => decideBlock(b.id, "execute")} disabled={busy} style={{ ...btnStyle, color: "var(--red)", borderColor: "rgba(248,81,73,.3)" }}>Execute (dry-run)</button>
                    <button onClick={() => decideBlock(b.id, "dismiss")} disabled={busy} style={{ ...btnStyle, background: "transparent" }}>Dismiss</button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {tab === "playbook" && (
        <div>
          {!playbook || playbook.total === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>No enabled playbook matches this incident. An admin can add one on the Playbooks page.</div>
          ) : (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <div style={{ flex: 1, height: 6, background: "var(--raised)", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ width: `${(playbook.done / playbook.total) * 100}%`, height: "100%", background: "var(--green)" }} />
                </div>
                <span style={{ fontSize: 11, color: "var(--muted)", fontFamily: "var(--mono)" }}>{playbook.done}/{playbook.total} done</span>
              </div>
              {actionMsg && <div style={{ fontSize: 11, color: "var(--blue)", marginBottom: 10 }}>{actionMsg}</div>}
              {playbook.steps.map((s, i) => (
                <div key={s.id}>
                  {(i === 0 || playbook.steps[i - 1].playbook_name !== s.playbook_name) && (
                    <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--dim)", margin: "10px 0 4px" }}>{s.playbook_name}</div>
                  )}
                  <div style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "7px 0", borderBottom: "1px solid var(--raised)" }}>
                    <input
                      type="checkbox" checked={s.done} disabled={busy || !writable}
                      onChange={(e) => toggleStep(s.id, e.target.checked)} style={{ marginTop: 3 }}
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 12, lineHeight: 1.6, color: s.done ? "var(--dim)" : "var(--text)", textDecoration: s.done ? "line-through" : "none" }}>{s.title}</div>
                      {s.done && s.done_at && (
                        <div style={{ fontSize: 10, color: "var(--dim)" }}>
                          Done by {users.find((u) => u.id === s.done_by)?.email ?? "an analyst"} · {new Date(s.done_at).toLocaleString()}
                        </div>
                      )}
                    </div>
                    {s.action && writable && (
                      <button onClick={() => runStepAction(s.action as "propose_block" | "open_ticket")} disabled={busy} style={btnStyle}>
                        {s.action === "propose_block" ? "Propose block" : "Open ticket tab"}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </Box>
  );
}

function SeverityPill({ tier }: { tier: string | null | undefined }) {
  const color = severityColor(tier);
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontWeight: 700,
        padding: "3px 8px", borderRadius: 20, color, background: `${color}1f`, border: `1px solid ${color}40`,
        textTransform: "uppercase", letterSpacing: "0.04em",
      }}
    >
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: color }} />
      {tier}
    </span>
  );
}

function PageHeader({ connected }: { connected: boolean }) {
  const writable = canWrite(getRole());
  return (
    <div style={{ marginBottom: 22, display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
      <div>
        <div style={{ fontSize: 11, color: "var(--dim)", marginBottom: 6 }}>SOC — IDS <span style={{ margin: "0 4px" }}>›</span> Incidents</div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Incident Queue</div>
        <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>Triage, assign, and investigate correlated incidents</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {writable && <TakeSnapshotButton />}
        <span
          style={{
            display: "inline-flex", alignItems: "center", gap: 6, fontSize: 10, fontWeight: 700,
            padding: "6px 12px", borderRadius: 20, color: connected ? "var(--green)" : "var(--dim)",
            background: connected ? "rgba(63,185,80,0.12)" : "var(--raised)",
            border: `1px solid ${connected ? "rgba(63,185,80,0.3)" : "var(--border)"}`,
            textTransform: "uppercase", letterSpacing: "0.06em",
          }}
        >
          <span className="live-dot" style={{ background: connected ? "var(--green)" : "var(--dim)" }} />
          {connected ? "Live" : "Offline"}
        </span>
      </div>
    </div>
  );
}

function TakeSnapshotButton() {
  const [taking, setTaking] = useState(false);
  const [done, setDone] = useState(false);

  async function take() {
    setTaking(true);
    setDone(false);
    try {
      await apiFetch("/api/snapshots", { method: "POST", body: JSON.stringify({}) });
      setDone(true);
      setTimeout(() => setDone(false), 2000);
    } finally {
      setTaking(false);
    }
  }

  return (
    <button
      onClick={take}
      disabled={taking}
      style={{
        background: "var(--raised)", border: "1px solid var(--border)", color: "var(--text)",
        borderRadius: 6, padding: "7px 14px", fontSize: 12, cursor: "pointer", fontWeight: 600,
        opacity: taking ? 0.6 : 1, display: "flex", alignItems: "center", gap: 7,
      }}
      className="transition-accent"
    >
      <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
        <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2ZM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z" />
      </svg>
      {taking ? "Capturing..." : done ? "Snapshot saved ✓" : "Take Snapshot"}
    </button>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      {children}
    </div>
  );
}

function Box({ title, icon, children }: { title: string; icon?: keyof typeof ICON_PATHS; children: React.ReactNode }) {
  return (
    <div className="card-hover" style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 14 }}>
        {icon && <span style={{ color: "var(--dim)", display: "flex" }}><Icon name={icon} size={13} /></span>}
        {title}
      </div>
      {children}
    </div>
  );
}

function pagerBtnStyle(disabled: boolean): React.CSSProperties {
  return {
    display: "flex", alignItems: "center", justifyContent: "center", width: 26, height: 26,
    background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
    color: disabled ? "var(--dim)" : "var(--text)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.5 : 1,
  };
}

const cellStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--raised)" };

const selectStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "6px 9px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, outline: "none",
};

const btnStyle: React.CSSProperties = {
  padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)",
  borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
};
