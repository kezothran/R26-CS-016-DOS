"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { canWrite, getRole } from "@/lib/auth";
import { useSocStream } from "@/lib/SocStreamContext";
import { severityColor, themeFor } from "@/lib/theme";
import type { SnapshotDetail, SnapshotSummary } from "@/lib/types";

const ICON_PATHS: Record<string, string> = {
  camera: "M4 8h3l2-3h6l2 3h3a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2ZM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z",
  layers: "M12 3 2 8l10 5 10-5-10-5ZM2 14l10 5 10-5M2 11l10 5 10-5",
  alert: "M12 3 2 20h20L12 3ZM12 10v5M12 18v.01",
  shield: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM9 12l2 2 4-4",
  clock: "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20ZM12 6v6l4 2",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7ZM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  download: "M12 3v12m0 0 4-4m-4 4-4-4M4 21h16",
  chevronLeft: "m15 6-6 6 6 6",
  chevronRight: "m9 6 6 6-6 6",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16ZM21 21l-4.3-4.3",
};

function Icon({ name, size = 15 }: { name: keyof typeof ICON_PATHS; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}

const RANGE_OPTIONS = [
  { value: "24h", label: "24 Hours" },
  { value: "7d", label: "7 Days" },
  { value: "30d", label: "30 Days" },
  { value: "all", label: "All Time" },
] as const;

const SEVERITY_OPTIONS = ["All", "Critical", "High", "Medium", "Elevated", "Low", "Normal"] as const;
const TRIGGER_OPTIONS = [
  { value: "all", label: "All" },
  { value: "auto_incident", label: "Auto (Critical Incident)" },
  { value: "manual", label: "Manual" },
] as const;
const STATUS_OPTIONS = [
  { value: "all", label: "All" },
  { value: "active", label: "Active Incidents" },
  { value: "clear", label: "No Incidents" },
] as const;
const PAGE_SIZES = [8, 10, 25, 50] as const;

const RANGE_MS: Record<string, number> = { "24h": 86_400_000, "7d": 604_800_000, "30d": 2_592_000_000 };

function csvEscape(v: string | number): string {
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export default function SnapshotsPage() {
  const { connected } = useSocStream();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[] | null>(null);
  const [selected, setSelected] = useState<SnapshotDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [taking, setTaking] = useState(false);
  const writable = canWrite(getRole());

  const [range, setRange] = useState<string>("24h");
  const [severity, setSeverity] = useState<string>("All");
  const [trigger, setTrigger] = useState<string>("all");
  const [status, setStatus] = useState<string>("all");
  const [sourceIp, setSourceIp] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const load = useCallback(async () => {
    setSnapshots(await apiFetch<SnapshotSummary[]>("/api/snapshots"));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function selectSnapshot(id: string) {
    setLoadingDetail(true);
    try {
      setSelected(await apiFetch<SnapshotDetail>(`/api/snapshots/${id}`));
    } finally {
      setLoadingDetail(false);
    }
  }

  async function takeSnapshot() {
    setTaking(true);
    try {
      await apiFetch("/api/snapshots", { method: "POST", body: JSON.stringify({}) });
      await load();
    } finally {
      setTaking(false);
    }
  }

  const filtered = useMemo(() => {
    if (!snapshots) return [];
    const now = Date.now();
    const ipQuery = sourceIp.trim().toLowerCase();
    return snapshots.filter((s) => {
      if (range !== "all") {
        const age = now - new Date(s.created_at).getTime();
        if (age > RANGE_MS[range]) return false;
      }
      if (severity !== "All" && s.security_tier !== severity) return false;
      if (trigger !== "all" && s.trigger !== trigger) return false;
      if (status === "active" && s.active_incident_count === 0) return false;
      if (status === "clear" && s.active_incident_count > 0) return false;
      if (ipQuery && !s.source_ips.some((ip) => ip.toLowerCase().includes(ipQuery))) return false;
      return true;
    });
  }, [snapshots, range, severity, trigger, status, sourceIp]);

  useEffect(() => { setPage(1); }, [range, severity, trigger, status, sourceIp, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageClamped = Math.min(page, totalPages);
  const pageRows = filtered.slice((pageClamped - 1) * pageSize, pageClamped * pageSize);

  const stats = useMemo(() => {
    const all = snapshots ?? [];
    const totalPackets = all.reduce((sum, s) => sum + s.total_packets, 0);
    const critical = all.filter((s) => s.security_tier === "Critical").length;
    const avgScore = all.length ? all.reduce((sum, s) => sum + s.security_score, 0) / all.length : 0;
    const latest = all[0] ?? null;
    return { total: all.length, totalPackets, critical, avgScore, latest };
  }, [snapshots]);

  function exportCsv() {
    const header = ["Taken", "Label", "Trigger", "Security Tier", "Score", "Active Incidents", "Total Packets", "Source IPs"];
    const rows = filtered.map((s) => [
      new Date(s.created_at).toLocaleString(),
      s.label ?? "",
      s.trigger === "auto_incident" ? "Auto (Critical Incident)" : "Manual",
      s.security_tier,
      s.security_score.toFixed(1),
      String(s.active_incident_count),
      String(s.total_packets),
      s.source_ips.join(" "),
    ]);
    const csv = [header, ...rows].map((r) => r.map(csvEscape).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `snapshots-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <PageHeader connected={connected} writable={writable} taking={taking} onTake={takeSnapshot} />

      <div
        className="fade-in-up"
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 18 }}
      >
        <StatTile icon="camera" color="#bc8cff" label="Total Snapshots" value={stats.total.toLocaleString()} sub="All time captures" />
        <StatTile icon="layers" color="#58a6ff" label="Total Packets Captured" value={stats.totalPackets.toLocaleString()} sub="Across all snapshots" />
        <StatTile icon="alert" color="#d03b3b" label="Critical Snapshots" value={stats.critical.toLocaleString()} sub="Auto & manual" />
        <StatTile icon="shield" color="#3fb950" label="Avg Confidence Score" value={`${stats.avgScore.toFixed(1)}%`} sub="Across all snapshots" />
        <StatTile
          icon="clock"
          color="#58a6ff"
          label="Latest Snapshot"
          value={stats.latest ? new Date(stats.latest.created_at).toLocaleString() : "—"}
          sub={stats.latest ? (stats.latest.trigger === "auto_incident" ? `Auto: ${stats.latest.label ?? "Critical Incident"}` : stats.latest.label ?? "Manual") : "No snapshots yet"}
        />
      </div>

      <FiltersBar
        range={range} setRange={setRange}
        severity={severity} setSeverity={setSeverity}
        trigger={trigger} setTrigger={setTrigger}
        status={status} setStatus={setStatus}
        sourceIp={sourceIp} setSourceIp={setSourceIp}
        onExport={exportCsv}
      />

      <Box title={`Snapshots ${snapshots ? `(${filtered.length})` : ""}`}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Taken", "Label", "Trigger", "Security Tier", "Score", "Active Incidents", "Total Packets", ""].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {snapshots === null ? (
                <tr><td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>Loading...</td></tr>
              ) : pageRows.length === 0 ? (
                <tr><td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>No snapshots match these filters</td></tr>
              ) : (
                pageRows.map((s) => (
                  <tr
                    key={s.id} className="row-hover"
                    style={{ background: selected?.id === s.id ? "var(--raised)" : undefined }}
                  >
                    <td style={cellStyle}>{new Date(s.created_at).toLocaleString()}</td>
                    <td style={cellStyle}>{s.label ?? "—"}</td>
                    <td style={cellStyle}>
                      <span style={{ color: s.trigger === "auto_incident" ? "var(--red)" : "var(--muted)" }}>
                        {s.trigger === "auto_incident" ? "Auto (Critical Incident)" : "Manual"}
                      </span>
                    </td>
                    <td style={cellStyle}><SeverityPill tier={s.security_tier} /></td>
                    <td style={cellStyle}><ScoreBar score={s.security_score} tier={s.security_tier} /></td>
                    <td style={cellStyle}>
                      <span style={{ color: s.active_incident_count > 0 ? "var(--blue)" : "var(--dim)", fontWeight: 600 }}>
                        {s.active_incident_count}
                      </span>
                    </td>
                    <td style={cellStyle}>{s.total_packets.toLocaleString()}</td>
                    <td style={cellStyle}>
                      <button onClick={() => selectSnapshot(s.id)} title="View snapshot" style={iconBtnStyle} className="transition-accent">
                        <Icon name="eye" size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {snapshots !== null && filtered.length > 0 && (
          <Pagination
            page={pageClamped} totalPages={totalPages} pageSize={pageSize}
            rangeStart={(pageClamped - 1) * pageSize + 1}
            rangeEnd={Math.min(pageClamped * pageSize, filtered.length)}
            total={filtered.length}
            onPage={setPage} onPageSize={setPageSize}
          />
        )}
      </Box>

      {selected && (
        <div className="fade-in-up">
          <SnapshotDetailPanel snapshot={selected} loading={loadingDetail} onClose={() => setSelected(null)} />
        </div>
      )}
    </div>
  );
}

function ScoreBar({ score, tier }: { score: number; tier: string }) {
  const color = severityColor(tier);
  const pct = Math.max(0, Math.min(100, score));
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 110 }}>
      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 12, color: "var(--text)", minWidth: 34 }}>{score.toFixed(1)}</span>
      <div style={{ flex: 1, height: 4, borderRadius: 2, background: "var(--raised)", overflow: "hidden", minWidth: 50 }}>
        <div style={{ width: `${pct}%`, height: "100%", borderRadius: 2, background: color }} />
      </div>
    </div>
  );
}

function StatTile({ icon, color, label, value, sub }: { icon: keyof typeof ICON_PATHS; color: string; label: string; value: string; sub: string }) {
  return (
    <div
      className="card-hover fade-in-up"
      style={{
        background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 14,
        display: "flex", flexDirection: "column", gap: 10, minWidth: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <span
          style={{
            width: 30, height: 30, borderRadius: 8, background: `${color}1f`, color,
            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
          }}
        >
          <Icon name={icon} size={15} />
        </span>
        <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      </div>
      <div>
        <div
          style={{
            fontSize: 18, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)",
            whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
          }}
          title={value}
        >
          {value}
        </div>
        <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={sub}>
          {sub}
        </div>
      </div>
    </div>
  );
}

function FiltersBar({
  range, setRange, severity, setSeverity, trigger, setTrigger, status, setStatus, sourceIp, setSourceIp, onExport,
}: {
  range: string; setRange: (v: string) => void;
  severity: string; setSeverity: (v: string) => void;
  trigger: string; setTrigger: (v: string) => void;
  status: string; setStatus: (v: string) => void;
  sourceIp: string; setSourceIp: (v: string) => void;
  onExport: () => void;
}) {
  return (
    <div
      className="card-hover fade-in-up"
      style={{
        background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 14,
        marginBottom: 16, display: "flex", flexWrap: "wrap", alignItems: "flex-end", gap: 14,
      }}
    >
      <FilterField label="Range">
        <select value={range} onChange={(e) => setRange(e.target.value)} style={selectStyle}>
          {RANGE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </FilterField>

      <FilterField label="Severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={selectStyle}>
          {SEVERITY_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
        </select>
      </FilterField>

      <FilterField label="Trigger">
        <select value={trigger} onChange={(e) => setTrigger(e.target.value)} style={selectStyle}>
          {TRIGGER_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </FilterField>

      <FilterField label="Status">
        <select value={status} onChange={(e) => setStatus(e.target.value)} style={selectStyle}>
          {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </FilterField>

      <FilterField label="Source IP">
        <div style={{ position: "relative" }}>
          <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: "var(--dim)", display: "flex", pointerEvents: "none" }}>
            <Icon name="search" size={12} />
          </span>
          <input
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            placeholder="e.g., 10.0.0.5"
            style={{ ...selectStyle, paddingLeft: 26, width: 150 }}
          />
        </div>
      </FilterField>

      <button onClick={onExport} style={{ ...btnStyle, marginLeft: "auto", display: "flex", alignItems: "center", gap: 7 }}>
        <Icon name="download" size={13} /> Export CSV
      </button>
    </div>
  );
}

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <span style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.07em" }}>{label}</span>
      {children}
    </div>
  );
}

function Pagination({
  page, totalPages, pageSize, rangeStart, rangeEnd, total, onPage, onPageSize,
}: {
  page: number; totalPages: number; pageSize: number; rangeStart: number; rangeEnd: number; total: number;
  onPage: (p: number) => void; onPageSize: (n: number) => void;
}) {
  const pages = Array.from({ length: totalPages }, (_, i) => i + 1).filter(
    (p) => p === 1 || p === totalPages || Math.abs(p - page) <= 1
  );
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 14, flexWrap: "wrap", gap: 10 }}>
      <div style={{ fontSize: 11, color: "var(--muted)" }}>
        Showing {rangeStart} to {rangeEnd} of {total} snapshots
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <button onClick={() => onPage(page - 1)} disabled={page <= 1} style={{ ...iconBtnStyle, opacity: page <= 1 ? 0.4 : 1 }}>
          <Icon name="chevronLeft" size={13} />
        </button>
        {pages.map((p, idx) => (
          <span key={p} style={{ display: "flex", alignItems: "center" }}>
            {idx > 0 && pages[idx - 1] !== p - 1 && <span style={{ color: "var(--dim)", padding: "0 4px" }}>…</span>}
            <button
              onClick={() => onPage(p)}
              style={{
                minWidth: 28, height: 28, borderRadius: 6, border: "1px solid var(--border)", fontSize: 12,
                background: p === page ? "var(--accent)" : "transparent", color: p === page ? "#fff" : "var(--muted)",
                cursor: "pointer",
              }}
              className="transition-accent"
            >
              {p}
            </button>
          </span>
        ))}
        <button onClick={() => onPage(page + 1)} disabled={page >= totalPages} style={{ ...iconBtnStyle, opacity: page >= totalPages ? 0.4 : 1 }}>
          <Icon name="chevronRight" size={13} />
        </button>
        <select value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))} style={{ ...selectStyle, marginLeft: 6 }}>
          {PAGE_SIZES.map((n) => <option key={n} value={n}>{n} / page</option>)}
        </select>
      </div>
    </div>
  );
}

function SnapshotDetailPanel({ snapshot, loading, onClose }: { snapshot: SnapshotDetail; loading: boolean; onClose: () => void }) {
  const attackEntries = Object.entries(snapshot.attacks ?? {});
  return (
    <Box
      title={`Snapshot Detail — ${new Date(snapshot.created_at).toLocaleString()}`}
      right={
        <button onClick={onClose} style={{ ...btnStyle, padding: "4px 10px" }}>
          Close
        </button>
      }
    >
      {loading ? (
        <div style={{ color: "var(--dim)", fontSize: 12 }}>Loading...</div>
      ) : (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 10, marginBottom: 16 }}>
            {attackEntries.map(([type, s]) => {
              const t = themeFor(type);
              return (
                <div key={type} style={{ background: "var(--raised)", borderRadius: 8, padding: 10, borderTop: `2px solid ${t.color}` }}>
                  <div style={{ fontSize: 9, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>{t.label}</div>
                  <div style={{ fontSize: 11, color: "var(--text)" }}>{s.flows} flows · {s.attacks} attack · {s.benign} normal</div>
                </div>
              );
            })}
          </div>

          <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--muted)", marginBottom: 10 }}>
            Captured Live Flows ({snapshot.live_flows?.length ?? 0})
          </div>
          <div style={{ overflowX: "auto", maxHeight: 360, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  {["Protocol", "Source IP", "Destination IP", "Packets", "Status", "Severity"].map((h) => (
                    <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)", position: "sticky", top: 0, background: "var(--surf)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(snapshot.live_flows ?? []).length === 0 ? (
                  <tr><td colSpan={6} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>No flows captured in this snapshot</td></tr>
                ) : (
                  snapshot.live_flows.map((f, idx) => (
                    <tr key={idx} className="row-hover">
                      <td style={{ ...cellStyle, color: themeFor(f.type).color, fontWeight: 600 }}>{themeFor(f.type).label.replace(" Flood", "")}</td>
                      <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{f.src}</td>
                      <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{f.dst}</td>
                      <td style={cellStyle}>{f.packets.toLocaleString()}</td>
                      <td style={{ ...cellStyle, color: f.status === "ATTACK" ? "var(--red)" : "var(--green)" }}>{f.status}</td>
                      <td style={{ ...cellStyle, color: severityColor(f.tier) }}>{f.tier}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
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

function PageHeader({ connected, writable, taking, onTake }: { connected: boolean; writable: boolean; taking: boolean; onTake: () => void }) {
  return (
    <div style={{ marginBottom: 20, display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
      <div>
        <div style={{ fontSize: 18, fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}>
          <Icon name="camera" size={17} /> Snapshots
        </div>
        <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>
          Point-in-time captures of the dashboard state - taken manually or automatically on Critical Incidents
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        {writable && (
          <button onClick={onTake} disabled={taking} style={{ ...btnStyle, display: "flex", alignItems: "center", gap: 7 }}>
            <Icon name="camera" size={13} /> {taking ? "Capturing..." : "Take Snapshot"}
          </button>
        )}
        <span
          style={{
            display: "inline-flex", alignItems: "center", gap: 6, fontSize: 10, fontWeight: 700, padding: "6px 12px",
            borderRadius: 20, color: connected ? "var(--green)" : "var(--dim)",
            background: connected ? "rgba(63,185,80,0.12)" : "var(--raised)", border: "1px solid var(--border)",
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

function Box({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div
      className="card-hover"
      style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>{title}</div>
        {right}
      </div>
      {children}
    </div>
  );
}

const cellStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--raised)" };
const btnStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", color: "var(--text)",
  borderRadius: 6, padding: "8px 14px", fontSize: 12, cursor: "pointer", fontWeight: 600,
};
const iconBtnStyle: React.CSSProperties = {
  width: 28, height: 28, borderRadius: 6, border: "1px solid var(--border)", background: "var(--raised)",
  color: "var(--muted)", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer",
};
const selectStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", color: "var(--text)",
  borderRadius: 6, padding: "7px 10px", fontSize: 12, outline: "none", height: 32,
};
