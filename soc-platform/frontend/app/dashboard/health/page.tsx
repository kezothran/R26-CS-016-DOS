"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { useSocStream } from "@/lib/SocStreamContext";
import { themeFor } from "@/lib/theme";
import type { HealthStatus } from "@/lib/types";
import { Sparkline } from "../charts";

// Operational status of the detection engine itself (uptime, model load state, per-interface
// throughput) - distinct from the Metrics page, which is security posture (MTTA/MTTR/alert
// volume), not engine health.

const ICON_PATHS: Record<string, string> = {
  activity: "M2 12h4l2-7 4 14 2-7h4l2-4",
  alert: "M12 3 2 20h20L12 3ZM12 10v5M12 18v.01",
  shield: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM9 12l2 2 4-4",
  layers: "M12 3 2 8l10 5 10-5-10-5ZM2 14l10 5 10-5M2 11l10 5 10-5",
  grid: "M3 3h7v7H3V3ZM14 3h7v7h-7V3ZM3 14h7v7H3v-7ZM14 14h7v7h-7v-7",
  wifi: "M2 8.5a16 16 0 0 1 20 0M5.5 12a11 11 0 0 1 13 0M9 15.5a6 6 0 0 1 6 0M12 19v.01",
  check: "M20 6 9 17l-5-5",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 7v5l3.5 2",
  cpu: "M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3M7 7h10v10H7z",
};

type IconName = keyof typeof ICON_PATHS;

function Icon({ name, size = 15 }: { name: IconName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d={ICON_PATHS[name]} />
    </svg>
  );
}

const ROLE_COLOR: Record<string, string> = {
  good: "var(--green)", critical: "var(--red)", info: "var(--blue)", neutral: "var(--muted)",
};

function StatCard({
  label, value, subtitle, role = "neutral", icon, sparklineData,
}: {
  label: string;
  value: string;
  subtitle?: string;
  role?: "good" | "critical" | "info" | "neutral";
  icon: IconName;
  sparklineData?: number[];
}) {
  const accent = ROLE_COLOR[role];
  const tinted = role !== "neutral";
  return (
    <div
      className="card-hover"
      style={{
        position: "relative", borderRadius: 10, padding: "14px 16px", background: "var(--surf)",
        borderTop: `2px solid ${tinted ? accent : "var(--border)"}`,
        borderInline: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
      }}
    >
      <span
        style={{
          position: "absolute", top: 12, right: 12, width: 26, height: 26, borderRadius: 7,
          background: tinted ? `${accent}1f` : "var(--raised)", color: tinted ? accent : "var(--dim)",
          display: "flex", alignItems: "center", justifyContent: "center",
        }}
      >
        <Icon name={icon} size={13} />
      </span>
      <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, maxWidth: "72%" }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--mono)", color: role === "neutral" ? "var(--text)" : accent }}>
        {value}
      </div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginTop: 8, minHeight: 18 }}>
        {subtitle && <span style={{ fontSize: 10.5, color: "var(--dim)" }}>{subtitle}</span>}
        {sparklineData && sparklineData.length >= 2 && (
          <Sparkline data={sparklineData} color={tinted ? accent : "var(--blue)"} width={44} height={16} />
        )}
      </div>
    </div>
  );
}

function Box({ title, icon, right, children }: { title: string; icon?: IconName; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card-hover" style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>
          {icon && <span style={{ color: "var(--dim)", display: "flex" }}><Icon name={icon} size={13} /></span>}
          {title}
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

function StatusPill({ ok, onLabel, offLabel }: { ok: boolean; onLabel: string; offLabel: string }) {
  const color = ok ? "var(--green)" : "var(--dim)";
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5, fontSize: 9, fontWeight: 700,
        padding: "2px 7px", borderRadius: 20, color, background: ok ? "rgba(63,185,80,0.12)" : "var(--raised)",
        textTransform: "uppercase", letterSpacing: "0.05em",
      }}
    >
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: color }} />
      {ok ? onLabel : offLabel}
    </span>
  );
}

const HISTORY_LIMIT = 24;

export default function HealthPage() {
  const { state, connected } = useSocStream();
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [windowSecs, setWindowSecs] = useState(5);
  const [rateHistory, setRateHistory] = useState<number[]>([]);
  const [ifaceHistory, setIfaceHistory] = useState<Record<string, number[]>>({});

  useEffect(() => {
    function load() {
      apiFetch<HealthStatus>("/health").then(setHealth);
    }
    load();
    apiFetch<{ window_secs: number }>("/api/settings").then((s) => setWindowSecs(s.window_secs || 5));
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  // Rolling client-side buffers so the packet-rate and per-interface trends show a genuine
  // recent shape rather than a single point - same pattern as the Overview page's statsHistory.
  useEffect(() => {
    if (!state) return;
    setRateHistory((prev) => [...prev, state.packets_per_sec ?? 0].slice(-HISTORY_LIMIT));
    setIfaceHistory((prev) => {
      const next = { ...prev };
      for (const i of state.interfaces) {
        const rate = (state.interface_packet_counts?.[i.name] ?? 0) / windowSecs;
        next[i.name] = [...(prev[i.name] ?? []), rate].slice(-HISTORY_LIMIT);
      }
      return next;
    });
  }, [state?.timestamp]);

  const allUp = state ? state.interfaces.length > 0 && state.interfaces.every((i) => i.up) : true;
  const downCount = state ? state.interfaces.filter((i) => !i.up).length : 0;
  const detectorCount = health ? Object.keys(health.model_status ?? {}).length || health.active_attacks.length : 0;
  const startTime = health ? new Date(Date.now() - health.uptime_seconds * 1000) : null;
  const maxIfaceLoad = state
    ? Math.max(1, ...state.interfaces.map((i) => state.interface_packet_counts?.[i.name] ?? 0))
    : 1;

  return (
    <div>
      <div style={{ marginBottom: 22, display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 600 }}>Engine Health</div>
          <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>
            Ensure high availability, model readiness, and optimal detection performance
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, color: "var(--dim)" }}>
          <span className="live-dot" style={{ background: connected ? "var(--green)" : "var(--dim)" }} />
          {connected ? "Live feed connected" : "Disconnected"}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12, marginBottom: 20 }}>
        <StatCard
          label="Engine Status" icon={connected ? "check" : "alert"} role={connected ? "good" : "critical"}
          value={connected ? "Online" : "Offline"}
          subtitle={connected ? "All systems operational" : "Not receiving live updates"}
        />
        <StatCard
          label="Uptime" icon="clock" role="info"
          value={health ? formatUptime(health.uptime_seconds) : "—"}
          subtitle={startTime ? `Since ${startTime.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}` : undefined}
        />
        <StatCard label="Detection Window" icon="layers" role="neutral" value={`${windowSecs}s`} subtitle="Real-time" />
        <StatCard
          label="Active Detectors" icon="shield" role="good"
          value={health ? String(detectorCount) : "—"}
          subtitle={health ? "All running" : undefined}
        />
        <StatCard
          label="Packet Rate" icon="cpu" role="info"
          value={state ? `${Math.round(state.packets_per_sec ?? 0).toLocaleString()}/s` : "—"}
          sparklineData={rateHistory}
        />
        <StatCard
          label="Interfaces" icon="wifi" role={allUp ? "good" : "critical"}
          value={state ? String(state.interfaces.length) : "—"}
          subtitle={state ? (allUp ? "All healthy" : `${downCount} down`) : undefined}
        />
      </div>

      <Box title="Model Status" icon="grid">
        {!health?.model_status ? (
          <div style={{ color: "var(--dim)", fontSize: 12 }}>
            {health ? "Backend is running an older /health response - restart it to see model status." : "Loading..."}
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Attack Type", "Model", "Status", "DL Model"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(health.model_status).map(([type, status]) => {
                const t = themeFor(type);
                return (
                  <tr key={type} className="row-hover">
                    <td style={cellStyle}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                        <span style={{ width: 7, height: 7, borderRadius: "50%", background: t.color, flexShrink: 0 }} />
                        {t.label}
                      </span>
                    </td>
                    <td style={cellStyle}>{status.trained ? "Hybrid ML" : "Rule-based"}</td>
                    <td style={cellStyle}><StatusPill ok={status.trained} onLabel="Loaded" offLabel="Fallback" /></td>
                    <td style={cellStyle}><StatusPill ok={status.has_dl_model} onLabel="Loaded" offLabel="None" /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Box>

      <Box title="Interface Throughput" icon="wifi" right={<span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "var(--green)", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em" }}><span className="live-dot" style={{ background: "var(--green)" }} />Live</span>}>
        {!state || state.interfaces.length === 0 ? (
          <div style={{ color: "var(--dim)", fontSize: 12 }}>No interfaces detected</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Interface", "IP", "Status", "Flagged pkts/sec", "Trend", "Share of load"].map((h) => (
                  <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.interfaces.map((i) => {
                const count = state.interface_packet_counts?.[i.name] ?? 0;
                const loadPct = Math.round((count / maxIfaceLoad) * 100);
                return (
                  <tr key={i.name} className="row-hover">
                    <td style={cellStyle}>{i.description || i.name}</td>
                    <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{i.ip}</td>
                    <td style={cellStyle}><StatusPill ok={i.up} onLabel="Up" offLabel="Down" /></td>
                    <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{(count / windowSecs).toFixed(1)}</td>
                    <td style={cellStyle}>
                      <Sparkline data={ifaceHistory[i.name] ?? []} color="var(--blue)" width={54} height={18} />
                    </td>
                    <td style={{ ...cellStyle, minWidth: 110 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, height: 5, borderRadius: 3, background: "var(--raised)", overflow: "hidden" }}>
                          <div style={{ width: `${loadPct}%`, height: "100%", background: "var(--blue)", borderRadius: 3, transition: "width 0.4s ease" }} />
                        </div>
                        <span style={{ fontSize: 10, color: "var(--dim)", width: 32, textAlign: "right" }}>{loadPct}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 10 }}>
          A packet flagged into multiple attack-type buckets (e.g. fragmentation + ICMP) counts once per bucket -
          this is a glance-level throughput figure, not an exact unique-packet rate. Share of load is relative to the busiest interface this cycle.
        </div>
      </Box>
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

const cellStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--raised)" };
