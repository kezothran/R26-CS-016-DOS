"use client";

import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { canWrite, getRole } from "@/lib/auth";
import { useSocStream } from "@/lib/SocStreamContext";
import { severityColor, themeFor, tierTheme } from "@/lib/theme";
import type { ActiveIncident, SecurityScoreState } from "@/lib/types";
import { Donut, RadialGauge, Sparkline, TrendChart, useCountUp } from "./charts";

const TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const SCORE_HISTORY_LIMIT = 40;
const CONF_HISTORY_LIMIT = 20;
const STATS_HISTORY_LIMIT = 30;

const ICON_PATHS: Record<string, string> = {
  activity: "M2 12h4l2-7 4 14 2-7h4l2-4",
  alert: "M12 3 2 20h20L12 3ZM12 10v5M12 18v.01",
  shield: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM9 12l2 2 4-4",
  layers: "M12 3 2 8l10 5 10-5-10-5ZM2 14l10 5 10-5M2 11l10 5 10-5",
  grid: "M3 3h7v7H3V3ZM14 3h7v7h-7V3ZM3 14h7v7H3v-7ZM14 14h7v7h-7v-7",
  pie: "M12 2v10h10a10 10 0 1 1-10-10Z M15 2.5A10 10 0 0 1 21.5 9H15V2.5Z",
  list: "M4 6h16M4 12h16M4 18h11",
  wifi: "M2 8.5a16 16 0 0 1 20 0M5.5 12a11 11 0 0 1 13 0M9 15.5a6 6 0 0 1 6 0M12 19v.01",
  check: "M20 6 9 17l-5-5",
  chevron: "m6 9 6 6 6-6",
  arrowUp: "M12 19V5M5 12l7-7 7 7",
  arrowDown: "M12 5v14M19 12l-7 7-7-7",
};

interface TrendPoint {
  t: string;
  value: number;
}

interface Trend {
  direction: "up" | "down" | "flat";
  deltaAbs: number;
  pct: number | null;
  windowLabel: string;
  sparkline: number[];
}

// Real deltas over whatever window the rolling client-side buffer actually holds (not a
// fabricated "vs last hour" - see STATS_HISTORY_LIMIT/SCORE_HISTORY_LIMIT above), with the
// elapsed time between the buffer's oldest and newest sample surfaced honestly in the label.
function computeTrend(history: TrendPoint[]): Trend | null {
  if (history.length < 2) return null;
  const oldest = history[0];
  const newest = history[history.length - 1];
  const deltaAbs = newest.value - oldest.value;
  const direction = deltaAbs > 0 ? "up" : deltaAbs < 0 ? "down" : "flat";
  const pct = oldest.value !== 0 ? (deltaAbs / oldest.value) * 100 : null;
  const elapsedMs = new Date(newest.t).getTime() - new Date(oldest.t).getTime();
  return { direction, deltaAbs, pct, windowLabel: formatElapsed(elapsedMs), sparkline: history.map((h) => h.value) };
}

function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 1000) return "moments ago";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  return `${h}h ago`;
}

function Icon({ name, size = 15 }: { name: keyof typeof ICON_PATHS; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d={ICON_PATHS[name]} />
    </svg>
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

function StatusPill({ up }: { up: boolean }) {
  const color = up ? "var(--green)" : "var(--dim)";
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5, fontSize: 9, fontWeight: 700,
        padding: "2px 7px", borderRadius: 20, color, background: up ? "rgba(63,185,80,0.12)" : "var(--raised)",
        textTransform: "uppercase", letterSpacing: "0.05em",
      }}
    >
      <span style={{ width: 5, height: 5, borderRadius: "50%", background: color }} />
      {up ? "Up" : "Down"}
    </span>
  );
}

export default function OverviewPage() {
  const { state, connected } = useSocStream();
  const theme = themeFor(state?.active_attack_type ?? null);
  const [scoreHistory, setScoreHistory] = useState<{ t: string; value: number }[]>([]);
  const [confHistory, setConfHistory] = useState<Record<string, number[]>>({});
  const [statsHistory, setStatsHistory] = useState<Record<string, TrendPoint[]>>({});

  // Rolling client-side buffers of the live aggregate score, per-attack-type confidence, and
  // the headline stat-card totals - mirroring the backend's own _history pattern
  // (backend/app/detection/loop.py). All of it already arrives on every WS tick, so no new API
  // calls are needed to chart trends, and every trend shown is a genuine delta over whatever
  // window this buffer actually spans (see computeTrend/formatElapsed above) rather than a
  // guessed "last hour".
  useEffect(() => {
    if (!state) return;
    setScoreHistory((prev) => {
      const next = [...prev, { t: state.timestamp, value: state.security.score }];
      return next.slice(-SCORE_HISTORY_LIMIT);
    });
    setConfHistory((prev) => {
      const next = { ...prev };
      for (const [type, s] of Object.entries(state.attacks)) {
        next[type] = [...(prev[type] ?? []), s.hybrid_conf].slice(-CONF_HISTORY_LIMIT);
      }
      return next;
    });
    setStatsHistory((prev) => {
      const entries = Object.values(state.attacks);
      const totalFlows = entries.reduce((sum, s) => sum + s.flows, 0);
      const totalAttacks = entries.reduce((sum, s) => sum + s.attacks, 0);
      const concurrent = entries.filter((s) => s.attacks > 0).length;
      const point = (value: number): TrendPoint => ({ t: state.timestamp, value });
      const push = (key: string, value: number) => [...(prev[key] ?? []), point(value)].slice(-STATS_HISTORY_LIMIT);
      return {
        totalFlows: push("totalFlows", totalFlows),
        totalAttacks: push("totalAttacks", totalAttacks),
        normalFlows: push("normalFlows", totalFlows - totalAttacks),
        concurrentAttacks: push("concurrentAttacks", concurrent),
        totalCaptured: push("totalCaptured", state.total_packets),
      };
    });
  }, [state?.timestamp]);

  if (!state) {
    return (
      <div>
        <PageHeader />
        <div style={{ color: "var(--muted)", fontSize: 13 }}>
          {connected ? "Waiting for first detection cycle..." : "Connecting to detection engine..."}
        </div>
      </div>
    );
  }

  const attackEntries = Object.entries(state.attacks);
  const activeAttackTypes = attackEntries.filter(([, s]) => s.attacks > 0);
  const activeAttackTypeCount = activeAttackTypes.length;
  const isMultiVector = activeAttackTypeCount > 1;
  const totalFlows = attackEntries.reduce((sum, [, s]) => sum + s.flows, 0);
  const totalAttacks = attackEntries.reduce((sum, [, s]) => sum + s.attacks, 0);
  const tierTotals: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const [, s] of attackEntries) {
    for (const t of TIERS) tierTotals[t] += s.tier_counts[t] ?? 0;
  }
  const allAttackers = attackEntries.flatMap(([type, s]) => s.attacker_ips.map((a) => ({ ...a, type })));
  const attackActivity = state.history.map((h) => ({ t: h.t, value: h.attacks }));

  return (
    <div>
      <PageHeader
        statusCard={
          <SystemStatusCard
            status={state.status}
            label={state.label}
            theme={theme}
            activeAttackTypes={activeAttackTypes}
            isMultiVector={isMultiVector}
            connected={connected}
          />
        }
      />

      <SecurityScoreCard security={state.security} delay={40} />

      <div
        className="fade-in-up"
        style={{ animationDelay: "80ms", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(138px, 1fr))", gap: 12, marginBottom: 20 }}
      >
        <StatCard label="Total Flows" value={totalFlows} role="info" icon="activity" trend={computeTrend(statsHistory.totalFlows ?? [])} />
        <StatCard label="Attack Flows" value={totalAttacks} role="critical" icon="alert" trend={computeTrend(statsHistory.totalAttacks ?? [])} />
        <StatCard label="Normal Flows" value={totalFlows - totalAttacks} role="good" icon="shield" trend={computeTrend(statsHistory.normalFlows ?? [])} />
        <StatCard
          label="Concurrent Attacks"
          value={activeAttackTypeCount}
          role={activeAttackTypeCount > 1 ? "critical" : activeAttackTypeCount === 1 ? "info" : "good"}
          icon="alert"
          trend={computeTrend(statsHistory.concurrentAttacks ?? [])}
        />
        <StatCard
          label="Total Captured" value={state.total_packets} role="info" icon="layers"
          format={(v) => Math.round(v).toLocaleString()} trend={computeTrend(statsHistory.totalCaptured ?? [])}
        />
        <StatCard label="Cycle" value={state.cycle} role="neutral" icon="activity" />
        <StatCard label="Interfaces" value={state.interfaces.length} role="neutral" icon="grid" />
      </div>

      <div
        className="fade-in-up"
        style={{ animationDelay: "120ms", display: "grid", gridTemplateColumns: `repeat(${attackEntries.length || 1}, 1fr)`, gap: 12, marginBottom: 20 }}
      >
        {attackEntries.map(([type, s]) => {
          const t = themeFor(type);
          return (
            <div
              key={type}
              className="card-hover"
              style={{
                background: "var(--surf)", borderRadius: 10, padding: "14px 10px 12px",
                border: "1px solid var(--border)", display: "flex", flexDirection: "column", alignItems: "center",
              }}
            >
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", color: "var(--muted)", textAlign: "center" }}>
                {t.label.toUpperCase()}
              </div>
              <RadialGauge value={s.hybrid_conf} label="" color={t.color} size={116} strokeWidth={10} />
              <div style={{ fontSize: 9, color: "var(--dim)", marginTop: 4, textAlign: "center" }}>
                XGB {s.xgb_conf.toFixed(0)}% · DL {s.dl_conf.toFixed(0)}% · {s.attacks} attack flow(s)
              </div>
              {(confHistory[type]?.length ?? 0) >= 2 && (
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
                  <span style={{ fontSize: 8, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Trend</span>
                  <Sparkline data={confHistory[type]} color={t.color} width={54} height={18} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="fade-in-up" style={{ animationDelay: "160ms", display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 20 }}>
        <Box title="Severity Breakdown" icon="pie">
          <Donut
            slices={TIERS.map((t) => ({ label: t, value: tierTotals[t], color: severityColor(t) }))}
            size={160}
          />
        </Box>

        <Box title="Interfaces" icon="wifi">
          {state.interfaces.length === 0 && <div style={{ color: "var(--dim)", fontSize: 12 }}>None detected</div>}
          {state.interfaces.map((i) => (
            <div key={i.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, marginBottom: 8 }}>
              <span style={{ color: "var(--muted)" }}>{i.description || i.name}</span>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontFamily: "var(--mono)", color: "var(--text)" }}>{i.ip}</span>
                <StatusPill up={i.up} />
              </div>
            </div>
          ))}
        </Box>

        <Box title="Security Score Trend" icon="activity">
          <TrendChart data={scoreHistory} color={severityColor(state.security.tier)} />
        </Box>
      </div>

      <div className="fade-in-up" style={{ animationDelay: "200ms", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
        <Box title="Attack Activity" icon="activity">
          <TrendChart data={attackActivity} color="var(--blue)" />
        </Box>
        <Box title="Top Attack Types" icon="pie">
          <Donut
            slices={attackEntries.map(([type, s]) => ({ label: themeFor(type).label, value: s.attacks, color: themeFor(type).color }))}
            size={160}
            centerLabel="total"
          />
        </Box>
      </div>

      <div className="fade-in-up" style={{ animationDelay: "240ms" }}>
        <Box title="Detected Attackers" icon="list">
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  {["Attack Type", "IP Address", "Packets", "Flows", "Hybrid %", "Severity", "Interface"].map((h) => (
                    <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {allAttackers.length === 0 ? (
                  <tr><td colSpan={7}><EmptyState text="No attackers detected" /></td></tr>
                ) : (
                  allAttackers.map((a, idx) => (
                    <tr key={idx} className="row-hover">
                      <td style={cellStyle}>{themeFor(a.type).label}</td>
                      <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{a.ip}</td>
                      <td style={cellStyle}>{a.pkts}</td>
                      <td style={cellStyle}>{a.flows}</td>
                      <td style={cellStyle}>{a.conf.toFixed(1)}%</td>
                      <td style={cellStyle}><SeverityPill tier={a.tier} /></td>
                      <td style={cellStyle}>{a.iface}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Box>
      </div>

      <div className="fade-in-up" style={{ animationDelay: "280ms" }}>
        <ActiveIncidentsBox incidents={state.security.active_incidents} />
      </div>
    </div>
  );
}

function SecurityScoreCard({ security, delay = 0 }: { security: SecurityScoreState; delay?: number }) {
  const t = tierTheme(security?.tier);
  const score = useCountUp(security?.score ?? 100);
  const hot = t.label === "Critical" || t.label === "High";
  const incidentCount = security?.active_incidents?.length ?? 0;

  return (
    <div
      className={`fade-in-up card-hover ${hot ? "glow-critical" : ""}`}
      style={{
        position: "relative", overflow: "hidden", animationDelay: `${delay}ms`,
        background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10,
        padding: "18px 24px", marginBottom: 20, display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap",
      }}
    >
      <div className="score-ring-pulse" style={{ position: "relative", zIndex: 1, "--pulse-color": t.color } as React.CSSProperties}>
        <RadialGauge value={score} label={t.label} color={t.color} />
      </div>

      <div style={{ position: "relative", zIndex: 1, flex: 1, minWidth: 180 }}>
        <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: 6 }}>
          Aggregate Security Score
        </div>
        <div style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.6 }}>
          {incidentCount === 0
            ? "No active incidents - all monitored traffic within normal parameters."
            : `${incidentCount} active incident${incidentCount === 1 ? "" : "s"} contributing to the current score.`}
        </div>
        <div style={{ display: "flex", gap: 18, marginTop: 12 }}>
          <div>
            <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Status</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: t.color, marginTop: 2 }}>{t.label}</div>
          </div>
          <div>
            <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Incidents</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text)", fontFamily: "var(--mono)", marginTop: 2 }}>{incidentCount}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActiveIncidentsBox({ incidents }: { incidents: ActiveIncident[] }) {
  const [busy, setBusy] = useState<string | null>(null);
  const writable = canWrite(getRole());

  async function acknowledge(id: string) {
    setBusy(id);
    try {
      await apiFetch(`/api/incidents/${id}/acknowledge`, { method: "POST" });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Box title="Active Incidents" icon="shield">
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr>
              {["Attack Types", "Source IPs", "Impact", "Severity", "Confidence", "Interface", ...(writable ? ["Action"] : [])].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {incidents.length === 0 ? (
              <tr><td colSpan={writable ? 7 : 6}><EmptyState text="No active incidents" /></td></tr>
            ) : (
              incidents.map((inc) => (
                <tr key={inc.incident_id} className="row-hover">
                  <td style={cellStyle}>{inc.attack_types.map((t) => themeFor(t).label).join(" + ")}</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{inc.src_ips.join(", ")}</td>
                  <td style={cellStyle}>{inc.combined_impact.toFixed(1)}</td>
                  <td style={cellStyle}><SeverityPill tier={inc.tier} /></td>
                  <td style={cellStyle}>{inc.confidence}</td>
                  <td style={cellStyle}>{inc.interface}</td>
                  {writable && (
                    <td style={cellStyle}>
                      <button
                        onClick={() => acknowledge(inc.incident_id)}
                        disabled={busy === inc.incident_id}
                        style={{
                          background: "transparent", border: "1px solid var(--border)", color: "var(--muted)",
                          borderRadius: 5, padding: "4px 9px", fontSize: 11, cursor: "pointer",
                          opacity: busy === inc.incident_id ? 0.5 : 1,
                        }}
                      >
                        Acknowledge
                      </button>
                    </td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Box>
  );
}

function PageHeader({ statusCard }: { statusCard?: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 22, display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
      <div>
        <div style={{ fontSize: 20, fontWeight: 700 }}>Overview</div>
        <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>Real-time security monitoring and threat detection</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <TakeSnapshotButton />
        {statusCard}
      </div>
    </div>
  );
}

// Collapsed replacement for the old full-width attack banner - same underlying info (status,
// live-feed state, and every currently-active attack type as its own pill), just tucked behind
// a click so the header stays compact when nothing is happening.
function SystemStatusCard({
  status, label, theme, activeAttackTypes, isMultiVector, connected,
}: {
  status: string;
  label: string;
  theme: { color: string; icon: string };
  activeAttackTypes: [string, unknown][];
  isMultiVector: boolean;
  connected: boolean;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const attackMode = status === "ATTACK";
  const title = attackMode ? (isMultiVector ? `${activeAttackTypes.length} ATTACKS` : label.toUpperCase()) : "NORMAL";
  const subtitle = attackMode ? label : "All systems operational";

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        className={`transition-accent ${attackMode ? "glow-critical" : ""}`}
        style={{
          display: "flex", alignItems: "center", gap: 10, minWidth: 230,
          background: attackMode ? "var(--accent-bg)" : "var(--surf)",
          border: `1px solid ${attackMode ? "var(--accent-border)" : "var(--border)"}`,
          borderRadius: 10, padding: "9px 14px", cursor: "pointer",
        }}
      >
        <span
          className="score-ring-pulse"
          style={{
            width: 30, height: 30, borderRadius: "50%", background: `${theme.color}1f`, color: theme.color,
            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
            "--pulse-color": theme.color,
          } as React.CSSProperties}
        >
          <Icon name={attackMode ? "alert" : "check"} size={15} />
        </span>
        <div style={{ textAlign: "left", flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.07em" }}>System Status</div>
          <div style={{ fontSize: 13, fontWeight: 700, color: theme.color, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {title}
          </div>
        </div>
        <span style={{ color: "var(--dim)", display: "flex", transform: open ? "rotate(180deg)" : undefined, transition: "transform 0.15s ease" }}>
          <Icon name="chevron" size={13} />
        </span>
      </button>

      {open && (
        <div
          className="fade-in-up"
          style={{
            position: "absolute", top: "calc(100% + 8px)", right: 0, minWidth: 270, zIndex: 15,
            background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10,
            boxShadow: "var(--shadow-card)", padding: 14,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, color: "var(--dim)" }}>
            <span className="live-dot" style={{ background: connected ? "var(--green)" : "var(--dim)" }} />
            {connected ? "Live feed connected" : "Disconnected"}
          </div>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 8 }}>{subtitle}</div>

          {attackMode && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
              {activeAttackTypes.map(([type]) => {
                const t = themeFor(type);
                return (
                  <span
                    key={type}
                    className="attack-pill-blink"
                    style={{
                      display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700,
                      padding: "4px 10px", borderRadius: 20, color: t.color, background: `${t.color}1f`,
                      border: `1px solid ${t.color}66`, textTransform: "uppercase", letterSpacing: "0.04em",
                    }}
                  >
                    <span style={{ width: 5, height: 5, borderRadius: "50%", background: t.color }} />
                    {t.label}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TakeSnapshotButton() {
  const [taking, setTaking] = useState(false);
  const [done, setDone] = useState(false);
  if (!canWrite(getRole())) return null;

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
        opacity: taking ? 0.6 : 1,
      }}
      className="transition-accent"
    >
      {taking ? "Capturing..." : done ? "Snapshot saved ✓" : "Take Snapshot"}
    </button>
  );
}

const ROLE_COLOR: Record<string, string> = {
  good: "var(--green)", critical: "var(--red)", info: "var(--blue)", neutral: "var(--muted)",
};

function StatCard({
  label, value, role = "neutral", icon, format = (v: number) => String(Math.round(v)), trend,
}: {
  label: string;
  value: number;
  role?: "good" | "critical" | "info" | "neutral";
  icon?: keyof typeof ICON_PATHS;
  format?: (v: number) => string;
  trend?: Trend | null;
}) {
  const display = useCountUp(value);
  const accent = ROLE_COLOR[role];
  const tinted = role !== "neutral";
  const trendColor = trend?.direction === "up" ? "var(--green)" : trend?.direction === "down" ? "var(--red)" : "var(--dim)";
  return (
    <div
      className="card-hover"
      style={{
        position: "relative", borderRadius: 10, padding: "14px 16px", background: "var(--surf)",
        borderTop: `2px solid ${tinted ? accent : "var(--border)"}`,
        borderInline: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
      }}
    >
      {icon && (
        <span
          style={{
            position: "absolute", top: 12, right: 12, width: 26, height: 26, borderRadius: 7,
            background: tinted ? `color-mix(in srgb, ${accent} 16%, transparent)` : "var(--raised)",
            color: tinted ? accent : "var(--dim)",
            display: "flex", alignItems: "center", justifyContent: "center",
          }}
        >
          <Icon name={icon} size={13} />
        </span>
      )}
      <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8, maxWidth: "78%" }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700, fontFamily: "var(--mono)", color: role === "neutral" ? "var(--text)" : accent }}>
        {format(display)}
      </div>
      {trend && (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginTop: 10 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10.5, color: trendColor, fontWeight: 600 }}>
            {trend.direction !== "flat" && <Icon name={trend.direction === "up" ? "arrowUp" : "arrowDown"} size={10} />}
            {trend.pct !== null ? `${Math.abs(trend.pct).toFixed(0)}%` : `${trend.deltaAbs > 0 ? "+" : ""}${trend.deltaAbs}`}
            <span style={{ color: "var(--dim)", fontWeight: 400 }}>vs {trend.windowLabel}</span>
          </span>
          <Sparkline data={trend.sparkline} color={trendColor} width={44} height={16} />
        </div>
      )}
    </div>
  );
}

function Box({ title, icon, children }: { title: string; icon?: keyof typeof ICON_PATHS; children: React.ReactNode }) {
  return (
    <div
      className="card-hover"
      style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 14 }}>
        {icon && <span style={{ color: "var(--dim)", display: "flex" }}><Icon name={icon} size={13} /></span>}
        {title}
      </div>
      {children}
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div style={{ padding: "28px 20px", textAlign: "center" }}>
      <div
        style={{
          width: 34, height: 34, borderRadius: "50%", background: "var(--raised)", color: "var(--dim)",
          display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 10px",
        }}
      >
        <Icon name="shield" size={16} />
      </div>
      <div style={{ color: "var(--dim)", fontSize: 12 }}>{text}</div>
    </div>
  );
}

const cellStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--raised)" };
