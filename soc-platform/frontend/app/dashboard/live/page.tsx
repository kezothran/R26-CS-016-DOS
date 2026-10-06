"use client";

import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { canWrite, getRole } from "@/lib/auth";
import { useSocStream } from "@/lib/SocStreamContext";
import { severityColor, themeFor } from "@/lib/theme";
import type { InterfaceInfo, LiveFlow, SocState } from "@/lib/types";
import { Sparkline, TrendChart, useCountUp } from "../charts";

const RATE_HISTORY_LIMIT = 40;
const STATUS_FILTERS = ["all", "attack", "normal"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];
const TIER_RANK = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function isLoopback(i: InterfaceInfo): boolean {
  return i.name.toLowerCase().includes("loopback") || i.description.toLowerCase().includes("loopback");
}

function highestTier(tiers: string[]): string {
  for (const t of TIER_RANK) if (tiers.includes(t)) return t;
  return "LOW";
}

interface CycleMetrics {
  rate: number;
  cyclePackets: number;
  attackFlows: number;
  normalFlows: number;
  upIfaces: number;
}

interface CycleDeltas {
  ratePct: number | null;
  cyclePacketsPct: number | null;
  attackFlowsPct: number | null;
  normalFlowsPct: number | null;
  activeIfacesDelta: number | null;
}

function pct(prev: number, cur: number): number | null {
  if (prev === 0) return cur === 0 ? 0 : null;
  return ((cur - prev) / prev) * 100;
}

export default function LiveTrafficPage() {
  const { state, connected } = useSocStream();
  const [rateHistory, setRateHistory] = useState<{ t: string; value: number }[]>([]);
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [ifaceSearch, setIfaceSearch] = useState("");
  const [windowSecs, setWindowSecs] = useState(5);
  const [deltas, setDeltas] = useState<CycleDeltas>({
    ratePct: null, cyclePacketsPct: null, attackFlowsPct: null, normalFlowsPct: null, activeIfacesDelta: null,
  });
  const prevMetricsRef = useRef<CycleMetrics | null>(null);

  useEffect(() => {
    apiFetch<{ window_secs: number }>("/api/settings").then((s) => setWindowSecs(s.window_secs || 5)).catch(() => {});
  }, []);

  // Rolling client-side buffer of the live incoming-packet rate, mirroring how the Overview
  // page charts security score history - the WS payload only ever carries the latest cycle.
  useEffect(() => {
    if (!state) return;
    setRateHistory((prev) => [...prev, { t: state.timestamp, value: state.packets_per_sec ?? 0 }].slice(-RATE_HISTORY_LIMIT));
  }, [state?.timestamp]);

  // Cycle-over-cycle deltas for the stat cards - computed from the previous cycle's snapshot,
  // never fabricated against a fixed clock window we can't actually guarantee.
  useEffect(() => {
    if (!state) return;
    const flows = state.live_flows ?? [];
    const attackFlows = flows.filter((f) => f.status === "ATTACK").length;
    const normalFlows = flows.length - attackFlows;
    const upIfaces = (state.interfaces ?? []).filter((i) => i.up && !isLoopback(i)).length;
    const current: CycleMetrics = { rate: state.packets_per_sec ?? 0, cyclePackets: state.cycle_packets ?? 0, attackFlows, normalFlows, upIfaces };

    if (prevMetricsRef.current) {
      const prev = prevMetricsRef.current;
      setDeltas({
        ratePct: pct(prev.rate, current.rate),
        cyclePacketsPct: pct(prev.cyclePackets, current.cyclePackets),
        attackFlowsPct: pct(prev.attackFlows, current.attackFlows),
        normalFlowsPct: pct(prev.normalFlows, current.normalFlows),
        activeIfacesDelta: current.upIfaces - prev.upIfaces,
      });
    }
    prevMetricsRef.current = current;
  }, [state?.cycle]);

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

  const flows = state.live_flows ?? [];
  const attackFlows = flows.filter((f) => f.status === "ATTACK").length;
  const normalFlows = flows.length - attackFlows;
  const visibleFlows = filter === "all" ? flows : flows.filter((f) => f.status.toLowerCase() === filter);
  const monitoredIfaces = (state.interfaces ?? []).filter((i) => !isLoopback(i));
  const upIfaces = monitoredIfaces.filter((i) => i.up).length;

  return (
    <div>
      <PageHeader connected={connected} />

      <div
        className="fade-in-up"
        style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14, marginBottom: 20 }}
      >
        <StatCard
          icon="activity" role="info" label="Current Rate (All Interfaces)"
          value={state.packets_per_sec ?? 0} suffix=" pkt/s"
          deltaPct={deltas.ratePct} sparkline={rateHistory.slice(-12).map((d) => d.value)}
        />
        <StatCard
          icon="layers" role="purple" label="Packets This Cycle"
          value={state.cycle_packets ?? 0} deltaPct={deltas.cyclePacketsPct}
        />
        <StatCard
          icon="database" role="amber" label="Total Captured"
          value={state.total_packets} format={(v) => Math.round(v).toLocaleString()}
          deltaPct={null} subtitle={`+${(state.cycle_packets ?? 0).toLocaleString()} this cycle`}
        />
        <StatCard
          icon="monitor" role="info" label="Active Interfaces"
          value={upIfaces} format={(v) => `${Math.round(v)}/${monitoredIfaces.length}`}
          deltaPct={null}
          subtitle={
            deltas.activeIfacesDelta === null || deltas.activeIfacesDelta === 0
              ? "No change" : `${deltas.activeIfacesDelta > 0 ? "+" : ""}${deltas.activeIfacesDelta} vs previous cycle`
          }
        />
        <StatCard icon="shieldAlert" role="critical" label="Attack Flows" value={attackFlows} deltaPct={deltas.attackFlowsPct} />
        <StatCard icon="shieldCheck" role="good" label="Normal Flows" value={normalFlows} deltaPct={deltas.normalFlowsPct} />
      </div>

      <div className="fade-in-up" style={{ animationDelay: "60ms" }}>
        <Box
          title="Real-Time Traffic Rate"
          right={<div style={{ fontSize: 10, color: "var(--dim)" }}>Live · updates every {windowSecs}s</div>}
        >
          <TrendChart data={rateHistory} color="var(--blue)" height={140} formatValue={(v) => `${v.toFixed(0)} pkt/s`} />
        </Box>
      </div>

      <div className="fade-in-up" style={{ animationDelay: "100ms" }}>
        <Box
          title="Monitored Interfaces"
          right={<SearchInput value={ifaceSearch} onChange={setIfaceSearch} placeholder="Search interface..." />}
        >
          <MonitoredInterfacesTable state={state} windowSecs={windowSecs} interfaces={monitoredIfaces} search={ifaceSearch} />
          <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 10 }}>
            Showing live data updated every {windowSecs}s. All times are in local timezone.
          </div>
        </Box>
      </div>

      <div className="fade-in-up" style={{ animationDelay: "140ms" }}>
        <Box
          title="Live Incoming Traffic"
          right={
            <div style={{ display: "flex", gap: 6 }}>
              {STATUS_FILTERS.map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  style={{
                    background: filter === f ? "var(--raised)" : "transparent",
                    border: `1px solid ${filter === f ? "var(--accent-border)" : "var(--border)"}`,
                    color: filter === f ? "var(--text)" : "var(--muted)",
                    borderRadius: 5, padding: "3px 10px", fontSize: 10, textTransform: "uppercase",
                    letterSpacing: "0.05em", cursor: "pointer",
                  }}
                  className="transition-accent"
                >
                  {f}
                </button>
              ))}
            </div>
          }
        >
          <div style={{ overflowX: "auto", maxHeight: 480, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  {["Protocol", "Source IP", "Destination IP", "Packets", "Interface", "Status", "Severity", "Confidence"].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase",
                        color: "var(--muted)", borderBottom: "1px solid var(--border)", position: "sticky", top: 0, background: "var(--surf)",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visibleFlows.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>
                      No traffic captured this cycle
                    </td>
                  </tr>
                ) : (
                  visibleFlows.map((f, idx) => <FlowRow key={`${f.type}-${f.src}-${f.dst}-${idx}`} flow={f} />)
                )}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 10 }}>
            Refreshes once per detection cycle ({state ? "live" : "—"}) - up to the 100 largest flows across ICMP, SYN,
            fragmentation, and UDP capture buckets, both normal and flagged.
          </div>
        </Box>
      </div>
    </div>
  );
}

function MonitoredInterfacesTable({
  state, windowSecs, interfaces, search,
}: {
  state: SocState;
  windowSecs: number;
  interfaces: InterfaceInfo[];
  search: string;
}) {
  const q = search.trim().toLowerCase();
  const rows = q
    ? interfaces.filter((i) => i.name.toLowerCase().includes(q) || i.description.toLowerCase().includes(q) || i.ip.toLowerCase().includes(q))
    : interfaces;

  if (interfaces.length === 0) {
    return <div style={{ color: "var(--dim)", fontSize: 12, padding: "12px 0" }}>No interfaces detected</div>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr>
            {["Interface", "IP Address", "Data Rate", "Packets", "Details", "Status", "Severity", "Flows"].map((h) => (
              <th
                key={h}
                style={{
                  textAlign: "left", padding: "8px 10px", fontSize: 10, textTransform: "uppercase",
                  color: "var(--muted)", borderBottom: "1px solid var(--border)",
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={8} style={{ padding: 20, textAlign: "center", color: "var(--dim)" }}>
                No interfaces match &ldquo;{search}&rdquo;
              </td>
            </tr>
          ) : (
            rows.map((i) => {
              const count = state.interface_packet_counts?.[i.name] ?? 0;
              const rate = windowSecs ? count / windowSecs : count;
              const ifaceFlows = (state.live_flows ?? []).filter((f) => f.iface === i.name);
              const attackOnIface = ifaceFlows.filter((f) => f.status === "ATTACK");
              const tier = attackOnIface.length ? highestTier(attackOnIface.map((f) => f.tier)) : "LOW";
              const attackPct = ifaceFlows.length ? Math.round((attackOnIface.length / ifaceFlows.length) * 100) : 0;

              return (
                <tr key={i.name} className="row-hover">
                  <td style={cellStyle}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
                      <span style={{ width: 6, height: 6, borderRadius: "50%", background: i.up ? "var(--green)" : "var(--dim)", flexShrink: 0 }} />
                      <span style={{ color: "var(--amber)", fontWeight: 600 }}>{i.name}</span>
                    </span>
                  </td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{i.ip}</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{rate.toFixed(0)} pkt/s</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{count.toLocaleString()}</td>
                  <td style={{ ...cellStyle, color: "var(--muted)", fontSize: 11 }}>{i.description || "—"}</td>
                  <td style={cellStyle}>
                    <span
                      style={{
                        display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontWeight: 700,
                        padding: "3px 8px", borderRadius: 20,
                        color: i.up ? "var(--green)" : "var(--dim)",
                        background: i.up ? "rgba(63,185,80,0.12)" : "rgba(77,87,99,0.15)",
                        border: `1px solid ${i.up ? "var(--green)" : "var(--dim)"}40`,
                        textTransform: "uppercase", letterSpacing: "0.04em",
                      }}
                    >
                      {i.up ? "ACTIVE" : "DOWN"}
                    </span>
                  </td>
                  <td style={{ ...cellStyle, color: severityColor(tier), fontWeight: 600 }}>{tier} ({attackPct}%)</td>
                  <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{ifaceFlows.length}</td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div style={{ position: "relative" }}>
      <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: "var(--dim)", display: "flex" }}>
        <Icon name="search" size={12} />
      </span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          background: "var(--raised)", border: "1px solid var(--border)", color: "var(--text)",
          borderRadius: 6, padding: "6px 10px 6px 28px", fontSize: 11, width: 180, outline: "none",
        }}
        className="transition-accent"
      />
    </div>
  );
}

function FlowRow({ flow }: { flow: LiveFlow }) {
  const t = themeFor(flow.type);
  const isAttack = flow.status === "ATTACK";
  return (
    <tr className="row-hover">
      <td style={{ ...cellStyle, color: t.color, fontWeight: 600 }}>{t.label.replace(" Flood", "")}</td>
      <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{flow.src}</td>
      <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{flow.dst}</td>
      <td style={cellStyle}>{flow.packets.toLocaleString()}</td>
      <td style={cellStyle}>{flow.iface}</td>
      <td style={cellStyle}>
        <span
          style={{
            display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontWeight: 700,
            padding: "3px 8px", borderRadius: 20,
            color: isAttack ? "var(--red)" : "var(--green)",
            background: isAttack ? "rgba(248,81,73,0.12)" : "rgba(63,185,80,0.12)",
            border: `1px solid ${isAttack ? "var(--red)" : "var(--green)"}40`,
            textTransform: "uppercase", letterSpacing: "0.04em",
          }}
        >
          <span style={{ width: 5, height: 5, borderRadius: "50%", background: isAttack ? "var(--red)" : "var(--green)" }} />
          {flow.status}
        </span>
      </td>
      <td style={{ ...cellStyle, color: severityColor(flow.tier) }}>{flow.tier}</td>
      <td style={cellStyle}>{flow.conf.toFixed(1)}%</td>
    </tr>
  );
}

function PageHeader({ connected }: { connected?: boolean }) {
  return (
    <div style={{ marginBottom: 22, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Live Traffic</div>
        <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>Real-time monitoring of network traffic and anomalies</div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        {connected !== undefined && (
          <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 10, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
            <span className="live-dot" style={{ background: connected ? "var(--green)" : "var(--dim)" }} />
            {connected ? "Live" : "Disconnected"}
          </div>
        )}
        <TakeSnapshotButton />
      </div>
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
        display: "flex", alignItems: "center", gap: 7,
        background: "var(--blue)", border: "1px solid var(--blue)", color: "#05121f",
        borderRadius: 6, padding: "7px 14px", fontSize: 12, cursor: "pointer", fontWeight: 700,
        opacity: taking ? 0.6 : 1,
      }}
      className="transition-accent"
    >
      <Icon name="camera" size={13} />
      {taking ? "Capturing..." : done ? "Snapshot saved ✓" : "Take Snapshot"}
    </button>
  );
}

const ROLE_COLOR: Record<string, string> = {
  good: "var(--green)", critical: "var(--red)", info: "var(--blue)", neutral: "var(--muted)",
  purple: "var(--purple)", amber: "var(--amber)",
};

function StatCard({
  icon, label, value, role = "neutral", suffix = "", format = (v: number) => String(Math.round(v)),
  deltaPct = null, subtitle, sparkline,
}: {
  icon: string;
  label: string;
  value: number;
  role?: keyof typeof ROLE_COLOR;
  suffix?: string;
  format?: (v: number) => string;
  deltaPct?: number | null;
  subtitle?: string;
  sparkline?: number[];
}) {
  const display = useCountUp(value);
  const accent = ROLE_COLOR[role];

  return (
    <div
      className="card-hover"
      style={{
        borderRadius: 10, padding: "14px 16px", background: "var(--surf)",
        borderTop: `2px solid ${accent}`,
        borderInline: "1px solid var(--border)", borderBottom: "1px solid var(--border)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
          <div
            style={{
              width: 24, height: 24, borderRadius: 6, background: `${accent}1f`, color: accent, flexShrink: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}
          >
            <Icon name={icon} size={13} />
          </div>
          <div style={{ fontSize: 9.5, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.07em", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {label}
          </div>
        </div>
        {sparkline && sparkline.length > 1 && <Sparkline data={sparkline} color={accent} width={52} height={20} />}
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>
        {format(display)}{suffix}
      </div>
      <div style={{ fontSize: 10, marginTop: 6, color: deltaPct == null ? "var(--dim)" : accent }}>
        {deltaPct == null
          ? subtitle ?? "—"
          : `${deltaPct >= 0 ? "↑" : "↓"} ${Math.abs(deltaPct).toFixed(1)}% vs previous cycle`}
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

const ICON_PATHS: Record<string, string[]> = {
  activity: ["M2 12h4l2-7 4 14 2-7h4l2-4"],
  layers: ["M4 5h16v4H4zM4 10.5h16v4H4zM4 16h16v4H4z"],
  database: ["M12 4c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3Z", "M4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7", "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"],
  monitor: ["M3 4h18v12H3zM8 20h8M12 16v4"],
  shieldAlert: ["M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3Z", "M12 8v4", "M12 15h.01"],
  shieldCheck: ["M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3Z", "M9 12l2 2 4-4"],
  search: ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16ZM21 21l-4.3-4.3"],
  camera: ["M4 8h3l2-3h6l2 3h3a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1Z", "M12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"],
};

function Icon({ name, size = 14 }: { name: string; size?: number }) {
  const paths = ICON_PATHS[name] ?? [];
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      {paths.map((d, i) => <path key={i} d={d} />)}
    </svg>
  );
}

const cellStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--raised)" };
