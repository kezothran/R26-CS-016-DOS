"use client";

import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { useSocStream } from "@/lib/SocStreamContext";
import { severityColor } from "@/lib/theme";
import type { AttackOrigin, MetricsSummary, TopSource, VolumePoint } from "@/lib/types";
import { Sparkline, TrendChart, useCountUp } from "../charts";

const RANGES = ["1h", "24h", "7d", "30d"];

export default function MetricsPage() {
  const { state } = useSocStream();
  const [range, setRange] = useState("24h");
  const [summary, setSummary] = useState<MetricsSummary | null>(null);
  const [volume, setVolume] = useState<VolumePoint[]>([]);
  const [topSources, setTopSources] = useState<TopSource[]>([]);
  const [origins, setOrigins] = useState<AttackOrigin[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<{ t: string; value: number }[]>([]);

  useEffect(() => {
    apiFetch<MetricsSummary>(`/api/metrics/summary?range=${range}`).then(setSummary);
    apiFetch<VolumePoint[]>(`/api/metrics/volume?range=${range}&bucket=${bucketFor(range)}`).then(setVolume);
    apiFetch<TopSource[]>(`/api/metrics/top-sources?range=${range}&limit=10`).then(setTopSources);
    apiFetch<AttackOrigin[]>(`/api/metrics/origins?range=${range}`).then(setOrigins);
  }, [range]);

  // Client-side traffic-volume (pkts/sec) rolling buffer, same pattern as the Overview page's
  // scoreHistory - derived from the delta of the already-broadcast cumulative total_packets
  // counter over the capture window, no new backend endpoint needed for this one.
  const lastTotal = useRef<number | null>(null);
  useEffect(() => {
    if (!state) return;
    if (lastTotal.current === null) {
      lastTotal.current = state.total_packets;
      return;
    }
    const windowSecs = summary?.detection_window_secs || 5;
    const delta = Math.max(0, state.total_packets - lastTotal.current);
    lastTotal.current = state.total_packets;
    setTrafficHistory((prev) => [...prev, { t: state.timestamp, value: delta / windowSecs }].slice(-40));
  }, [state?.timestamp]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div>
      <PageHeader range={range} setRange={setRange} />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
        <StatCard
          label="Total Alerts" value={summary?.total_alerts ?? 0} icon="bell" color="var(--blue)"
          sparkline={volume.length >= 2 ? volume.map((v) => v.value) : undefined}
        />
        <StatCard label="Total Incidents" value={summary?.total_incidents ?? 0} icon="shield" color="var(--purple)" />
        <StatCard label="MTTA" value={summary?.mtta_seconds ?? null} format={formatDuration} icon="chip" color="#39c5cf" />
        <StatCard label="MTTR" value={summary?.mttr_seconds ?? null} format={formatDuration} icon="hourglass" color="var(--amber)" />
        <StatCard
          label="False Positive Rate" value={summary?.false_positive_rate ?? null}
          format={(v) => v === null ? "—" : `${(v * 100).toFixed(0)}%`} icon="target" color="var(--red)"
        />
        <StatCard
          label="Detection Window" value={summary?.detection_window_secs ?? null}
          format={(v) => v === null ? "—" : `${v}s`} icon="clock" color="var(--blue)" caption="Real-time"
        />
        <StatCard
          label="FP Feedback Logged" value={summary?.false_positive_feedback_count ?? 0} icon="fingerprint" color="var(--green)"
          caption={(summary?.false_positive_feedback_count ?? 0) === 0 ? "No feedback" : "Logged this period"}
        />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <Box title="Alert Volume">
          <TrendChart data={volume.map((v) => ({ t: new Date(v.t).toLocaleTimeString(), value: v.value }))} color="var(--blue)" />
        </Box>
        <Box title="Traffic Volume (pkts/sec, live)">
          <TrendChart data={trafficHistory} color="var(--blue)" />
        </Box>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <Box title="Top Talkers">
          {topSources.length === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>No traffic in this range</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={headerCellStyle}>Source IP</th>
                  <th style={headerCellStyle}>Severity</th>
                  <th style={headerCellStyle}>Country</th>
                  <th style={{ ...headerCellStyle, textAlign: "right" }}>Packets</th>
                </tr>
              </thead>
              <tbody>
                {topSources.map((s) => (
                  <tr key={s.src_ip} className="row-hover">
                    <td style={{ ...cellStyle, fontFamily: "var(--mono)" }}>{s.src_ip}</td>
                    <td style={cellStyle}>
                      <span
                        style={{
                          fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 20, color: severityColor(s.max_tier),
                          background: `${severityColor(s.max_tier)}1f`, border: `1px solid ${severityColor(s.max_tier)}40`,
                          textTransform: "uppercase", letterSpacing: "0.04em",
                        }}
                      >
                        {s.max_tier}
                      </span>
                    </td>
                    <td style={{ ...cellStyle, color: "var(--muted)" }}>{s.country ?? "—"}</td>
                    <td style={{ ...cellStyle, textAlign: "right", fontFamily: "var(--mono)" }}>{s.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Box>
        <Box title="Attack Origins (Geo-IP)">
          {origins.length === 0 ? (
            <div style={{ color: "var(--dim)", fontSize: 12 }}>
              No data - if this stays empty, GEOIP_DB_PATH may not be configured on the backend (optional, see backend/app/geoip.py).
            </div>
          ) : (
            <div
              style={{
                display: "flex", flexDirection: "column", gap: 10, padding: 10, borderRadius: 8,
                backgroundColor: "var(--raised)", backgroundImage: "radial-gradient(var(--border) 1px, transparent 1px)",
                backgroundSize: "9px 9px",
              }}
            >
              {(() => {
                const max = Math.max(...origins.map((o) => o.count), 1);
                return origins.map((o) => (
                  <div key={o.country_code} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12 }}>
                    <span style={{ width: 64, flexShrink: 0, color: "var(--text)" }}>{o.country}</span>
                    <div style={{ flex: 1, height: 6, background: "var(--surf)", borderRadius: 4, overflow: "hidden" }}>
                      <div style={{ width: `${(o.count / max) * 100}%`, height: "100%", background: "var(--blue)", borderRadius: 4, transition: "width 0.4s ease" }} />
                    </div>
                    <span style={{ width: 28, textAlign: "right", fontFamily: "var(--mono)", color: "var(--muted)" }}>{o.count}</span>
                  </div>
                ));
              })()}
            </div>
          )}
        </Box>
      </div>
    </div>
  );
}

function bucketFor(range: string): string {
  if (range === "1h") return "2m";
  if (range === "24h") return "1h";
  return "1d";
}

function formatDuration(v: number | null): string {
  if (v === null) return "—";
  if (v < 60) return `${Math.round(v)}s`;
  if (v < 3600) return `${Math.round(v / 60)}m`;
  return `${(v / 3600).toFixed(1)}h`;
}

function PageHeader({ range, setRange }: { range: string; setRange: (r: string) => void }) {
  return (
    <div style={{ marginBottom: 22, display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
      <div>
        <div style={{ fontSize: 18, fontWeight: 600 }}>Metrics & KPIs</div>
        <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>Detection performance and traffic trends</div>
      </div>
      <select value={range} onChange={(e) => setRange(e.target.value)} style={selectStyle}>
        {RANGES.map((r) => <option key={r} value={r}>{r}</option>)}
      </select>
    </div>
  );
}

function StatCard({
  label, value, format = (v: number | null) => (v === null ? "—" : String(Math.round(v))),
  icon, color, sparkline, caption,
}: {
  label: string;
  value: number | null;
  format?: (v: number | null) => string;
  icon: StatIconName;
  color: string;
  sparkline?: number[];
  caption?: string;
}) {
  const display = useCountUp(value ?? 0);
  const captionText = caption ?? (value === null ? "No data available" : undefined);

  return (
    <div
      className="card-hover"
      style={{
        background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: "14px 16px",
        boxShadow: "var(--shadow-card)", display: "flex", flexDirection: "column", gap: 10, minHeight: 116,
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 9 }}>
        <span
          style={{
            width: 30, height: 30, borderRadius: 8, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center",
            background: `${color}1f`, color,
          }}
        >
          <StatIcon name={icon} />
        </span>
        <div style={{ fontSize: 10, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.07em", lineHeight: 1.3, paddingTop: 4 }}>
          {label}
        </div>
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)" }}>
        {value === null ? "—" : format(display)}
      </div>
      <div style={{ marginTop: "auto" }}>
        {sparkline && sparkline.length >= 2 ? (
          <Sparkline data={sparkline} color={color} width={110} height={22} />
        ) : captionText ? (
          <div style={{ fontSize: 10.5, color: "var(--dim)" }}>{captionText}</div>
        ) : null}
      </div>
    </div>
  );
}

type StatIconName = "bell" | "shield" | "chip" | "hourglass" | "target" | "clock" | "fingerprint";

function StatIcon({ name }: { name: StatIconName }) {
  const props = { width: 15, height: 15, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  switch (name) {
    case "bell":
      return <svg {...props}><path d="M6 8a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6Z" /><path d="M9.5 18a2.5 2.5 0 0 0 5 0" /></svg>;
    case "shield":
      return <svg {...props}><path d="M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3Z" /><path d="M9 12l2 2 4-4" /></svg>;
    case "chip":
      return (
        <svg {...props}>
          <rect x="6" y="6" width="12" height="12" rx="1.5" />
          <rect x="9.5" y="9.5" width="5" height="5" />
          <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
        </svg>
      );
    case "hourglass":
      return <svg {...props}><path d="M6 2h12M6 22h12" /><path d="M6 2v3.5c0 2.5 2 4 6 6.5-4 2.5-6 4-6 6.5V22" /><path d="M18 2v3.5c0 2.5-2 4-6 6.5 4 2.5 6 4 6 6.5V22" /></svg>;
    case "target":
      return <svg {...props}><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.5" fill="currentColor" /></svg>;
    case "clock":
      return <svg {...props}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3.5 2" /></svg>;
    case "fingerprint":
      return (
        <svg {...props}>
          <path d="M8 12a4 4 0 0 1 8 0v1.5" />
          <path d="M6 15c-.7-1.4-1-2.8-1-4a7 7 0 0 1 12-5" />
          <path d="M4 18c-1-2-1.5-4-1.5-6a9 9 0 0 1 15.3-6.4" />
          <path d="M17.5 6.3A9 9 0 0 1 20.5 12c0 1.4-.2 2.7-.6 4" />
          <path d="M12 11.5c.5 1 .7 2 .4 3.8-.2 1.2-.2 2.4.4 3.7" />
        </svg>
      );
  }
}

function Box({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card-hover" style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 14 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

const cellStyle: React.CSSProperties = { padding: "7px 8px", borderBottom: "1px solid var(--raised)" };

const headerCellStyle: React.CSSProperties = {
  padding: "0 8px 8px", textAlign: "left", fontSize: 10, fontWeight: 600, color: "var(--dim)",
  textTransform: "uppercase", letterSpacing: "0.06em", borderBottom: "1px solid var(--border)",
};

const selectStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "6px 9px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, outline: "none",
};
