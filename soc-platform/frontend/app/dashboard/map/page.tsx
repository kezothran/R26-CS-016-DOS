"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";
import { severityColor } from "@/lib/theme";
import type { LiveOriginPoint, LiveOrigins } from "@/lib/types";
import { buildDots, LAT_BOTTOM, LAT_TOP } from "../WorldMap";

const WINDOWS = [[15, "15 min"], [60, "1 hour"], [360, "6 hours"], [1440, "24 hours"]] as const;
const VIEW_W = 360;
const VIEW_H = LAT_TOP - LAT_BOTTOM;

// Browser-only sample attackers for the "Preview" toggle - never sent to or stored by the backend.
function samplePoints(): LiveOrigins {
  const now = Date.now();
  const mk = (ip: string, country: string, code: string, city: string, lat: number, lon: number, count: number, tier: string, types: string[], agoSec: number): LiveOriginPoint => ({
    src_ip: ip, count, max_tier: tier, attack_types: types, last_seen: new Date(now - agoSec * 1000).toISOString(),
    country, country_code: code, city, lat, lon,
  });
  return {
    geoip_ready: true, local_count: 0,
    points: [
      mk("203.0.113.24", "China", "CN", "Zhengzhou", 34.77, 113.72, 412, "Critical", ["udp", "syn"], 12),
      mk("198.51.100.7", "Russia", "RU", "Moscow", 55.75, 37.62, 268, "High", ["syn"], 35),
      mk("192.0.2.88", "United States", "US", "Ashburn", 39.04, -77.49, 190, "High", ["icmp"], 240),
      mk("203.0.113.150", "Brazil", "BR", "Sao Paulo", -23.55, -46.63, 96, "Medium", ["udp"], 20),
      mk("198.51.100.201", "Germany", "DE", "Frankfurt", 50.11, 8.68, 64, "Medium", ["fragmentation"], 500),
      mk("192.0.2.14", "India", "IN", "Mumbai", 19.08, 72.88, 41, "Low", ["icmp"], 900),
      mk("203.0.113.77", "Nigeria", "NG", "Lagos", 6.52, 3.38, 28, "Low", ["syn"], 15),
      mk("198.51.100.99", "Australia", "AU", "Sydney", -33.87, 151.21, 17, "Low", ["udp"], 1500),
    ],
  };
}

// Same equirectangular projection the dotted world backdrop is drawn with (WorldMap.tsx).
const project = (lon: number, lat: number) => ({ x: lon + 180, y: LAT_TOP - Math.max(LAT_BOTTOM, Math.min(LAT_TOP, lat)) });

export default function AttackMapPage() {
  const [minutes, setMinutes] = useState<number>(60);
  const [data, setData] = useState<LiveOrigins | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hover, setHover] = useState<LiveOriginPoint | null>(null);
  const [preview, setPreview] = useState(false);
  const dots = useMemo(buildDots, []);

  useEffect(() => {
    let alive = true;
    const load = () =>
      apiFetch<LiveOrigins>(`/api/metrics/live-origins?minutes=${minutes}`)
        .then((d) => { if (alive) { setData(d); setError(null); } })
        .catch((e) => { if (alive) setError(e instanceof ApiError ? e.message : "Could not load attacker locations"); });
    load();
    const t = setInterval(load, 10000);
    return () => { alive = false; clearInterval(t); };
  }, [minutes]);

  const view: LiveOrigins | null = preview ? samplePoints() : data;
  const mapped = (view?.points ?? []).filter((p) => p.lat !== null && p.lon !== null);
  const maxCount = Math.max(...mapped.map((p) => p.count), 1);
  const byCountry = useMemo(() => {
    const m = new Map<string, { country: string; code: string; count: number }>();
    for (const p of view?.points ?? []) {
      const key = p.country_code ?? "??";
      const e = m.get(key) ?? { country: p.country ?? "Unknown", code: key, count: 0 };
      e.count += p.count;
      m.set(key, e);
    }
    return [...m.values()].sort((a, b) => b.count - a.count).slice(0, 8);
  }, [view]);
  const now = Date.now();

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 18 }}>Live attack map</h1>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>Where flagged traffic is coming from. Updates every 10 seconds.</div>
        </div>
        <div style={{ flex: 1 }} />
        <button
          onClick={() => setPreview((v) => !v)}
          style={{ padding: "6px 14px", fontSize: 12, borderRadius: 6, cursor: "pointer", border: `1px solid ${preview ? "var(--amber)" : "var(--border)"}`, background: preview ? "rgba(227,179,65,.12)" : "transparent", color: preview ? "var(--amber)" : "var(--muted)" }}
        >
          {preview ? "Exit preview" : "Preview with sample data"}
        </button>
        <div style={{ display: "flex", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
          {WINDOWS.map(([m, label]) => (
            <button key={m} onClick={() => setMinutes(m)} style={{ padding: "6px 14px", fontSize: 12, border: "none", cursor: "pointer", background: minutes === m ? "rgba(88,166,255,.15)" : "transparent", color: minutes === m ? "var(--blue)" : "var(--muted)" }}>{label}</button>
          ))}
        </div>
      </div>

      {preview && (
        <div style={{ background: "rgba(227,179,65,.08)", border: "1px solid rgba(227,179,65,.3)", borderRadius: 8, padding: "8px 12px", fontSize: 12, marginBottom: 14, color: "var(--amber)" }}>
          Preview mode - these attackers are made-up sample data drawn in your browser. Nothing is stored and no real traffic is shown.
        </div>
      )}
      {error && !preview && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 12 }}>{error}</div>}
      {!preview && data && !data.geoip_ready && (
        <div style={{ background: "rgba(227,179,65,.08)", border: "1px solid rgba(227,179,65,.3)", borderRadius: 8, padding: 12, fontSize: 12, lineHeight: 1.7, marginBottom: 14 }}>
          <b>Geo-IP database not loaded.</b> Download <b>GeoLite2-City.mmdb</b> (free MaxMind account: maxmind.com → GeoLite2), put it on the server, set
          {" "}<code>GEOIP_DB_PATH=C:\path\to\GeoLite2-City.mmdb</code> in <code>backend/.env</code> and restart the backend. Pins appear after that.
        </div>
      )}

      <div style={{ position: "relative", background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
        <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} style={{ width: "100%", display: "block", background: "radial-gradient(ellipse at 30% 25%, rgba(88,166,255,.08), transparent 70%)" }}>
          <g fill="var(--accent)" opacity={0.4}>
            {dots.map((d, i) => <circle key={i} cx={d.x} cy={d.y} r={d.r} />)}
          </g>
          {mapped.map((p) => {
            const { x, y } = project(p.lon as number, p.lat as number);
            const color = severityColor(p.max_tier);
            const r = 1.6 + 3.4 * (Math.log(p.count + 1) / Math.log(maxCount + 1));
            const fresh = now - new Date(p.last_seen).getTime() < 60000;
            return (
              <g key={p.src_ip} onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} style={{ cursor: "pointer" }}>
                {fresh && (
                  <circle cx={x} cy={y} r={r} fill="none" stroke={color} strokeWidth={0.5}>
                    <animate attributeName="r" values={`${r};${r * 3}`} dur="1.8s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.8;0" dur="1.8s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle cx={x} cy={y} r={r} fill={color} fillOpacity={0.55} stroke={color} strokeWidth={0.5} />
              </g>
            );
          })}
        </svg>

        {hover && (
          <div style={{ position: "absolute", left: 14, bottom: 14, background: "var(--bg, #0b1422)", border: "1px solid var(--border)", borderRadius: 8, padding: "10px 12px", fontSize: 12, minWidth: 220 }}>
            <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{hover.src_ip}</div>
            <div style={{ color: "var(--muted)", margin: "2px 0 6px" }}>{[hover.city, hover.country].filter(Boolean).join(", ") || "Unknown location"}</div>
            <div>{hover.count} alert(s) · <b style={{ color: severityColor(hover.max_tier) }}>{hover.max_tier}</b></div>
            <div style={{ color: "var(--dim)", fontSize: 11 }}>{hover.attack_types.map((a) => a.toUpperCase()).join(", ")}</div>
          </div>
        )}
      </div>

      <div style={{ display: "flex", gap: 16, marginTop: 16, flexWrap: "wrap" }}>
        <Card title="Top origin countries">
          {byCountry.length === 0 ? <Dim>No public attacker IPs in this window.</Dim> : byCountry.map((c) => (
            <div key={c.code} style={{ display: "flex", justifyContent: "space-between", fontSize: 12, padding: "5px 0", borderBottom: "1px solid var(--raised)" }}>
              <span>{c.country} <span style={{ color: "var(--dim)" }}>{c.code}</span></span><b>{c.count}</b>
            </div>
          ))}
        </Card>
        <Card title="Attackers">
          {(view?.points ?? []).length === 0 ? <Dim>None.</Dim> : (view?.points ?? []).slice(0, 8).map((p) => (
            <div key={p.src_ip} style={{ display: "flex", gap: 10, fontSize: 12, padding: "5px 0", borderBottom: "1px solid var(--raised)" }}>
              <span style={{ width: 8, height: 8, borderRadius: 4, background: severityColor(p.max_tier), marginTop: 4 }} />
              <span style={{ fontFamily: "var(--mono)", flex: 1 }}>{p.src_ip}</span>
              <span style={{ color: "var(--muted)" }}>{p.country_code ?? "??"}</span>
              <b>{p.count}</b>
            </div>
          ))}
          {!preview && data && data.local_count > 0 && <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 8 }}>{data.local_count} alert(s) came from private/local addresses and can&apos;t be placed on the map.</div>}
        </Card>
      </div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ flex: 1, minWidth: 260, background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 10 }}>{title}</div>
      {children}
    </div>
  );
}
const Dim = ({ children }: { children: React.ReactNode }) => <div style={{ color: "var(--dim)", fontSize: 12 }}>{children}</div>;
