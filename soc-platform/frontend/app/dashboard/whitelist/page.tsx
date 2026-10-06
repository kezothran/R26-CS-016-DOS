"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { canWrite, getRole } from "@/lib/auth";

interface Whitelist {
  ips: string[];
  networks: string[];
  ports: number[];
}

export default function WhitelistPage() {
  const [wl, setWl] = useState<Whitelist>({ ips: [], networks: [], ports: [] });
  const [ipInput, setIpInput] = useState("");
  const [netInput, setNetInput] = useState("");
  const [showInsights, setShowInsights] = useState(false);
  const writable = canWrite(getRole());

  async function load() {
    setWl(await apiFetch<Whitelist>("/api/whitelist"));
  }

  useEffect(() => {
    load();
  }, []);

  async function add(kind: "ip" | "network", value: string) {
    if (!value.trim()) return;
    await apiFetch(`/api/whitelist/${kind}/add`, { method: "POST", body: JSON.stringify({ value: value.trim() }) });
    if (kind === "ip") setIpInput(""); else setNetInput("");
    load();
  }

  async function remove(kind: "ip" | "network", value: string) {
    await apiFetch(`/api/whitelist/${kind}/remove`, { method: "POST", body: JSON.stringify({ value }) });
    load();
  }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 22, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
          <div
            style={{
              width: 42, height: 42, borderRadius: 10, background: "rgba(88,166,255,.12)",
              border: "1px solid rgba(88,166,255,.28)", display: "flex", alignItems: "center",
              justifyContent: "center", color: "var(--blue)", flexShrink: 0,
            }}
          >
            <ShieldIcon />
          </div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Whitelist Management</div>
            <div style={{ fontSize: 12, color: "var(--muted)", maxWidth: 560, lineHeight: 1.5 }}>
              Whitelisted IPs / networks are excluded from detection entirely — use this for known-legitimate
              high-rate traffic (e.g. streaming/CDN sources) so it isn't mistaken for a flood.
            </div>
          </div>
        </div>

        <button onClick={() => setShowInsights((s) => !s)} style={insightsBtnStyle(showInsights)} className="transition-accent">
          <BarsIcon /> Whitelist Insights
        </button>
      </div>

      {showInsights && (
        <div className="fade-in-up" style={{ display: "flex", gap: 12, marginBottom: 18, flexWrap: "wrap" }}>
          <InsightTile label="Whitelisted IPs" value={wl.ips.length} />
          <InsightTile label="Whitelisted Networks" value={wl.networks.length} />
          <InsightTile label="Allowed Ports" value={wl.ports.length} />
        </div>
      )}

      <Box title="IP Address Whitelist" right={<CopyButton items={wl.ips} />}>
        {writable && (
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input value={ipInput} onChange={(e) => setIpInput(e.target.value)} placeholder="e.g. 192.168.1.100" style={inputStyle} />
            <button onClick={() => add("ip", ipInput)} style={btnStyle}>+ Add IP</button>
          </div>
        )}
        <Chips items={wl.ips} onRemove={writable ? (v) => remove("ip", v) : undefined} />
      </Box>

      <Box title="Network / CIDR Whitelist" right={<CopyButton items={wl.networks} />}>
        {writable && (
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input value={netInput} onChange={(e) => setNetInput(e.target.value)} placeholder="e.g. 192.168.0.0/24" style={inputStyle} />
            <button onClick={() => add("network", netInput)} style={btnStyle}>+ Add Network</button>
          </div>
        )}
        <Chips items={wl.networks} onRemove={writable ? (v) => remove("network", v) : undefined} />
      </Box>

      <Box
        title="Whitelisted Ports (Read-Only Default Set)"
        titleExtra={
          <span
            title="Standard service ports (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS) excluded from flood detection by default. Managed by the platform, not editable here."
            style={{ color: "var(--dim)", cursor: "help", display: "flex" }}
          >
            <InfoIcon />
          </span>
        }
        right={<PortCountCard count={wl.ports.length} />}
      >
        <PortGrid ports={wl.ports} />
      </Box>

      <div
        style={{
          display: "flex", alignItems: "center", gap: 10, padding: "12px 16px", background: "var(--surf)",
          border: "1px solid var(--border)", borderRadius: 8, fontSize: 12, color: "var(--muted)",
        }}
      >
        <span style={{ color: "var(--blue)", display: "flex", flexShrink: 0 }}><InfoIcon /></span>
        Whitelist rules are applied in real-time and persist across engine restarts.
      </div>
    </div>
  );
}

function Box({
  title, titleExtra, right, children,
}: {
  title: string; titleExtra?: React.ReactNode; right?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="card-hover fade-in-up" style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14, gap: 12, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>
          {title}
          {titleExtra}
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

function Chips({ items, onRemove }: { items: string[]; onRemove?: (v: string) => void }) {
  if (items.length === 0) return <div style={{ color: "var(--dim)", fontSize: 12 }}>None</div>;
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      {items.map((v) => (
        <span
          key={v}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6, background: "var(--raised)",
            border: "1px solid var(--border)", borderRadius: 5, padding: "5px 8px 5px 10px", fontFamily: "var(--mono)", fontSize: 11.5,
          }}
        >
          {v}
          {onRemove && (
            <span
              onClick={() => onRemove(v)}
              title="Remove"
              style={{
                display: "flex", alignItems: "center", justifyContent: "center", width: 15, height: 15,
                borderRadius: "50%", cursor: "pointer", color: "var(--dim)", fontSize: 13, lineHeight: 1,
              }}
              className="transition-accent"
            >
              ×
            </span>
          )}
        </span>
      ))}
    </div>
  );
}

function PortGrid({ ports }: { ports: number[] }) {
  if (ports.length === 0) return <div style={{ color: "var(--dim)", fontSize: 12 }}>None</div>;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(76px, 1fr))", gap: 8 }}>
      {ports.map((p) => (
        <div
          key={p}
          style={{
            display: "flex", alignItems: "center", justifyContent: "center", gap: 6, padding: "9px 6px",
            background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 6,
            fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600,
          }}
        >
          {p}
          <span style={{ color: "var(--blue)", display: "flex" }}><CheckIcon /></span>
        </div>
      ))}
    </div>
  );
}

function PortCountCard({ count }: { count: number }) {
  return (
    <div
      style={{
        display: "flex", alignItems: "center", gap: 10, padding: "6px 14px", background: "rgba(63,185,80,.08)",
        border: "1px solid rgba(63,185,80,.26)", borderRadius: 8,
      }}
    >
      <span style={{ color: "var(--green)", display: "flex" }}><ShieldIcon size={16} /></span>
      <div>
        <div style={{ fontSize: 15, fontWeight: 700, lineHeight: 1.1 }}>{count}</div>
        <div style={{ fontSize: 9.5, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.05em", whiteSpace: "nowrap" }}>
          Allowed Ports
        </div>
      </div>
    </div>
  );
}

function InsightTile({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ flex: "1 1 160px", background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 8, padding: "12px 16px" }}>
      <div style={{ fontSize: 20, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 2 }}>{label}</div>
    </div>
  );
}

function CopyButton({ items }: { items: string[] }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    if (items.length === 0) return;
    await navigator.clipboard.writeText(items.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <button
      onClick={copy}
      title="Copy list to clipboard"
      style={{
        display: "flex", alignItems: "center", justifyContent: "center", width: 26, height: 26,
        background: "transparent", border: "1px solid var(--border)", borderRadius: 6,
        color: copied ? "var(--green)" : "var(--dim)", cursor: items.length ? "pointer" : "default",
      }}
      className="transition-accent"
    >
      {copied ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  );
}

function ShieldIcon({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3Z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function BarsIcon() {
  return (
    <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 20h18M6 20V10M12 20V4M18 20v-7" />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v6M12 8h.01" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

function ClipboardIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <rect x="8" y="2" width="8" height="4" rx="1" />
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
    </svg>
  );
}

function insightsBtnStyle(active: boolean): React.CSSProperties {
  return {
    display: "flex", alignItems: "center", gap: 7, padding: "8px 14px",
    background: active ? "rgba(88,166,255,.14)" : "var(--raised)",
    border: `1px solid ${active ? "rgba(88,166,255,.35)" : "var(--border)"}`,
    borderRadius: 7, color: active ? "var(--blue)" : "var(--muted)", fontSize: 12, fontWeight: 500,
    cursor: "pointer", whiteSpace: "nowrap", flexShrink: 0,
  };
}

const inputStyle: React.CSSProperties = {
  flex: 1, background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "7px 10px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, outline: "none",
};

const btnStyle: React.CSSProperties = {
  padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)",
  borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
};
