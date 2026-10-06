"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import type { InterfaceInfo } from "@/lib/types";

interface DetectionSettings {
  window_secs: number;
  threshold: number;
  min_pps: number;
  min_bps: number;
  xgb_weight: number;
  cnn_weight: number;
  capture_all: boolean;
  selected_interfaces: string[];
}

interface Whitelist {
  ips: string[];
  networks: string[];
  ports: number[];
}

type IfaceFilter = "all" | "active" | "inactive";

export default function SettingsPage() {
  const [cfg, setCfg] = useState<DetectionSettings | null>(null);
  const [ifaces, setIfaces] = useState<InterfaceInfo[]>([]);
  const [ports, setPorts] = useState<number[]>([]);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [ifaceQuery, setIfaceQuery] = useState("");
  const [ifaceFilter, setIfaceFilter] = useState<IfaceFilter>("all");
  const initialCfg = useRef<string | null>(null);

  useEffect(() => {
    apiFetch<DetectionSettings>("/api/settings").then((c) => {
      setCfg(c);
      initialCfg.current = JSON.stringify(c);
    });
    apiFetch<InterfaceInfo[]>("/api/settings/interfaces").then(setIfaces);
    apiFetch<Whitelist>("/api/whitelist").then((wl) => setPorts(wl.ports));
  }, []);

  const filteredIfaces = useMemo(() => {
    const q = ifaceQuery.trim().toLowerCase();
    return ifaces.filter((i) => {
      if (ifaceFilter === "active" && !i.up) return false;
      if (ifaceFilter === "inactive" && i.up) return false;
      if (!q) return true;
      return (
        i.name.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.ip.includes(q)
      );
    });
  }, [ifaces, ifaceQuery, ifaceFilter]);

  const activeCount = ifaces.filter((i) => i.up).length;
  const dirty = cfg ? JSON.stringify(cfg) !== initialCfg.current : false;

  if (!cfg) return null;

  function update<K extends keyof DetectionSettings>(key: K, value: DetectionSettings[K]) {
    setCfg((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  async function save() {
    if (!cfg) return;
    setSaving(true);
    try {
      await apiFetch("/api/settings", { method: "POST", body: JSON.stringify(cfg) });
      initialCfg.current = JSON.stringify(cfg);
      setSaved(true);
      setTimeout(() => setSaved(false), 1600);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 14, marginBottom: 22 }}>
        <div
          style={{
            width: 42, height: 42, borderRadius: 10, background: "rgba(88,166,255,.12)",
            border: "1px solid rgba(88,166,255,.28)", display: "flex", alignItems: "center",
            justifyContent: "center", color: "var(--blue)", flexShrink: 0,
          }}
        >
          <GearIcon />
        </div>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>Configuration</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            Detection thresholds · model weights · interface selection
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.85fr 1fr", gap: 16, alignItems: "start" }}>
        <div>
          <Box title="Detection Parameters">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <div>
                <Field icon={<ClockIcon />} label="Window (seconds)" desc="Capture window per detection cycle" suffix="s">
                  <input type="number" min={2} max={30} value={cfg.window_secs}
                    onChange={(e) => update("window_secs", Number(e.target.value))} />
                </Field>
                <Field icon={<TargetIcon />} label="Detection Threshold" desc="Minimum hybrid score to flag as attack">
                  <input type="number" min={0.1} max={0.99} step={0.05} value={cfg.threshold}
                    onChange={(e) => update("threshold", Number(e.target.value))} />
                </Field>
                <Field icon={<ActivityIcon />} label="Min Packets / sec" desc="Minimum packet rate to classify" suffix="pps">
                  <input type="number" min={1} value={cfg.min_pps}
                    onChange={(e) => update("min_pps", Number(e.target.value))} />
                </Field>
              </div>
              <div>
                <Field icon={<DatabaseIcon />} label="Min Bytes / sec" desc="Minimum throughput to classify" suffix="B/s">
                  <input type="number" min={1} value={cfg.min_bps}
                    onChange={(e) => update("min_bps", Number(e.target.value))} />
                </Field>
                <Field icon={<SlidersIcon />} label="XGBoost Weight" desc="XGBoost contribution in hybrid score">
                  <input type="number" min={0} max={1} step={0.05} value={cfg.xgb_weight}
                    onChange={(e) => {
                      const v = Number(e.target.value);
                      update("xgb_weight", v);
                      update("cnn_weight", Math.round((1 - v) * 100) / 100);
                    }} />
                </Field>
                <Field icon={<LockIcon />} label="DL Model Weight" desc="Auto-synced: 1 − XGBoost weight">
                  <input type="number" value={cfg.cnn_weight} disabled />
                </Field>
              </div>
            </div>

            <WeightBar xgb={cfg.xgb_weight} dl={cfg.cnn_weight} />
          </Box>

          <Box
            title="Interface Selection"
            right={
              <div style={{ display: "flex", gap: 8 }}>
                <SearchBox value={ifaceQuery} onChange={setIfaceQuery} disabled={cfg.capture_all} />
                <FilterSelect value={ifaceFilter} onChange={setIfaceFilter} disabled={cfg.capture_all} />
              </div>
            }
          >
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, fontSize: 12.5, cursor: "pointer", fontWeight: 500 }}>
              <input type="checkbox" checked={cfg.capture_all} onChange={(e) => update("capture_all", e.target.checked)} />
              Capture all interfaces (recommended)
              <span style={{ fontSize: 10.5, color: "var(--dim)", fontWeight: 400 }}>All available interfaces will be monitored</span>
            </label>

            <div
              style={{
                border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden",
                opacity: cfg.capture_all ? 0.4 : 1, pointerEvents: cfg.capture_all ? "none" : "auto",
              }}
            >
              {filteredIfaces.length === 0 ? (
                <div style={{ padding: 16, textAlign: "center", fontSize: 12, color: "var(--dim)" }}>
                  No interfaces match the current filter.
                </div>
              ) : (
                filteredIfaces.map((i, idx) => (
                  <label
                    key={i.name}
                    className="row-hover"
                    style={{
                      display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", fontSize: 12.5, cursor: "pointer",
                      borderBottom: idx === filteredIfaces.length - 1 ? "none" : "1px solid var(--border)",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={cfg.selected_interfaces.includes(i.name)}
                      onChange={(e) => {
                        const set = new Set(cfg.selected_interfaces);
                        e.target.checked ? set.add(i.name) : set.delete(i.name);
                        update("selected_interfaces", Array.from(set));
                      }}
                    />
                    <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {i.description || i.name}
                    </span>
                    <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 11 }}>{i.ip}</span>
                    <StatusBadge up={i.up} />
                  </label>
                ))
              )}
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10, fontSize: 11, color: "var(--dim)" }}>
              <span>{ifaces.length} interface{ifaces.length === 1 ? "" : "s"} available</span>
              <div style={{ display: "flex", gap: 14 }}>
                <Legend color="var(--green)" label="Active — interface is capturing traffic" />
                <Legend color="var(--dim)" label="Inactive — interface is not active" />
              </div>
            </div>
          </Box>
        </div>

        <div>
          <Box
            title="Whitelisted Ports (Read-Only Default Set)"
            titleExtra={
              <span
                title="Standard service ports (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS) excluded from flood detection by default. Managed on the Whitelist page, not editable here."
                style={{ color: "var(--dim)", cursor: "help", display: "flex" }}
              >
                <InfoIcon />
              </span>
            }
          >
            {ports.length === 0 ? (
              <div style={{ color: "var(--dim)", fontSize: 12 }}>None</div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(64px, 1fr))", gap: 8, marginBottom: 14 }}>
                {ports.map((p) => (
                  <div
                    key={p}
                    style={{
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 5, padding: "8px 4px",
                      background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 6,
                      fontFamily: "var(--mono)", fontSize: 12.5, fontWeight: 600,
                    }}
                  >
                    {p}
                    <span style={{ color: "var(--blue)", display: "flex" }}><CheckIcon /></span>
                  </div>
                ))}
              </div>
            )}
            <div
              style={{
                display: "flex", alignItems: "flex-start", gap: 8, padding: "10px 12px", background: "rgba(88,166,255,.08)",
                border: "1px solid rgba(88,166,255,.22)", borderRadius: 7, fontSize: 11, color: "var(--muted)", lineHeight: 1.5,
              }}
            >
              <span style={{ color: "var(--blue)", display: "flex", flexShrink: 0, marginTop: 1 }}><InfoIcon /></span>
              These ports are always allowed and excluded from detection. Manage IP / network exceptions on the Whitelist page.
            </div>
          </Box>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 4 }}>
        <button onClick={save} disabled={saving} style={btnStyle(saving)} className="transition-accent">
          <SaveIcon /> {saving ? "Saving…" : "Save Configuration"}
        </button>
        {saved && <span style={{ fontSize: 11, color: "var(--green)", display: "flex", alignItems: "center", gap: 5 }}><CheckIcon /> Saved</span>}
        {!saved && dirty && <span style={{ fontSize: 11, color: "var(--amber)" }}>Unsaved changes</span>}
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

function Field({
  icon, label, desc, suffix, children,
}: {
  icon: React.ReactNode; label: string; desc: string; suffix?: string;
  children: React.ReactElement<React.InputHTMLAttributes<HTMLInputElement>>;
}) {
  const inputProps = children.props;
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ fontSize: 11, fontWeight: 500, color: "var(--muted)", marginBottom: 5, display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ color: "var(--dim)", display: "flex" }}>{icon}</span>
        {label}
      </label>
      <div style={{ position: "relative" }}>
        {React.cloneElement(children, {
          style: { ...inputStyle, paddingRight: suffix ? 40 : 10, opacity: inputProps.disabled ? 0.6 : 1 },
        })}
        {suffix && (
          <span style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", fontSize: 10.5, color: "var(--dim)", pointerEvents: "none" }}>
            {suffix}
          </span>
        )}
      </div>
      <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 3 }}>{desc}</div>
    </div>
  );
}

function WeightBar({ xgb, dl }: { xgb: number; dl: number }) {
  const xgbPct = Math.round(xgb * 100);
  const dlPct = 100 - xgbPct;
  return (
    <div style={{ marginTop: 4 }}>
      <div style={{ display: "flex", height: 8, borderRadius: 4, overflow: "hidden", background: "var(--raised)" }}>
        <div style={{ width: `${xgbPct}%`, background: "var(--blue)" }} className="transition-accent" />
        <div style={{ width: `${dlPct}%`, background: "var(--purple)" }} className="transition-accent" />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6, fontSize: 10.5, color: "var(--muted)" }}>
        <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 7, height: 7, borderRadius: 2, background: "var(--blue)", display: "inline-block" }} /> XGBoost {xgbPct}%
        </span>
        <span style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 7, height: 7, borderRadius: 2, background: "var(--purple)", display: "inline-block" }} /> DL Model {dlPct}%
        </span>
      </div>
    </div>
  );
}

function SearchBox({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  return (
    <div style={{ position: "relative" }}>
      <span style={{ position: "absolute", left: 9, top: "50%", transform: "translateY(-50%)", color: "var(--dim)", display: "flex", pointerEvents: "none" }}>
        <SearchIcon />
      </span>
      <input
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Search interfaces…"
        style={{
          width: 180, height: 30, padding: "0 10px 0 28px", background: "var(--raised)",
          border: "1px solid var(--border)", borderRadius: 6, color: "var(--text)", fontSize: 12, outline: "none",
        }}
        className="transition-accent"
      />
    </div>
  );
}

function FilterSelect({ value, onChange, disabled }: { value: IfaceFilter; onChange: (v: IfaceFilter) => void; disabled?: boolean }) {
  return (
    <div style={{ position: "relative" }}>
      <select
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value as IfaceFilter)}
        style={{
          height: 30, padding: "0 26px 0 10px", background: "var(--raised)", border: "1px solid var(--border)",
          borderRadius: 6, color: "var(--text)", fontSize: 12, outline: "none", appearance: "none", cursor: "pointer",
        }}
        className="transition-accent"
      >
        <option value="all">All Interfaces</option>
        <option value="active">Active Only</option>
        <option value="inactive">Inactive Only</option>
      </select>
      <span style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", color: "var(--dim)", display: "flex", pointerEvents: "none" }}>
        <ChevronDownIcon />
      </span>
    </div>
  );
}

function StatusBadge({ up }: { up: boolean }) {
  const color = up ? "var(--green)" : "var(--dim)";
  return (
    <span
      style={{
        fontSize: 9.5, fontWeight: 700, padding: "2px 8px", borderRadius: 20, color,
        background: up ? "rgba(63,185,80,.12)" : "rgba(77,87,99,.14)", border: `1px solid ${up ? "rgba(63,185,80,.32)" : "var(--border)"}`,
        textTransform: "uppercase", letterSpacing: "0.04em", whiteSpace: "nowrap", flexShrink: 0,
      }}
    >
      {up ? "Active" : "Inactive"}
    </span>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span title={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, display: "inline-block" }} />
      {label.split(" — ")[0]}
    </span>
  );
}

function GearIcon() {
  return (
    <svg width={20} height={20} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-1c.6.5 1.3.9 2 1.2L10 21h4l.5-2.6c.7-.3 1.4-.7 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z" />
    </svg>
  );
}

function ClockIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" /><path d="M12 7v5l3.5 2" />
    </svg>
  );
}

function TargetIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1" />
    </svg>
  );
}

function ActivityIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}

function DatabaseIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3c-4.4 0-8 1.1-8 2.5S7.6 8 12 8s8-1.1 8-2.5S16.4 3 12 3Z" />
      <path d="M4 5.5V12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5V5.5" />
      <path d="M4 12v6.5c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5V12" />
    </svg>
  );
}

function SlidersIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3" />
      <path d="M1 14h6M9 8h6M17 16h6" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg width={11} height={11} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 8h.01" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width={12} height={12} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

function SaveIcon() {
  return (
    <svg width={13} height={13} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z" />
      <path d="M17 21v-8H7v8M7 3v5h8" />
    </svg>
  );
}

const inputStyle: React.CSSProperties = {
  width: "100%", background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "7px 10px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, outline: "none",
};

function btnStyle(disabled: boolean): React.CSSProperties {
  return {
    display: "flex", alignItems: "center", gap: 8, padding: "9px 20px", background: "rgba(63,185,80,.1)",
    border: "1px solid rgba(63,185,80,.28)", borderRadius: 6, color: "var(--green)", fontSize: 12.5, fontWeight: 600,
    cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.6 : 1,
  };
}
