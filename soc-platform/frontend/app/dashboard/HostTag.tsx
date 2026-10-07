"use client";

import { parseInterface } from "@/lib/hostTag";

/** Shows which PC traffic/an incident came from - the headline ("mayu"), with the raw interface
 * name underneath in small print. Agent-tagged iface strings look like "Wi-Fi@mayu"; a bare
 * interface (no "@host") means this server's own local capture. */
export default function HostTag({ iface, compact = false }: { iface: string | null | undefined; compact?: boolean }) {
  const { iface: ifaceOnly, host } = parseInterface(iface);
  if (!host) {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: compact ? 11 : 12, color: "var(--muted)" }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--dim)" }} />
        This server
        {!compact && ifaceOnly && <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 10 }}>({ifaceOnly})</span>}
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span
        style={{
          display: "inline-flex", alignItems: "center", gap: 5, fontSize: compact ? 11 : 12, fontWeight: 700,
          color: "var(--amber)", background: "rgba(227,179,65,.12)", border: "1px solid rgba(227,179,65,.35)",
          borderRadius: 5, padding: compact ? "1px 7px" : "2px 9px",
        }}
        title={`Detected on the "${ifaceOnly}" interface of agent "${host}"`}
      >
        <svg width={compact ? 10 : 11} height={compact ? 10 : 11} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round">
          <rect x="3" y="4" width="18" height="12" rx="1.5" /><path d="M8 20h8M12 16v4" />
        </svg>
        {host}
      </span>
      {!compact && <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 10 }}>{ifaceOnly}</span>}
    </span>
  );
}
