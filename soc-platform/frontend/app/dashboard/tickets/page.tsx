"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";
import { severityColor } from "@/lib/theme";
import type { TicketRow } from "@/lib/types";
import { fmt, StatusBadge, TicketCard } from "./ticket-ui";

const STATES = [["all", "All"], ["open", "Open"], ["done", "Done"]] as const;

export default function TicketsPage() {
  const [state, setState] = useState<"all" | "open" | "done">("open");
  const [rows, setRows] = useState<TicketRow[] | null>(null);
  const [jiraOn, setJiraOn] = useState(true);
  const [query, setQuery] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async (refresh: boolean) => {
    setError(null);
    setRefreshing(refresh);
    try {
      const r = await apiFetch<{ jira_configured: boolean; tickets: TicketRow[] }>(`/api/tickets?state=${state}${refresh ? "&refresh=true" : ""}`);
      setRows(r.tickets);
      setJiraOn(r.jira_configured);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load tickets");
    } finally {
      setRefreshing(false);
    }
  }, [state]);

  useEffect(() => { load(true); }, [load]);

  const q = query.trim().toLowerCase();
  const shown = (rows ?? []).filter((t) => !q || t.external_ref.toLowerCase().includes(q) || t.src_ips.some((ip) => ip.includes(q)) || t.attack_types.some((a) => a.includes(q)));

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 18 }}>Tickets</h1>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>Jira tickets raised from incidents, with live status.</div>
        </div>
        <div style={{ flex: 1 }} />
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search key, IP, attack..." style={inputStyle} />
        <div style={{ display: "flex", border: "1px solid var(--border)", borderRadius: 6, overflow: "hidden" }}>
          {STATES.map(([v, label]) => (
            <button key={v} onClick={() => setState(v)} style={{ padding: "6px 14px", fontSize: 12, border: "none", cursor: "pointer", background: state === v ? "rgba(88,166,255,.15)" : "transparent", color: state === v ? "var(--blue)" : "var(--muted)" }}>{label}</button>
          ))}
        </div>
        <button style={btnStyle} onClick={() => load(true)} disabled={refreshing}>{refreshing ? "Refreshing..." : "Refresh status"}</button>
      </div>

      {!jiraOn && <div style={{ fontSize: 12, color: "var(--amber)", marginBottom: 12 }}>Jira is not configured on the backend - existing tickets are simulated placeholders.</div>}
      {error && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 12 }}>{error}</div>}

      <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
        {rows === null ? (
          <div style={{ padding: 18, color: "var(--dim)", fontSize: 12 }}>Loading...</div>
        ) : shown.length === 0 ? (
          <div style={{ padding: 18, color: "var(--dim)", fontSize: 12 }}>No tickets match. Create one from an incident&apos;s Ticket tab.</div>
        ) : shown.map((t) => (
          <div key={t.ticket_id} style={{ borderBottom: "1px solid var(--raised)" }}>
            <div onClick={() => setOpenId(openId === t.ticket_id ? null : t.ticket_id)} style={{ display: "flex", alignItems: "center", gap: 14, padding: "12px 16px", cursor: "pointer", flexWrap: "wrap" }}>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, width: 80 }}>{t.external_ref}</span>
              <StatusBadge status={t.status} category={t.status_category} />
              <span style={{ fontSize: 11, fontWeight: 700, color: severityColor(t.tier), width: 62 }}>{t.tier}</span>
              <span style={{ fontSize: 12, flex: 1, minWidth: 180 }}>{t.attack_types.map((a) => a.toUpperCase()).join(", ")} <span style={{ color: "var(--dim)" }}>from</span> <span style={{ fontFamily: "var(--mono)" }}>{t.src_ips.join(", ")}</span></span>
              <span style={{ fontSize: 11, color: "var(--dim)" }}>{t.created_by} · {fmt(t.created_at)}</span>
              <span style={{ color: "var(--dim)" }}>{openId === t.ticket_id ? "▾" : "▸"}</span>
            </div>
            {openId === t.ticket_id && (
              <div style={{ padding: "0 16px 14px" }}>
                <TicketCard ticketId={t.ticket_id} externalRef={t.external_ref} url={t.url} simulated={t.simulated} status={t.status} category={t.status_category} createdAt={t.created_at} />
                <Link href={`/dashboard/incidents?open=${t.incident_id}`} style={{ fontSize: 12, color: "var(--blue)" }}>Open the incident →</Link>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = { background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5, padding: "7px 10px", color: "var(--text)", fontSize: 12, outline: "none", width: 200 };
const btnStyle: React.CSSProperties = { padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)", borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap" };
