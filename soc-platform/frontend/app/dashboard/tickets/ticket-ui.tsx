"use client";

import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";
import type { TicketDetails, TicketPreview } from "@/lib/types";

export const CATEGORY_COLOR: Record<string, string> = { new: "var(--blue)", indeterminate: "var(--amber)", done: "var(--green)" };
const PRIORITY_COLOR: Record<string, string> = { Highest: "var(--red)", High: "var(--amber)", Medium: "var(--blue)", Low: "var(--green)" };

export function StatusBadge({ status, category }: { status: string | null; category: string | null }) {
  const color = CATEGORY_COLOR[category ?? "new"] ?? "var(--dim)";
  return (
    <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 10, border: `1px solid ${color}`, color, textTransform: "uppercase", letterSpacing: "0.04em", whiteSpace: "nowrap" }}>
      {status ?? "Unknown"}
    </span>
  );
}

export function fmt(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "-";
}

/** Live Jira card: key, status, priority, assignee, status timeline and comments. */
export function TicketCard({
  ticketId, externalRef, url, simulated, status, category, createdAt,
}: {
  ticketId: string; externalRef: string; url: string | null; simulated: boolean;
  status: string | null; category: string | null; createdAt: string;
}) {
  const [d, setD] = useState<TicketDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    if (simulated) return;
    setLoading(true);
    setError(null);
    try {
      setD(await apiFetch<TicketDetails>(`/api/tickets/${ticketId}/details`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach Jira");
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [ticketId]);

  const shownStatus = d?.status ?? status;
  const shownCategory = d?.status_category ?? category;
  const accent = CATEGORY_COLOR[shownCategory ?? "new"] ?? "var(--border)";

  return (
    <div style={{ background: "var(--raised)", border: "1px solid var(--border)", borderLeft: `3px solid ${accent}`, borderRadius: 8, padding: 14, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 16, fontWeight: 700 }}>{externalRef}</span>
        <StatusBadge status={shownStatus} category={shownCategory} />
        {simulated && <span style={{ fontSize: 10, color: "var(--dim)" }}>simulated</span>}
        <div style={{ flex: 1 }} />
        {!simulated && <button style={ghostBtn} onClick={load} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</button>}
        {url && <a href={url} target="_blank" rel="noreferrer" style={{ ...ghostBtn, textDecoration: "none", color: "var(--blue)" }}>Open in Jira ↗</a>}
      </div>

      {d?.summary && <div style={{ fontSize: 13, margin: "10px 0 2px" }}>{d.summary}</div>}

      <div style={{ display: "flex", gap: 22, flexWrap: "wrap", margin: "10px 0 0" }}>
        <Meta label="Priority">{d?.priority ? <span style={{ color: PRIORITY_COLOR[d.priority] ?? "var(--text)", fontWeight: 600 }}>{d.priority}</span> : "-"}</Meta>
        <Meta label="Assignee">{simulated ? "-" : d ? (d.assignee ?? "Unassigned") : "..."}</Meta>
        <Meta label="Created">{fmt(d?.created ?? createdAt)}</Meta>
        {d?.updated && <Meta label="Last update">{fmt(d.updated)}</Meta>}
      </div>

      {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 10 }}>{error}</div>}

      {d && d.history.length > 0 && (
        <Section title="Status timeline">
          {d.history.map((h, i) => (
            <div key={i} style={{ display: "flex", gap: 8, fontSize: 11, padding: "3px 0", color: "var(--muted)" }}>
              <span style={{ color: "var(--dim)", width: 130 }}>{fmt(h.at)}</span>
              <span>{h.from} → <b style={{ color: "var(--text)" }}>{h.to}</b></span>
              <span style={{ color: "var(--dim)" }}>by {h.by}</span>
            </div>
          ))}
        </Section>
      )}

      {d && (
        <Section title={`Comments (${d.comments.length})`}>
          {d.comments.length === 0 ? (
            <div style={{ fontSize: 11, color: "var(--dim)" }}>No comments in Jira yet.</div>
          ) : d.comments.map((c, i) => (
            <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
              <div style={{ fontSize: 10, color: "var(--dim)" }}>{c.author} · {fmt(c.at)}</div>
              <div style={{ fontSize: 12, whiteSpace: "pre-wrap", marginTop: 2 }}>{c.body}</div>
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}

/** Create-ticket form pre-filled from the incident; the analyst can edit before it is sent. */
export function CreateTicketForm({ incidentId, onCreated, onCancel }: { incidentId: string; onCreated: () => void; onCancel?: () => void }) {
  const [preview, setPreview] = useState<TicketPreview | null>(null);
  const [summary, setSummary] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState("Medium");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiFetch<TicketPreview>(`/api/incidents/${incidentId}/ticket/preview`)
      .then((p) => { setPreview(p); setSummary(p.summary); setDescription(p.description); setPriority(p.priority); })
      .catch((e) => setError(e instanceof ApiError ? e.message : "Could not load the ticket form"));
  }, [incidentId]);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/incidents/${incidentId}/ticket`, { method: "POST", body: JSON.stringify({ provider: "jira", summary, description, priority }) });
      onCreated();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Ticket creation failed");
    } finally {
      setBusy(false);
    }
  }

  if (!preview) return <div style={{ fontSize: 12, color: error ? "var(--red)" : "var(--dim)" }}>{error ?? "Loading form..."}</div>;

  return (
    <div style={{ background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 8, padding: 14, marginBottom: 12 }}>
      <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 10 }}>
        New {preview.jira_configured ? `Jira ticket in ${preview.project_key}` : "ticket (Jira is not configured - this will be a simulated placeholder)"}
      </div>
      {preview.open_ticket && <div style={{ color: "var(--amber)", fontSize: 12, marginBottom: 10 }}>This incident already has an open ticket ({preview.open_ticket}). Close it in Jira before creating another.</div>}

      <label style={labelStyle}>Title
        <input value={summary} onChange={(e) => setSummary(e.target.value)} maxLength={250} style={inputStyle} />
      </label>
      <label style={{ ...labelStyle, marginTop: 10 }}>Description
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={8} style={{ ...inputStyle, fontFamily: "var(--mono)", fontSize: 11, resize: "vertical" }} />
      </label>
      <div style={{ display: "flex", gap: 16, alignItems: "flex-end", marginTop: 10, flexWrap: "wrap" }}>
        <label style={labelStyle}>Priority
          <select value={priority} onChange={(e) => setPriority(e.target.value)} style={inputStyle}>
            {preview.priorities.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
        <div style={{ fontSize: 10, color: "var(--dim)", flex: 1 }}>Labels: {preview.labels.join(", ")}</div>
      </div>
      {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 10 }}>{error}</div>}
      <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
        <button style={primaryBtn} onClick={submit} disabled={busy || !summary.trim() || !!preview.open_ticket}>{busy ? "Creating..." : "Create ticket"}</button>
        {onCancel && <button style={ghostBtn} onClick={onCancel}>Cancel</button>}
      </div>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{label}</div>
      <div style={{ fontSize: 12, marginTop: 2 }}>{children}</div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 14 }}>
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 4 }}>{title}</div>
      {children}
    </div>
  );
}

const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" };
const inputStyle: React.CSSProperties = { background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 5, padding: "7px 10px", color: "var(--text)", fontSize: 12, outline: "none", textTransform: "none", letterSpacing: 0 };
const primaryBtn: React.CSSProperties = { padding: "8px 18px", background: "var(--blue)", border: "none", borderRadius: 5, color: "#fff", fontSize: 12, fontWeight: 600, cursor: "pointer" };
const ghostBtn: React.CSSProperties = { padding: "5px 12px", background: "transparent", border: "1px solid var(--border)", borderRadius: 5, color: "var(--muted)", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap" };
