"use client";

import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";
import { getRole, isAdmin } from "@/lib/auth";
import type { Playbook, PlaybookAction, PlaybookStepDef } from "@/lib/types";

const ATTACK_TYPES = ["icmp", "syn", "fragmentation", "udp"];
const TIERS = ["Low", "Medium", "High", "Critical"];
const ACTION_LABEL: Record<string, string> = { "": "No action", propose_block: "Propose block", open_ticket: "Open ticket tab" };

interface Draft {
  id: string | null;
  name: string;
  attack_type: string;
  tier: string;
  enabled: boolean;
  steps: PlaybookStepDef[];
}

const emptyDraft = (): Draft => ({ id: null, name: "", attack_type: "", tier: "", enabled: true, steps: [{ title: "", action: null }] });

export default function PlaybooksPage() {
  const admin = isAdmin(getRole());
  const [playbooks, setPlaybooks] = useState<Playbook[] | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setPlaybooks(await apiFetch<Playbook[]>("/api/playbooks"));
  }
  useEffect(() => { load(); }, []);

  function edit(p: Playbook) {
    setError(null);
    setDraft({ id: p.id, name: p.name, attack_type: p.attack_type ?? "", tier: p.tier ?? "", enabled: p.enabled, steps: p.steps.map((s) => ({ ...s })) });
  }

  async function save() {
    if (!draft) return;
    const steps = draft.steps.filter((s) => s.title.trim()).map((s) => ({ title: s.title.trim(), action: s.action }));
    if (!draft.name.trim() || steps.length === 0) { setError("A name and at least one step are required."); return; }
    setBusy(true);
    setError(null);
    try {
      const body = JSON.stringify({ name: draft.name, attack_type: draft.attack_type || null, tier: draft.tier || null, enabled: draft.enabled, steps });
      await apiFetch(draft.id ? `/api/playbooks/${draft.id}` : "/api/playbooks", { method: draft.id ? "PUT" : "POST", body });
      setDraft(null);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function remove(p: Playbook) {
    if (!confirm(`Delete playbook "${p.name}"? Incidents already using it keep their checklist.`)) return;
    await apiFetch(`/api/playbooks/${p.id}`, { method: "DELETE" });
    await load();
  }

  function setStep(i: number, patch: Partial<PlaybookStepDef>) {
    if (!draft) return;
    setDraft({ ...draft, steps: draft.steps.map((s, j) => (j === i ? { ...s, ...patch } : s)) });
  }
  function moveStep(i: number, dir: -1 | 1) {
    if (!draft) return;
    const j = i + dir;
    if (j < 0 || j >= draft.steps.length) return;
    const steps = [...draft.steps];
    [steps[i], steps[j]] = [steps[j], steps[i]];
    setDraft({ ...draft, steps });
  }

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 18 }}>Response Playbooks</h1>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>
            Checklists analysts follow per incident. The most specific enabled playbook for an incident&apos;s attack type and severity is used.
          </div>
        </div>
        <div style={{ flex: 1 }} />
        {admin && !draft && <button style={btnStyle} onClick={() => { setError(null); setDraft(emptyDraft()); }}>+ New playbook</button>}
      </div>

      {!admin && <div style={{ fontSize: 12, color: "var(--dim)", marginBottom: 12 }}>Read-only - only admins can edit playbooks.</div>}

      {draft && (
        <Box title={draft.id ? "Edit playbook" : "New playbook"}>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 14 }}>
            <label style={labelStyle}>Name
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} style={{ ...inputStyle, width: 260 }} />
            </label>
            <label style={labelStyle}>Attack type
              <select value={draft.attack_type} onChange={(e) => setDraft({ ...draft, attack_type: e.target.value })} style={inputStyle}>
                <option value="">Any</option>
                {ATTACK_TYPES.map((a) => <option key={a} value={a}>{a.toUpperCase()}</option>)}
              </select>
            </label>
            <label style={labelStyle}>Severity
              <select value={draft.tier} onChange={(e) => setDraft({ ...draft, tier: e.target.value })} style={inputStyle}>
                <option value="">Any</option>
                {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label style={{ ...labelStyle, justifyContent: "flex-end" }}>Enabled
              <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
            </label>
          </div>

          <div style={{ fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>Steps</div>
          {draft.steps.map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6, alignItems: "center" }}>
              <span style={{ width: 20, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{i + 1}.</span>
              <input value={s.title} onChange={(e) => setStep(i, { title: e.target.value })} placeholder="Describe the step" style={{ ...inputStyle, flex: 1 }} />
              <select value={s.action ?? ""} onChange={(e) => setStep(i, { action: (e.target.value || null) as PlaybookAction })} style={inputStyle}>
                {Object.entries(ACTION_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
              <button style={miniBtn} onClick={() => moveStep(i, -1)} disabled={i === 0}>↑</button>
              <button style={miniBtn} onClick={() => moveStep(i, 1)} disabled={i === draft.steps.length - 1}>↓</button>
              <button style={miniBtn} onClick={() => setDraft({ ...draft, steps: draft.steps.filter((_, j) => j !== i) })} disabled={draft.steps.length === 1}>✕</button>
            </div>
          ))}
          <button style={{ ...btnStyle, marginTop: 4 }} onClick={() => setDraft({ ...draft, steps: [...draft.steps, { title: "", action: null }] })}>+ Add step</button>

          {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 10 }}>{error}</div>}
          <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
            <button style={btnStyle} onClick={save} disabled={busy}>{busy ? "Saving..." : "Save playbook"}</button>
            <button style={{ ...btnStyle, background: "transparent" }} onClick={() => setDraft(null)}>Cancel</button>
          </div>
        </Box>
      )}

      <Box title={`Playbooks ${playbooks ? `(${playbooks.length})` : ""}`}>
        {playbooks === null ? (
          <div style={{ color: "var(--dim)", fontSize: 12 }}>Loading...</div>
        ) : playbooks.length === 0 ? (
          <div style={{ color: "var(--dim)", fontSize: 12 }}>No playbooks yet.</div>
        ) : (
          playbooks.map((p) => (
            <div key={p.id} style={{ padding: "10px 0", borderBottom: "1px solid var(--raised)", opacity: p.enabled ? 1 : 0.55 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</span>
                <span style={pill}>{p.attack_type ? p.attack_type.toUpperCase() : "Any attack"}</span>
                <span style={pill}>{p.tier ?? "Any severity"}</span>
                {!p.enabled && <span style={{ ...pill, color: "var(--amber)" }}>Disabled</span>}
                <div style={{ flex: 1 }} />
                <span style={{ fontSize: 11, color: "var(--dim)" }}>{p.steps.length} steps</span>
                {admin && (
                  <>
                    <button style={btnStyle} onClick={() => edit(p)}>Edit</button>
                    <button style={{ ...btnStyle, color: "var(--red)", borderColor: "rgba(248,81,73,.3)", background: "rgba(248,81,73,.08)" }} onClick={() => remove(p)}>Delete</button>
                  </>
                )}
              </div>
              <ol style={{ margin: "8px 0 0", paddingLeft: 20, fontSize: 12, lineHeight: 1.7, color: "var(--muted)" }}>
                {p.steps.map((s, i) => (
                  <li key={i}>{s.title}{s.action && <em style={{ color: "var(--blue)", fontStyle: "normal", fontSize: 10 }}> · {ACTION_LABEL[s.action]}</em>}</li>
                ))}
              </ol>
            </div>
          ))
        )}
      </Box>
    </div>
  );
}

function Box({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 14 }}>{title}</div>
      {children}
    </div>
  );
}

const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" };
const inputStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "6px 9px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, outline: "none",
};
const btnStyle: React.CSSProperties = {
  padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)",
  borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
};
const miniBtn: React.CSSProperties = { ...inputStyle, cursor: "pointer", padding: "5px 8px" };
const pill: React.CSSProperties = { fontSize: 10, padding: "2px 8px", borderRadius: 10, background: "var(--raised)", border: "1px solid var(--border)", color: "var(--muted)" };
