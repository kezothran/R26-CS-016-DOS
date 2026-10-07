"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch, ApiError, postDownload } from "@/lib/api";
import { getRole, isAdmin } from "@/lib/auth";
import type { AgentRow, AgentsResponse } from "@/lib/types";

const STATUS_COLOR: Record<string, string> = { online: "var(--green)", offline: "var(--dim)", revoked: "var(--red)" };

function ago(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export default function AgentsPage() {
  const admin = isAdmin(getRole());
  const [data, setData] = useState<AgentsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [serverUrl, setServerUrl] = useState("");
  const [note, setNote] = useState("");
  const [ttl, setTtl] = useState(24);
  const [token, setToken] = useState<{ value: string; expires: string } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [hostName, setHostName] = useState("");
  const [bundled, setBundled] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<AgentsResponse>("/api/agents"));
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load agents");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    setServerUrl(process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000");
  }, []);

  async function createToken() {
    setBusy(true);
    setError(null);
    try {
      const r = await apiFetch<{ token: string; expires_at: string }>("/api/agents/enrollment-tokens", {
        method: "POST", body: JSON.stringify({ note: note.trim() || null, ttl_hours: ttl }),
      });
      setToken({ value: r.token, expires: r.expires_at });
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create a token");
    } finally {
      setBusy(false);
    }
  }

  async function downloadBundle() {
    setBusy(true);
    setError(null);
    try {
      const safe = hostName.trim().replace(/\s+/g, "_");
      await postDownload(
        "/api/agents/bundle",
        { server_url: serverUrl.trim(), name: hostName.trim() || null, note: note.trim() || null, ttl_hours: ttl },
        `SentrixAgent-Bundle${safe ? "-" + safe : ""}.zip`,
      );
      setBundled(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create the bundle");
    } finally {
      setBusy(false);
    }
  }

  async function patch(a: AgentRow, body: { revoked?: boolean; name?: string }) {
    await apiFetch(`/api/agents/${a.id}`, { method: "PATCH", body: JSON.stringify(body) });
    await load();
  }

  async function remove(a: AgentRow) {
    if (!window.confirm(`Delete agent "${a.name}"? Its alert history stays, but it must be re-enrolled to reconnect.`)) return;
    await apiFetch(`/api/agents/${a.id}`, { method: "DELETE" });
    await load();
  }

  async function copy(label: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard blocked - user can still select the text */
    }
  }

  const url = serverUrl.trim().replace(/\/$/, "");
  const winCmd = token ? `.\\install_windows.ps1 -Server "${url}" -Token "${token.value}"` : "";
  const linCmd = token ? `sudo ./install_linux.sh --server ${url} --token ${token.value}` : "";
  const s = data?.summary;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 18 }}>Agents</h1>
          <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>
            PCs and servers running the Sentrix Agent. Their traffic is analysed here, and their alerts show the host in the interface column (e.g. <code>Wi-Fi@LAPTOP-1</code>).
          </div>
        </div>
        <div style={{ flex: 1 }} />
        {admin && !adding && <button style={btnStyle} onClick={() => { setAdding(true); setToken(null); }}>+ Add agent</button>}
      </div>

      {error && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 12 }}>{error}</div>}

      <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <Stat label="Total" value={s?.total} color="var(--text)" />
        <Stat label="Online" value={s?.online} color="var(--green)" />
        <Stat label="Offline" value={s?.offline} color="var(--amber)" />
        <Stat label="Revoked" value={s?.revoked} color="var(--red)" />
        <Stat label="This server" value={data ? (data.local_capture ? "sniffs locally" : "agents only") : undefined} color="var(--blue)" small />
      </div>

      {adding && admin && (
        <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>Add an agent</div>
          {!token ? (
            <>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
                <label style={labelStyle}>Address the agent will connect to
                  <input value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} style={{ ...inputStyle, width: 300 }} />
                </label>
                <label style={labelStyle}>Computer name (optional)
                  <input value={hostName} onChange={(e) => setHostName(e.target.value)} placeholder="e.g. Friend-PC" style={{ ...inputStyle, width: 160 }} />
                </label>
                <label style={labelStyle}>Note (who / where)
                  <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Lab PC 3" style={{ ...inputStyle, width: 200 }} />
                </label>
                <label style={labelStyle}>Token valid for
                  <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))} style={inputStyle}>
                    <option value={1}>1 hour</option><option value={24}>24 hours</option><option value={72}>3 days</option><option value={168}>7 days</option>
                  </select>
                </label>
                <button style={{ ...btnStyle, background: "var(--blue)", color: "#fff", border: "none" }} onClick={downloadBundle} disabled={busy}>{busy ? "Creating..." : "Download install bundle (.zip)"}</button>
                <button style={btnStyle} onClick={createToken} disabled={busy}>Show install commands instead</button>
                <button style={{ ...btnStyle, background: "transparent" }} onClick={() => setAdding(false)}>Cancel</button>
              </div>
              {bundled && (
                <div style={{ fontSize: 12, color: "var(--green)", marginTop: 10 }}>
                  Bundle downloaded. Send the zip privately to the other person - it contains a one-time token (valid {ttl}h) that works once.
                  They unzip it and double-click <b>INSTALL.cmd</b>.
                </div>
              )}
              <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 10 }}>
                Use the address that the other machine can reach - the VPN address of this server in cloud mode, or this PC&apos;s LAN IP for a test.
              </div>
            </>
          ) : (
            <>
              <div style={{ fontSize: 12, color: "var(--amber)", marginBottom: 10 }}>
                This one-time token is shown only now (expires {new Date(token.expires).toLocaleString()}). It stops working after the first agent uses it.
              </div>
              <ol style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.8, paddingLeft: 18, margin: "0 0 12px" }}>
                <li>Copy the <code>agent</code> folder from the project to the target machine.</li>
                <li>Open an <b>elevated</b> PowerShell (Windows) or a root shell (Linux) in that folder and run the matching command:</li>
              </ol>
              <Cmd label="Windows (PowerShell as Administrator)" text={winCmd} copied={copied === "win"} onCopy={() => copy("win", winCmd)} />
              <Cmd label="Linux (root)" text={linCmd} copied={copied === "lin"} onCopy={() => copy("lin", linCmd)} />
              <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 8 }}>
                Needs Python 3.10+ (and Npcap on Windows). The agent appears in the table below within a few seconds of installing.
              </div>
              <button style={{ ...btnStyle, marginTop: 12 }} onClick={() => { setAdding(false); setToken(null); }}>Done</button>
            </>
          )}
        </div>
      )}

      <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--shadow-card)", overflow: "hidden" }}>
        {data === null ? (
          <div style={{ padding: 18, color: "var(--dim)", fontSize: 12 }}>Loading...</div>
        ) : data.agents.length === 0 ? (
          <div style={{ padding: 18, color: "var(--dim)", fontSize: 12 }}>
            No agents yet. {admin ? "Click “+ Add agent” to enrol your first PC or server." : "An admin can enrol agents."}
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>{["Status", "Name", "Host / OS", "Last seen", "Last window", "Total packets", "Alerts 24h", "Version", ""].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "9px 12px", fontSize: 10, textTransform: "uppercase", color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {data.agents.map((a) => (
                <tr key={a.id} style={{ opacity: a.status === "revoked" ? 0.6 : 1 }}>
                  <td style={cell}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontWeight: 600, color: STATUS_COLOR[a.status] }}>
                      <span style={{ width: 8, height: 8, borderRadius: 4, background: STATUS_COLOR[a.status] }} />{a.status}
                    </span>
                  </td>
                  <td style={{ ...cell, fontWeight: 600 }}>{a.name}</td>
                  <td style={cell}>
                    <div style={{ fontFamily: "var(--mono)" }}>{a.hostname}</div>
                    <div style={{ fontSize: 10, color: "var(--dim)" }}>{a.os ?? "-"} · {a.remote_ip ?? "-"}</div>
                  </td>
                  <td style={cell}>{ago(a.last_seen_at)}</td>
                  <td style={cell}>{a.last_window_packets.toLocaleString()} pkts</td>
                  <td style={cell}>{a.total_packets.toLocaleString()}</td>
                  <td style={{ ...cell, color: a.alerts_24h ? "var(--red)" : "var(--muted)", fontWeight: a.alerts_24h ? 700 : 400 }}>{a.alerts_24h}</td>
                  <td style={cell}>{a.agent_version ?? "-"}</td>
                  <td style={cell}>
                    {admin && (
                      <div style={{ display: "flex", gap: 6 }}>
                        <button style={miniBtn} onClick={() => patch(a, { revoked: !a.revoked })}>{a.revoked ? "Restore" : "Revoke"}</button>
                        <button style={{ ...miniBtn, color: "var(--red)" }} onClick={() => remove(a)}>Delete</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {data && <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 8 }}>Refreshes every 10 s. An agent counts as offline after {data.online_window_secs}s without contact.</div>}
    </div>
  );
}

function Stat({ label, value, color, small }: { label: string; value: number | string | undefined; color: string; small?: boolean }) {
  return (
    <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: "12px 18px", minWidth: 120, boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: small ? 15 : 24, fontWeight: 700, color, lineHeight: small ? "32px" : "inherit" }}>{value ?? "-"}</div>
      <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>{label}</div>
    </div>
  );
}

function Cmd({ label, text, copied, onCopy }: { label: string; text: string; copied: boolean; onCopy: () => void }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 10, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>{label}</div>
      <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
        <code style={{ flex: 1, background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5, padding: "8px 10px", fontSize: 11.5, wordBreak: "break-all", color: "var(--text)" }}>{text}</code>
        <button style={btnStyle} onClick={onCopy}>{copied ? "Copied" : "Copy"}</button>
      </div>
    </div>
  );
}

const cell: React.CSSProperties = { padding: "10px 12px", borderBottom: "1px solid var(--raised)", verticalAlign: "top" };
const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 9, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" };
const inputStyle: React.CSSProperties = { background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5, padding: "7px 10px", color: "var(--text)", fontSize: 12, outline: "none", textTransform: "none", letterSpacing: 0 };
const btnStyle: React.CSSProperties = { padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)", borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap" };
const miniBtn: React.CSSProperties = { padding: "4px 10px", background: "transparent", border: "1px solid var(--border)", borderRadius: 5, color: "var(--muted)", fontSize: 11, cursor: "pointer" };
