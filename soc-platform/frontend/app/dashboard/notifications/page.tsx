"use client";

import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";

interface Status {
  schedule: string;
  hour_utc: number;
  smtp_ready: boolean;
  recipients: string[];
  channels: { telegram: boolean; whatsapp: boolean; email: boolean; slack: boolean; sms: boolean };
  phone_count: number;
}

const CHANNELS: { key: keyof Status["channels"]; label: string; hint: string; testable: boolean }[] = [
  { key: "telegram", label: "Telegram", hint: "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID", testable: true },
  { key: "whatsapp", label: "WhatsApp", hint: "META_WA_TOKEN, META_WA_PHONE_NUMBER_ID, META_WA_TO (official) or CALLMEBOT_RECIPIENTS (free)", testable: true },
  { key: "email", label: "Email", hint: "SMTP_HOST, SMTP_FROM, ALERT_EMAIL_TO (+ SMTP_USER, SMTP_PASSWORD)", testable: true },
  { key: "slack", label: "Slack", hint: "SLACK_WEBHOOK_URL", testable: true },
  { key: "sms", label: "SMS (Twilio, optional)", hint: "TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM, ALERT_PHONE_TO", testable: false },
];

export default function NotificationsPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<string, { ok: boolean; msg: string }>>({});

  async function sendTest(channel: string) {
    setTesting(channel);
    try {
      await apiFetch(`/api/notifications/test?channel=${channel}`, { method: "POST" });
      setTestResult((r) => ({ ...r, [channel]: { ok: true, msg: "Test message sent - check your phone or inbox." } }));
    } catch (e) {
      setTestResult((r) => ({ ...r, [channel]: { ok: false, msg: e instanceof ApiError ? e.message : "Test failed" } }));
    } finally {
      setTesting(null);
    }
  }

  useEffect(() => {
    apiFetch<Status>("/api/summary/status").then(setStatus).catch((e) => setError(e instanceof ApiError ? e.message : "Could not load status"));
  }, []);

  async function send(days: number) {
    setBusy(days);
    setError(null);
    setNotice(null);
    try {
      const r = await apiFetch<{ sent_to: string[]; incidents: number }>(`/api/summary/send?days=${days}`, { method: "POST" });
      setNotice(`Sent to ${r.sent_to.join(", ")} (${r.incidents} incidents in the period).`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Send failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div style={{ maxWidth: 760 }}>
      <h1 style={{ margin: 0, fontSize: 18 }}>Notifications</h1>
      <div style={{ fontSize: 12, color: "var(--muted)", margin: "4px 0 16px" }}>
        Where Critical incident alerts go, and the management summary email. Channels are configured in <code>backend/.env</code>.
      </div>

      <Card title="Critical incident alerts">
        {status === null ? <Dim>Loading...</Dim> : CHANNELS.map((c) => {
          const on = status.channels[c.key];
          const res = testResult[c.key];
          return (
            <div key={c.key} style={{ padding: "9px 0", borderBottom: "1px solid var(--raised)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <span style={{ width: 8, height: 8, borderRadius: 4, background: on ? "var(--green)" : "var(--dim)" }} />
                <span style={{ fontSize: 13, width: 170 }}>{c.label}</span>
                <span style={{ fontSize: 11, color: on ? "var(--green)" : "var(--dim)", width: 100 }}>{on ? "Configured" : "Not configured"}</span>
                {!on && <span style={{ fontSize: 10, color: "var(--dim)", fontFamily: "var(--mono)", flex: 1 }}>{c.hint}</span>}
                {on && c.key === "sms" && <span style={{ fontSize: 11, color: "var(--muted)", flex: 1 }}>{status.phone_count} recipient(s)</span>}
                {on && c.testable && (
                  <button style={{ ...btnStyle, marginLeft: "auto" }} disabled={testing !== null} onClick={() => sendTest(c.key)}>
                    {testing === c.key ? "Sending..." : "Send test"}
                  </button>
                )}
              </div>
              {res && <div style={{ fontSize: 11, marginTop: 6, marginLeft: 20, color: res.ok ? "var(--green)" : "var(--red)" }}>{res.msg}</div>}
            </div>
          );
        })}
      </Card>

      <Card title="Summary email">
        {status === null ? <Dim>Loading...</Dim> : (
          <>
            <div style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.7, marginBottom: 12 }}>
              Schedule: <b style={{ color: "var(--text)" }}>{status.schedule === "off" ? "Off" : `${status.schedule} at ${String(status.hour_utc).padStart(2, "0")}:00 UTC`}</b>
              {" "}(<code>SUMMARY_SCHEDULE</code> = off | daily | weekly).<br />
              Recipients: {status.recipients.length ? status.recipients.join(", ") : <i>none - set SUMMARY_EMAIL_TO or ALERT_EMAIL_TO</i>}
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {[[1, "Send last 24 hours"], [7, "Send last 7 days"], [30, "Send last 30 days"]].map(([d, label]) => (
                <button key={d as number} style={btnStyle} disabled={busy !== null || !status.smtp_ready} onClick={() => send(d as number)}>
                  {busy === d ? "Sending..." : (label as string)}
                </button>
              ))}
            </div>
            {!status.smtp_ready && <div style={{ fontSize: 11, color: "var(--amber)", marginTop: 10 }}>Email is not configured yet (SMTP_HOST, SMTP_FROM and a recipient), so sending is disabled.</div>}
          </>
        )}
        {notice && <div style={{ color: "var(--green)", fontSize: 12, marginTop: 10 }}>{notice}</div>}
        {error && <div style={{ color: "var(--red)", fontSize: 12, marginTop: 10 }}>{error}</div>}
      </Card>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 16, marginBottom: 16, boxShadow: "var(--shadow-card)" }}>
      <div style={{ fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)", marginBottom: 12 }}>{title}</div>
      {children}
    </div>
  );
}
const Dim = ({ children }: { children: React.ReactNode }) => <div style={{ color: "var(--dim)", fontSize: 12 }}>{children}</div>;
const btnStyle: React.CSSProperties = {
  padding: "7px 14px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)",
  borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
};
