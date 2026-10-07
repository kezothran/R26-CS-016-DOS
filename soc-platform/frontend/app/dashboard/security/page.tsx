"use client";

import { useEffect, useState } from "react";
import { apiFetch, ApiError } from "@/lib/api";

interface Setup {
  secret: string;
  otpauth_uri: string;
  qr_png: string;
}

export default function SecurityPage() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [disabling, setDisabling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setEnabled((await apiFetch<{ enabled: boolean }>("/auth/2fa/status")).enabled);
  }
  useEffect(() => { load().catch(() => setEnabled(false)); }, []);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  const startSetup = () => run(async () => {
    setSetup(await apiFetch<Setup>("/auth/2fa/setup", { method: "POST" }));
    setCode("");
  });

  const confirmEnable = () => run(async () => {
    await apiFetch("/auth/2fa/enable", { method: "POST", body: JSON.stringify({ code }) });
    setSetup(null);
    setCode("");
    setNotice("Two-factor authentication is now on. You will be asked for a code at every sign-in.");
    await load();
  });

  const confirmDisable = () => run(async () => {
    await apiFetch("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password, code }) });
    setDisabling(false);
    setPassword("");
    setCode("");
    setNotice("Two-factor authentication has been turned off.");
    await load();
  });

  return (
    <div style={{ maxWidth: 640 }}>
      <h1 style={{ margin: 0, fontSize: 18 }}>Account security</h1>
      <div style={{ fontSize: 12, color: "var(--muted)", margin: "4px 0 16px" }}>
        Protect your account with a one-time code from an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password).
      </div>

      <div style={{ background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, padding: 18, boxShadow: "var(--shadow-card)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>Two-factor authentication</span>
          {enabled !== null && (
            <span style={{
              fontSize: 10, padding: "2px 9px", borderRadius: 10, fontWeight: 700,
              color: enabled ? "var(--green)" : "var(--amber)", border: `1px solid ${enabled ? "var(--green)" : "var(--amber)"}`,
            }}>{enabled ? "ON" : "OFF"}</span>
          )}
        </div>

        {notice && <div style={{ color: "var(--green)", fontSize: 12, margin: "8px 0" }}>{notice}</div>}
        {error && <div style={{ color: "var(--red)", fontSize: 12, margin: "8px 0" }}>{error}</div>}

        {enabled === false && !setup && (
          <>
            <p style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.6 }}>
              After you enter your password, you will also need a 6-digit code that changes every 30 seconds.
              If you lose your phone, an administrator can reset 2FA for your account.
            </p>
            <button style={btnStyle} onClick={startSetup} disabled={busy}>Set up two-factor authentication</button>
          </>
        )}

        {setup && (
          <div style={{ marginTop: 12 }}>
            <ol style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.8, paddingLeft: 18, margin: "0 0 12px" }}>
              <li>Open your authenticator app and add an account by scanning this QR code.</li>
              <li>Enter the 6-digit code the app shows to confirm.</li>
            </ol>
            <div style={{ display: "flex", gap: 18, alignItems: "flex-start", flexWrap: "wrap" }}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={setup.qr_png} alt="2FA QR code" width={170} height={170} style={{ background: "#fff", padding: 6, borderRadius: 8 }} />
              <div style={{ flex: 1, minWidth: 220 }}>
                <div style={{ fontSize: 10, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>Can&apos;t scan? Enter this key</div>
                <code style={{ display: "block", fontSize: 12, margin: "4px 0 14px", wordBreak: "break-all", color: "var(--text)" }}>{setup.secret}</code>
                <input
                  value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ""))} placeholder="000000"
                  inputMode="numeric" maxLength={7} style={{ ...inputStyle, letterSpacing: "0.3em", width: 130 }}
                />
                <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                  <button style={btnStyle} onClick={confirmEnable} disabled={busy || code.replace(/\s/g, "").length < 6}>Confirm and turn on</button>
                  <button style={{ ...btnStyle, background: "transparent" }} onClick={() => { setSetup(null); setError(null); }}>Cancel</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {enabled === true && !disabling && (
          <>
            <p style={{ fontSize: 12, color: "var(--muted)", lineHeight: 1.6 }}>Your account asks for an authenticator code at sign-in.</p>
            <button style={{ ...btnStyle, color: "var(--red)", borderColor: "rgba(248,81,73,.3)", background: "rgba(248,81,73,.08)" }} onClick={() => { setDisabling(true); setError(null); setNotice(null); }}>
              Turn off two-factor authentication
            </button>
          </>
        )}

        {enabled === true && disabling && (
          <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 10, maxWidth: 320 }}>
            <div style={{ fontSize: 12, color: "var(--muted)" }}>Confirm with your password and a current code.</div>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" style={inputStyle} autoComplete="current-password" />
            <input value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ""))} placeholder="6-digit code" inputMode="numeric" maxLength={7} style={inputStyle} />
            <div style={{ display: "flex", gap: 8 }}>
              <button style={{ ...btnStyle, color: "var(--red)", borderColor: "rgba(248,81,73,.3)", background: "rgba(248,81,73,.08)" }} onClick={confirmDisable} disabled={busy || !password || code.replace(/\s/g, "").length < 6}>Turn off</button>
              <button style={{ ...btnStyle, background: "transparent" }} onClick={() => { setDisabling(false); setError(null); }}>Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 5,
  padding: "8px 10px", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, outline: "none",
};
const btnStyle: React.CSSProperties = {
  padding: "8px 16px", background: "rgba(88,166,255,.1)", border: "1px solid rgba(88,166,255,.26)",
  borderRadius: 5, color: "var(--blue)", fontSize: 12, fontWeight: 500, cursor: "pointer", whiteSpace: "nowrap",
};
