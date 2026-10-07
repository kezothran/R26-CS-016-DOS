"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api";
import { setSession } from "@/lib/auth";

const FEATURES = [
  {
    icon: <ActivityIcon />,
    color: "var(--sx-blue)",
    title: "Real-time Detection",
    desc: "ICMP / SYN / Fragmentation attack detection in real time.",
  },
  {
    icon: <BrainIcon />,
    color: "var(--sx-purple)",
    title: "AI-Powered Scoring",
    desc: "Hybrid XGBoost + Deep Learning models for accurate severity scoring.",
  },
  {
    icon: <ShieldCheckIcon />,
    color: "var(--sx-cyan)",
    title: "Smart Triage",
    desc: "Correlated, severity-weighted incident triage to reduce noise.",
  },
];

interface HealthResponse {
  ok: boolean;
  active_attacks: string[];
  trained: Record<string, boolean>;
}

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<HealthResponse | "unreachable" | null>(null);
  const [showForgotHint, setShowForgotHint] = useState(false);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState("");

  // Public, unauthenticated endpoint - shows real engine state on the login screen instead of
  // static marketing copy (the point isn't decoration, it's proof the console is actually live).
  useEffect(() => {
    apiFetch<HealthResponse>("/health").then(setHealth).catch(() => setHealth("unreachable"));
  }, []);

  type LoginRes = { access_token: string; role: string; must_change_password: boolean; mfa_required?: boolean; mfa_token?: string | null };

  function finish(res: LoginRes) {
    setSession(res.access_token, res.role, remember);
    router.push(res.must_change_password ? "/dashboard/change-password" : "/dashboard");
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await apiFetch<LoginRes>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
        setCode("");
      } else {
        finish(res);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't reach the detection engine. Check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      finish(await apiFetch<LoginRes>("/auth/2fa/login", { method: "POST", body: JSON.stringify({ mfa_token: mfaToken, code }) }));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && /expired|invalid sign-in/i.test(err.message)) {
        setMfaToken(null);
        setPassword("");
      }
      setError(err instanceof ApiError ? err.message : "Couldn't reach the detection engine. Check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="sx-page">
      <NetworkBackground />
      <div className="sx-bg-glow" aria-hidden />
      <div className="sx-shell sx-page-enter">
        <div className="sx-hero">
          <section className="sx-content">
            <div className="sx-brand">
              <Mark id="hero" size={44} className="sx-logo-in" />
              <div className="sx-logo-text-in">
                <div className="sx-brand-name">SENTRIX</div>
                <div className="sx-brand-sub">Security Operations Console</div>
              </div>
            </div>

            <span className="sx-badge">REAL-TIME THREAT DETECTION</span>
            <h1 className="sx-heading">
              Network threats don&rsquo;t wait.
              <br />
              <span className="sx-accent">Neither do we.</span>
            </h1>
            <p className="sx-desc">
              Monitor. Detect. Respond. — All from one powerful console built for speed, accuracy,
              and complete visibility.
            </p>

            <ul className="sx-features">
              {FEATURES.map((f, i) => (
                <li key={f.title} className="sx-feature" style={{ animationDelay: `${160 + i * 100}ms` }}>
                  <span className="sx-feature-icon" style={{ color: f.color }}>{f.icon}</span>
                  <div>
                    <div className="sx-feature-title">{f.title}</div>
                    <div className="sx-feature-desc">{f.desc}</div>
                  </div>
                </li>
              ))}
            </ul>

            <EngineStatus health={health} />
          </section>

          <ShieldGlobe />

          <section className="sx-card sx-card-enter" style={{ animationDelay: "120ms" }}>
            <div className="sx-card-brand sx-stagger" style={{ animationDelay: "170ms" }}>
              <Mark id="card" size={30} />
              <span className="sx-card-brand-name">SENTRIX</span>
            </div>

            <h2 className="sx-card-title sx-stagger" style={{ animationDelay: "230ms" }}>{mfaToken ? "Two-factor verification" : "Welcome back"}</h2>
            <p className="sx-card-sub sx-stagger" style={{ animationDelay: "290ms" }}>
              {mfaToken ? "Enter the 6-digit code from your authenticator app." : "Sign in to access the SOC console."}
            </p>

            {mfaToken ? (
              <form onSubmit={handleCode} style={{ display: "flex", flexDirection: "column" }}>
                <Field label="Authentication code">
                  <span className="sx-input-icon"><LockIcon /></span>
                  <input
                    inputMode="numeric" autoComplete="one-time-code" autoFocus required maxLength={7} value={code}
                    onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ""))}
                    style={{ ...inputStyle, letterSpacing: "0.3em", fontFamily: "monospace" }} className="sx-input" placeholder="000000"
                  />
                </Field>
                {error && (
                  <div role="alert" className="sx-error">
                    <span style={{ marginTop: 1, flexShrink: 0 }}><AlertIcon /></span>
                    {error}
                  </div>
                )}
                <button type="submit" disabled={loading || code.replace(/\s/g, "").length < 6} className="sx-submit" style={{ marginTop: error ? 14 : 22 }}>
                  {loading && <Spinner />}
                  {loading ? "Verifying" : "Verify and sign in"}
                </button>
                <button type="button" className="sx-link" style={{ marginTop: 14 }} onClick={() => { setMfaToken(null); setError(null); setPassword(""); }}>
                  Back to sign in
                </button>
              </form>
            ) : (
            <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column" }}>
              <div className="sx-stagger" style={{ animationDelay: "350ms" }}>
                <Field label="Email">
                  <span className="sx-input-icon"><MailIcon /></span>
                  <input
                    type="email" required autoComplete="email" autoFocus value={email}
                    onChange={(e) => setEmail(e.target.value)} style={inputStyle} className="sx-input"
                  />
                </Field>
              </div>

              <div className="sx-stagger" style={{ animationDelay: "410ms" }}>
                <Field label="Password">
                  <span className="sx-input-icon"><LockIcon /></span>
                  <input
                    type={showPassword ? "text" : "password"} required autoComplete="current-password" value={password}
                    onChange={(e) => setPassword(e.target.value)} style={{ ...inputStyle, paddingRight: 38 }} className="sx-input"
                  />
                  <button
                    type="button" className="sx-input-toggle" onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                  </button>
                </Field>
              </div>

              <div className="sx-row sx-stagger" style={{ animationDelay: "470ms" }}>
                <label className="sx-remember">
                  <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
                  Remember me
                </label>
                <button type="button" className="sx-link" onClick={() => setShowForgotHint((v) => !v)}>
                  Forgot password?
                </button>
              </div>

              {showForgotHint && (
                <p className="sx-hint">Password resets are handled by an administrator — contact your SOC lead.</p>
              )}

              {error && (
                <div role="alert" className="sx-error">
                  <span style={{ marginTop: 1, flexShrink: 0 }}><AlertIcon /></span>
                  {error}
                </div>
              )}

              <button
                type="submit" disabled={loading} className="sx-submit sx-stagger"
                style={{ marginTop: error ? 14 : 22, animationDelay: "530ms" }}
              >
                {loading && <Spinner />}
                {loading ? "Signing in" : "Sign in"}
                {!loading && <span className="sx-arrow"><ArrowRightIcon /></span>}
              </button>

              <div className="sx-divider sx-stagger" style={{ animationDelay: "590ms" }}><span>OR</span></div>

              <button
                type="button" className="sx-sso sx-stagger" disabled title="SSO is not configured for this deployment"
                style={{ animationDelay: "650ms" }}
              >
                <ShieldCheckIcon />
                Sign in with SSO
              </button>

              <p className="sx-footer sx-stagger" style={{ animationDelay: "710ms" }}>
                <LockOutlineIcon />
                <span>
                  Access is provided by an administrator.
                  <br />
                  Contact your SOC lead if you need an account.
                </span>
              </p>
            </form>
            )}
          </section>
        </div>

        <p className="sx-copyright">© {new Date().getFullYear()} SENTRIX. All rights reserved.</p>
      </div>

      {/* dangerouslySetInnerHTML, not a text child: <style> is HTML "raw text" (entities are
          never decoded by the browser), but React's server renderer HTML-escapes normal text
          children - any quote character inside a `<style>{...}</style>` string desyncs the
          server-escaped markup from the client's literal textContent and throws a hydration
          mismatch. This sidesteps that entirely. */}
      <style dangerouslySetInnerHTML={{ __html: `
        .sx-page {
          --sx-bg: #05070B;
          --sx-bg2: #070A10;
          --sx-card: #0C131C;
          --sx-input: #0F1720;
          --sx-elevated: #0C131D;
          --sx-text: #F3F6FA;
          --sx-muted: #A7B2C3;
          --sx-dim: #66758A;
          --sx-disabled: #465366;
          --sx-blue: #3B9CFF;
          --sx-blue-bright: #58AEFF;
          --sx-blue-deep: #1769D2;
          --sx-cyan: #22D3EE;
          --sx-green: #22C55E;
          --sx-amber: #F59E0B;
          --sx-red: #EF4444;
          --sx-purple: #8B5CF6;
          --sx-border: rgba(148,163,184,0.12);
          --sx-input-border: #1C2733;
          font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;

          min-height: 100vh; padding: 40px 24px; position: relative; overflow: hidden;
          background:
            radial-gradient(760px 480px at 62% 38%, rgba(59,156,255,0.06), transparent 65%),
            linear-gradient(180deg, var(--sx-bg2), var(--sx-bg) 40%);
          color: var(--sx-text);
        }
        .sx-shell { max-width: 1240px; margin: 0 auto; position: relative; z-index: 1; }

        .sx-net-bg {
          position: absolute; inset: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; opacity: 0.28;
        }
        .sx-net-line { opacity: 0.18; }
        .sx-bg-glow {
          position: absolute; inset: -10%; z-index: 0; pointer-events: none;
          background: radial-gradient(640px 480px at 60% 35%, rgba(59,156,255,0.06), rgba(34,211,238,0.03) 45%, transparent 70%);
        }

        .sx-hero { display: grid; grid-template-columns: 1fr 360px 460px; gap: 40px; align-items: center; }

        .sx-content { min-width: 0; }
        .sx-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; }
        .sx-brand-name { font-weight: 700; font-size: 21px; letter-spacing: -0.02em; }
        .sx-brand-sub { font-size: 12.5px; color: var(--sx-muted); margin-top: 1px; }

        .sx-badge {
          display: inline-block; font-size: 11px; font-weight: 500; letter-spacing: 0.06em;
          color: var(--sx-blue); background: rgba(59,156,255,0.06); border: 1px solid rgba(59,156,255,0.4);
          border-radius: 6px; padding: 6px 12px; margin-bottom: 20px;
        }
        .sx-heading {
          font-weight: 700; font-size: clamp(30px, 3.6vw, 46px); line-height: 1.1;
          letter-spacing: -0.035em; margin-bottom: 16px;
        }
        .sx-accent { color: var(--sx-blue); }
        .sx-desc { font-weight: 400; font-size: 15px; line-height: 1.6; color: var(--sx-muted); margin-bottom: 30px; max-width: 460px; }

        .sx-features { list-style: none; display: flex; flex-direction: column; gap: 18px; margin-bottom: 26px; }
        .sx-feature {
          display: flex; align-items: flex-start; gap: 14px; padding: 6px; margin: -6px; border-radius: 10px;
          border: 1px solid transparent;
          transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .sx-feature:hover { transform: translateY(-2px); border-color: rgba(59,156,255,0.35); }
        .sx-feature-icon {
          width: 38px; height: 38px; border-radius: 9px; background: var(--sx-elevated); border: 1px solid var(--sx-border);
          display: flex; align-items: center; justify-content: center; flex-shrink: 0;
          transition: box-shadow 0.2s ease;
        }
        .sx-feature:hover .sx-feature-icon { box-shadow: 0 0 0 1px rgba(59,156,255,0.3), 0 0 14px -4px rgba(59,156,255,0.5); }
        .sx-feature-title { font-weight: 600; font-size: 14.5px; color: var(--sx-text); margin-bottom: 2px; }
        .sx-feature-desc { font-weight: 400; font-size: 13px; color: var(--sx-dim); line-height: 1.5; }

        .sx-status {
          display: inline-flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--sx-muted);
          border: 1px solid var(--sx-border); background: var(--sx-elevated); border-radius: 8px; padding: 10px 16px;
        }
        .sx-status-sep { color: var(--sx-border); }
        .sx-online-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }

        .sx-graphic { justify-self: center; }

        .sx-card {
          background: var(--sx-card); border: 1px solid var(--sx-border); border-radius: 14px;
          padding: 40px 38px; align-self: start;
          box-shadow: 0 20px 50px rgba(0,0,0,0.45), 0 0 0 1px rgba(59,156,255,0.04), 0 0 40px -20px rgba(59,156,255,0.2);
        }
        .sx-card-brand { display: flex; align-items: center; gap: 10px; margin-bottom: 22px; }
        .sx-card-brand-name { font-weight: 700; font-size: 16px; letter-spacing: -0.02em; }
        .sx-card-title { font-weight: 700; font-size: 24px; letter-spacing: -0.01em; margin-bottom: 6px; }
        .sx-card-sub { font-weight: 400; font-size: 14px; color: var(--sx-muted); margin-bottom: 28px; }

        .sx-field-label { display: block; font-weight: 500; font-size: 13px; color: var(--sx-muted); margin-bottom: 16px; }
        .sx-input-icon {
          position: absolute; left: 14px; top: 50%; transform: translateY(-50%);
          color: var(--sx-dim); display: flex; pointer-events: none; transition: color 0.18s ease;
        }
        label:focus-within .sx-input-icon { color: var(--sx-blue); }
        .sx-input-toggle {
          position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
          background: none; border: none; padding: 4px; color: var(--sx-dim); cursor: pointer;
          display: flex; align-items: center;
        }
        .sx-input-toggle:hover { color: var(--sx-muted); }

        .sx-row { display: flex; align-items: center; justify-content: space-between; margin-top: -6px; margin-bottom: 6px; }
        .sx-remember { display: flex; align-items: center; gap: 7px; font-size: 13px; color: var(--sx-muted); cursor: pointer; }
        .sx-remember input { accent-color: var(--sx-blue); width: 15px; height: 15px; }
        .sx-link {
          background: none; border: none; padding: 0; font-weight: 500; font-size: 13px; color: var(--sx-blue);
          cursor: pointer; font-family: inherit;
        }
        .sx-hint { font-size: 12px; color: var(--sx-dim); line-height: 1.5; margin-bottom: 14px; }

        .sx-error {
          display: flex; gap: 8px; align-items: flex-start; font-size: 13px; color: var(--sx-red);
          background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25);
          border-radius: 8px; padding: 10px 12px; margin-top: 14px; margin-bottom: 4px; line-height: 1.5;
        }

        .sx-submit {
          display: flex; align-items: center; justify-content: center; gap: 8px;
          height: 50px; border-radius: 8px; border: none;
          background: linear-gradient(90deg, #287FE8, #3B9CFF); color: #ffffff;
          font-weight: 600; font-size: 15px; cursor: pointer;
          box-shadow: 0 8px 20px -8px rgba(59,156,255,0.5);
          transition: background 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
        }
        .sx-submit:hover:not(:disabled) {
          background: linear-gradient(90deg, #348CF0, #58AEFF);
          transform: translateY(-1px);
          box-shadow: 0 10px 24px -8px rgba(59,156,255,0.6);
        }
        .sx-submit:active:not(:disabled) { transform: translateY(1px); }
        .sx-submit:disabled { opacity: 0.75; cursor: default; }
        .sx-arrow { display: flex; transition: transform 0.2s ease; }
        .sx-submit:hover:not(:disabled) .sx-arrow { transform: translateX(4px); }

        .sx-divider { display: flex; align-items: center; gap: 12px; margin: 22px 0; font-size: 11.5px; font-weight: 500; color: var(--sx-dim); letter-spacing: 0.05em; }
        .sx-divider::before, .sx-divider::after { content: ''; flex: 1; height: 1px; background: var(--sx-border); }

        .sx-sso {
          display: flex; align-items: center; justify-content: center; gap: 9px;
          height: 48px; border-radius: 8px; border: 1px solid #2A394B; background: transparent;
          color: #E2E8F0; font-weight: 600; font-size: 14px; cursor: not-allowed;
          transition: background 0.18s ease, border-color 0.18s ease;
        }
        .sx-sso svg { transition: color 0.18s ease; }
        .sx-sso:hover { background: var(--sx-input); border-color: #3A4D63; }
        .sx-sso:hover svg { color: var(--sx-blue); }

        .sx-footer {
          display: flex; align-items: flex-start; gap: 9px; font-size: 12px; color: var(--sx-dim);
          margin-top: 24px; line-height: 1.6;
        }
        .sx-footer svg { flex-shrink: 0; margin-top: 2px; }

        .sx-copyright { text-align: center; font-size: 12px; color: var(--sx-disabled); margin-top: 40px; }

        .sx-input:focus {
          border-color: var(--sx-blue) !important;
          box-shadow: 0 0 0 3px rgba(59,156,255,0.12);
        }
        .sx-input::placeholder { color: #64748B; }

        @media (prefers-reduced-motion: no-preference) {
          .sx-ring { animation: sx-ring-pulse 3s ease-out infinite; transform-box: fill-box; transform-origin: center; }
          .sx-dot { animation: sx-dot-pulse 2.4s ease-in-out infinite; }
          .sx-shield-pulse { animation: sx-shield-breathe 3.6s ease-in-out infinite; }
          .sx-online-dot { animation: sx-online-pulse 2s ease-in-out infinite; }

          .sx-page-enter { animation: sx-page-in 600ms ease-out both; }
          .sx-logo-in { animation: sx-logo-pop 650ms cubic-bezier(0.22, 1, 0.36, 1) both; }
          .sx-logo-text-in { animation: sx-fade-in 500ms ease-out 120ms both; }
          .sx-card-enter { animation: sx-card-in 600ms cubic-bezier(0.22, 1, 0.36, 1) both; }
          .sx-stagger { animation: sx-stagger-in 450ms cubic-bezier(0.22, 1, 0.36, 1) both; }
          .sx-feature { animation: sx-feature-in 500ms ease-out both; }

          .sx-net-node { animation: sx-net-drift var(--dur, 20s) ease-in-out infinite alternate; }
          .sx-net-line { animation: sx-net-line-fade var(--dur, 10s) ease-in-out infinite alternate; }
          .sx-bg-glow { animation: sx-bg-drift 18s ease-in-out infinite alternate; }
        }
        @media (prefers-reduced-motion: reduce) {
          .sx-net-node, .sx-net-line { opacity: 0.15; }
        }

        @keyframes sx-dot-pulse {
          0%, 100% { r: var(--r, 3); opacity: 1; }
          50% { r: var(--r-p, 5); opacity: 0.5; }
        }
        @keyframes sx-ring-pulse {
          0% { transform: scale(0.8); opacity: 0.35; }
          100% { transform: scale(1.4); opacity: 0; }
        }
        @keyframes sx-shield-breathe {
          0%, 100% { transform: scale(1); opacity: 0.85; }
          50% { transform: scale(1.03); opacity: 1; }
        }
        @keyframes sx-online-pulse {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
        @keyframes sx-spin { to { transform: rotate(360deg); } }

        @keyframes sx-page-in {
          from { opacity: 0; transform: translateY(12px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes sx-fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes sx-logo-pop {
          from { opacity: 0; transform: scale(0.92); filter: drop-shadow(0 0 0 rgba(59,156,255,0)); }
          to { opacity: 1; transform: scale(1); filter: drop-shadow(0 0 6px rgba(59,156,255,0.35)); }
        }
        @keyframes sx-card-in {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes sx-stagger-in {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes sx-feature-in {
          from { opacity: 0; transform: translateX(-10px); }
          to { opacity: 1; transform: translateX(0); }
        }
        @keyframes sx-net-drift {
          from { transform: translate(0, 0); }
          to { transform: translate(var(--dx, 6px), var(--dy, 4px)); }
        }
        @keyframes sx-net-line-fade {
          0%, 100% { opacity: 0.1; }
          50% { opacity: 0.3; }
        }
        @keyframes sx-bg-drift {
          from { transform: translate(-2%, -2%) scale(1); }
          to { transform: translate(2%, 2%) scale(1.03); }
        }

        @media (max-width: 1180px) {
          .sx-hero { grid-template-columns: 1fr 320px; }
          .sx-graphic { display: none; }
        }
        @media (max-width: 900px) {
          .sx-hero { grid-template-columns: 1fr; }
          .sx-graphic { display: flex; order: 1; margin: 8px 0 4px; }
          .sx-content { order: 0; }
          .sx-card { order: 2; }
          .sx-features { display: none; }

          /* Lighter background motion on small screens - keeps entrance/focus/hover feedback,
             drops the ambient decoration that costs battery without adding legibility. */
          .sx-net-bg { opacity: 0.12; }
          .sx-net-node, .sx-net-line, .sx-bg-glow { animation: none; }
          .sx-ring { animation: none; opacity: 0.2; }
        }
        @media (max-width: 640px) {
          .sx-page { padding: 28px 16px; }
          .sx-card { padding: 30px 20px; }
          .sx-heading { font-size: 30px; }
          .sx-brand-name { font-size: 19px; }
        }
      ` }} />
    </main>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="sx-field-label">
      {label}
      <div style={{ position: "relative", marginTop: 6 }}>{children}</div>
    </label>
  );
}

function EngineStatus({ health }: { health: HealthResponse | "unreachable" | null }) {
  if (health === "unreachable") {
    return (
      <div className="sx-status">
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--sx-dim)" }} />
        Detection engine unreachable
      </div>
    );
  }
  if (!health) {
    return (
      <div className="sx-status">
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--sx-dim)" }} />
        Checking engine status…
      </div>
    );
  }
  const trainedCount = Object.values(health.trained).filter(Boolean).length;
  const moduleCount = Object.keys(health.trained).length;
  return (
    <div className="sx-status">
      <span className="sx-online-dot" style={{ background: "var(--sx-green)" }} />
      <span style={{ color: "var(--sx-green)" }}>Engine online</span>
      <span className="sx-status-sep">|</span>
      {moduleCount} detectors active
      <span className="sx-status-sep">|</span>
      {trainedCount} model-trained
    </div>
  );
}

// Ambient network motif for the page backdrop - deliberately quiet (low opacity, very slow
// drift) so it reads as texture rather than competing with the form for attention. Reduced-motion
// users get a static render (see the no-preference gate around .sx-net-node / .sx-net-line).
const NET_NODES = [
  { x: 8, y: 10, dx: 5, dy: -3, dur: 21 }, { x: 28, y: 22, dx: -4, dy: 4, dur: 24 },
  { x: 50, y: 8, dx: 3, dy: 5, dur: 19 }, { x: 70, y: 18, dx: -5, dy: -4, dur: 26 },
  { x: 90, y: 12, dx: 4, dy: 3, dur: 22 }, { x: 15, y: 45, dx: -3, dy: -5, dur: 25 },
  { x: 40, y: 50, dx: 5, dy: 2, dur: 20 }, { x: 62, y: 42, dx: -4, dy: 4, dur: 23 },
  { x: 85, y: 48, dx: 3, dy: -4, dur: 18 }, { x: 50, y: 30, dx: -3, dy: 3, dur: 27 },
];
const NET_LINES = [
  [0, 1], [1, 2], [2, 3], [3, 4], [0, 5], [1, 9], [9, 2], [9, 6], [5, 6], [6, 7], [7, 8], [3, 9], [7, 3],
];

function NetworkBackground() {
  return (
    <svg aria-hidden className="sx-net-bg" viewBox="0 0 100 60" preserveAspectRatio="none">
      {NET_LINES.map(([a, b], i) => {
        const n1 = NET_NODES[a], n2 = NET_NODES[b];
        return (
          <line
            key={i} className="sx-net-line" x1={n1.x} y1={n1.y} x2={n2.x} y2={n2.y}
            stroke="var(--sx-blue)" strokeWidth="0.12"
            style={{ "--dur": `${(n1.dur + n2.dur) / 2}s` } as React.CSSProperties}
          />
        );
      })}
      {NET_NODES.map((n, i) => (
        <circle
          key={i} className="sx-net-node" cx={n.x} cy={n.y} r="0.6" fill="var(--sx-blue)"
          style={{ "--dur": `${n.dur}s`, "--dx": `${n.dx}px`, "--dy": `${n.dy}px` } as React.CSSProperties}
        />
      ))}
    </svg>
  );
}

// Nodes/edges standing in for a monitored global network, layered behind the shield mark - a
// bespoke motif tied to what this product actually watches. Reduced-motion users get a static
// render (see the sx-ring / sx-dot animation gate above).
function ShieldGlobe() {
  const dots = [
    { x: 46, y: 54, r: 3.5, color: "var(--sx-red, #EF4444)" },
    { x: 250, y: 34, r: 3, color: "var(--sx-amber, #F59E0B)" },
    { x: 278, y: 168, r: 3.5, color: "var(--sx-blue)" },
    { x: 30, y: 190, r: 3, color: "var(--sx-purple)" },
    { x: 160, y: 14, r: 2.5, color: "var(--sx-cyan)" },
  ];
  return (
    <div className="sx-graphic" style={{ position: "relative", width: 300, height: 300 }}>
      <div
        aria-hidden
        style={{
          position: "absolute", inset: 0, borderRadius: "50%",
          backgroundImage: "radial-gradient(rgba(59,156,255,0.35) 1px, transparent 1px)",
          backgroundSize: "13px 13px",
          maskImage: "radial-gradient(closest-side, black 55%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(closest-side, black 55%, transparent 100%)",
          opacity: 0.5,
        }}
      />
      <svg aria-hidden width="300" height="300" viewBox="0 0 300 300" style={{ position: "relative" }}>
        {dots.map((d, i) => (
          <path key={`arc-${i}`} d={`M ${d.x} ${d.y} Q 150 150 150 150`} stroke={d.color} strokeWidth="1" fill="none" opacity="0.3" strokeDasharray="2 4" />
        ))}
        {dots.map((d, i) => (
          <circle
            key={i} cx={d.x} cy={d.y} r={d.r} fill={d.color} className="sx-dot"
            style={{ "--r": d.r, "--r-p": d.r + 2 } as React.CSSProperties}
          />
        ))}

        <circle cx="150" cy="150" r="70" stroke="var(--sx-blue)" strokeWidth="1" fill="none" opacity="0.4" className="sx-ring" />
        <circle cx="150" cy="150" r="54" stroke="var(--sx-cyan)" strokeWidth="1" fill="none" opacity="0.3" />

        <defs>
          <linearGradient id="sx-shield-grad-graphic" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--sx-blue-bright)" />
            <stop offset="100%" stopColor="var(--sx-blue-deep)" />
          </linearGradient>
        </defs>
        <g className="sx-shield-pulse" style={{ transformOrigin: "150px 156px" }}>
          <path
            d="M150 100 L192 116 V154 C192 184 174 204 150 212 C126 204 108 184 108 154 V116 Z"
            fill="url(#sx-shield-grad-graphic)" fillOpacity="0.9" stroke="var(--sx-blue-bright)" strokeWidth="2"
          />
          <text x="150" y="168" textAnchor="middle" fontFamily="Inter, sans-serif" fontWeight={800} fontSize="34" fill="#F3F6FA">S</text>
        </g>
      </svg>
    </div>
  );
}

function Mark({ id, size = 28, className }: { id: string; size?: number; className?: string }) {
  const gradId = `sx-shield-grad-${id}`;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#58AEFF" />
          <stop offset="100%" stopColor="#1769D2" />
        </linearGradient>
      </defs>
      <path d="M12 2.2 20 5.4v6.2c0 5.3-3.3 9.1-8 10.6-4.7-1.5-8-5.3-8-10.6V5.4Z" fill={`url(#${gradId})`} stroke="#58AEFF" strokeWidth="0.6" />
      <text x="12" y="16.2" textAnchor="middle" fontFamily="Inter, sans-serif" fontWeight={800} fontSize="11" fill="#F3F6FA">S</text>
    </svg>
  );
}

function MailIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

function LockOutlineIcon() {
  return (
    <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

function EyeIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function EyeOffIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.3 20.3 0 0 1 5.06-5.94M9.9 4.24A10.4 10.4 0 0 1 12 4c7 0 11 8 11 8a20.3 20.3 0 0 1-3.22 4.44M14.12 14.12a3 3 0 1 1-4.24-4.24" />
      <path d="M1 1l22 22" />
    </svg>
  );
}

function ActivityIcon() {
  return (
    <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}

function BrainIcon() {
  return (
    <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.5 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3.5 3.5 0 0 0 1 6.8A3 3 0 0 0 9.5 21a3 3 0 0 0 3-3V6a3 3 0 0 0-3-3Z" />
      <path d="M14.5 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3.5 3.5 0 0 1-1 6.8A3 3 0 0 1 14.5 21a3 3 0 0 1-3-3V6a3 3 0 0 1 3-3Z" />
    </svg>
  );
}

function ShieldCheckIcon() {
  return (
    <svg width={17} height={17} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3 20 6v6c0 5-3.4 8.4-8 9-4.6-.6-8-4-8-9V6Z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 3 2 20h20L12 3ZM12 10v5M12 18v.01" />
    </svg>
  );
}

function ArrowRightIcon() {
  return (
    <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round">
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

function Spinner() {
  return (
    <svg width={14} height={14} viewBox="0 0 24 24" fill="none" style={{ animation: "sx-spin 0.7s linear infinite" }}>
      <circle cx="12" cy="12" r="9" stroke="rgba(255,255,255,0.35)" strokeWidth={3} />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="#fff" strokeWidth={3} strokeLinecap="round" />
    </svg>
  );
}

const inputStyle: React.CSSProperties = {
  display: "block", width: "100%", height: 48, padding: "0 14px 0 40px",
  background: "var(--sx-input)", border: "1px solid var(--sx-input-border)", borderRadius: 8,
  color: "var(--sx-text)", fontSize: 14, outline: "none", transition: "border-color 0.18s ease, box-shadow 0.18s ease",
};
