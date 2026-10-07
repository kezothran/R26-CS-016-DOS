"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { canWrite, clearSession, getRole, getToken, isAdmin } from "@/lib/auth";
import { SocStreamProvider, useSocStream } from "@/lib/SocStreamContext";
import { severityColor, themeFor } from "@/lib/theme";
import type { ActiveIncident } from "@/lib/types";

const NAV_ICON_PATHS: Record<string, string> = {
  overview: "M3 3h7v7H3V3ZM14 3h7v7h-7V3ZM3 14h7v7H3v-7ZM14 14h7v7h-7v-7",
  incidents: "M12 3 2 20h20L12 3ZM12 10v5M12 18v.01",
  metrics: "M3 20h18M6 20V10M12 20V4M18 20v-7",
  whitelist: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM9 12l2 2 4-4",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-1c.6.5 1.3.9 2 1.2L10 21h4l.5-2.6c.7-.3 1.4-.7 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z",
  users: "M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M17 11a3 3 0 1 0 0-6M21 20c0-2.5-1.6-4.6-4-5.4",
  playbooks: "M8 6h13M8 12h13M8 18h13M3 6l1 1 2-2M3 12l1 1 2-2M3 18l1 1 2-2",
  map: "M12 21s-7-6.2-7-11a7 7 0 0 1 14 0c0 4.8-7 11-7 11ZM12 12a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z",
  tickets: "M3 9a2 2 0 0 0 0 6v3h18v-3a2 2 0 0 1 0-6V6H3v3ZM13 6v12",
  security: "M12 3l7 3v5c0 5-3.2 8.4-7 10-3.8-1.6-7-5-7-10V6l7-3ZM12 11v3M10 11h4",
  notifications: "M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9ZM13.7 21a2 2 0 0 1-3.4 0",
  health: "M22 12h-4l-3 9L9 3l-3 9H2",
  live: "M2 12h4l2-7 4 14 2-7h4l2-4",
  snapshots: "M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2ZM12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z",
};

const NAV = [
  { href: "/dashboard", label: "Overview", icon: "overview" },
  { href: "/dashboard/live", label: "Live Traffic", icon: "live" },
  { href: "/dashboard/incidents", label: "Incidents", icon: "incidents" },
  { href: "/dashboard/map", label: "Attack Map", icon: "map" },
  { href: "/dashboard/tickets", label: "Tickets", icon: "tickets" },
  { href: "/dashboard/playbooks", label: "Playbooks", icon: "playbooks" },
  { href: "/dashboard/snapshots", label: "Snapshots", icon: "snapshots" },
  { href: "/dashboard/metrics", label: "Metrics", icon: "metrics" },
  { href: "/dashboard/health", label: "Health", icon: "health" },
  { href: "/dashboard/whitelist", label: "Whitelist", icon: "whitelist" },
  { href: "/dashboard/settings", label: "Settings", icon: "settings", writeOnly: true },
  { href: "/dashboard/notifications", label: "Notifications", icon: "notifications", adminOnly: true },
  { href: "/dashboard/security", label: "Security", icon: "security" },
  { href: "/dashboard/users", label: "Users", icon: "users", adminOnly: true },
];

function NavIcon({ name }: { name: string }) {
  return (
    <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d={NAV_ICON_PATHS[name]} />
    </svg>
  );
}

// Same shield mark as the login page (app/login/page.tsx's <Mark>) - duplicated rather than
// shared since there's no components/ dir yet in this app and it's a single small SVG.
function SentrixMark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" style={{ flexShrink: 0 }}>
      <defs>
        <linearGradient id="sentrix-mark-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#58AEFF" />
          <stop offset="100%" stopColor="#1769D2" />
        </linearGradient>
      </defs>
      <path d="M12 2.2 20 5.4v6.2c0 5.3-3.3 9.1-8 10.6-4.7-1.5-8-5.3-8-10.6V5.4Z" fill="url(#sentrix-mark-grad)" stroke="#58AEFF" strokeWidth="0.6" />
      <text x="12" y="16.2" textAnchor="middle" fontFamily="Inter, sans-serif" fontWeight={800} fontSize="11" fill="#F3F6FA">S</text>
    </svg>
  );
}

// The dark navy/network world-map photo (public/dashboard-bg.jpg) plus its dark overlay is all
// drawn by the .dash-bg CSS class (globals.css) - this is just the fixed, full-viewport element
// that class attaches to, sitting behind the sidebar/topbar/content (see the root layout below).
function DashboardBackground() {
  return <div className="dash-bg" aria-hidden />;
}

const ROLE_LABEL: Record<string, string> = {
  admin: "Super Administrator",
  analyst: "Security Analyst",
  viewer: "Read-Only Viewer",
};

function LiveStatus() {
  const { connected } = useSocStream();
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10, color: "var(--dim)", marginTop: 8, textTransform: "uppercase", letterSpacing: "0.07em" }}>
      <span className="live-dot" style={{ background: connected ? "var(--green)" : "var(--dim)" }} />
      {connected ? "Live feed" : "Offline"}
    </div>
  );
}

function LiveClock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  // Renders nothing until mounted so server/client markup match (no clock on the server).
  return (
    <div style={{ textAlign: "right", lineHeight: 1.35, minWidth: 90 }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", fontWeight: 600 }}>
        {now ? now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}
      </div>
      <div style={{ fontSize: 10, color: "var(--dim)" }}>
        {now ? now.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" }) : ""}
      </div>
    </div>
  );
}

function NotificationBell() {
  const { state } = useSocStream();
  const incidents = state?.security?.active_incidents ?? [];
  const count = incidents.length;
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        title={`${count} active incident${count === 1 ? "" : "s"}`}
        style={{
          position: "relative", background: "transparent", border: "none", cursor: "pointer", padding: 4,
          color: count > 0 ? "var(--red)" : "var(--muted)", display: "flex",
        }}
      >
        <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 8a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6Z" />
          <path d="M9.5 18a2.5 2.5 0 0 0 5 0" />
        </svg>
        {count > 0 && (
          <span
            style={{
              position: "absolute", top: -2, right: -3, background: "var(--red)", color: "#fff", fontSize: 9, fontWeight: 700,
              borderRadius: 8, minWidth: 15, height: 15, display: "flex", alignItems: "center", justifyContent: "center", padding: "0 3px",
            }}
          >
            {count}
          </span>
        )}
      </button>

      {open && (
        <div
          className="fade-in-up"
          style={{
            position: "absolute", top: "calc(100% + 10px)", right: 0, width: 340, maxHeight: 400, overflowY: "auto",
            background: "var(--surf)", border: "1px solid var(--border)", borderRadius: 10, boxShadow: "var(--shadow-card)", zIndex: 20,
          }}
        >
          <div style={{ padding: "12px 14px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--muted)" }}>Alerts</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{count} active</span>
          </div>

          {count === 0 ? (
            <div style={{ padding: 20, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>No active incidents</div>
          ) : (
            <div>
              {incidents.map((inc) => (
                <AlertRow key={inc.incident_id} incident={inc} onNavigate={() => setOpen(false)} />
              ))}
            </div>
          )}

          <Link
            href="/dashboard/incidents"
            onClick={() => setOpen(false)}
            style={{
              display: "block", textAlign: "center", padding: "10px 14px", fontSize: 11, color: "var(--blue)",
              borderTop: "1px solid var(--border)",
            }}
          >
            View all incidents
          </Link>
        </div>
      )}
    </div>
  );
}

function AlertRow({ incident, onNavigate }: { incident: ActiveIncident; onNavigate: () => void }) {
  const color = severityColor(incident.tier);
  return (
    <Link
      href="/dashboard/incidents"
      onClick={onNavigate}
      style={{ display: "block", padding: "10px 14px", borderBottom: "1px solid var(--raised)", color: "inherit" }}
      className="row-hover"
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 4 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text)" }}>
          {incident.attack_types.map((t) => themeFor(t).label).join(" + ")}
        </span>
        <span
          style={{
            fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 20, color,
            background: `${color}1f`, border: `1px solid ${color}40`, textTransform: "uppercase", letterSpacing: "0.04em",
          }}
        >
          {incident.tier}
        </span>
      </div>
      <div style={{ fontSize: 11, color: "var(--muted)", fontFamily: "var(--mono)" }}>{incident.src_ips.join(", ")}</div>
      <div style={{ fontSize: 10, color: "var(--dim)", marginTop: 3 }}>
        {incident.interface} · last seen {incident.last_seen}
      </div>
    </Link>
  );
}

// Quick-jump search over the sidebar's own nav list - real navigation (not a decorative input
// that does nothing), scoped to what this app actually has a "search" over right now.
function NavSearch({ role }: { role: string | null }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const items = NAV.filter((item) => (!item.writeOnly || canWrite(role)) && (!item.adminOnly || isAdmin(role)));
  const matches = q.trim() ? items.filter((i) => i.label.toLowerCase().includes(q.trim().toLowerCase())) : [];

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  function go(href: string) {
    router.push(href);
    setQ("");
    setOpen(false);
  }

  return (
    <div ref={rootRef} style={{ position: "relative", flex: 1, maxWidth: 420 }}>
      <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "var(--dim)", display: "flex", pointerEvents: "none" }}>
        <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>
      </span>
      <input
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => { if (e.key === "Enter" && matches[0]) go(matches[0].href); if (e.key === "Escape") setOpen(false); }}
        placeholder="Search pages..."
        style={{
          width: "100%", height: 34, padding: "0 12px 0 34px", background: "var(--raised)",
          border: "1px solid var(--border)", borderRadius: 8, color: "var(--text)", fontSize: 12.5, outline: "none",
        }}
        className="transition-accent"
      />
      {open && q.trim() && (
        <div
          className="fade-in-up"
          style={{
            position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, background: "var(--surf)",
            border: "1px solid var(--border)", borderRadius: 8, boxShadow: "var(--shadow-card)", zIndex: 20, overflow: "hidden",
          }}
        >
          {matches.length === 0 ? (
            <div style={{ padding: "10px 12px", fontSize: 12, color: "var(--dim)" }}>No pages match "{q}"</div>
          ) : (
            matches.map((m) => (
              <button
                key={m.href}
                onClick={() => go(m.href)}
                className="row-hover"
                style={{
                  display: "flex", alignItems: "center", gap: 9, width: "100%", textAlign: "left",
                  padding: "9px 12px", background: "transparent", border: "none", color: "var(--text)",
                  fontSize: 12.5, cursor: "pointer",
                }}
              >
                <span style={{ color: "var(--dim)", display: "flex" }}><NavIcon name={m.icon} /></span>
                {m.label}
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function Avatar({ role }: { role: string | null }) {
  const initial = (role || "?")[0]?.toUpperCase();
  return (
    <div
      title={ROLE_LABEL[role ?? ""] ?? role ?? "Account"}
      style={{
        width: 30, height: 30, borderRadius: "50%", background: "var(--accent)", color: "#fff",
        display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12.5, fontWeight: 700, flexShrink: 0,
      }}
    >
      {initial}
    </div>
  );
}

const THEME_KEY = "soc_theme";

function SunIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />
    </svg>
  );
}

// Reads the theme the beforeInteractive script (app/layout.tsx) already applied to <html>, so
// there's nothing to guess client-side - just mirror the DOM's current state into this button.
function ThemeToggle() {
  const [theme, setTheme] = useState<"dark" | "light" | null>(null);

  useEffect(() => {
    setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");
  }, []);

  function toggle() {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    if (next === "light") document.documentElement.setAttribute("data-theme", "light");
    else document.documentElement.removeAttribute("data-theme");
    try { localStorage.setItem(THEME_KEY, next); } catch { /* private mode / storage disabled - toggle still works for this tab */ }
  }

  // Renders a same-size placeholder until mounted, so the topbar layout doesn't shift once the
  // real (theme-dependent) icon appears.
  if (theme === null) return <span style={{ width: 30, height: 30, flexShrink: 0 }} />;

  return (
    <button
      onClick={toggle}
      title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
      style={{
        width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center",
        background: "transparent", border: "1px solid var(--border)", borderRadius: 7,
        color: "var(--muted)", cursor: "pointer", flexShrink: 0,
      }}
      className="transition-accent"
    >
      {theme === "light" ? <MoonIcon /> : <SunIcon />}
    </button>
  );
}

function MenuIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6h18M3 12h18M3 18h18" />
    </svg>
  );
}

function TopBar({ role, onMenuClick }: { role: string | null; onMenuClick: () => void }) {
  return (
    <div
      className="dash-panel dash-glass dash-topbar"
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, padding: "13px 24px",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, flex: 1, minWidth: 0 }}>
        <button
          onClick={onMenuClick}
          className="mobile-menu-btn transition-accent"
          aria-label="Open menu"
          style={{
            width: 34, height: 34, alignItems: "center", justifyContent: "center", flexShrink: 0,
            background: "var(--raised)", border: "1px solid var(--border)", borderRadius: 8, color: "var(--muted)", cursor: "pointer",
          }}
        >
          <MenuIcon />
        </button>
        <div className="dash-topbar-search" style={{ flex: 1, minWidth: 0 }}>
          <NavSearch role={role} />
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 18, flexShrink: 0 }}>
        <LiveClock />
        <NotificationBell />
        <ThemeToggle />
        <Avatar role={role} />
      </div>
    </div>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);
  const [role, setRole] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Closing on route change covers both a nav-link tap and the browser back/forward buttons -
  // leaving the drawer open after either would strand it over the new page's content.
  useEffect(() => { setMobileNavOpen(false); }, [pathname]);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    setRole(getRole());
    setReady(true);
  }, [router]);

  if (!ready) return null;

  return (
    <SocStreamProvider>
      <DashboardBackground />
      <div
        className={`mobile-nav-scrim${mobileNavOpen ? " open" : ""}`}
        onClick={() => setMobileNavOpen(false)}
      />
      <div style={{ display: "flex", minHeight: "100vh", position: "relative", zIndex: 1 }}>
        <nav
          className={`dash-panel dash-glass dash-sidebar${mobileNavOpen ? " open" : ""}`}
          style={{
            width: 216, flexShrink: 0, borderRight: "1px solid var(--border)",
            display: "flex", flexDirection: "column", height: "100vh", position: "fixed", top: 0, left: 0,
          }}
        >
          <div style={{ padding: "20px 18px", borderBottom: "1px solid var(--border)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <SentrixMark size={26} />
              <div>
                <div style={{ fontWeight: 700, fontSize: 14, letterSpacing: "-0.01em" }}>SENTRIX</div>
                <div style={{ fontSize: 9.5, color: "var(--dim)" }}>Security Operations Console</div>
              </div>
            </div>
            <LiveStatus />
          </div>

          <div style={{ padding: "10px 10px", flex: 1 }}>
            {NAV.filter((item) => (!item.writeOnly || canWrite(role)) && (!item.adminOnly || isAdmin(role))).map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", fontSize: 13, fontWeight: 500,
                    borderRadius: 8, marginBottom: 2,
                    color: active ? "#ffffff" : "var(--muted)",
                    background: active ? "var(--accent)" : "transparent",
                    boxShadow: active ? "0 0 16px -3px rgba(34,197,94,.6), inset 0 0 0 1px rgba(255,255,255,.08)" : "none",
                  }}
                  className={active ? "transition-accent" : "transition-accent nav-link"}
                >
                  <span style={{ color: active ? "#ffffff" : "var(--dim)", display: "flex" }}>
                    <NavIcon name={item.icon} />
                  </span>
                  {item.label}
                </Link>
              );
            })}
          </div>

          <div style={{ padding: "14px 16px", borderTop: "1px solid var(--border)", fontSize: 11, color: "var(--dim)" }}>
            <div style={{ marginBottom: 10, display: "flex", alignItems: "center", gap: 9 }}>
              <Avatar role={role} />
              <div style={{ minWidth: 0 }}>
                <div style={{ color: "var(--text)", fontWeight: 700, fontSize: 12.5, textTransform: "capitalize" }}>{role}</div>
                <div style={{ color: "var(--dim)", fontSize: 10.5, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {ROLE_LABEL[role ?? ""] ?? "Account"}
                </div>
              </div>
            </div>
            <button
              onClick={() => {
                clearSession();
                router.replace("/login");
              }}
              style={{
                width: "100%", background: "transparent", border: "1px solid var(--border)", color: "var(--muted)",
                borderRadius: 6, padding: "6px 10px", fontSize: 11, cursor: "pointer",
              }}
              className="transition-accent"
            >
              Log out
            </button>
          </div>
        </nav>

        <div className="dash-content" style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          <TopBar role={role} onMenuClick={() => setMobileNavOpen((o) => !o)} />
          <main className="dash-main" style={{ flex: 1, padding: 24, minWidth: 0, marginTop: 60 }}>{children}</main>
        </div>
      </div>
    </SocStreamProvider>
  );
}
