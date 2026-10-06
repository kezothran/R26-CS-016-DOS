"use client";

// The JWT is kept in localStorage (not an httpOnly cookie) so the client-side WebSocket hook can
// attach it as a query param without a server-side proxy - see README "Security notes" for the
// tradeoff this implies (readable by any JS on the page, i.e. no protection if an XSS bug is
// ever introduced). Acceptable for this milestone; revisit if the app grows third-party scripts.
const TOKEN_KEY = "soc_token";
const ROLE_KEY = "soc_role";

// "Remember me" unchecked -> sessionStorage (cleared when the tab/browser closes) instead of
// localStorage. getToken/getRole check both so a session started either way keeps working.
export function setSession(token: string, role: string, remember: boolean = true) {
  const store = remember ? localStorage : sessionStorage;
  store.setItem(TOKEN_KEY, token);
  store.setItem(ROLE_KEY, role);
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(ROLE_KEY);
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(TOKEN_KEY) || localStorage.getItem(TOKEN_KEY);
}

export function getRole(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(ROLE_KEY) || localStorage.getItem(ROLE_KEY);
}

export function canWrite(role: string | null): boolean {
  return role === "admin" || role === "analyst";
}

// Stricter than canWrite (which also allows analyst) - gates User & Access Management, the one
// area where "analyst" shouldn't have write access (analysts can be granted/edited but
// shouldn't grant/edit others).
export function isAdmin(role: string | null): boolean {
  return role === "admin";
}
