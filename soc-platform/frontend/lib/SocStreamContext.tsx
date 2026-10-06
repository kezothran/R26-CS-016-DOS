"use client";

import { createContext, useContext, useEffect, useRef, useState } from "react";
import { wsUrl } from "./api";
import { getToken } from "./auth";
import type { SocState } from "./types";

interface SocStreamValue {
  state: SocState | null;
  connected: boolean;
}

const SocStreamCtx = createContext<SocStreamValue>({ state: null, connected: false });

export function SocStreamProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<SocState | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const token = getToken();
    if (!token) return;

    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      if (cancelled) return;
      const ws = new WebSocket(wsUrl(token));
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!cancelled) retryTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (event) => {
        try {
          setState(JSON.parse(event.data));
        } catch {
          /* ignore malformed frame */
        }
      };
    };

    connect();
    return () => {
      cancelled = true;
      clearTimeout(retryTimer);
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-attack", state?.active_attack_type ?? "none");
  }, [state?.active_attack_type]);

  useEffect(() => {
    document.documentElement.setAttribute("data-security-tier", (state?.security?.tier ?? "normal").toLowerCase());
  }, [state?.security?.tier]);

  return <SocStreamCtx.Provider value={{ state, connected }}>{children}</SocStreamCtx.Provider>;
}

export function useSocStream() {
  return useContext(SocStreamCtx);
}
