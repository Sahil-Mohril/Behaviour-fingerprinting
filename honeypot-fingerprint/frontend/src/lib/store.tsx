import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./api";
import type { Alert, EventRow, FingerprintSummary, Kpis, Marker, Narration, ReplayStatus, Rule, SeriesPoint } from "./types";

const MAX_EVENTS = 3000;
const MAX_SERIES = 900;

interface LiveState {
  connected: boolean;
  status: ReplayStatus | null;
  kpis: Kpis | null;
  series: SeriesPoint[];
  events: EventRow[];
  alerts: Record<string, Alert>;
  fingerprints: Record<string, FingerprintSummary>;
  rules: Record<string, Rule>;
  narration: Narration[];
  markers: Marker[];
  version: number;
}

interface Ctx extends LiveState {
  refresh: () => Promise<void>;
  setStatus: (s: ReplayStatus) => void;
  toast: (msg: string, kind?: "ok" | "error") => void;
  toasts: { id: number; msg: string; kind: string }[];
}

const LiveCtx = createContext<Ctx | null>(null);

function mergeSeries(prev: SeriesPoint[], incoming: SeriesPoint[]): SeriesPoint[] {
  if (!incoming.length) return prev;
  const map = new Map(prev.map((p) => [p.t, p]));
  for (const p of incoming) map.set(p.t, p);
  const out = [...map.values()].sort((a, b) => a.t - b.t);
  return out.length > MAX_SERIES ? out.slice(-MAX_SERIES) : out;
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>({
    connected: false, status: null, kpis: null, series: [], events: [], alerts: {}, fingerprints: {}, rules: {},
    narration: [], markers: [], version: 0,
  });
  const [toasts, setToasts] = useState<{ id: number; msg: string; kind: string }[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  const toast = useCallback((msg: string, kind: "ok" | "error" = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);

  const refresh = useCallback(async () => {
    const [ov, alerts, fps, rules] = await Promise.all([
      api.get<any>("/api/metrics/overview?seconds=900"),
      api.get<Alert[]>("/api/alerts?limit=1000"),
      api.get<FingerprintSummary[]>("/api/fingerprints"),
      api.get<Rule[]>("/api/rules"),
    ]);
    setState((s) => ({
      ...s, status: ov.status, kpis: ov.kpis, series: ov.series, markers: ov.markers, narration: ov.narration,
      events: [...ov.recent].reverse(),
      alerts: Object.fromEntries(alerts.map((a) => [a.id, a])),
      fingerprints: Object.fromEntries(fps.map((f) => [f.id, f])),
      rules: Object.fromEntries(rules.map((r) => [r.id, r])),
      version: s.version + 1,
    }));
  }, []);

  useEffect(() => {
    let stopped = false;
    let retry: ReturnType<typeof setTimeout>;
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws`);
      wsRef.current = ws;
      ws.onopen = () => {
        setState((s) => ({ ...s, connected: true }));
        refresh().catch(() => undefined);
      };
      ws.onclose = () => {
        setState((s) => ({ ...s, connected: false }));
        if (!stopped) retry = setTimeout(connect, 1500);
      };
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data);
        if (msg.type !== "tick") return;
        // one batched state update per tick (~4/s) regardless of event volume
        setState((s) => {
          const events = msg.events.length
            ? [...msg.events.slice().reverse(), ...s.events].slice(0, MAX_EVENTS)
            : s.events;
          const alerts = msg.alerts.length ? { ...s.alerts } : s.alerts;
          for (const a of msg.alerts) alerts[a.id] = a;
          const fingerprints = msg.fingerprints.length ? { ...s.fingerprints } : s.fingerprints;
          for (const f of msg.fingerprints) fingerprints[f.id] = { ...fingerprints[f.id], ...f };
          const rules = msg.rules.length ? { ...s.rules } : s.rules;
          for (const r of msg.rules) rules[r.id] = r;
          return {
            ...s, status: msg.status, kpis: msg.kpis, series: mergeSeries(s.series, msg.series), events, alerts,
            fingerprints, rules,
            narration: msg.narration.length ? [...s.narration, ...msg.narration].slice(-200) : s.narration,
            markers: msg.markers.length ? [...s.markers, ...msg.markers].slice(-200) : s.markers,
            version: s.version + 1,
          };
        });
      };
    };
    connect();
    return () => {
      stopped = true;
      clearTimeout(retry);
      wsRef.current?.close();
    };
  }, [refresh]);

  const setStatus = useCallback((st: ReplayStatus) => setState((s) => ({ ...s, status: st })), []);

  return <LiveCtx.Provider value={{ ...state, refresh, setStatus, toast, toasts }}>{children}</LiveCtx.Provider>;
}

export function useLive(): Ctx {
  const c = useContext(LiveCtx);
  if (!c) throw new Error("useLive outside provider");
  return c;
}

/** Run an API action with toast feedback. */
export function useAction() {
  const { toast, refresh } = useLive();
  return useCallback(
    async <T,>(fn: () => Promise<T>, ok?: string, doRefresh = true): Promise<T | undefined> => {
      try {
        const r = await fn();
        if (ok) toast(ok);
        if (doRefresh) refresh().catch(() => undefined);
        return r;
      } catch (e) {
        toast((e as Error).message, "error");
        return undefined;
      }
    },
    [toast, refresh],
  );
}
