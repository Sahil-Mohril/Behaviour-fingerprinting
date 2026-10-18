import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { Activity, BarChart3, Bell, Fingerprint, Moon, Play, Settings, Shield, Sun } from "lucide-react";
import { useLive } from "../lib/store";
import { fmtRel } from "../lib/format";
import { StatusChip, Toasts } from "./ui";

const NAV = [
  { to: "/", label: "Replay Control", icon: Play },
  { to: "/overview", label: "Live Overview", icon: Activity },
  { to: "/fingerprints", label: "Fingerprints", icon: Fingerprint },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/rules", label: "Firewall Rules", icon: Shield },
  { to: "/evaluation", label: "Evaluation", icon: BarChart3 },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Layout() {
  const { connected, status, kpis, alerts, narration } = useLive();
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem("hfp-theme") ?? "dark"; } catch { return "dark"; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("hfp-theme", theme); } catch { /* storage unavailable */ }
  }, [theme]);
  const openAlerts = Object.values(alerts).filter((a) => a.status === "open").length;
  const last = narration[narration.length - 1];
  return (
    <div className="flex h-full">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-surface md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <Shield className="text-accent" size={22} />
          <div>
            <div className="text-sm font-semibold leading-tight">Honeypot Fingerprint</div>
            <div className="text-[11px] text-muted">behaviour SOC</div>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 px-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"}
              className={({ isActive }) => `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-surface2 text-ink" : "text-ink2 hover:bg-surface2"}`}>
              <Icon size={16} />{label}
              {label === "Alerts" && openAlerts > 0 && <span className="ml-auto rounded-full px-1.5 text-[11px] text-white" style={{ background: "var(--critical)" }}>{openAlerts}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 text-[11px] text-muted">
          Replayed data only. Firewall rules are text; enforcement is simulated in-app.
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-4 py-2">
          <span className="flex items-center gap-1.5 text-xs text-ink2">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: connected ? "var(--good)" : "var(--critical)" }} />
            {connected ? "live" : "offline"}
          </span>
          {status && <StatusChip status={status.state} />}
          {status?.plan && <span className="truncate text-xs text-ink2">{status.plan.name}</span>}
          {status && status.state !== "idle" && (
            <span className="tabular text-xs text-muted">
              {fmtRel(status.now, status.base_epoch)} / {fmtRel(status.base_epoch + status.end_t, status.base_epoch)} · {status.speed}× (eff. {status.effective_speed}×)
            </span>
          )}
          {kpis && <span className="chip">mode: {kpis.rule_mode === "auto" ? "auto-apply" : "suggest only"}</span>}
          {last && <span className="hidden min-w-0 flex-1 truncate text-xs text-ink2 lg:block" title={last.text}>› {last.text}</span>}
          <button className="btn ml-auto !px-2" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle theme">
            {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
          </button>
        </header>
        <nav className="flex gap-1 overflow-x-auto border-b border-line bg-surface px-2 py-1 md:hidden">
          {NAV.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `whitespace-nowrap rounded px-2 py-1 text-xs ${isActive ? "bg-surface2 text-ink" : "text-ink2"}`}>{label}</NavLink>
          ))}
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto px-4 py-4 md:px-6">
          <Outlet />
        </main>
      </div>
      <Toasts />
    </div>
  );
}
