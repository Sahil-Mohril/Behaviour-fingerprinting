import type { ReactNode } from "react";
import { X } from "lucide-react";
import { SEVERITY_STYLE, categoryColor } from "../lib/colors";
import { useLive } from "../lib/store";

export function Card({ title, actions, children, className = "", bodyClass = "p-4" }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={`card min-w-0 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-medium text-ink">{title}</h2>
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="label">{label}</div>
      <div className="mt-1 text-2xl font-semibold" style={tone ? { color: tone } : undefined}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY_STYLE[severity] ?? SEVERITY_STYLE.info;
  return (
    <span className="chip font-medium" style={{ color: s.color, borderColor: s.color }}>
      <span aria-hidden>{s.icon}</span>{severity}
    </span>
  );
}

export function CategoryChip({ category, name }: { category: string; name?: string }) {
  return (
    <span className="chip">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: categoryColor(category) }} />
      <span className="text-ink2">{name ?? category.replace(/_/g, " ")}</span>
    </span>
  );
}

export function StatusChip({ status }: { status: string }) {
  const tone: Record<string, string> = {
    active: "var(--good)", suggested: "var(--warning)", approved: "var(--accent)", expired: "var(--text-muted)",
    rejected: "var(--critical)", candidate: "var(--warning)", dismissed: "var(--text-muted)", open: "var(--serious)",
    acknowledged: "var(--accent)", resolved: "var(--good)", running: "var(--good)", paused: "var(--warning)",
    finished: "var(--text-muted)", idle: "var(--text-muted)",
  };
  return <span className="chip" style={{ color: tone[status] ?? "var(--text-secondary)" }}>{status}</span>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="flex min-h-[120px] items-center justify-center px-4 text-center text-sm text-muted">{children}</div>;
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className={`card max-h-[90vh] w-full overflow-auto ${wide ? "max-w-4xl" : "max-w-lg"}`} onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h3 className="font-medium">{title}</h3>
          <button className="text-muted hover:text-ink" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

export function Toasts() {
  const { toasts } = useLive();
  return (
    <div className="fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
      {toasts.map((t) => (
        <div key={t.id} className="card px-3 py-2 text-sm shadow-lg"
          style={{ borderColor: t.kind === "error" ? "var(--critical)" : "var(--good)" }}>
          {t.kind === "error" ? "⚠ " : "✓ "}{t.msg}
        </div>
      ))}
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-muted">{hint}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange }:
  { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-surface2 p-0.5">
      {options.map((o) => (
        <button key={o.value} onClick={() => onChange(o.value)}
          className={`rounded-md px-2.5 py-1 text-xs ${value === o.value ? "bg-accent text-white" : "text-ink2 hover:text-ink"}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function ChartTooltip({ active, payload, label, labelFmt, valueFmt }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="card px-3 py-2 text-xs shadow-xl">
      {label !== undefined && <div className="mb-1 font-medium text-ink">{labelFmt ? labelFmt(label) : label}</div>}
      {payload.filter((p: any) => p.value !== 0 && p.value !== undefined).map((p: any) => (
        <div key={p.dataKey ?? p.name} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-ink2">
            <span className="inline-block h-2 w-2 rounded-sm" style={{ background: p.color ?? p.fill }} />{p.name}
          </span>
          <span className="tabular text-ink">{valueFmt ? valueFmt(p.value) : p.value}</span>
        </div>
      ))}
    </div>
  );
}
