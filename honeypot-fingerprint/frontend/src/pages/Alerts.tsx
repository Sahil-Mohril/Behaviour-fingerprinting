import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { useAction, useLive } from "../lib/store";
import { featureLabel, fmtRel, fmtTime } from "../lib/format";
import type { Alert } from "../lib/types";
import { Card, CategoryChip, Empty, SeverityBadge, StatusChip } from "../components/ui";

const TYPE_LABEL: Record<string, string> = {
  returning: "Returning behaviour", match: "Fingerprint match", anomaly: "Unknown anomaly", new_fingerprint: "New fingerprint",
};

export default function AlertsPage() {
  const { alerts, status } = useLive();
  const act = useAction();
  const [params] = useSearchParams();
  const [sev, setSev] = useState("");
  const [type, setType] = useState("");
  const [st, setSt] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(params.get("focus"));
  useEffect(() => { if (params.get("focus")) setOpen(params.get("focus")); }, [params]);

  const list = useMemo(() => Object.values(alerts)
    .filter((a) => (!sev || a.severity === sev) && (!type || a.type === type) && (!st || a.status === st) &&
      (!q || `${a.title} ${a.ips.join(" ")} ${a.fp_id}`.toLowerCase().includes(q.toLowerCase())))
    .sort((a, b) => b.last_seen - a.last_seen), [alerts, sev, type, st, q]);

  const setStatus = (a: Alert, action: string) =>
    act(() => api.post(`/api/alerts/${a.id}/${action}`), `${a.id} ${action === "ack" ? "acknowledged" : "resolved"}`);

  return (
    <div className="mx-auto flex max-w-[1400px] flex-col gap-4">
      <div>
        <h1 className="text-xl font-semibold">Alerts</h1>
        <p className="text-sm text-ink2">Deduplicated per fingerprint episode; severity escalates after 10 and 50 repeated hits.</p>
      </div>
      <Card title={`Feed (${list.length})`} bodyClass="p-0" actions={<>
        <input className="input w-44" placeholder="search title / IP / FP" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="input" value={type} onChange={(e) => setType(e.target.value)}><option value="">all types</option>
          {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select className="input" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">all severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select>
        <select className="input" value={st} onChange={(e) => setSt(e.target.value)}><option value="">any status</option>
          {["open", "acknowledged", "resolved"].map((s) => <option key={s}>{s}</option>)}</select></>}>
        {!list.length ? <Empty>No alerts match.</Empty> : (
          <div className="divide-y divide-[var(--line)]">
            {list.map((a) => (
              <div key={a.id} className={`px-4 py-3 ${a.type === "returning" ? "border-l-2" : ""}`}
                style={a.type === "returning" ? { borderColor: "var(--serious)" } : undefined}>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="chip">{TYPE_LABEL[a.type]}</span>
                  <button className="text-left text-sm font-medium hover:underline" onClick={() => setOpen(open === a.id ? null : a.id)}>{a.title}</button>
                  <span className="font-mono text-xs text-muted">{a.id}</span>
                  <span className="ml-auto tabular text-xs text-muted">{fmtTime(a.last_seen)} ({fmtRel(a.last_seen, status?.base_epoch)}) · ×{a.count}</span>
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-ink2">
                  <CategoryChip category={a.category} />
                  {a.score > 0 && <span className="chip tabular">score {a.score.toFixed(3)}</span>}
                  {typeof a.breakdown?.numeric === "number" && (
                    <span className="chip tabular">cos {a.breakdown.numeric.toFixed(3)} · traits {typeof a.breakdown.categorical === "number" ? a.breakdown.categorical.toFixed(3) : "n/a"}</span>)}
                  <span className="truncate">{a.ips.slice(0, 4).join(", ")}{a.ips.length > 4 ? ` +${a.ips.length - 4}` : ""}</span>
                  <StatusChip status={a.status} />
                  <span className="ml-auto flex gap-1.5">
                    {a.fp_id && <Link className="btn !py-1" to={`/fingerprints/${a.fp_id}`}>{a.fp_id}</Link>}
                    {a.rule_ids.map((r) => <Link key={r} className="btn !py-1" to={`/rules?focus=${r}`}>{r}</Link>)}
                    {a.status === "open" && <button className="btn !py-1" onClick={() => setStatus(a, "ack")}>Acknowledge</button>}
                    {a.status !== "resolved" && <button className="btn !py-1" onClick={() => setStatus(a, "resolve")}>Resolve</button>}
                  </span>
                </div>
                {open === a.id && <Why a={a} />}
              </div>
            ))}
          </div>)}
      </Card>
    </div>
  );
}

function Why({ a }: { a: Alert }) {
  const b = a.breakdown ?? {};
  const top = b.numeric_detail?.top_shared ?? [];
  const div = b.numeric_detail?.top_divergent ?? [];
  const cat = b.categorical_detail;
  return (
    <div className="mt-3 grid gap-3 rounded-lg bg-surface2 p-3 text-xs md:grid-cols-2">
      <div className="md:col-span-2">
        <div className="label mb-1">Why this matched</div>
        <p className="text-ink2">{a.explanation || "—"}</p>
      </div>
      {b.weights && (
        <div className="md:col-span-2">
          <div className="label mb-1">Score breakdown</div>
          <div className="tabular text-ink2">
            combined {Number(b.score).toFixed(3)} = {b.weights.numeric} × {Number(b.numeric).toFixed(3)} (cosine, numeric)
            {b.categorical !== null && b.categorical !== undefined
              ? <> + {b.weights.categorical} × {Number(b.categorical).toFixed(3)} (trait containment)</>
              : " (no categorical traits observable in this window)"}
            {" "}· threshold {b.threshold}
          </div>
        </div>
      )}
      {top.length > 0 && (
        <div><div className="label mb-1">Strongest shared features</div>
          {top.map((t: any) => <div key={t.feature} className="tabular text-ink2">{featureLabel(t.feature)}: live z {t.live_z} · fingerprint z {t.fp_z}</div>)}</div>)}
      {div.length > 0 && (
        <div><div className="label mb-1">Where it differs</div>
          {div.map((t: any) => <div key={t.feature} className="tabular text-ink2">{featureLabel(t.feature)}: {t.live_z} vs {t.fp_z}</div>)}</div>)}
      {cat && (
        <div className="md:col-span-2"><div className="label mb-1">Trait containment by family</div>
          <div className="flex flex-wrap gap-1">{Object.entries(cat.per_family ?? {}).map(([k, v]) => <span key={k} className="chip tabular">{k} {(v as number).toFixed(2)}</span>)}</div>
          {!!cat.shared?.length && <div className="mt-1 text-ink2">known: <span className="font-mono">{cat.shared.join("  ")}</span></div>}
          {!!cat.novel?.length && <div className="text-muted">new: <span className="font-mono">{cat.novel.join("  ")}</span></div>}
        </div>)}
      {b.category_reasons && (
        <div><div className="label mb-1">Rule-layer reasons</div>
          <ul className="list-disc pl-4 text-ink2">{b.category_reasons.map((r: string) => <li key={r}>{r}</li>)}</ul></div>)}
      {b.anomaly_score !== undefined && (
        <div><div className="label mb-1">Isolation Forest</div><div className="text-ink2">decision score {b.anomaly_score} (&lt; 0 = anomalous)</div></div>)}
      {!!a.escalations.length && (
        <div><div className="label mb-1">Escalations</div>
          {a.escalations.map((e, i) => <div key={i} className="text-ink2">{e.from} → {e.to} at ×{e.count}</div>)}</div>)}
    </div>
  );
}
