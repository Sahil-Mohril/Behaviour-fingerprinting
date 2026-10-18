import { useEffect, useMemo, useState } from "react";
import { FastForward, Pause, Play, Plus, RefreshCw, RotateCcw, Square, Trash2, Wand2 } from "lucide-react";
import { api } from "../lib/api";
import { useAction, useLive } from "../lib/store";
import { fmtNum, fmtRel, fmtTime } from "../lib/format";
import type { Behaviour, Source } from "../lib/types";
import { Card, CategoryChip, Empty, Field, StatusChip } from "../components/ui";

interface SelRow {
  source_id: string; labels: string[]; offset: number; compress: number; max_rows: number; sample_every: number;
  remap_ips: boolean; repeat: number; repeat_new_ips: boolean; label_override: string;
}
const newRow = (sid = ""): SelRow => ({ source_id: sid, labels: [], offset: 0, compress: 1, max_rows: 50000,
  sample_every: 1, remap_ips: false, repeat: 1, repeat_new_ips: false, label_override: "" });

export default function ReplayPage() {
  const { status, narration, setStatus } = useLive();
  const act = useAction();
  const [sources, setSources] = useState<Source[]>([]);
  const [catStatus, setCatStatus] = useState("…");
  const [dataDirs, setDataDirs] = useState<string[]>([]);
  const [behaviours, setBehaviours] = useState<Behaviour[]>([]);
  const [speed, setSpeed] = useState(10);
  const [ret, setRet] = useState({ source_id: "", label: "", split: 0.5, target_seconds: 60, gap: 30, fast_warmup: true, reset_learning: false });
  const [rows, setRows] = useState<SelRow[]>([]);
  const [campaigns, setCampaigns] = useState<any[]>([]);

  const loadSources = async () => {
    const r = await api.get<any>("/api/sources");
    setSources(r.sources);
    setCatStatus(r.status);
    setDataDirs(r.data_dirs);
  };
  useEffect(() => {
    loadSources().catch(() => undefined);
    api.get<Behaviour[]>("/api/behaviours").then(setBehaviours).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (catStatus !== "indexing") return;
    const t = setInterval(() => loadSources().catch(() => undefined), 1500);
    return () => clearInterval(t);
  }, [catStatus]);
  useEffect(() => {
    if (!status || status.state === "idle") return;
    api.get<any[]>("/api/replay/campaigns").then(setCampaigns).catch(() => undefined);
  }, [status?.plan?.name, status?.state]);

  const ready = sources.filter((s) => s.status === "ready");
  const retSource = ready.find((s) => s.id === ret.source_id);
  const attackLabels = retSource ? Object.entries(retSource.labels).filter(([, v]) => v.behaviour !== "benign" && v.count >= 4) : [];
  useEffect(() => {
    if (!ret.source_id && ready.length) {
      const pick = ready.find((s) => !s.fixture && Object.values(s.labels).some((l) => l.behaviour !== "benign" && l.behaviour !== "unlabelled")) ?? ready[0];
      setRet((r) => ({ ...r, source_id: pick.id }));
    }
  }, [ready.length]);
  useEffect(() => {
    if (retSource && !retSource.labels[ret.label]) setRet((r) => ({ ...r, label: attackLabels[0]?.[0] ?? "" }));
  }, [ret.source_id, sources]);

  const running = status?.state === "running";
  const paused = status?.state === "paused";
  const control = (p: string, body?: unknown) => act(async () => setStatus(await api.post(p, body)), undefined, false);
  const start = (p: string, body: unknown, msg: string) => act(async () => setStatus(await api.post(p, body)), msg);

  const nonFixture = sources.filter((s) => !s.fixture).length;
  const demoHint = useMemo(() => nonFixture ? "Uses your datasets (prefers CIC-IDS2017 SSH-Patator)." :
    "No datasets found yet: the demo will run on the bundled fixtures (looped, tiny).", [nonFixture]);

  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Replay Control</h1>
          <p className="text-sm text-ink2">Stream real honeypot logs and labelled flow datasets through the pipeline. Nothing is sent on the network.</p>
        </div>
        <div className="card flex flex-wrap items-center gap-2 px-3 py-2">
          {status && <StatusChip status={status.state} />}
          <span className="tabular text-xs text-muted">{status ? `${fmtRel(status.now, status.base_epoch)} · ${fmtNum(status.total_events - status.remaining_events)}/${fmtNum(status.total_events)} events` : ""}</span>
          <button className="btn" disabled={!running} onClick={() => control("/api/replay/pause")}><Pause size={14} />Pause</button>
          <button className="btn" disabled={!paused} onClick={() => control("/api/replay/resume")}><Play size={14} />Resume</button>
          <button className="btn" disabled={!running && !paused} onClick={() => control("/api/replay/stop")}><Square size={14} />Stop</button>
          <div className="inline-flex rounded-lg border border-line bg-surface2 p-0.5">
            {[1, 10, 100].map((s) => (
              <button key={s} className={`rounded-md px-2.5 py-1 text-xs ${status?.speed === s ? "bg-accent text-white" : "text-ink2"}`}
                onClick={() => { setSpeed(s); control("/api/replay/speed", { speed: s }); }}>{s}×</button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Scripted demo" className="xl:col-span-1"
          actions={<button className="btn btn-primary" onClick={() => start("/api/replay/demo?speed=1", undefined, "Demo started")}><Wand2 size={14} />Run demo (1×)</button>}>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-ink2">
            <li>Benign baseline from the dataset calibrates the scaler and Isolation Forest.</li>
            <li>Part A of an attack class (original IPs) streams; HDBSCAN builds a fingerprint; a rule is suggested.</li>
            <li>The operator switches to auto-apply (simulated firewall only).</li>
            <li>Part B returns from remapped IPs with timestamps shifted to now: "Returning behaviour" alert, auto-block, traffic drops.</li>
          </ol>
          <p className="mt-3 text-xs text-muted">{demoHint} Deterministic: fixed split, seed and IP remap. Resets learned state.</p>
          <button className="btn mt-3" onClick={() => start("/api/replay/demo?speed=10", undefined, "Demo started at 10×")}><FastForward size={14} />Run at 10×</button>
        </Card>

        <Card title="Returning attacker" className="xl:col-span-2"
          actions={<button className="btn btn-primary" disabled={!ret.source_id || !ret.label}
            onClick={() => start("/api/replay/returning", { ...ret, speed }, "Returning-attacker replay started")}><RotateCcw size={14} />Start</button>}>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Source">
              <select className="input" value={ret.source_id} onChange={(e) => setRet({ ...ret, source_id: e.target.value, label: "" })}>
                {ready.map((s) => <option key={s.id} value={s.id}>{s.name}{s.fixture ? " (fixture)" : ""}</option>)}
              </select>
            </Field>
            <Field label="Attack class">
              <select className="input" value={ret.label} onChange={(e) => setRet({ ...ret, label: e.target.value })}>
                {attackLabels.map(([l, v]) => <option key={l} value={l}>{l} ({fmtNum(v.count)})</option>)}
              </select>
            </Field>
            <Field label={`Split at ${Math.round(ret.split * 100)}%`} hint="Part A builds the fingerprint">
              <input type="range" min={0.1} max={0.9} step={0.05} value={ret.split} onChange={(e) => setRet({ ...ret, split: +e.target.value })} />
            </Field>
            <Field label="Part A replay length (s)">
              <input className="input" type="number" value={ret.target_seconds} onChange={(e) => setRet({ ...ret, target_seconds: +e.target.value })} />
            </Field>
            <Field label="Gap before return (s)">
              <input className="input" type="number" value={ret.gap} onChange={(e) => setRet({ ...ret, gap: +e.target.value })} />
            </Field>
            <Field label="Speed">
              <select className="input" value={speed} onChange={(e) => setSpeed(+e.target.value)}>
                {[1, 10, 100].map((s) => <option key={s} value={s}>{s}×</option>)}
              </select>
            </Field>
            <label className="flex items-center gap-2 text-sm text-ink2"><input type="checkbox" checked={ret.fast_warmup} onChange={(e) => setRet({ ...ret, fast_warmup: e.target.checked })} />Fast-forward part A</label>
            <label className="flex items-center gap-2 text-sm text-ink2"><input type="checkbox" checked={ret.reset_learning} onChange={(e) => setRet({ ...ret, reset_learning: e.target.checked })} />Reset learned fingerprints</label>
          </div>
        </Card>
      </div>

      <Card title="Custom mix" actions={<>
        <button className="btn" onClick={() => setRows([...rows, newRow(ready[0]?.id)])}><Plus size={14} />Add slice</button>
        <button className="btn btn-primary" disabled={!rows.length}
          onClick={() => start("/api/replay/custom", { name: "Custom mix", speed, selections: rows.map((r) => ({ ...r, labels: r.labels.length ? r.labels : null, label_override: r.label_override || null })) }, "Custom replay started")}>
          <Play size={14} />Start mix</button></>}>
        {!rows.length ? <Empty>Add one or more slices: pick a source, attack labels, an offset on the replay timeline and a compression factor (dataset seconds per replay second). Slices are merged in timestamp order.</Empty> : (
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Source</th><th>Labels (none = all)</th><th>Offset s</th><th>Compress</th><th>Max rows</th><th>Sample 1/N</th><th>Loop ×</th><th>Remap IPs</th><th>Label override</th><th /></tr></thead>
              <tbody>
                {rows.map((r, i) => {
                  const src = ready.find((s) => s.id === r.source_id);
                  const set = (p: Partial<SelRow>) => setRows(rows.map((x, k) => (k === i ? { ...x, ...p } : x)));
                  return (
                    <tr key={i}>
                      <td><select className="input w-48" value={r.source_id} onChange={(e) => set({ source_id: e.target.value, labels: [] })}>
                        {ready.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></td>
                      <td><select multiple className="input h-20 w-56" value={r.labels} onChange={(e) => set({ labels: [...e.target.selectedOptions].map((o) => o.value) })}>
                        {src && Object.entries(src.labels).map(([l, v]) => <option key={l} value={l}>{l || "(unlabelled)"} · {fmtNum(v.count)}</option>)}</select></td>
                      <td><input className="input w-20" type="number" value={r.offset} onChange={(e) => set({ offset: +e.target.value })} /></td>
                      <td><input className="input w-20" type="number" step="0.1" value={r.compress} onChange={(e) => set({ compress: +e.target.value })} /></td>
                      <td><input className="input w-24" type="number" value={r.max_rows} onChange={(e) => set({ max_rows: +e.target.value })} /></td>
                      <td><input className="input w-16" type="number" min={1} value={r.sample_every} onChange={(e) => set({ sample_every: +e.target.value })} /></td>
                      <td><input className="input w-16" type="number" min={1} value={r.repeat} onChange={(e) => set({ repeat: +e.target.value })} /></td>
                      <td><input type="checkbox" checked={r.remap_ips} onChange={(e) => set({ remap_ips: e.target.checked })} /></td>
                      <td><select className="input w-40" value={r.label_override} onChange={(e) => set({ label_override: e.target.value })}>
                        <option value="">(dataset label)</option>
                        {behaviours.map((b) => <option key={b.key} value={b.key}>{b.name}</option>)}</select></td>
                      <td><button className="btn btn-danger !px-2" onClick={() => setRows(rows.filter((_, k) => k !== i))}><Trash2 size={14} /></button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>)}
      </Card>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title={`Data sources (${catStatus})`} className="xl:col-span-2" bodyClass="p-0"
          actions={<button className="btn" onClick={() => act(async () => { await api.post("/api/sources/refresh"); setCatStatus("indexing"); }, "Re-indexing data folder", false)}><RefreshCw size={14} />Rescan</button>}>
          <div className="max-h-[420px] overflow-auto">
            <table className="tbl">
              <thead><tr><th>File</th><th>Adapter</th><th className="text-right">Rows</th><th>Labels → behaviour</th><th>Status</th></tr></thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.id}>
                    <td className="font-mono text-xs" title={s.path}>{s.name}{s.fixture && <span className="chip ml-2">fixture</span>}</td>
                    <td>{s.adapter ?? "—"}</td>
                    <td className="tabular text-right">{fmtNum(s.rows)}</td>
                    <td><div className="flex flex-wrap gap-1">{Object.entries(s.labels).slice(0, 8).map(([l, v]) => (
                      <span key={l} className="chip" title={`${v.count} records`}>{l || "(unlabelled)"} → {v.behaviour}</span>))}</div></td>
                    <td>{s.status === "error" ? <span className="text-xs" style={{ color: "var(--critical)" }} title={s.error}>error</span> : <StatusChip status={s.status === "ready" ? "active" : s.status} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!nonFixture && <p className="px-4 py-3 text-xs text-muted">Put CIC-IDS2017 / CIC-DDoS2019 CSVs, Cowrie or OpenCanary JSON, or Zeek conn.log files in {dataDirs[0] ?? "the data folder"} and press Rescan.</p>}
          </div>
        </Card>
        <Card title="Behaviour coverage" bodyClass="p-0">
          <div className="max-h-[420px] overflow-auto">
            <table className="tbl">
              <tbody>
                {behaviours.map((b) => (
                  <tr key={b.key}>
                    <td><CategoryChip category={b.key} name={b.name} /></td>
                    <td className="text-right">{b.data_source === "no data source"
                      ? <span className="chip" title={b.note} style={{ color: "var(--warning)" }}>no data source</span>
                      : <span className="text-xs text-muted" title={b.dataset_labels.join(", ")}>{b.dataset_labels.length} labels</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Story / narration" bodyClass="p-0">
          <div className="max-h-72 overflow-auto px-4 py-2 font-mono text-xs">
            {narration.length ? [...narration].reverse().map((n, i) => (
              <div key={i} className="flex gap-3 border-b border-line py-1.5">
                <span className="tabular shrink-0 text-muted">{fmtRel(n.t, status?.base_epoch)}</span>
                <span className="shrink-0 text-ink2">[{n.kind}]</span>
                <span className={n.kind === "alert" ? "text-ink" : "text-ink2"}>{n.text}</span>
              </div>)) : <Empty>Start a replay to see the story unfold.</Empty>}
          </div>
        </Card>
        <Card title="Plan & ground-truth campaigns" bodyClass="p-0">
          <div className="max-h-72 overflow-auto">
            {status?.plan ? (<>
              {status.plan.note && <p className="px-4 pt-3 text-xs text-ink2">{status.plan.note}</p>}
              <table className="tbl">
                <thead><tr><th>Campaign</th><th>Label</th><th className="text-right">Events</th><th className="text-right">IPs</th><th>Window</th></tr></thead>
                <tbody>{campaigns.map((c) => (
                  <tr key={c.campaign_id}>
                    <td className="font-mono text-xs">{c.campaign_id}{c.parent_id && <span className="chip ml-1">returns {c.parent_id.split("#").pop()}</span>}</td>
                    <td>{c.label || "—"}</td><td className="tabular text-right">{fmtNum(c.events)}</td><td className="tabular text-right">{c.n_ips}</td>
                    <td className="tabular text-xs">{fmtTime(c.first_ts)}–{fmtTime(c.last_ts)}</td>
                  </tr>))}</tbody>
              </table></>) : <Empty>No plan loaded.</Empty>}
          </div>
        </Card>
      </div>
    </div>
  );
}
