import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from "recharts";
import { Check, GitMerge, RefreshCw, Scissors, Trash2, X } from "lucide-react";
import { api } from "../lib/api";
import { useAction, useLive } from "../lib/store";
import { FAMILIES, categoryColor, familyOf } from "../lib/colors";
import { featureLabel, fmtNum, fmtRel, fmtTime } from "../lib/format";
import type { FingerprintDetail, FingerprintSummary } from "../lib/types";
import { Card, CategoryChip, ChartTooltip, Empty, Modal, Segmented, SeverityBadge, StatusChip } from "../components/ui";
import { RadarCompare } from "../components/RadarCompare";

interface Projection { method: string; points: any[]; centroids: any[] }

export default function FingerprintsPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const { fingerprints, version, status } = useLive();
  const act = useAction();
  const [method, setMethod] = useState<"pca" | "tsne">("pca");
  const [proj, setProj] = useState<Projection | null>(null);
  const [projBusy, setProjBusy] = useState(false);
  const [filter, setFilter] = useState<"active" | "candidate" | "dismissed" | "all">("all");
  const [detail, setDetail] = useState<FingerprintDetail | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [compare, setCompare] = useState<any | null>(null);

  const list = useMemo(() => Object.values(fingerprints)
    .filter((f) => filter === "all" ? f.status !== "dismissed" : f.status === filter)
    .sort((a, b) => Number(a.benign) - Number(b.benign) || b.hit_count - a.hit_count), [fingerprints, filter]);

  const loadProj = async (m = method) => {
    setProjBusy(true);
    try { setProj(await api.get<Projection>(`/api/fingerprints/projection?method=${m}&limit=${m === "tsne" ? 700 : 1500}`)); }
    finally { setProjBusy(false); }
  };
  useEffect(() => { loadProj().catch(() => undefined); }, [method]);
  useEffect(() => {
    if (!id) { setDetail(null); return; }
    api.get<FingerprintDetail>(`/api/fingerprints/${id}`).then(setDetail).catch(() => setDetail(null));
  }, [id, Math.floor(version / 8)]); // refetch roughly every 2 s while live

  const byFamily = useMemo(() => {
    const groups: Record<string, any[]> = {};
    for (const p of proj?.points ?? []) (groups[familyOf(p.category)] ??= []).push(p);
    return groups;
  }, [proj]);

  const togglePick = (fid: string) => setPicked((p) => p.includes(fid) ? p.filter((x) => x !== fid) : p.length >= 3 ? p : [...p, fid]);
  const openCompare = async () => setCompare(await api.get(`/api/fingerprints/compare?ids=${picked.join(",")}`));

  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Fingerprint Explorer</h1>
          <p className="text-sm text-ink2">Behavioural profiles discovered by HDBSCAN without labels. Click a point or card to open a fingerprint.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn" disabled={picked.length < 2} onClick={() => openCompare()}>Compare {picked.length ? `(${picked.length})` : ""}</button>
          <button className="btn" disabled={picked.length < 2}
            onClick={() => act(async () => { const r = await api.post<FingerprintSummary>("/api/fingerprints/merge", { ids: picked }); setPicked([]); nav(`/fingerprints/${r.id}`); }, "Merged")}>
            <GitMerge size={14} />Merge selected</button>
        </div>
      </div>

      <Card title="Feature-window map" actions={<>
        <Segmented value={method} onChange={(v) => setMethod(v)} options={[{ value: "pca", label: "PCA" }, { value: "tsne", label: "t-SNE" }]} />
        <button className="btn" onClick={() => loadProj()} disabled={projBusy}><RefreshCw size={14} className={projBusy ? "animate-spin" : ""} />Refresh</button></>}>
        {!proj?.points.length ? <Empty>{projBusy ? "Projecting…" : "No feature windows yet. Start a replay."}</Empty> : (
          <ResponsiveContainer width="100%" height={380}>
            <ScatterChart margin={{ top: 8, right: 16, bottom: 0, left: -12 }}>
              <CartesianGrid />
              <XAxis type="number" dataKey="x" tick={false} stroke="var(--axis)" name="component 1" />
              <YAxis type="number" dataKey="y" tick={false} stroke="var(--axis)" name="component 2" />
              <ZAxis range={[36, 36]} />
              <Tooltip cursor={false} content={({ active, payload }) => {
                const p = active && payload?.[0]?.payload;
                if (!p) return null;
                return (<div className="card px-3 py-2 text-xs">
                  <div className="font-medium">{p.name ? `${p.fp} centroid: ${p.name}` : p.entity}</div>
                  {!p.name && <><div className="text-ink2">{p.fp_name ?? (p.anomaly ? "anomalous, unassigned" : "unassigned")}</div>
                    <div className="text-muted">{p.n_events} events · {Object.keys(p.services ?? {}).join(", ")} · {fmtTime(p.t)}</div></>}
                  <div className="mt-1"><CategoryChip category={p.category} /></div>
                </div>);
              }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              {FAMILIES.filter((f) => byFamily[f.key]?.length).map((f) => (
                <Scatter key={f.key} name={f.name} data={byFamily[f.key]} fill={f.color} isAnimationActive={false}
                  onClick={(p: any) => p.fp && nav(`/fingerprints/${p.fp}`)}
                  shape={(props: any) => {
                    const dim = id && props.payload.fp !== id;
                    return <circle cx={props.cx} cy={props.cy} r={4} fill={f.color} stroke="var(--surface-1)" strokeWidth={1}
                      opacity={dim ? 0.18 : 0.85} style={{ cursor: props.payload.fp ? "pointer" : "default" }} />;
                  }} />
              ))}
              <Scatter name="Fingerprint centroids" data={proj.centroids} fill="var(--text-primary)" legendType="diamond" isAnimationActive={false}
                onClick={(p: any) => nav(`/fingerprints/${p.fp}`)}
                shape={(props: any) => (
                  <g style={{ cursor: "pointer" }}>
                    <rect x={props.cx - 5} y={props.cy - 5} width={10} height={10} transform={`rotate(45 ${props.cx} ${props.cy})`}
                      fill={categoryColor(props.payload.category)} stroke="var(--text-primary)" strokeWidth={props.payload.fp === id ? 2.5 : 1.2} />
                    <text x={props.cx + 8} y={props.cy - 6} fontSize={10} fill="var(--text-secondary)">{props.payload.fp}</text>
                  </g>)} />
            </ScatterChart>
          </ResponsiveContainer>)}
        <p className="mt-1 text-xs text-muted">Each dot is one sliding window (per source IP or per sparse-source group), coloured by the family of its fingerprint. Diamonds are fingerprint centroids.</p>
      </Card>

      <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <Card title={`Fingerprints (${list.length})`} bodyClass="p-2"
          actions={<Segmented value={filter} onChange={setFilter} options={[{ value: "all", label: "All" }, { value: "active", label: "Active" }, { value: "candidate", label: "Candidates" }, { value: "dismissed", label: "Dismissed" }]} />}>
          <div className="flex max-h-[900px] flex-col gap-2 overflow-auto">
            {!list.length && <Empty>No fingerprints yet.</Empty>}
            {list.map((f) => (
              <div key={f.id} onClick={() => nav(`/fingerprints/${f.id}`)}
                className={`cursor-pointer rounded-lg border p-3 transition-colors ${f.id === id ? "border-accent bg-surface2" : "border-line hover:bg-surface2"}`}>
                <div className="flex items-start gap-2">
                  <input type="checkbox" checked={picked.includes(f.id)} onClick={(e) => e.stopPropagation()} onChange={() => togglePick(f.id)} aria-label={`select ${f.id}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-muted">{f.id}</span>
                      <span className="truncate text-sm font-medium">{f.name}</span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      <CategoryChip category={f.category} name={f.category_name} />
                      {!f.benign && <SeverityBadge severity={f.severity} />}
                      {f.status !== "active" && <StatusChip status={f.status} />}
                      {f.returning && <span className="chip" style={{ color: "var(--serious)" }}>↻ returning</span>}
                    </div>
                    <div className="tabular mt-1.5 text-xs text-muted">{fmtNum(f.hit_count)} hits · {f.n_ips} IPs · {f.episodes} episodes · conf {f.confidence.toFixed(2)} · v{f.version}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
        {detail ? <Detail fp={detail} base={status?.base_epoch} onChanged={() => api.get<FingerprintDetail>(`/api/fingerprints/${detail.id}`).then(setDetail)} />
          : <Card title="Fingerprint"><Empty>Select a fingerprint to see its radar profile, distinguishing features, traits and history.</Empty></Card>}
      </div>

      {compare && (
        <Modal title="Compare fingerprints" wide onClose={() => setCompare(null)}>
          <RadarCompare height={360} series={compare.fingerprints.map((f: any) => ({ name: `${f.id} ${f.name}`, radar: f.radar }))} />
          <table className="tbl mt-3">
            <thead><tr><th>Pair</th><th className="text-right">Cosine (numeric)</th><th className="text-right">MinHash Jaccard</th><th className="text-right">Combined</th><th>Most different features</th></tr></thead>
            <tbody>{compare.pairs.map((p: any) => (
              <tr key={p.a + p.b}>
                <td className="font-mono text-xs">{p.a} ↔ {p.b}</td>
                <td className="tabular text-right">{p.cosine.toFixed(3)}</td>
                <td className="tabular text-right">{p.jaccard_minhash.toFixed(3)}</td>
                <td className="tabular text-right font-medium text-ink">{p.combined.toFixed(3)}</td>
                <td className="text-xs">{p.most_different.slice(0, 3).map((d: any) => `${featureLabel(d.feature)} (${d.a_z} vs ${d.b_z})`).join("; ")}</td>
              </tr>))}</tbody>
          </table>
          <p className="mt-2 text-xs text-muted">Combined = {compare.pairs[0]?.weights.numeric} × cosine + {compare.pairs[0]?.weights.categorical} × Jaccard (weights from Settings).</p>
        </Modal>
      )}
    </div>
  );
}

function Detail({ fp, base, onChanged }: { fp: FingerprintDetail; base?: number; onChanged: () => void }) {
  const act = useAction();
  const nav = useNavigate();
  const [name, setName] = useState(fp.name);
  useEffect(() => setName(fp.name), [fp.id, fp.name]);
  const timeline = fp.timeline.map(([t, n]) => ({ t, n }));
  const imp = fp.importance.map((i) => ({ ...i, label: featureLabel(i.feature) }));
  const run = (fn: () => Promise<unknown>, msg: string) => act(async () => { await fn(); onChanged(); }, msg);
  return (
    <Card title={<span className="flex items-center gap-2"><span className="font-mono text-muted">{fp.id}</span>{fp.name}</span>}
      actions={<>
        {fp.status === "candidate" && <button className="btn" onClick={() => run(() => api.post(`/api/fingerprints/${fp.id}/promote`), "Promoted")}><Check size={14} />Promote</button>}
        {fp.status !== "dismissed" && <button className="btn" onClick={() => run(() => api.post(`/api/fingerprints/${fp.id}/dismiss`), "Dismissed")}><X size={14} />Dismiss</button>}
        <button className="btn" onClick={() => run(() => api.post(`/api/fingerprints/${fp.id}/split`), "Split into two")}><Scissors size={14} />Split</button>
        <button className="btn btn-danger" onClick={() => { if (confirm(`Delete ${fp.id}?`)) act(async () => { await api.del(`/api/fingerprints/${fp.id}`); nav("/fingerprints"); }, "Deleted"); }}><Trash2 size={14} /></button>
      </>}>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-3">
          <div className="flex gap-2">
            <input className="input flex-1" value={name} onChange={(e) => setName(e.target.value)} aria-label="Fingerprint name" />
            <button className="btn" disabled={name === fp.name} onClick={() => run(() => api.patch(`/api/fingerprints/${fp.id}`, { name }), "Renamed")}>Rename</button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <CategoryChip category={fp.category} name={fp.category_name} /><SeverityBadge severity={fp.severity} /><StatusChip status={fp.status} />
            <span className="chip">confidence {fp.confidence.toFixed(2)}</span><span className="chip">origin: {fp.origin}</span>
          </div>
          <ul className="list-disc pl-5 text-xs text-ink2">{fp.category_reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
          <div className="tabular grid grid-cols-3 gap-2 text-center text-xs">
            <div className="rounded-lg bg-surface2 p-2"><div className="text-lg font-semibold text-ink">{fmtNum(fp.hit_count)}</div>hits</div>
            <div className="rounded-lg bg-surface2 p-2"><div className="text-lg font-semibold text-ink">{fp.n_ips}</div>source IPs</div>
            <div className="rounded-lg bg-surface2 p-2"><div className="text-lg font-semibold text-ink">{fp.episodes.length}</div>episodes</div>
          </div>
          <div className="text-xs text-muted">first seen {fmtTime(fp.first_seen)} · last seen {fmtTime(fp.last_seen)}</div>
        </div>
        <div>
          <div className="label mb-1">Radar (0.5 = benign baseline)</div>
          <RadarCompare series={[{ name: fp.name, radar: fp.radar, color: categoryColor(fp.category) }]} height={260} />
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div className="label mb-1">Top distinguishing features (z vs baseline)</div>
          {imp.length ? (
            <ResponsiveContainer width="100%" height={Math.max(120, imp.length * 26)}>
              <BarChart data={imp} layout="vertical" margin={{ left: 0, right: 16 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" stroke="var(--axis)" />
                <YAxis type="category" dataKey="label" width={130} stroke="var(--axis)" tick={{ fontSize: 11 }} />
                <Tooltip content={<ChartTooltip valueFmt={(v: number) => `z ${v.toFixed(2)}`} />} cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="z" name="z-score" fill={categoryColor(fp.category)} radius={[0, 4, 4, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>) : <Empty>Indistinguishable from the baseline.</Empty>}
        </div>
        <div>
          <div className="label mb-1">Hits over time (10 s buckets)</div>
          {timeline.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={timeline} margin={{ left: -16, right: 8 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="t" tickFormatter={(t) => fmtRel(t, base)} stroke="var(--axis)" />
                <YAxis allowDecimals={false} stroke="var(--axis)" />
                <Tooltip content={<ChartTooltip labelFmt={(t: number) => fmtTime(t)} />} cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="n" name="Matched windows" fill={categoryColor(fp.category)} radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>) : <Empty>No live hits yet.</Empty>}
        </div>
      </div>

      <div className="mt-4">
        <div className="label mb-1">Signature traits (MinHash over these tokens)</div>
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {Object.entries(fp.traits).map(([fam, toks]) => (
            <div key={fam} className="rounded-lg border border-line p-2">
              <div className="mb-1 text-xs font-medium text-ink2">{fam}</div>
              <div className="flex flex-wrap gap-1">{toks.slice(0, 10).map((t) => <span key={t.token} className="chip font-mono" title={`${t.count} windows`}>{t.token}</span>)}</div>
            </div>))}
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div className="label mb-1">Episodes (returning = new episode from unseen sources)</div>
          <table className="tbl"><thead><tr><th>Episode</th><th>Start</th><th>End</th><th className="text-right">IPs</th><th /></tr></thead>
            <tbody>{fp.episodes.map((e: any) => (
              <tr key={e.id}><td className="font-mono text-xs">{e.id}</td><td>{fmtTime(e.start)}</td><td>{fmtTime(e.end)}</td>
                <td className="tabular text-right" title={e.ips.join(", ")}>{e.n_ips}</td>
                <td>{e.returning ? <span className="chip" style={{ color: "var(--serious)" }}>↻ returning</span> : e.repeat_sources ? <span className="chip">same sources</span> : null}</td></tr>))}
            </tbody></table>
          <div className="label mb-1 mt-3">Top sources</div>
          <div className="flex flex-wrap gap-1">{fp.ips.slice(0, 20).map((i) => <span key={i.ip} className="chip font-mono">{i.ip} · {i.hits}</span>)}</div>
          <div className="mt-2 flex flex-wrap gap-1">{fp.countries.map((c) => <span key={c.country} className="chip">{c.country} {c.hits}</span>)}
            {fp.asns.slice(0, 4).map((a) => <span key={a.asn} className="chip">{a.asn}</span>)}</div>
        </div>
        <div>
          <div className="label mb-1">Version history</div>
          <div className="max-h-48 overflow-auto"><table className="tbl"><tbody>{[...fp.versions].reverse().map((v) => (
            <tr key={v.version}><td className="font-mono text-xs">v{v.version}</td><td className="text-xs">{fmtTime(v.t)}</td><td className="text-xs">{v.reason}</td><td className="text-xs">{v.category}</td></tr>))}
          </tbody></table></div>
          <div className="label mb-1 mt-3">Related</div>
          <div className="flex flex-wrap gap-1">
            {fp.rules.map((r) => <Link key={r.id} to={`/rules?focus=${r.id}`} className="chip hover:border-accent">{r.id} {r.kind} · {r.status}</Link>)}
            {fp.alerts.slice(0, 8).map((a) => <Link key={a.id} to={`/alerts?focus=${a.id}`} className="chip hover:border-accent">{a.id} {a.type}</Link>)}
          </div>
          {!!fp.notes.length && <ul className="mt-2 list-disc pl-5 text-xs text-muted">{fp.notes.slice(-5).map((n, i) => <li key={i}>{n}</li>)}</ul>}
        </div>
      </div>
    </Card>
  );
}
