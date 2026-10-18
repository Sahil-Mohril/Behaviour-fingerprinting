import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Check, Download, Pencil, Plus, Trash2, X } from "lucide-react";
import { api } from "../lib/api";
import { useAction, useLive } from "../lib/store";
import { fmtNum, fmtTime } from "../lib/format";
import type { Rule } from "../lib/types";
import { Card, CategoryChip, Empty, Field, Modal, Segmented, StatusChip } from "../components/ui";

type Fmt = "nftables" | "iptables" | "suricata";
const TABS = ["suggested", "active", "expired", "rejected"] as const;

export default function RulesPage() {
  const { rules, kpis } = useLive();
  const act = useAction();
  const [params] = useSearchParams();
  const [tab, setTab] = useState<(typeof TABS)[number]>("suggested");
  const [fmt, setFmt] = useState<Fmt>("nftables");
  const [sel, setSel] = useState<string | null>(params.get("focus"));
  const [edit, setEdit] = useState<Rule | null>(null);
  const [allow, setAllow] = useState<{ cidr: string; note: string }[]>([]);
  const [newCidr, setNewCidr] = useState("");
  const [newNote, setNewNote] = useState("");

  useEffect(() => {
    const f = params.get("focus");
    if (f && rules[f]) { setSel(f); setTab(rules[f].status === "approved" ? "active" : (rules[f].status as any)); }
  }, [params, rules]);
  const loadAllow = () => api.get<{ cidr: string; note: string }[]>("/api/allowlist").then(setAllow);
  useEffect(() => { loadAllow().catch(() => undefined); }, []);

  const byTab = useMemo(() => {
    const out: Record<string, Rule[]> = { suggested: [], active: [], expired: [], rejected: [] };
    for (const r of Object.values(rules)) (out[r.status === "approved" ? "active" : r.status] ??= []).push(r);
    for (const k of Object.keys(out)) out[k].sort((a, b) => b.created - a.created);
    return out;
  }, [rules]);
  const list = byTab[tab] ?? [];
  const cur = sel ? rules[sel] : list[0];

  const mode = kpis?.rule_mode ?? "suggest";
  const setMode = (m: string) => act(() => api.put("/api/settings", { rule_mode: m }), m === "auto" ? "Auto-apply on (simulated firewall only)" : "Suggest-only mode");
  const download = (f: Fmt, status = "active") => { window.location.href = `/api/rules/export?format=${f}&status=${status}`; };

  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Firewall Rules</h1>
          <p className="text-sm text-ink2">Generated as text for nftables, iptables and Suricata. Nothing is executed on this host; active rules only drive the in-app simulated firewall.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="label">Mode</span>
          <Segmented value={mode} onChange={setMode} options={[{ value: "suggest", label: "Suggest only" }, { value: "auto", label: "Auto-apply (simulated)" }]} />
          <span className="label ml-2">Export active</span>
          {(["nftables", "iptables", "suricata"] as Fmt[]).map((f) => <button key={f} className="btn" onClick={() => download(f)}><Download size={14} />{f}</button>)}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1.1fr]">
        <Card title={<Segmented value={tab} onChange={(v) => { setTab(v); setSel(null); }}
          options={TABS.map((t) => ({ value: t, label: `${t} (${byTab[t]?.length ?? 0})` }))} />} bodyClass="p-0">
          {!list.length ? <Empty>No {tab} rules.</Empty> : (
            <div className="max-h-[640px] overflow-auto">
              <table className="tbl">
                <thead><tr><th>Rule</th><th>Fingerprint</th><th>Kind</th><th className="text-right">Targets</th><th className="text-right">Dropped</th><th>Expires</th><th /></tr></thead>
                <tbody>{list.map((r) => (
                  <tr key={r.id} onClick={() => setSel(r.id)} className={`cursor-pointer ${cur?.id === r.id ? "bg-surface2" : ""}`}>
                    <td className="font-mono text-xs">{r.id}<div className="text-[10px] text-muted">{fmtTime(r.created)}</div></td>
                    <td><Link to={`/fingerprints/${r.fp_id}`} className="text-xs hover:underline" onClick={(e) => e.stopPropagation()}>{r.fp_id}</Link>
                      <div className="mt-0.5"><CategoryChip category={r.category} /></div></td>
                    <td className="text-xs">{r.kind}</td>
                    <td className="tabular text-right">{r.n_ips || (r.params.ports?.length ? `ports ${r.params.ports.join(",")}` : "—")}</td>
                    <td className="tabular text-right">{fmtNum(r.hits)}</td>
                    <td className="text-xs">{r.status === "active" ? fmtTime(r.expires) : "—"}</td>
                    <td className="whitespace-nowrap">
                      {r.status === "suggested" && <>
                        <button className="btn !px-2 !py-1" title="Approve" onClick={(e) => { e.stopPropagation(); act(() => api.post(`/api/rules/${r.id}/approve`), `${r.id} active in simulated firewall`); }}><Check size={14} /></button>{" "}
                        <button className="btn !px-2 !py-1" title="Reject" onClick={(e) => { e.stopPropagation(); act(() => api.post(`/api/rules/${r.id}/reject`), `${r.id} rejected`); }}><X size={14} /></button></>}
                      {r.status === "active" && <button className="btn !px-2 !py-1" title="Expire now" onClick={(e) => { e.stopPropagation(); act(() => api.post(`/api/rules/${r.id}/expire`), `${r.id} expired`); }}><X size={14} /></button>}
                      {(r.status === "expired" || r.status === "rejected") && <button className="btn !px-2 !py-1" title="Re-activate" onClick={(e) => { e.stopPropagation(); act(() => api.post(`/api/rules/${r.id}/approve`), `${r.id} re-activated`); }}><Check size={14} /></button>}
                    </td>
                  </tr>))}</tbody>
              </table>
            </div>)}
        </Card>

        <Card title={cur ? <span><span className="font-mono">{cur.id}</span> · {cur.fp_name}</span> : "Rule"}
          actions={cur && <>
            <Segmented value={fmt} onChange={setFmt} options={[{ value: "nftables", label: "nftables" }, { value: "iptables", label: "iptables" }, { value: "suricata", label: "Suricata" }]} />
            <button className="btn" onClick={() => setEdit(cur)}><Pencil size={14} />Edit</button></>}>
          {!cur ? <Empty>Select a rule.</Empty> : (<>
            <div className="mb-2 flex flex-wrap gap-1.5"><StatusChip status={cur.status} /><span className="chip">{cur.kind}</span><span className="chip">rev {cur.rev}</span>
              {cur.edited && <span className="chip">edited</span>}{cur.alert_id && <Link className="chip hover:border-accent" to={`/alerts?focus=${cur.alert_id}`}>{cur.alert_id}</Link>}</div>
            <p className="mb-2 text-sm text-ink2">{cur.reason}</p>
            <pre className="code max-h-[380px]">{cur.formats[fmt]}</pre>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div><div className="label mb-1">Lifecycle</div>
                {cur.history.map((h, i) => <div key={i} className="text-xs text-ink2">{fmtTime(h.t)} · {h.status} · {h.by}</div>)}</div>
              <div><div className="label mb-1">Parameters</div>
                <pre className="code !p-2 text-[11px]">{JSON.stringify({ ...cur.params, ips: cur.params.ips?.length > 8 ? [...cur.params.ips.slice(0, 8), `… +${cur.params.ips.length - 8}`] : cur.params.ips }, null, 1)}</pre></div>
            </div>
          </>)}
        </Card>
      </div>

      <Card title="Allowlist (never blocked)" actions={<>
        <input className="input w-44" placeholder="CIDR e.g. 203.0.113.0/24" value={newCidr} onChange={(e) => setNewCidr(e.target.value)} />
        <input className="input w-48" placeholder="note" value={newNote} onChange={(e) => setNewNote(e.target.value)} />
        <button className="btn" disabled={!newCidr} onClick={() => act(async () => { await api.post("/api/allowlist", { cidr: newCidr, note: newNote }); setNewCidr(""); setNewNote(""); await loadAllow(); }, "Allowlist updated")}><Plus size={14} />Add</button></>}>
        <div className="flex flex-wrap gap-2">
          {allow.map((a) => (
            <span key={a.cidr} className="chip !py-1 font-mono">{a.cidr}{a.note && <span className="font-sans text-muted"> · {a.note}</span>}
              <button className="ml-1 text-muted hover:text-ink" aria-label={`remove ${a.cidr}`}
                onClick={() => act(async () => { await api.del(`/api/allowlist?cidr=${encodeURIComponent(a.cidr)}`); await loadAllow(); }, "Removed")}><Trash2 size={12} /></button></span>))}
          {!allow.length && <span className="text-sm text-muted">Empty.</span>}
        </div>
        <p className="mt-2 text-xs text-muted">Allowlisted sources are stripped from every rule and bypass the simulated firewall, including rate limits.</p>
      </Card>

      {edit && <EditRule rule={edit} onClose={() => setEdit(null)} />}
    </div>
  );
}

function EditRule({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const act = useAction();
  const [ips, setIps] = useState((rule.params.ips ?? []).join("\n"));
  const [rate, setRate] = useState<number | "">(rule.params.rate ?? "");
  const [max, setMax] = useState<number | "">(rule.params.max ?? "");
  const [ports, setPorts] = useState((rule.params.ports ?? []).join(","));
  const [expiresIn, setExpiresIn] = useState(900);
  const save = () => act(async () => {
    await api.patch(`/api/rules/${rule.id}`, {
      ips: ips.split(/[\s,]+/).filter(Boolean), rate: rate === "" ? null : rate, max: max === "" ? null : max,
      ports: ports.split(",").map((p: string) => p.trim()).filter(Boolean).map(Number), expires_in: expiresIn,
    });
    onClose();
  }, `${rule.id} updated`);
  return (
    <Modal title={`Edit ${rule.id}`} onClose={onClose}>
      <div className="flex flex-col gap-3">
        <Field label="Source IPs (one per line)" hint="Allowlisted entries are removed automatically">
          <textarea className="input h-32 font-mono" value={ips} onChange={(e) => setIps(e.target.value)} />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          {rule.params.rate !== undefined && <Field label="Rate /s"><input className="input" type="number" value={rate} onChange={(e) => setRate(e.target.value === "" ? "" : +e.target.value)} /></Field>}
          {rule.params.max !== undefined && <Field label="Max conns"><input className="input" type="number" value={max} onChange={(e) => setMax(e.target.value === "" ? "" : +e.target.value)} /></Field>}
          <Field label="Ports"><input className="input" value={ports} onChange={(e) => setPorts(e.target.value)} /></Field>
          <Field label="Expires in (s)"><input className="input" type="number" value={expiresIn} onChange={(e) => setExpiresIn(+e.target.value)} /></Field>
        </div>
        <div className="flex justify-end gap-2"><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" onClick={save}>Save</button></div>
      </div>
    </Modal>
  );
}
