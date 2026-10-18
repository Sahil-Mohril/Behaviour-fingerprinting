import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import { useLive } from "../lib/store";
import { fmtDuration, fmtNum, fmtPct } from "../lib/format";
import { Card, CategoryChip, Empty, Kpi, Segmented } from "../components/ui";

// Sequential single-hue ramp (blue) for the confusion matrix; 0 recedes to the surface.
const RAMP = ["#0d366b", "#104281", "#184f95", "#1c5cab", "#256abf", "#2a78d6", "#3987e5", "#5598e7", "#6da7ec"];
function cellColor(share: number): string {
  if (share <= 0) return "transparent";
  return RAMP[Math.min(RAMP.length - 1, Math.floor(share * RAMP.length))];
}

export default function EvaluationPage() {
  const { version } = useLive();
  const [m, setM] = useState<any | null>(null);
  const [mode, setMode] = useState<"online" | "final">("online");
  const [busy, setBusy] = useState(false);
  const load = () => { setBusy(true); api.get<any>("/api/metrics/evaluation").then(setM).finally(() => setBusy(false)); };
  useEffect(load, [Math.floor(version / 20)]);

  if (!m) return <Empty>Loading…</Empty>;
  const names: Record<string, string> = m.category_names ?? {};
  const block = m[mode];
  const ret = m.returning ?? {};
  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Evaluation</h1>
          <p className="text-sm text-ink2">Scored against the datasets' own ground-truth labels, mapped to behaviours through the label table. Unlabelled sources (Cowrie, OpenCanary, plain Zeek) are excluded unless a label override was set.</p>
        </div>
        <div className="flex gap-2">
          <Segmented value={mode} onChange={setMode} options={[{ value: "online", label: "Online (at detection time)" }, { value: "final", label: "After clustering" }]} />
          <button className="btn" onClick={load} disabled={busy}><RefreshCw size={14} />Refresh</button>
        </div>
      </div>
      {m.empty ? <Card><Empty>No labelled windows evaluated yet. Run a replay of a labelled dataset (CIC-IDS2017, CIC-DDoS2019 or an IoT-23 conn.log.labeled).</Empty></Card> : (<>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <Kpi label="Attack precision" value={fmtPct(m.binary?.precision)} sub={`TP ${m.binary?.tp} · FP ${m.binary?.fp}`} />
          <Kpi label="Attack recall" value={fmtPct(m.binary?.recall)} sub={`FN ${m.binary?.fn} · TN ${m.binary?.tn}`} />
          <Kpi label="Attack F1" value={fmtPct(m.binary?.f1)} sub="window-level, attack vs benign" />
          <Kpi label={`Macro F1 (${mode})`} value={fmtPct(block?.macro?.f1)} sub={`accuracy ${fmtPct(block?.accuracy)}`} />
          <Kpi label="Mean time to detect" value={fmtDuration(m.mean_time_to_detect)} sub="first event → first flagged window" />
          <Kpi label="Mean time to rule" value={fmtDuration(m.mean_time_to_rule)} sub="first event → first rule" />
          <Kpi label="Returning recognised" value={ret.rate === null || ret.rate === undefined ? "–" : fmtPct(ret.rate)}
            sub={`${ret.recognised ?? 0}/${ret.replays ?? 0} replays · alert ${fmtPct(ret.alert_rate)}`} />
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
          <Card title={`Confusion matrix: true behaviour × detected category (${fmtNum(m.windows_evaluated)} windows, row-normalised)`}>
            {block ? (
              <div className="overflow-auto">
                <table className="text-[11px]">
                  <thead><tr><th className="p-1" />{block.confusion.cols.map((c: string) => (
                    <th key={c} className="h-28 p-1 align-bottom font-normal text-muted"><div className="w-6 origin-bottom-left -rotate-45 translate-x-3 whitespace-nowrap">{names[c] ?? c}</div></th>))}</tr></thead>
                  <tbody>{block.confusion.rows.map((r: string, i: number) => {
                    const row: number[] = block.confusion.matrix[i];
                    const tot = row.reduce((a, b) => a + b, 0) || 1;
                    return (<tr key={r}>
                      <td className="whitespace-nowrap p-1 pr-2 text-right text-ink2">{names[r] ?? r}</td>
                      {row.map((v, j) => (
                        <td key={j} title={`${names[r] ?? r} → ${names[block.confusion.cols[j]] ?? block.confusion.cols[j]}: ${v} (${fmtPct(v / tot)})`}
                          className="tabular h-8 w-10 border border-[var(--line)] text-center"
                          style={{ background: cellColor(v / tot), color: v / tot > 0.15 ? "#fff" : "var(--text-muted)",
                            outline: r === block.confusion.cols[j] ? "1.5px solid var(--text-secondary)" : undefined, outlineOffset: -2 }}>
                          {v || ""}</td>))}
                    </tr>);
                  })}</tbody>
                </table>
                <p className="mt-2 text-xs text-muted">Outlined cells are correct detections. "Unclassified" = no fingerprint matched yet (common before the first clustering run); "after clustering" credits windows that HDBSCAN later assigned to a fingerprint.</p>
              </div>) : <Empty>—</Empty>}
          </Card>
          <Card title="Per-behaviour scores" bodyClass="p-0">
            <table className="tbl">
              <thead><tr><th>Behaviour</th><th className="text-right">Precision</th><th className="text-right">Recall</th><th className="text-right">F1</th><th className="text-right">Support</th></tr></thead>
              <tbody>{block && Object.entries(block.per_class).map(([k, v]: [string, any]) => (
                <tr key={k}><td><CategoryChip category={k} name={names[k]} /></td><td className="tabular text-right">{fmtPct(v.precision)}</td>
                  <td className="tabular text-right">{fmtPct(v.recall)}</td><td className="tabular text-right">{fmtPct(v.f1)}</td><td className="tabular text-right">{v.support}</td></tr>))}</tbody>
            </table>
          </Card>
        </div>
      </>)}

      <Card title="Ground-truth campaigns" bodyClass="p-0">
        {!m.campaigns?.length ? <Empty>No campaigns yet.</Empty> : (
          <div className="max-h-[420px] overflow-auto">
            <table className="tbl">
              <thead><tr><th>Campaign</th><th>Dataset label</th><th>Behaviour</th><th className="text-right">Events</th><th className="text-right">Dropped</th><th className="text-right">IPs</th><th className="text-right">Time to detect</th><th className="text-right">Time to rule</th><th>Fingerprints</th></tr></thead>
              <tbody>{m.campaigns.map((c: any) => (
                <tr key={c.campaign_id}>
                  <td className="font-mono text-xs">{c.campaign_id}{c.parent_id && <span className="chip ml-1">returning</span>}</td>
                  <td>{c.label || "—"}</td><td><CategoryChip category={c.behaviour} name={names[c.behaviour] ?? c.behaviour} /></td>
                  <td className="tabular text-right">{fmtNum(c.events)}</td><td className="tabular text-right">{fmtNum(c.dropped)}</td>
                  <td className="tabular text-right">{c.n_ips}</td><td className="tabular text-right">{fmtDuration(c.time_to_detect)}</td>
                  <td className="tabular text-right">{fmtDuration(c.time_to_rule)}</td><td className="font-mono text-xs">{c.fingerprints.join(", ")}</td>
                </tr>))}</tbody>
            </table>
          </div>)}
      </Card>

      {!!ret.details?.length && (
        <Card title="Returning-attacker recognition" bodyClass="p-0">
          <table className="tbl">
            <thead><tr><th>Replay (new IPs)</th><th>Original</th><th>Recognised</th><th>Returning alert</th><th>Shared fingerprints</th><th className="text-right">Windows on parent FP</th></tr></thead>
            <tbody>{ret.details.map((d: any) => (
              <tr key={d.campaign_id}><td className="font-mono text-xs">{d.campaign_id}</td><td className="font-mono text-xs">{d.parent_id}</td>
                <td>{d.recognised ? "✓ yes" : "✗ no"}</td><td>{d.returning_alert ? "✓ raised" : "✗ none"}</td>
                <td className="font-mono text-xs">{d.shared_fingerprints.join(", ") || "—"}</td><td className="tabular text-right">{d.child_windows_on_parent_fp}</td></tr>))}</tbody>
          </table>
        </Card>)}
    </div>
  );
}
