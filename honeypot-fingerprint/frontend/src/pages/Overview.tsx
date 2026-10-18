import { useMemo, useState } from "react";
import { Area, Bar, BarChart, CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useLive } from "../lib/store";
import { FAMILIES, familyOf, type FamilyKey } from "../lib/colors";
import { fmtNum, fmtRel, fmtTime } from "../lib/format";
import { Card, ChartTooltip, Empty, Kpi } from "../components/ui";
import { EventTable } from "../components/EventTable";

export default function OverviewPage() {
  const { kpis, series, markers, events, status } = useLive();
  const [ip, setIp] = useState("");
  const [svc, setSvc] = useState("");
  const [action, setAction] = useState("");
  const [label, setLabel] = useState("");

  const { data, present } = useMemo(() => {
    const present = new Set<FamilyKey>();
    const data = series.slice(-300).map((p) => {
      const row: Record<string, number> = { t: p.t, dropped: p.dropped };
      for (const f of FAMILIES) row[f.key] = 0;
      for (const [cat, n] of Object.entries(p.by_cat)) {
        const f = familyOf(cat);
        row[f] += n;
        if (n) present.add(f);
      }
      return row;
    });
    return { data, present };
  }, [series]);
  const fams = FAMILIES.filter((f) => present.has(f.key));
  const t0 = data[0]?.t ?? 0;

  const geo = useMemo(() => {
    const c = new Map<string, number>();
    for (const e of events) c.set(e.country, (c.get(e.country) ?? 0) + 1);
    return [...c.entries()].map(([country, n]) => ({ country, n })).sort((a, b) => b.n - a.n).slice(0, 12);
  }, [events]);

  const filtered = useMemo(() => events.filter((e) =>
    (!ip || e.src_ip.includes(ip)) && (!svc || e.dst_service === svc) && (!action || e.action === action) &&
    (!label || (e.ground_truth_label || "—").toLowerCase().includes(label.toLowerCase()))), [events, ip, svc, action, label]);
  const services = useMemo(() => [...new Set(events.map((e) => e.dst_service))].sort(), [events]);

  return (
    <div className="mx-auto flex max-w-[1500px] flex-col gap-4">
      <div>
        <h1 className="text-xl font-semibold">Live Overview</h1>
        <p className="text-sm text-ink2">Events are coloured by the behaviour family their source was last detected as. Ground truth is shown only in the table, for evaluation.</p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Events" value={fmtNum(kpis?.events_total)} sub={`${fmtNum(kpis?.events_per_sec, 1)} /s now`} />
        <Kpi label="Active attackers" value={fmtNum(kpis?.active_attackers)} sub="non-benign sources, last 60 s" />
        <Kpi label="Open alerts" value={fmtNum(kpis?.open_alerts)} />
        <Kpi label="Active rules" value={fmtNum(kpis?.active_rules)} sub={`${kpis?.suggested_rules ?? 0} suggested`} />
        <Kpi label="Blocked events" value={fmtNum(kpis?.dropped)} sub="dropped by the simulated firewall" />
        <Kpi label="Fingerprints" value={fmtNum(kpis?.fingerprints)} sub={`${kpis?.candidates ?? 0} candidates · baseline ${kpis?.baseline_ready ? "ready" : "calibrating"}`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card title="Events per second by detected behaviour family" className="xl:col-span-2">
          {data.length < 2 ? <Empty>No traffic yet: start a replay on the Replay Control page.</Empty> : (
            <ResponsiveContainer width="100%" height={300}>
              <ComposedChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -8 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} tickFormatter={(t) => fmtRel(t, status?.base_epoch ?? t0)} stroke="var(--axis)" />
                <YAxis stroke="var(--axis)" allowDecimals={false} />
                <Tooltip content={<ChartTooltip labelFmt={(t: number) => `${fmtTime(t)} (${fmtRel(t, status?.base_epoch)})`} />} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                {fams.map((f) => (
                  <Area key={f.key} type="stepAfter" dataKey={f.key} name={f.name} stackId="a" stroke={f.color} fill={f.color}
                    fillOpacity={0.85} strokeWidth={0} isAnimationActive={false} />
                ))}
                <Line type="stepAfter" dataKey="dropped" name="Dropped by firewall" stroke="var(--text-primary)" strokeDasharray="4 3" strokeWidth={2} dot={false} isAnimationActive={false} />
                {markers.filter((m) => m.t >= t0).map((m) => (
                  <ReferenceLine key={m.rule_id + m.t} x={m.t} stroke="var(--good)" strokeDasharray="3 3"
                    label={{ value: m.label, position: "insideTopLeft", fill: "var(--text-secondary)", fontSize: 10 }} />
                ))}
              </ComposedChart>
            </ResponsiveContainer>)}
          <p className="mt-2 text-xs text-muted">Green dashed lines mark rule activations; the dashed line shows traffic dropped by the simulated firewall (before/after enforcement).</p>
        </Card>
        <Card title="Source countries (mock GeoIP, recent events)">
          {!geo.length ? <Empty>No events yet.</Empty> : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={geo} layout="vertical" margin={{ left: 0, right: 16 }}>
                <CartesianGrid horizontal={false} />
                <XAxis type="number" stroke="var(--axis)" allowDecimals={false} />
                <YAxis type="category" dataKey="country" width={36} stroke="var(--axis)" />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="n" name="Events" fill="var(--s1)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>)}
        </Card>
      </div>

      <Card title={`Live events (${fmtNum(filtered.length)} of last ${fmtNum(events.length)})`} bodyClass="p-0"
        actions={<>
          <input className="input w-36" placeholder="source IP" value={ip} onChange={(e) => setIp(e.target.value)} />
          <select className="input" value={svc} onChange={(e) => setSvc(e.target.value)}>
            <option value="">all services</option>{services.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select className="input" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">all actions</option><option value="accepted">accepted</option><option value="dropped">dropped</option>
          </select>
          <input className="input w-36" placeholder="ground truth" value={label} onChange={(e) => setLabel(e.target.value)} />
        </>}>
        {filtered.length ? <EventTable rows={filtered} /> : <Empty>No matching events.</Empty>}
      </Card>
    </div>
  );
}
