import { Legend, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";
import { featureLabel } from "../lib/format";
import type { RadarPoint } from "../lib/types";

const OVERLAY = ["var(--s1)", "var(--s2)", "var(--s3)"]; // first three slots validate all-pairs

/** Radar of normalised features (0.5 = benign baseline; sigmoid of baseline z-score). */
export function RadarCompare({ series, height = 300 }: { series: { name: string; radar: RadarPoint[]; color?: string }[]; height?: number }) {
  if (!series.length || !series[0].radar?.length) return null;
  const data = series[0].radar.map((p, i) => {
    const row: Record<string, any> = { axis: featureLabel(p.axis) };
    series.forEach((s, k) => {
      row[`v${k}`] = s.radar[i]?.value ?? 0;
      row[`z${k}`] = s.radar[i]?.z ?? 0;
    });
    return row;
  });
  return (
    <ResponsiveContainer width="100%" height={height}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke="var(--line)" />
        <PolarAngleAxis dataKey="axis" tick={{ fill: "var(--text-muted)", fontSize: 10 }} />
        <PolarRadiusAxis domain={[0, 1]} tick={false} axisLine={false} />
        {series.map((s, k) => (
          <Radar key={k} name={s.name} dataKey={`v${k}`} stroke={s.color ?? OVERLAY[k]} fill={s.color ?? OVERLAY[k]}
            fillOpacity={series.length > 1 ? 0.12 : 0.22} strokeWidth={2} dot={{ r: 2 }} isAnimationActive={false} />
        ))}
        <Tooltip content={({ active, payload, label }) => active && payload?.length ? (
          <div className="card px-3 py-2 text-xs">
            <div className="mb-1 font-medium">{label ?? payload[0].payload.axis}</div>
            {payload.map((p: any, k: number) => (
              <div key={k} className="flex justify-between gap-3 text-ink2">
                <span style={{ color: p.color }}>■</span><span>{p.name}</span>
                <span className="tabular text-ink">z {Number(p.payload[`z${k}`]).toFixed(1)}</span>
              </div>
            ))}
          </div>) : null} />
        {series.length > 1 && <Legend wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }} />}
      </RadarChart>
    </ResponsiveContainer>
  );
}
