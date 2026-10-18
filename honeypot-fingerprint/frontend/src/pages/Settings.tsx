import { useEffect, useState } from "react";
import { Save } from "lucide-react";
import { api } from "../lib/api";
import { useAction } from "../lib/store";
import { Card, Field } from "../components/ui";

type S = Record<string, any>;
const GROUPS: { title: string; fields: { key: string; label: string; hint?: string; step?: number; options?: string[] }[] }[] = [
  { title: "Feature windows", fields: [
    { key: "window_seconds", label: "Window size (s)", hint: "Sliding window length" },
    { key: "hop_seconds", label: "Hop (s)", hint: "How often windows are computed" },
    { key: "long_horizon_seconds", label: "Long horizon (s)", hint: "History for slow behaviours" },
    { key: "min_events_per_ip", label: "Min events per IP", hint: "Sparser sources are grouped by traffic shape" },
    { key: "baseline_seconds", label: "Baseline period (s)", hint: "Presumed-benign start of each replay" },
  ] },
  { title: "Similarity & detection", fields: [
    { key: "similarity_threshold", label: "Match threshold", step: 0.01 },
    { key: "weight_numeric", label: "Weight: numeric cosine", step: 0.05 },
    { key: "weight_categorical", label: "Weight: categorical Jaccard", step: 0.05 },
    { key: "anomaly_contamination", label: "Isolation Forest contamination", step: 0.005 },
    { key: "episode_gap_seconds", label: "Episode gap (s)", hint: "Quiet time that ends an episode" },
    { key: "alert_dedupe_seconds", label: "Alert dedupe window (s)" },
  ] },
  { title: "Clustering (HDBSCAN)", fields: [
    { key: "cluster_interval_seconds", label: "Cluster every (s)" },
    { key: "min_cluster_size", label: "min_cluster_size" },
    { key: "min_samples", label: "min_samples" },
    { key: "cluster_buffer_size", label: "Window buffer size" },
  ] },
  { title: "Rules & decoys", fields: [
    { key: "rule_mode", label: "Mode", options: ["suggest", "auto"] },
    { key: "rule_min_severity", label: "Min severity for a rule", options: ["low", "medium", "high", "critical"] },
    { key: "rule_expiry_seconds", label: "Default rule expiry (s)" },
    { key: "syn_rate_limit", label: "SYN limit /s per source" },
    { key: "udp_rate_limit", label: "UDP limit /s" },
    { key: "icmp_rate_limit", label: "ICMP limit /s" },
    { key: "http_rate_limit", label: "HTTP limit /s per source" },
    { key: "connlimit", label: "Max concurrent conns" },
    { key: "fake_accept_after", label: "Decoy fake login after N attempts", hint: "0 = never (for unresolved auth attempts)" },
  ] },
];

export default function SettingsPage() {
  const act = useAction();
  const [s, setS] = useState<S | null>(null);
  const [orig, setOrig] = useState<S | null>(null);
  useEffect(() => { api.get<S>("/api/settings").then((x) => { setS(x); setOrig(x); }); }, []);
  if (!s) return null;
  const dirty = JSON.stringify(s) !== JSON.stringify(orig);
  const save = () => act(async () => {
    const r = await api.put<{ settings: S; changed: string[] }>("/api/settings", s);
    setS(r.settings); setOrig(r.settings);
  }, "Settings saved");
  return (
    <div className="mx-auto flex max-w-[1200px] flex-col gap-4">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold">Settings</h1>
          <p className="text-sm text-ink2">Applied immediately. Changing window parameters resets the feature extractor's sliding state.</p>
        </div>
        <button className="btn btn-primary" disabled={!dirty} onClick={save}><Save size={14} />Save</button>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {GROUPS.map((g) => (
          <Card key={g.title} title={g.title}>
            <div className="grid grid-cols-2 gap-3">
              {g.fields.map((f) => (
                <Field key={f.key} label={f.label} hint={f.hint}>
                  {f.options ? (
                    <select className="input" value={s[f.key]} onChange={(e) => setS({ ...s, [f.key]: e.target.value })}>
                      {f.options.map((o) => <option key={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input className="input" type="number" step={f.step ?? 1} value={s[f.key]} onChange={(e) => setS({ ...s, [f.key]: e.target.value === "" ? "" : +e.target.value })} />
                  )}
                </Field>))}
            </div>
            {g.title.startsWith("Similarity") && (
              <p className="mt-3 text-xs text-muted">score = w₁·cosine(numeric) + w₂·containment(categorical), normalised by w₁+w₂. Default 0.6 / 0.4, threshold 0.85.</p>)}
          </Card>))}
      </div>
    </div>
  );
}
