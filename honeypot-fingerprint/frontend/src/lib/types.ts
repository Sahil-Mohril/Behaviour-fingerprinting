export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface EventRow {
  seq: number; ts: number; src_ip: string; src_port: number | null; dst_ip: string | null; dst_service: string;
  dst_port: number | null; protocol: string; tcp_flags: string | null; packet_size: number | null; bytes: number | null;
  packets: number | null; duration: number | null; http_method: string | null; http_path: string | null;
  user_agent: string | null; username: string | null; password: string | null; command: string | null;
  payload_snippet: string | null; response_code: number | null; session_id: string | null; event_type: string;
  source: string; ground_truth_label: string; campaign_id: string; country: string; asn: string; action: string;
  rule_id: string | null; honeypot_note: string | null;
}

export interface RadarPoint { axis: string; value: number; z: number }

export interface FingerprintSummary {
  id: string; name: string; category: string; category_name: string; severity: Severity; confidence: number;
  status: "active" | "candidate" | "dismissed"; benign: boolean; origin: string; hit_count: number; n_windows: number;
  first_seen: number; last_seen: number; n_ips: number; episodes: number; version: number; top_ips: string[];
  returning: boolean; top_features: Importance[]; radar?: RadarPoint[];
}
export interface Importance { feature: string; z: number; value: number | null; baseline: number }
export interface Episode { id: string; start: number; end: number; hits: number; returning: boolean; repeat_sources: boolean; n_ips: number; ips: string[] }

export interface FingerprintDetail extends FingerprintSummary {
  centroid: Record<string, number | null>; spread: Record<string, number | null>; importance: Importance[];
  category_reasons: string[]; traits: Record<string, { token: string; count: number }[]>;
  ips: { ip: string; hits: number }[]; asns: { asn: string; hits: number }[]; countries: { country: string; hits: number }[];
  episodes: Episode[] & any; versions: { version: number; t: number; reason: string; n_windows: number; category: string; confidence: number }[];
  timeline: [number, number][]; notes: string[]; radar: RadarPoint[]; rules: Rule[]; alerts: Alert[];
}

export interface Alert {
  id: string; type: "match" | "returning" | "anomaly" | "new_fingerprint"; title: string; fp_id: string | null;
  fp_name: string; category: string; severity: Severity; base_severity: Severity; first_seen: number; last_seen: number;
  count: number; status: "open" | "acknowledged" | "resolved"; ips: string[]; entity: string; score: number;
  breakdown: any; explanation: string; episode_id: string | null; rule_ids: string[];
  escalations: { t: number; from: string; to: string; count: number }[];
}

export interface Rule {
  id: string; fp_id: string; fp_name: string; category: string; episode_id: string | null; kind: string;
  params: Record<string, any>; reason: string; created: number; expires: number;
  status: "suggested" | "approved" | "active" | "expired" | "rejected"; history: { t: number; status: string; by: string }[];
  hits: number; rev: number; alert_id: string | null; formats: Record<string, string>; n_ips: number; edited: boolean;
}

export interface SeriesPoint { t: number; accepted: number; dropped: number; by_cat: Record<string, number> }
export interface Narration { t: number; text: string; kind: string }
export interface Marker { t: number; rule_id: string; label: string }

export interface Kpis {
  events_total: number; accepted: number; dropped: number; events_per_sec: number; active_attackers: number;
  open_alerts: number; active_rules: number; suggested_rules: number; fingerprints: number; candidates: number;
  baseline_ready: boolean; now: number; rule_mode: "suggest" | "auto";
}

export interface ReplayStatus {
  state: "idle" | "running" | "paused" | "finished"; t: number; end_t: number; speed: number; base_epoch: number;
  now: number; remaining_events: number; total_events: number; effective_speed: number; catalog_status: string;
  plan: null | { name: string; mode: string; note: string; fast_until: number; selections: any[];
    script: { t: number; action: string; args: any; done: boolean }[] };
}

export interface Source {
  id: string; path: string; name: string; size: number; adapter: string | null; status: string; rows: number;
  fixture: boolean; error?: string;
  labels: Record<string, { count: number; t_min: number | null; t_max: number | null; behaviour: string }>;
}

export interface Behaviour { key: string; name: string; severity: Severity; benign: boolean; dataset_labels: string[]; data_source: string; note: string }
