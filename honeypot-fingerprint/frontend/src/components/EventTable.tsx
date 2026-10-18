import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { fmtTime } from "../lib/format";
import type { EventRow } from "../lib/types";

const COLS: { key: string; label: string; w: string; render: (e: EventRow) => string }[] = [
  { key: "ts", label: "Time", w: "84px", render: (e) => fmtTime(e.ts) },
  { key: "src", label: "Source", w: "150px", render: (e) => `${e.src_ip}${e.src_port ? ":" + e.src_port : ""}` },
  { key: "dst", label: "Dest", w: "120px", render: (e) => `${e.dst_service}:${e.dst_port ?? "-"}` },
  { key: "proto", label: "Proto", w: "60px", render: (e) => `${e.protocol}${e.tcp_flags ? " " + e.tcp_flags : ""}` },
  { key: "type", label: "Type", w: "80px", render: (e) => e.event_type },
  { key: "detail", label: "Detail", w: "minmax(220px,1fr)", render: (e) => detail(e) },
  { key: "geo", label: "Geo", w: "60px", render: (e) => e.country },
  { key: "label", label: "Ground truth", w: "150px", render: (e) => e.ground_truth_label || "—" },
  { key: "action", label: "Action", w: "90px", render: (e) => (e.action === "dropped" ? `⛔ ${e.rule_id}` : "✓") },
];

function detail(e: EventRow): string {
  if (e.command) return `$ ${e.command}`;
  if (e.username !== null && e.username !== undefined) return `login ${e.username}/${e.password ?? ""} → ${e.response_code ?? "?"}`;
  if (e.http_path) return `${e.http_method ?? ""} ${e.http_path} ${e.response_code ?? ""}`;
  const parts = [];
  if (e.packets !== null) parts.push(`${e.packets} pkts`);
  if (e.bytes !== null) parts.push(`${e.bytes} B`);
  if (e.duration !== null) parts.push(`${e.duration.toFixed(2)} s`);
  if (e.honeypot_note) parts.push(e.honeypot_note);
  return parts.join(" · ") || e.payload_snippet || "";
}

/** Virtualised: renders only visible rows, so thousands of rows stay smooth. */
export function EventTable({ rows, height = 420 }: { rows: EventRow[]; height?: number }) {
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => 28, overscan: 12 });
  const grid = useMemo(() => COLS.map((c) => c.w).join(" "), []);
  return (
    <div className="overflow-x-auto">
      <div className="min-w-[1000px]">
        <div className="grid border-b border-line px-2 py-1.5 text-[11px] uppercase tracking-wide text-muted" style={{ gridTemplateColumns: grid }}>
          {COLS.map((c) => <div key={c.key} className="truncate px-1">{c.label}</div>)}
        </div>
        <div ref={parent} style={{ height }} className="overflow-y-auto">
          <div style={{ height: v.getTotalSize(), position: "relative" }}>
            {v.getVirtualItems().map((it) => {
              const e = rows[it.index];
              return (
                <div key={it.key} className="absolute left-0 right-0 grid items-center border-b border-line px-2 font-mono text-[12px] text-ink2 hover:bg-surface2"
                  style={{ top: it.start, height: it.size, gridTemplateColumns: grid, opacity: e.action === "dropped" ? 0.6 : 1 }}>
                  {COLS.map((c) => <div key={c.key} className="truncate px-1" title={c.render(e)}>{c.render(e)}</div>)}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
