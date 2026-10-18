export function fmtNum(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "–";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + "k";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function fmtTime(epoch: number | null | undefined): string {
  if (!epoch) return "–";
  return new Date(epoch * 1000).toLocaleTimeString([], { hour12: false });
}

export function fmtRel(epoch: number | null | undefined, base: number | null | undefined): string {
  if (!epoch || !base) return "–";
  const s = Math.max(0, epoch - base);
  const m = Math.floor(s / 60);
  return `T+${m}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
}

export function fmtPct(x: number | null | undefined): string {
  return x === null || x === undefined ? "–" : `${(x * 100).toFixed(1)}%`;
}

export function fmtDuration(s: number | null | undefined): string {
  if (s === null || s === undefined) return "–";
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`;
}

export function featureLabel(f: string): string {
  return f.replace(/^log_/, "").replace(/_/g, " ");
}
