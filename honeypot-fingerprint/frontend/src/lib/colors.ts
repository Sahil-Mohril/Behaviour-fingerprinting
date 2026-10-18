/**
 * Colour follows the entity: every behaviour category belongs to one fixed family, and each
 * family owns one validated categorical slot (dark: worst adjacent CVD dE 8.4, normal dE 19.3).
 * There are more categories than safe hues, so charts stack/colour by family and name the
 * category in tooltips and labels.
 */
export const FAMILIES = [
  { key: "recon", name: "Recon / scans", color: "var(--s1)" },
  { key: "flood", name: "Floods / DoS", color: "var(--s2)" },
  { key: "bruteforce", name: "Brute force", color: "var(--s3)" },
  { key: "web", name: "Web probing", color: "var(--s4)" },
  { key: "c2", name: "C2 / malware", color: "var(--s5)" },
  { key: "intrusion", name: "Intrusion", color: "var(--s6)" },
  { key: "unknown", name: "Unknown anomaly", color: "var(--s7)" },
  { key: "benign", name: "Benign", color: "var(--benign)" },
  { key: "unclassified", name: "Unclassified", color: "var(--unclassified)" },
] as const;
export type FamilyKey = (typeof FAMILIES)[number]["key"];

const CATEGORY_FAMILY: Record<string, FamilyKey> = {
  port_scan_fast: "recon", port_scan_slow: "recon",
  syn_flood: "flood", udp_flood: "flood", icmp_flood: "flood", http_flood: "flood", slowloris: "flood",
  ssh_bruteforce: "bruteforce", ftp_bruteforce: "bruteforce", web_bruteforce: "bruteforce", credential_stuffing: "bruteforce",
  web_vuln_probe: "web", scraper: "web",
  botnet_c2: "c2", malware_download: "c2",
  post_login_shell: "intrusion", infiltration: "intrusion",
  unknown_anomaly: "unknown",
  benign: "benign", crawler: "benign",
  unmatched: "unclassified",
};

export function familyOf(category: string | null | undefined): FamilyKey {
  return CATEGORY_FAMILY[category ?? "unmatched"] ?? "unknown";
}
export function familyColor(f: FamilyKey): string {
  return FAMILIES.find((x) => x.key === f)!.color;
}
export function categoryColor(category: string | null | undefined): string {
  return familyColor(familyOf(category));
}

export const SEVERITY_STYLE: Record<string, { color: string; icon: string }> = {
  info: { color: "var(--text-muted)", icon: "i" },
  low: { color: "var(--good)", icon: "▾" },
  medium: { color: "var(--warning)", icon: "▴" },
  high: { color: "var(--serious)", icon: "▲" },
  critical: { color: "var(--critical)", icon: "⬣" },
};
