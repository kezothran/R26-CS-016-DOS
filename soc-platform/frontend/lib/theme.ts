// Mirrors app/detection/registry.py's `color` field for each attack module. Kept in sync by
// hand for now (only 3 active entries); if this list grows, consider exposing color via the
// backend's /health response instead of duplicating it here.
export const ATTACK_THEME: Record<string, { label: string; color: string; icon: string }> = {
  icmp: { label: "ICMP Flood", color: "#ef4444", icon: "⚠" },
  syn: { label: "SYN Flood", color: "#a78bfa", icon: "⚠" },
  fragmentation: { label: "Fragmentation Flood", color: "#f59e0b", icon: "⚠" },
  udp: { label: "UDP Flood", color: "#3b9cff", icon: "⚠" },
};

export const DEFAULT_THEME = { label: "Normal", color: "#22c55e", icon: "✓" };

export function themeFor(attackType: string | null) {
  if (!attackType) return DEFAULT_THEME;
  return ATTACK_THEME[attackType] ?? DEFAULT_THEME;
}

// One severity ramp shared by every tier scale in the app - the per-event tier
// (LOW/MEDIUM/HIGH/CRITICAL from backend/app/detection/base.py::assign_tier_by_pps),
// the incident tier (Low/Medium/High/Critical from app/scoring/incident_scorer.py),
// and the aggregate dashboard tier (Normal/Elevated/High/Critical from
// app/scoring/aggregate.py). Validated with the dataviz skill's validate_palette.js
// against this app's dark card surface (#161b22): CVD-separation and contrast both
// pass; ship with direct labels/legends per the skill's mitigation for the one
// adjacent pair that sits just under the normal-vision floor.
export const SEVERITY = {
  good: "#0ca30c",
  warning: "#fab219",
  serious: "#ec835a",
  critical: "#d03b3b",
} as const;

type SeverityRole = keyof typeof SEVERITY;

const TIER_TO_SEVERITY: Record<string, SeverityRole> = {
  Low: "good", LOW: "good", Normal: "good",
  Medium: "warning", MEDIUM: "warning", Elevated: "warning",
  High: "serious", HIGH: "serious",
  Critical: "critical", CRITICAL: "critical",
};

export function severityColor(tier: string | null | undefined): string {
  const role = (tier && TIER_TO_SEVERITY[tier]) || "good";
  return SEVERITY[role];
}

export function tierTheme(tier: string | null | undefined): { label: string; color: string } {
  return { label: tier ?? "Normal", color: severityColor(tier) };
}
