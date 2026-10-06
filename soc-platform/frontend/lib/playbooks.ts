// Static recommended-response-steps content, shown in the Incidents queue detail panel's
// Evidence/Playbook tab. Genuinely static per attack type - no DB table needed for this.

export const PLAYBOOKS: Record<string, string[]> = {
  icmp: [
    "Confirm the flagged source IP(s) against the whitelist - legitimate monitoring tools (ping sweeps, uptime checks) can trigger ICMP volume alerts.",
    "Check ICMP rate-limiting/throttling on the affected interface's edge device.",
    "If confirmed malicious, propose a block via the incident's Block Action tab (dry-run - requires manual execution).",
    "Escalate to network team if the source is internal (possible compromised host).",
  ],
  syn: [
    "Check SYN backlog/half-open connection count on the destination host - SYN floods exhaust the connection table.",
    "Enable SYN cookies on the affected host/load balancer if not already active.",
    "Correlate source IP(s) against known botnet/scanner threat intel if available.",
    "Propose a block for sustained high-confidence sources via the Block Action tab.",
  ],
  fragmentation: [
    "Verify this isn't legitimate large-payload traffic (some protocols fragment normally) before escalating.",
    "Check for teardrop-style overlapping fragment patterns in the evidence panel, a stronger malicious signal than fragmentation alone.",
    "Consider a fragment-reassembly timeout/limit on the edge firewall if not already configured.",
  ],
  udp: [
    "Check for UDP reflection/amplification signatures (e.g. small request, large unsolicited response) in the evidence panel.",
    "Rate-limit or ACL the affected UDP service port(s) if externally reachable.",
    "Propose a block for confirmed flood sources via the Block Action tab.",
  ],
};

export const DEFAULT_PLAYBOOK = [
  "Review the evidence panel for the flagged flow features and confidence scores.",
  "Cross-check the source IP(s) against the whitelist and any available threat intel.",
  "Assign to an analyst and move to Investigating once triage begins.",
];

export function playbookFor(attackTypes: string[]): string[] {
  for (const t of attackTypes) {
    if (PLAYBOOKS[t]) return PLAYBOOKS[t];
  }
  return DEFAULT_PLAYBOOK;
}
