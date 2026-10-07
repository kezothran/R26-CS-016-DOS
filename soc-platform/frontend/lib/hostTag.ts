// Agent traffic is tagged "<interface>@<hostname>" by the backend (app/agents_buffer.py) so a
// remote PC's alerts/incidents can be told apart from this server's own local capture. This
// splits that back apart for display - everywhere an interface name is shown, the originating
// PC should be the headline, not buried inside a string like "Wi-Fi@mayu".

export interface ParsedInterface {
  iface: string;
  host: string | null; // null = this server's own local capture, not a remote agent
}

export function parseInterface(raw: string | null | undefined): ParsedInterface {
  const value = raw ?? "";
  const at = value.lastIndexOf("@");
  if (at === -1) return { iface: value, host: null };
  return { iface: value.slice(0, at), host: value.slice(at + 1) };
}

export function hostLabel(raw: string | null | undefined): string {
  const { host } = parseInterface(raw);
  return host ?? "This server";
}
