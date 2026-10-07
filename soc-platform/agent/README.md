# Sentrix Agent

Installs on every PC / server you want to monitor. It captures that machine's traffic, drops whitelisted
addresses, and ships **packet metadata only** (addresses, ports, sizes, TCP flags - never payload) to the
Sentrix server, where the detection models run. Alerts appear in the dashboard with the host in the
interface column, e.g. `Wi-Fi@LAPTOP-1`.

## Install (about 2 minutes per machine)

1. In the dashboard open **Agents → + Add agent**, set the address the agent will connect to, and click
   **Generate install commands**. The one-time token is shown once.
2. Copy this `agent/` folder to the target machine.
3. Run the matching command, elevated:

| OS | Command |
|---|---|
| Windows (PowerShell as Administrator) | `.\install_windows.ps1 -Server "http://10.8.0.1:8000" -Token "sxe_..."` |
| Linux (root) | `sudo ./install_linux.sh --server http://10.8.0.1:8000 --token sxe_...` |

Prerequisites: Python 3.10+. Windows also needs [Npcap](https://npcap.com) with "WinPcap API-compatible mode".
The installers create a virtual environment, enrol the agent, and register it to start at boot
(Windows scheduled task as SYSTEM, Linux systemd unit with only `CAP_NET_RAW`/`CAP_NET_ADMIN`).

## Commands

```
python sentrix_agent.py status         # is the server reachable, is the key accepted, how many windows are queued
python sentrix_agent.py test-capture   # sniff 3 s and show what was seen (checks privileges / Npcap)
python sentrix_agent.py selftest       # send a tiny harmless window to the server
python sentrix_agent.py run            # normal operation (the service runs this)
```

## How it behaves

- **Outbound only** - it opens no listening ports. Put the server behind a VPN and point `--server` at the VPN address.
- **Config from the cloud** - capture window length and the whitelist are pulled from the server every minute.
- **Offline queue** - if the server or VPN is unreachable, windows are spooled to disk (up to ~200 MB) and replayed in order.
- **Heartbeat** every 30 s; the Agents page shows online / offline and last-seen time.
- **Revocation** - an admin can revoke or delete an agent; it stops itself on its next request (exit code 3, not restarted).
- **Keys** - the agent key lives in `agent.json` (Windows `%ProgramData%\SentrixAgent`, Linux `/etc/sentrix-agent`, mode 600).
  The server stores only a hash of it.

## Server side

Run the backend in cloud mode so it only receives agent traffic (no packet sniffing, no Administrator/root needed):

```
LOCAL_CAPTURE=false
```

in `backend/.env`. With the default `LOCAL_CAPTURE=true` the server keeps sniffing its own interfaces **and** accepts agents.
