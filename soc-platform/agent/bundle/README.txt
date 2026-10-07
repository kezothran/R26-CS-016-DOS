SENTRIX AGENT - INSTALL GUIDE (Windows)
=======================================

What this does
  Watches the network traffic of THIS computer and sends only packet metadata
  (addresses, ports, sizes) to the Sentrix security dashboard. It never sends the
  content of your traffic, files or passwords. It only connects OUT to the server.

Before you install (once)
  1. Connect to the VPN: install Tailscale (https://tailscale.com/download),
     sign in with the account you were invited with, and check that it says "Connected".
  2. Install Npcap (https://npcap.com) - during setup tick
     "Install Npcap in WinPcap API-compatible Mode".

Install
  1. Unzip this folder anywhere (e.g. your Desktop).
  2. Double-click INSTALL.cmd and click YES when Windows asks for permission.
  3. Wait for the green "Done" message. That's it - the agent now starts by itself
     every time the PC boots.

Check it works
  The dashboard owner should see your computer as ONLINE on the Agents page.
  On your PC you can also run (in an Administrator PowerShell):
     & "C:\Program Files\SentrixAgent\sentrix-agent.exe" status

If something fails
  - "Cannot reach the server"   -> the VPN is not connected. Open Tailscale and sign in.
  - "Npcap is not installed"     -> install it (link above), then run INSTALL.cmd again.
  - "Enrolment token ... used or expired" -> ask for a new bundle (each is single-use).
  - Windows SmartScreen / antivirus warns about sentrix-agent.exe -> it is not code-signed
    (this is a student project). Choose "More info > Run anyway" if you trust whoever sent it.

Uninstall
  Double-click UNINSTALL.cmd.

SECURITY NOTE: this zip contains a one-time enrolment token. Do not share it publicly.
It stops working after the first install or when it expires.
