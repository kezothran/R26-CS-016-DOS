#!/usr/bin/env python3
"""Sentrix Agent - small desktop app (the "app launcher").

Shows whether this PC is connected to the Sentrix dashboard and lets you start / stop / reconnect the
background agent. It only reads status.json written by the agent and never touches the agent key.
Stdlib only (tkinter), so it stays tiny. Actions that need Administrator (start / stop the service)
ask Windows for permission only at that moment.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
import time
import tkinter as tk
import webbrowser
from pathlib import Path

TASK = "SentrixAgent"
IS_WIN = platform.system() == "Windows"


def home() -> Path:
    if os.environ.get("SENTRIX_AGENT_HOME"):
        return Path(os.environ["SENTRIX_AGENT_HOME"])
    if IS_WIN:
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SentrixAgent"
    return Path("/etc/sentrix-agent")


HOME = home()
STATUS = HOME / "status.json"
LOG = HOME / "agent.log"
FLAG = HOME / "reconnect.flag"
CFG = HOME / "agent.json"

BG, CARD, TEXT, MUTED = "#0B1B33", "#12294A", "#E8EEF7", "#8DA2BF"
GREEN, AMBER, RED, BLUE = "#3FB950", "#E3B341", "#F85149", "#58A6FF"
STALE_SECS = 10


def read_status() -> dict | None:
    try:
        return json.loads(STATUS.read_text())
    except (OSError, ValueError):
        return None


def evaluate(st: dict | None) -> tuple[str, str, str, str]:
    """(colour, headline, detail, kind) kind: ok | retry | stopped | none | revoked"""
    if st is None:
        if CFG.exists():
            return RED, "Agent is not running", "Press Start to run it. It also starts automatically when the PC boots.", "stopped"
        return RED, "Not set up on this PC", "Run INSTALL.cmd from the Sentrix Agent bundle to enrol this computer.", "none"
    age = time.time() - st.get("updated", 0)
    if st.get("state") == "revoked":
        return RED, "Disconnected by the administrator", st.get("last_error") or "This agent was revoked or deleted on the dashboard.", "revoked"
    if age > STALE_SECS:
        return RED, "Agent is not running", "Press Start to run it. It also starts automatically when the PC boots.", "stopped"
    if st.get("state") != "running":
        return AMBER, "Starting...", st.get("last_error") or "Waiting for the server and the network drivers.", "retry"
    if st.get("connected"):
        return GREEN, "Connected to the dashboard", "Everything is working. This PC is being monitored.", "ok"
    return AMBER, "Reconnecting...", (st.get("last_error") or "No contact with the server.") + " The agent keeps trying and queues data meanwhile.", "retry"


def ago(ts: float) -> str:
    if not ts:
        return "never"
    s = max(0, int(time.time() - ts))
    return f"{s}s ago" if s < 60 else (f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago")


def run_elevated(cmdline: str) -> None:
    """Runs a cmd.exe command line as Administrator (UAC prompt), hidden."""
    if not IS_WIN:
        return
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {cmdline}", None, 0)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Sentrix Agent")
        root.configure(bg=BG)
        root.minsize(520, 0)
        root.resizable(False, False)

        head = tk.Frame(root, bg=BG)
        head.pack(fill="x", padx=18, pady=(16, 6))
        tk.Label(head, text="SENTRIX", bg=BG, fg=TEXT, font=("Segoe UI", 15, "bold")).pack(side="left")
        tk.Label(head, text="  Agent", bg=BG, fg=BLUE, font=("Segoe UI", 15)).pack(side="left")
        self.ver = tk.Label(head, text="", bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.ver.pack(side="right")

        card = tk.Frame(root, bg=CARD)
        card.pack(fill="x", padx=18, pady=6)
        row = tk.Frame(card, bg=CARD)
        row.pack(fill="x", padx=14, pady=(14, 4))
        self.dot = tk.Canvas(row, width=22, height=22, bg=CARD, highlightthickness=0)
        self.dot.pack(side="left")
        self.circle = self.dot.create_oval(3, 3, 19, 19, fill=RED, outline="")
        self.headline = tk.Label(row, text="", bg=CARD, fg=TEXT, font=("Segoe UI", 14, "bold"))
        self.headline.pack(side="left", padx=8)
        self.detail = tk.Label(card, text="", bg=CARD, fg=MUTED, font=("Segoe UI", 9), wraplength=440, justify="left", anchor="w")
        self.detail.pack(fill="x", padx=14, pady=(0, 14), anchor="w")

        info = tk.Frame(root, bg=BG)
        info.pack(fill="x", padx=18, pady=4)
        self.fields: dict[str, tk.Label] = {}
        for i, (key, label) in enumerate([
            ("name", "Computer"), ("server", "Server"), ("contact", "Last contact"), ("packets", "Packets (last window)"),
            ("sent", "Windows sent"), ("queued", "Waiting to send"), ("ifaces", "Watching"),
        ]):
            tk.Label(info, text=label, bg=BG, fg=MUTED, font=("Segoe UI", 9), anchor="w", width=20).grid(row=i, column=0, sticky="w", pady=2)
            v = tk.Label(info, text="-", bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold"), anchor="w", wraplength=300, justify="left")
            v.grid(row=i, column=1, sticky="w", pady=2)
            self.fields[key] = v

        btns = tk.Frame(root, bg=BG)
        btns.pack(fill="x", padx=18, pady=(14, 4))
        self.b_reconnect = self._btn(btns, "Reconnect now", self.reconnect, primary=True)
        self.b_start = self._btn(btns, "Start", self.start)
        self.b_stop = self._btn(btns, "Stop", self.stop)
        self.b_restart = self._btn(btns, "Restart", self.restart)
        btns2 = tk.Frame(root, bg=BG)
        btns2.pack(fill="x", padx=18, pady=4)
        self.b_log = self._btn(btns2, "View log", self.view_log)
        self.b_dash = self._btn(btns2, "Open dashboard", self.open_dashboard)
        self.note = tk.Label(root, text="", bg=BG, fg=AMBER, font=("Segoe UI", 9), wraplength=480, justify="left", anchor="w")
        self.note.pack(fill="x", padx=18, pady=(8, 0), anchor="w")
        tk.Label(root, text="The agent runs in the background even when this window is closed.", bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(side="bottom", pady=8)

        self.refresh()

    def _btn(self, parent, text, cmd, primary=False):
        b = tk.Button(parent, text=text, command=cmd, bg=BLUE if primary else CARD, fg="#fff" if primary else TEXT,
                      activebackground="#2F6FD1", activeforeground="#fff", relief="flat", padx=12, pady=6, font=("Segoe UI", 9, "bold"), cursor="hand2")
        b.pack(side="left", padx=(0, 8))
        return b

    # ---- actions
    def say(self, msg: str) -> None:
        self.note.config(text=msg)
        self.root.after(8000, lambda: self.note.config(text=""))

    def reconnect(self):
        try:
            FLAG.write_text("1")
        except OSError:
            run_elevated(f'echo 1> "{FLAG}"')
        self.say("Reconnect requested - the agent will retry within a few seconds.")

    def start(self):
        run_elevated(f"schtasks /run /tn {TASK}")
        self.say("Starting the agent (approve the Windows prompt)...")

    def stop(self):
        run_elevated(f"schtasks /end /tn {TASK} & taskkill /f /im sentrix-agent.exe")
        self.say("Stopping the agent (approve the Windows prompt). Monitoring pauses until you press Start.")

    def restart(self):
        run_elevated(f"schtasks /end /tn {TASK} & taskkill /f /im sentrix-agent.exe & timeout /t 2 /nobreak >nul & schtasks /run /tn {TASK}")
        self.say("Restarting the agent (approve the Windows prompt)...")

    def view_log(self):
        if LOG.exists():
            try:
                os.startfile(str(LOG))  # type: ignore[attr-defined]
            except (AttributeError, OSError):
                self.say(f"Log file: {LOG}")
        else:
            self.say("No log yet - the agent has not run on this PC.")

    def open_dashboard(self):
        st = read_status() or {}
        url = st.get("dashboard_url") or ""
        if url and "localhost" not in url and "127.0.0.1" not in url:
            webbrowser.open(url)
        else:
            self.say("The dashboard address is not set up for remote PCs. Ask the dashboard owner for the link.")

    # ---- refresh
    def refresh(self):
        st = read_status()
        colour, headline, detail, kind = evaluate(st)
        self.dot.itemconfig(self.circle, fill=colour)
        self.headline.config(text=headline)
        self.detail.config(text=detail)
        st = st or {}
        self.ver.config(text=f"v{st.get('version', '')}" if st.get("version") else "")
        running = kind in ("ok", "retry")
        iface = st.get("interfaces") or []
        vals = {
            "name": st.get("name") or "-", "server": st.get("server") or "-",
            "contact": ago(st.get("last_ok", 0)) if running else "-",
            "packets": f"{st.get('window_packets', 0):,}" if running else "-",
            "sent": f"{st.get('windows_sent', 0):,}" if running else "-",
            "queued": f"{st.get('queued', 0):,}" if running else "-",
            "ifaces": (f"{len(iface)} interfaces" + (": " + ", ".join(iface[:3]) + ("..." if len(iface) > 3 else ""))) if iface else "-",
        }
        for k, v in vals.items():
            self.fields[k].config(text=v)
        self.b_reconnect.config(state="normal" if running else "disabled")
        self.b_start.config(state="normal" if kind in ("stopped",) and IS_WIN else "disabled")
        self.b_stop.config(state="normal" if running and IS_WIN else "disabled")
        self.b_restart.config(state="normal" if kind in ("ok", "retry", "stopped") and IS_WIN else "disabled")
        self.root.after(1500, self.refresh)


def main() -> None:
    if IS_WIN:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
