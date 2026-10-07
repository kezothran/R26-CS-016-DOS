#!/usr/bin/env bash
# Installs the Sentrix Agent on Linux as a systemd service.
#
#   sudo ./install_linux.sh --server http://10.8.0.1:8000 --token sxe_...  [--name myhost]
#
# Needs: python3 (+ python3-venv). Runs as an unprivileged user with only CAP_NET_RAW/CAP_NET_ADMIN.
# Uninstall: sudo systemctl disable --now sentrix-agent; sudo rm -rf /opt/sentrix-agent /etc/sentrix-agent /etc/systemd/system/sentrix-agent.service
set -euo pipefail

SERVER=""; TOKEN=""; NAME="$(hostname)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token)  TOKEN="$2";  shift 2 ;;
    --name)   NAME="$2";   shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
[[ -n "$SERVER" && -n "$TOKEN" ]] || { echo "usage: sudo $0 --server URL --token TOKEN [--name NAME]"; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

DIR=/opt/sentrix-agent; CONF=/etc/sentrix-agent; HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
id sentrix-agent &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin sentrix-agent
mkdir -p "$DIR" "$CONF"
cp "$HERE/sentrix_agent.py" "$HERE/requirements.txt" "$DIR/"

echo "Creating virtual environment and installing dependencies..."
python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install --quiet --upgrade pip
"$DIR/venv/bin/pip" install --quiet -r "$DIR/requirements.txt"

echo "Enrolling with $SERVER ..."
SENTRIX_AGENT_HOME="$CONF" "$DIR/venv/bin/python" "$DIR/sentrix_agent.py" enroll --server "$SERVER" --token "$TOKEN" --name "$NAME"
chown -R sentrix-agent:sentrix-agent "$CONF"; chmod 700 "$CONF"

cat > /etc/systemd/system/sentrix-agent.service <<EOF
[Unit]
Description=Sentrix Agent
After=network-online.target
Wants=network-online.target

[Service]
User=sentrix-agent
Environment=SENTRIX_AGENT_HOME=$CONF
ExecStart=$DIR/venv/bin/python $DIR/sentrix_agent.py run
Restart=always
RestartSec=10
RestartPreventExitStatus=3
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sentrix-agent
echo
echo "Sentrix Agent installed and started."
echo "Logs:   journalctl -u sentrix-agent -f"
echo "Status: sudo SENTRIX_AGENT_HOME=$CONF $DIR/venv/bin/python $DIR/sentrix_agent.py status"
