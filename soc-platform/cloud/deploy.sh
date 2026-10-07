#!/usr/bin/env bash
# Deploys/updates Sentrix on the EC2 instance provisioned by provision_ec2.sh.
# Run from Windows Git Bash / WSL after provision_ec2.sh has produced instance_info.env.
#
#   ./deploy.sh            # first deploy or a full redeploy
#   ./deploy.sh --app-only # just push updated code + restart containers (skip Docker install etc.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

[ -f "$HERE/instance_info.env" ] || { echo "Run provision_ec2.sh first."; exit 1; }
source "$HERE/instance_info.env"
[ -f "$ROOT/backend/.env" ] || { echo "backend/.env is missing - it holds DATABASE_URL etc. and is needed on the server."; exit 1; }

SSH="ssh -o StrictHostKeyChecking=accept-new -i $KEY_FILE ubuntu@$PUBLIC_IP"
SCP="scp -o StrictHostKeyChecking=accept-new -i $KEY_FILE"

echo "== Waiting for SSH on $PUBLIC_IP =="
for i in $(seq 1 30); do $SSH -o ConnectTimeout=5 true 2>/dev/null && break; sleep 5; done

if [ "${1:-}" != "--app-only" ]; then
  echo "== Installing Docker on the server (first run only) =="
  $SSH 'bash -s' <<'REMOTE'
    if ! command -v docker >/dev/null; then
      curl -fsSL https://get.docker.com | sudo sh
      sudo usermod -aG docker ubuntu
      sudo systemctl enable --now docker
    fi
REMOTE
fi

echo "== Copying the app to the server (excluding node_modules/.venv/models cache etc.) =="
$SSH "mkdir -p ~/sentrix"
tar -C "$ROOT" --exclude='frontend/node_modules' --exclude='frontend/.next' --exclude='backend/.venv' \
    --exclude='backend/__pycache__' --exclude='**/__pycache__' --exclude='*.log' --exclude='.git' \
    -czf /tmp/sentrix.tar.gz backend frontend docker-compose.yml
$SCP /tmp/sentrix.tar.gz ubuntu@$PUBLIC_IP:~/sentrix/
$SSH "cd ~/sentrix && tar xzf sentrix.tar.gz && rm sentrix.tar.gz"

echo "== Uploading backend/.env (not in the tarball - never committed to git) =="
$SCP "$ROOT/backend/.env" ubuntu@$PUBLIC_IP:~/sentrix/backend/.env

echo "== Building and starting containers =="
$SSH "cd ~/sentrix && PUBLIC_API_URL=http://$PUBLIC_IP:8000 sudo docker compose up -d --build"

echo ""
echo "== Done =="
echo "Backend:  http://$PUBLIC_IP:8000/health"
echo "Frontend: http://$PUBLIC_IP:3000"
echo "Logs:     $SSH 'cd ~/sentrix && sudo docker compose logs -f'"
