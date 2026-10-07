# Deploying Sentrix to AWS

Everything here was tested locally before use: both Docker images build cleanly, and the
backend image was run locally in cloud mode (`LOCAL_CAPTURE=false`) and confirmed to connect to
the real Supabase database, load all four trained models, and serve `/health` - with zero
Administrator/root/Npcap needed (that's only required for *local* packet capture).

## 1. Create your AWS account (you do this)

1. https://aws.amazon.com/free → **Create a Free Account**.
2. Needs a card (not charged unless you exceed free-tier limits) and phone verification.
3. Pick the **Basic support plan (Free)**.
4. **IAM → Users → Create user**
   - Name: `sentrix-deploy`
   - Attach policy: `AdministratorAccess`
   - Create an **access key** → "Command Line Interface (CLI)" → download the CSV.
5. On this PC, run `aws configure` (already installed) and paste in the Access Key ID / Secret
   from that CSV when prompted, region `ap-south-1` (Mumbai), format `json`. The keys are typed
   directly into that prompt, never pasted into chat.

## 2. Provision the server

```
cd soc-platform/cloud
./provision_ec2.sh
```

Creates (idempotent - safe to re-run):
- A `t3.medium` (4GB RAM, 2 vCPU - needed for TensorFlow/XGBoost; the free-tier `t2/t3.micro`'s
  1GB is not enough) Ubuntu 22.04 instance, 30GB disk.
- A security group open on 22 (SSH), 3000 (frontend), 8000 (backend API/agents).
- A key pair saved as `sentrix-key.pem` next to the script - this is the only copy, keep it.
- An Elastic IP, so the address never changes even across a stop/start.

Writes `cloud/instance_info.env` with the public IP and instance ID.

## 3. Deploy

```
./deploy.sh
```

Installs Docker on the server (first run only), copies the app code and `backend/.env` over SSH,
and runs `docker compose up -d --build`. Takes a few minutes the first time (same TensorFlow
build as the local test). Re-run with `./deploy.sh --app-only` for a faster update once Docker is
already installed.

## 4. Verify

```
curl http://<public-ip>:8000/health
```

Open `http://<public-ip>:3000` in a browser - log in with the same admin account as before (same
database). Point any agent's `--server` at `http://<public-ip>:8000`.

## 5. Point agents and the VPN at the cloud server

- New agents: use that IP in the install bundle instead of your PC's Tailscale address.
- Existing agents (faran, mayu, noel): re-run `INSTALL.cmd` with a bundle built for the new
  address (the installer is safe to re-run - see `agent/README.md`), or edit
  `agent.json`'s `"server"` field directly and restart the `SentrixAgent` task.
- If agents should keep reaching the server over the private Tailscale network rather than the
  public internet: install `tailscale` on the EC2 instance too (`curl -fsSL https://tailscale.com/install.sh | sh`
  then `sudo tailscale up`), and use its `100.x.x.x` address instead of the public IP - then the
  security group's 8000/3000 rules can be tightened to the Tailscale CIDR only.

## Cost

- `t3.medium` on-demand: ~$0.0416/hr in `ap-south-1` (~$30/month if left running 24/7). The
  trial's ~$200-300 credit covers roughly 2-3 months of this one instance.
- EBS 30GB gp3: ~$2.40/month.
- To stop the clock without losing anything: `aws ec2 stop-instances --instance-ids <id>` (Elastic
  IP keeps billing a small amount while stopped unless released - `aws ec2 release-address`).

## Rollback / teardown

```
aws ec2 terminate-instances --instance-ids $(grep INSTANCE_ID cloud/instance_info.env | cut -d= -f2)
aws ec2 release-address --allocation-id <alloc-id-from-the-console>
```
