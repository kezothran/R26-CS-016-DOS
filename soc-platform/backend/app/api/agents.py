"""Remote capture agents: enrolment, fleet management (admin/dashboard side) and the agent-facing
ingest API.

Dashboard side  (/api/agents, JWT):  create one-time enrolment tokens, list the fleet with live
                                     status, rename / revoke / delete agents.
Agent side      (/agent/v1):         enrol with a token, pull config, push capture windows, heartbeat.

Security model: enrolment tokens and agent keys are random, stored only as SHA-256 hashes, and
compared in constant time. Agents authenticate every request with `X-Agent-Key: <agent_id>.<secret>`;
revoking an agent takes effect on its next request. Windows contain packet metadata only (addresses,
ports, sizes, flags - never payload) and are validated and capped before they reach the detectors.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json as _json
import zipfile
from pathlib import Path
import hmac
import ipaddress
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import agents_buffer, audit, settings_cache, whitelist_cache
from app.auth.security import get_current_user, require_role
from app.config import settings
from app.db.base import get_session
from app.db.models import Agent, AgentToken, Alert, User
from app.detection.registry import ACTIVE_ATTACKS

admin_router = APIRouter(prefix="/api/agents", tags=["agents"])
agent_router = APIRouter(prefix="/agent/v1", tags=["agent"])

BUCKETS = ("icmp", "syn", "fragmentation", "udp")
MAX_ROWS_PER_BUCKET = 50_000

# Row fields the detectors read (see app/capture/engine.py) with the type each must be coerced to.
_INT_FIELDS = ("length", "icmp_seq", "dport", "sport", "proto", "ttl", "ip_len", "tcp_sport", "tcp_dport",
               "tcp_flags", "tcp_window", "tcp_header_len", "tcp_payload_len")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _is_ip(value: object) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _clean_row(raw: object) -> dict | None:
    """Validates and re-builds one packet-metadata row; returns None for anything malformed."""
    if not isinstance(raw, dict):
        return None
    if not (_is_ip(raw.get("src")) and _is_ip(raw.get("dst"))):
        return None
    try:
        row: dict = {"time": float(raw["time"]), "src": str(raw["src"]), "dst": str(raw["dst"]), "iface": str(raw.get("iface") or "?")[:40]}
        for f in _INT_FIELDS:
            row[f] = int(raw.get(f) or 0)
        icmp_type = raw.get("icmp_type")
        row["icmp_type"] = int(icmp_type) if icmp_type is not None else None
    except (KeyError, TypeError, ValueError):
        return None
    return row


# ---------------------------------------------------------------- agent authentication

async def current_agent(
    x_agent_key: str | None = Header(default=None), session: AsyncSession = Depends(get_session),
) -> Agent:
    if not x_agent_key or "." not in x_agent_key:
        raise HTTPException(status_code=401, detail="Missing agent key")
    agent_id, _, _secret = x_agent_key.partition(".")
    try:
        agent = await session.get(Agent, uuid.UUID(agent_id))
    except ValueError:
        agent = None
    if agent is None or not hmac.compare_digest(agent.key_hash, _hash(x_agent_key)):
        raise HTTPException(status_code=401, detail="Invalid agent key")
    if agent.revoked:
        raise HTTPException(status_code=403, detail="This agent has been revoked")
    return agent


# ---------------------------------------------------------------- dashboard side

class TokenBody(BaseModel):
    note: str | None = Field(default=None, max_length=120)
    ttl_hours: int = Field(default=24, ge=1, le=168)


@admin_router.post("/enrollment-tokens")
async def create_enrollment_token(
    body: TokenBody, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    """Returns the token ONCE - only its hash is stored."""
    token = "sxe_" + secrets.token_urlsafe(24)
    expires = datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)
    session.add(AgentToken(token_hash=_hash(token), note=body.note, created_by=user.id, expires_at=expires))
    await audit.log(session, user.id, "agent.token_created", "agent_token", _hash(token)[:12], {"note": body.note, "ttl_hours": body.ttl_hours})
    await session.commit()
    return {"token": token, "expires_at": expires.isoformat()}


AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"


def build_bundle(server: str, token: str, name: str | None) -> bytes:
    """Windows install bundle: the agent exe (if built), one-click installer scripts, a bundle.json with
    the server address + one-time token, and the Python agent / Linux installer under other-os/."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def add_text(arc: str, text: str) -> None:
            if arc.endswith(".cmd"):
                text = text.replace("\r\n", "\n").replace("\n", "\r\n")  # cmd.exe wants CRLF
            z.writestr(arc, text)

        for f in ("INSTALL.cmd", "UNINSTALL.cmd", "install_exe.ps1", "README.txt"):
            add_text(f, (AGENT_DIR / "bundle" / f).read_text(encoding="utf-8"))
        exe = AGENT_DIR / "dist" / "sentrix-agent.exe"
        if exe.exists():
            z.write(exe, "sentrix-agent.exe")
        ui_exe = AGENT_DIR / "dist" / "sentrix-agent-ui.exe"
        if ui_exe.exists():
            z.write(ui_exe, "sentrix-agent-ui.exe")
        for f in ("sentrix_agent.py", "agent_ui.py", "requirements.txt", "install_windows.ps1", "install_linux.sh", "README.md"):
            p = AGENT_DIR / f
            if p.exists():
                z.writestr(f"other-os/{f}", p.read_text(encoding="utf-8"))
        z.writestr("bundle.json", _json.dumps({"server": server, "token": token, "name": name}, indent=2))
    return buf.getvalue()


class BundleBody(BaseModel):
    server_url: str = Field(min_length=8, max_length=200)
    name: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=120)
    ttl_hours: int = Field(default=24, ge=1, le=168)


@admin_router.post("/bundle")
async def download_bundle(
    body: BundleBody, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    """Creates a fresh one-time token and returns a ready-to-send install zip containing it."""
    server = body.server_url.strip().rstrip("/")
    if not server.startswith(("http://", "https://")) or " " in server:
        raise HTTPException(status_code=400, detail="server_url must look like http://100.x.y.z:8000")
    token = "sxe_" + secrets.token_urlsafe(24)
    expires = datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)
    session.add(AgentToken(token_hash=_hash(token), note=body.note or f"bundle {body.name or ''}".strip(), created_by=user.id, expires_at=expires))
    await audit.log(session, user.id, "agent.bundle_created", "agent_token", _hash(token)[:12], {"server": server, "name": body.name})
    await session.commit()
    data = build_bundle(server, token, body.name.strip() if body.name else None)
    fname = f"SentrixAgent-Bundle{('-' + body.name.strip().replace(' ', '_')) if body.name else ''}.zip"
    return Response(data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _agent_out(a: Agent, alerts_24h: int) -> dict:
    now = datetime.now(timezone.utc)
    seen = a.last_seen_at
    online = bool(seen) and (now - seen).total_seconds() <= settings.agent_online_secs and not a.revoked
    return {
        "id": str(a.id), "name": a.name, "hostname": a.hostname, "os": a.os, "agent_version": a.agent_version,
        "remote_ip": a.remote_ip, "interfaces": a.interfaces, "revoked": a.revoked,
        "status": "revoked" if a.revoked else ("online" if online else "offline"),
        "enrolled_at": a.enrolled_at.isoformat(), "last_seen_at": seen.isoformat() if seen else None,
        "last_window_packets": a.last_window_packets, "total_packets": a.total_packets, "alerts_24h": alerts_24h,
    }


@admin_router.get("")
async def list_agents(user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    agents = (await session.execute(select(Agent).order_by(Agent.enrolled_at.desc()))).scalars().all()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    host_expr = func.split_part(Alert.iface, "@", 2)
    counts = dict((await session.execute(
        select(host_expr, func.count()).where(Alert.created_at >= since, Alert.iface.like("%@%")).group_by(host_expr)
    )).all())
    rows = [_agent_out(a, int(counts.get(a.hostname, 0))) for a in agents]
    return {
        "online_window_secs": settings.agent_online_secs,
        "local_capture": settings.local_capture,
        "summary": {
            "total": len(rows), "online": sum(r["status"] == "online" for r in rows),
            "offline": sum(r["status"] == "offline" for r in rows), "revoked": sum(r["status"] == "revoked" for r in rows),
        },
        "agents": rows,
    }


class AgentPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    revoked: bool | None = None


@admin_router.patch("/{agent_id}")
async def patch_agent(
    agent_id: uuid.UUID, body: AgentPatch, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if body.name is not None:
        agent.name = body.name.strip()
    if body.revoked is not None:
        agent.revoked = body.revoked
    await audit.log(session, user.id, "agent.updated", "agent", str(agent_id), body.model_dump(exclude_none=True))
    await session.commit()
    return _agent_out(agent, 0)


@admin_router.delete("/{agent_id}")
async def delete_agent(
    agent_id: uuid.UUID, user: User = Depends(require_role("admin")), session: AsyncSession = Depends(get_session),
):
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    await audit.log(session, user.id, "agent.deleted", "agent", str(agent_id), {"hostname": agent.hostname})
    await session.execute(delete(Agent).where(Agent.id == agent_id))
    await session.commit()
    return {"ok": True}


# ---------------------------------------------------------------- agent side

_enroll_attempts: dict[str, list[float]] = {}


class EnrollBody(BaseModel):
    token: str
    hostname: str = Field(min_length=1, max_length=120)
    os: str | None = Field(default=None, max_length=120)
    version: str | None = Field(default=None, max_length=40)
    interfaces: list[str] = Field(default_factory=list, max_length=50)


@agent_router.post("/enroll")
async def enroll(body: EnrollBody, request: Request, session: AsyncSession = Depends(get_session)):
    ip = request.client.host if request.client else "?"
    now = time.time()
    recent = [t for t in _enroll_attempts.get(ip, []) if now - t < 60]
    if len(recent) >= 10:
        raise HTTPException(status_code=429, detail="Too many enrolment attempts - wait a minute")
    _enroll_attempts[ip] = recent + [now]

    token = (await session.execute(select(AgentToken).where(AgentToken.token_hash == _hash(body.token)))).scalar_one_or_none()
    if token is None or token.used_at is not None or token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Enrolment token is invalid, already used or expired")

    agent_id = uuid.uuid4()
    key = f"{agent_id}.{secrets.token_urlsafe(32)}"
    agent = Agent(
        id=agent_id, name=body.hostname, hostname=body.hostname, os=body.os, agent_version=body.version,
        remote_ip=ip, interfaces=body.interfaces, key_hash=_hash(key), last_seen_at=datetime.now(timezone.utc),
    )
    session.add(agent)
    await session.flush()
    token.used_at = datetime.now(timezone.utc)
    token.used_by_agent = agent_id
    if token.created_by:
        await audit.log(session, token.created_by, "agent.enrolled", "agent", str(agent_id), {"hostname": body.hostname, "ip": ip})
    await session.commit()
    return {"agent_id": str(agent_id), "agent_key": key, "name": agent.name}


def _config_payload(agent: Agent) -> dict:
    cfg = settings_cache.current()
    with whitelist_cache._lock:  # read the cache's three collections atomically
        wl = {"ips": sorted(whitelist_cache._ips), "networks": list(whitelist_cache._networks), "ports": sorted(whitelist_cache._ports)}
    return {
        "agent_name": agent.name, "window_secs": cfg.get("window_secs", 5), "whitelist": wl,
        "dashboard_url": settings.dashboard_url,
        "active_attacks": list(ACTIVE_ATTACKS), "server_time": time.time(),
    }


@agent_router.get("/config")
async def agent_config(agent: Agent = Depends(current_agent), session: AsyncSession = Depends(get_session)):
    agent.last_seen_at = datetime.now(timezone.utc)
    await session.commit()
    return _config_payload(agent)


class HeartbeatBody(BaseModel):
    version: str | None = None
    interfaces: list[str] | None = None


@agent_router.post("/heartbeat")
async def heartbeat(
    body: HeartbeatBody, request: Request, agent: Agent = Depends(current_agent), session: AsyncSession = Depends(get_session),
):
    agent.last_seen_at = datetime.now(timezone.utc)
    agent.remote_ip = request.client.host if request.client else agent.remote_ip
    if body.version:
        agent.agent_version = body.version
    if body.interfaces is not None:
        agent.interfaces = body.interfaces[:50]
    await session.commit()
    return {"ok": True}


@agent_router.post("/windows")
async def ingest_window(
    request: Request, agent: Agent = Depends(current_agent), session: AsyncSession = Depends(get_session),
):
    """One capture window from an agent: `{"window_secs": 5, "buckets": {"icmp": [rows], ...}}`,
    optionally gzip-compressed (Content-Encoding: gzip)."""
    limit = settings.agent_max_body_mb * 1024 * 1024
    raw = await request.body()
    if len(raw) > limit:
        raise HTTPException(status_code=413, detail="Window too large")
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise HTTPException(status_code=400, detail="Bad gzip body") from exc
        if len(raw) > limit * 6:
            raise HTTPException(status_code=413, detail="Window too large")
    try:
        import json

        payload = json.loads(raw)
        buckets_in = payload.get("buckets", {})
        assert isinstance(buckets_in, dict)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Body must be JSON with a 'buckets' object") from exc

    clean: dict[str, list[dict]] = {}
    dropped = 0
    for name in BUCKETS:
        rows_in = buckets_in.get(name) or []
        if not isinstance(rows_in, list):
            continue
        rows = []
        for r in rows_in[:MAX_ROWS_PER_BUCKET]:
            row = _clean_row(r)
            # The server's whitelist is authoritative - the agent's copy can be a few windows stale.
            if row is None or whitelist_cache.is_whitelisted(row["src"]) or whitelist_cache.is_whitelisted(row["dst"]):
                dropped += 1
                continue
            rows.append(row)
        if rows:
            clean[name] = rows

    accepted = agents_buffer.push(agent.hostname, clean)
    agent.last_seen_at = datetime.now(timezone.utc)
    agent.last_window_packets = accepted
    agent.total_packets = (agent.total_packets or 0) + accepted
    await session.commit()
    return {"accepted": accepted, "dropped": dropped}
