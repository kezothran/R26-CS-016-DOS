import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    alerts as alerts_api,
    audit as audit_api,
    auth,
    block_actions as block_actions_api,
    health,
    metrics as metrics_api,
    playbooks as playbooks_api,
    scoring as scoring_api,
    settings as settings_api,
    snapshots as snapshots_api,
    users as users_api,
    whitelist,
)
from app.capture.privileges import check_capture_privileges
from app.detection.loop import run_detection_loop
from app.scoring.engine import resolve_orphaned_incidents
from app.ws.routes import router as ws_router

# Without this, every logging.getLogger("soc").info/.warning/.exception call in the app
# (detection loop, scoring engine, etc.) was silently dropped - no handler was ever attached to
# the root logger, so anything below WARNING never reached a stream, and even WARNING+ only hit
# Python's bare "handler of last resort" with no timestamp/module context. Uvicorn's own request
# log lines were unaffected (uvicorn configures its own loggers independently); this only adds
# visibility for the application's own logging.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

logger = logging.getLogger("soc")

app = FastAPI(title="SOC Flood Detection Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://localhost:3001",
        # Temporary Cloudflare quick-tunnel origin for a demo session (started 2026-09-01)
        # - exact origin only, not a wildcard on *.trycloudflare.com, so a stranger's unrelated
        # tunnel can't piggyback on this CORS allowance. Remove once the demo tunnel is torn down.
        "https://sleeps-however-testing-voip.trycloudflare.com",
    ],
    # Dev environments that proxy/forward the frontend's port (e.g. localhost:3000 exposed to
    # the browser as localhost:3010) still need requests from that forwarded origin allowed.
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(whitelist.router)
app.include_router(settings_api.router)
app.include_router(scoring_api.router)
app.include_router(alerts_api.router)
app.include_router(block_actions_api.router)
app.include_router(metrics_api.router)
app.include_router(users_api.router)
app.include_router(playbooks_api.router)
app.include_router(audit_api.router)
app.include_router(snapshots_api.router)
app.include_router(health.router)
app.include_router(ws_router)


@app.on_event("startup")
async def on_startup() -> None:
    check_capture_privileges()
    await resolve_orphaned_incidents()
    await playbooks_api.seed_default_playbooks()
    asyncio.create_task(run_detection_loop())
    logger.info("Detection loop started.")
