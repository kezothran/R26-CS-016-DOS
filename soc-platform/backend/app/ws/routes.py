from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.auth.security import decode_token
from app.ws.broadcaster import manager

router = APIRouter()


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str):
    try:
        decode_token(token)  # raises HTTPException -> connection refused below if invalid
    except Exception:
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # client sends nothing meaningful; just detects disconnect
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
