"""
Event routes:
  POST /api/v1/events/ingest   – public, honeypot agents post here (rate-limited)
  GET  /api/v1/events/         – protected, paginated list with filters
  GET  /api/v1/events/stream   – protected, SSE real-time feed (legacy)
  WS   /api/v1/events/ws       – protected, WebSocket real-time feed (preferred)
"""
import asyncio
import json
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sse_starlette.sse import EventSourceResponse

from app.api.deps import get_event_service
from app.core.config import get_settings
from app.core.security import get_current_user
from app.core.websocket_manager import ws_manager
from app.schemas.auth import UserInDB
from app.schemas.event import EventFilters, EventIngest, EventResponse, IngestResponse, LocationInfo
from app.services.event_service import EventService
from app.services.geo_service import resolve_ip

router = APIRouter(prefix="/events", tags=["Events"])
settings = get_settings()


def _get_real_ip(request: Request) -> str:
    for header in ("X-Forwarded-For", "X-Real-IP"):
        value = request.headers.get(header)
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ── Ingest (PUBLIC, rate-limited) ─────────────────────────────────────────────

@router.post(
    "/ingest",
    response_model=IngestResponse,
    status_code=201,
    summary="Ingest honeypot event (public)",
)
def ingest_event(
    payload: EventIngest,
    request: Request,
    background_tasks: BackgroundTasks,
    svc: EventService = Depends(get_event_service),
):
    """
    Public endpoint consumed by honeypot agents.
    Returns 201 immediately; geo-IP lookup, profiling, and alerts
    execute as background tasks (non-blocking).
    """
    source_ip = resolve_ip(payload.source_ip or _get_real_ip(request))
    event = svc.ingest(payload, source_ip, background_tasks=background_tasks)
    return IngestResponse(status="received", id=event.id)


# ── List (PROTECTED) ──────────────────────────────────────────────────────────

@router.get("/", response_model=list[EventResponse], summary="List attack events")
def list_events(
    filters: EventFilters = Depends(),
    current_user: UserInDB = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
):
    return [_model_to_response(e) for e in svc.list_events(filters)]


# ── SSE stream (PROTECTED, legacy) ────────────────────────────────────────────

@router.get("/stream", summary="Real-time SSE event feed (legacy)")
async def event_stream(
    current_user: UserInDB = Depends(get_current_user),
    svc: EventService = Depends(get_event_service),
):
    """Server-Sent Events – polls DB every 2s. Use /ws for lower latency."""
    async def generator():
        last_id = 0
        while True:
            events = svc.list_events(EventFilters(limit=500))
            for e in events:
                if e.id > last_id:
                    last_id = e.id
                    yield {
                        "event": "new_attack",
                        "data": json.dumps(
                            _model_to_response(e).model_dump(), default=str
                        ),
                    }
            await asyncio.sleep(2)

    return EventSourceResponse(generator())


# ── WebSocket (PROTECTED) ─────────────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_feed(websocket: WebSocket):
    """
    WebSocket real-time event feed.

    Authentication: pass JWT as query param:
      ws://localhost:8000/api/v1/events/ws?token=<bearer_token>

    Message format (server → client):
      {
        "type": "new_attack",
        "data": { ...event fields... }
      }

    The client may also send:
      { "type": "ping" }
    and will receive:
      { "type": "pong", "connections": N }
    """
    token = websocket.query_params.get("token", "")
    username = _verify_ws_token(token)
    if not username:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    client_id = f"{username}:{uuid.uuid4().hex[:8]}"
    await ws_manager.connect(client_id, websocket)

    # Send welcome frame
    await websocket.send_json({
        "type": "connected",
        "client_id": client_id,
        "message": f"Welcome {username}! Streaming live attack events.",
    })

    try:
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=30)
                if msg.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "connections": ws_manager.connection_count,
                    })
            except asyncio.TimeoutError:
                # Keep-alive heartbeat
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(client_id)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _verify_ws_token(token: str) -> str | None:
    """Validate JWT for WebSocket auth. Returns username or None."""
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": True},
        )
        return payload.get("sub")
    except JWTError:
        return None


def _model_to_response(event) -> EventResponse:
    geo = event.geolocation or {}
    return EventResponse(
        id=event.id,
        timestamp=event.timestamp,
        service=event.service,
        source_ip=event.source_ip,
        source_port=event.source_port or 0,
        username=event.username,
        password=event.password,
        command=event.command,
        payload=event.payload,
        method=event.method or "UNKNOWN",
        endpoint=event.endpoint,
        severity=event.severity,
        ai_label=event.ai_label or "unknown",
        threat_score=event.threat_score or 0.0,
        location=LocationInfo(**geo) if geo else LocationInfo(),
        metadata=event.meta_data or {},
    )
