"""
WebSocketManager – manages all active WebSocket connections.

One global singleton is used by the ingest pipeline to broadcast
new attack events to every connected dashboard client in real-time.

Why WebSocket over SSE?
  - Bi-directional: client can send filter preferences
  - Better browser support across all environments
  - No polling overhead – pure push-based delivery
  - Works through all proxies when upgraded correctly
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Thread-safe connection registry with broadcast capability.

    Connections are stored keyed by client id (unique per WebSocket handshake).
    Dead connections are silently removed on broadcast failure.
    """

    def __init__(self):
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self, client_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections[client_id] = ws
        logger.info("WebSocket connected: %s (total=%d)", client_id, len(self._connections))

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            self._connections.pop(client_id, None)
        logger.info("WebSocket disconnected: %s (total=%d)", client_id, len(self._connections))

    # ── Broadcast ─────────────────────────────────────────────────────────────

    async def broadcast(self, message: dict[str, Any]) -> None:
        """
        Send a JSON message to all connected clients.
        Stale/closed connections are removed automatically.
        """
        if not self._connections:
            return

        payload = json.dumps(message, default=str)
        dead: list[str] = []

        async with self._lock:
            clients = list(self._connections.items())

        for client_id, ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(client_id)

        if dead:
            async with self._lock:
                for cid in dead:
                    self._connections.pop(cid, None)
            logger.debug("Removed %d stale WebSocket connections.", len(dead))

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# ── Global singleton (created once, reused everywhere) ───────────────────────
ws_manager = WebSocketManager()
