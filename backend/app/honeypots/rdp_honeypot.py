from __future__ import annotations

import asyncio
from typing import Optional

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

class _RDPSession(asyncio.Protocol):
    def __init__(self, honeypot: RDPHoneypot):
        self._hp = honeypot
        self._transport: Optional[asyncio.Transport] = None
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername", ("0.0.0.0", 0))
        self._peer_ip, self._peer_port = peer[0], peer[1]
        logger.info("[RDP] Connection from %s:%d", self._peer_ip, self._peer_port)
        
        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer_ip,
                source_port=self._peer_port,
                severity="HIGH",
                method="RDP_CONNECTION",
                command="RDP connection attempt",
            )
        )
        # Immediately close the connection after logging
        self._transport.close()

    def data_received(self, data: bytes):
        # Log any data received, though we expect to close quickly
        logger.debug("[RDP] Data received from %s:%d: %s", self._peer_ip, self._peer_port, data.hex())

    def connection_lost(self, exc):
        logger.debug("[RDP] Connection closed: %s:%d", self._peer_ip, self._peer_port)


class RDPHoneypot(BaseHoneypot):
    protocol = "RDP"

    def __init__(self):
        super().__init__()
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self, port: int) -> None:
        loop = asyncio.get_event_loop()
        try:
            self._server = await loop.create_server(
                lambda: _RDPSession(self),
                host="",
                port=port,
            )
            self._running = True
            logger.info("[RDP] Honeypot listening on port %d", port)
        except Exception as exc:
            logger.error("[RDP] Failed to start honeypot: %s", exc)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[RDP] Honeypot stopped.")
