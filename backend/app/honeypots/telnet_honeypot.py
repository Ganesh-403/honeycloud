from __future__ import annotations

import asyncio
from typing import Optional

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

BANNER = b"\r\nWelcome to the HoneyCloud Telnet Service\r\nLogin: "

class _TelnetSession(asyncio.Protocol):
    def __init__(self, honeypot: TelnetHoneypot):
        self._hp = honeypot
        self._transport: Optional[asyncio.Transport] = None
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0
        self._username = ""
        self._password_attempt = ""
        self._state = "USERNAME"
        self._buffer = b""

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername", ("0.0.0.0", 0))
        self._peer_ip, self._peer_port = peer[0], peer[1]
        logger.info("[TELNET] Connection from %s:%d", self._peer_ip, self._peer_port)
        self._write(BANNER)

    def data_received(self, data: bytes):
        self._buffer += data
        if b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            self._handle_line(line.decode("utf-8", errors="ignore").strip())

    def connection_lost(self, exc):
        logger.debug("[TELNET] Connection closed: %s:%d", self._peer_ip, self._peer_port)

    def _handle_line(self, line: str):
        if self._state == "USERNAME":
            self._username = line
            self._write(b"Password: ")
            self._state = "PASSWORD"
        elif self._state == "PASSWORD":
            self._password_attempt = line
            logger.info("[TELNET] Credentials | ip=%s user=%s pass=%s",
                        self._peer_ip, self._username, self._password_attempt)
            self._hp._post_event(
                self._hp._build_event(
                    source_ip=self._peer_ip,
                    source_port=self._peer_port,
                    username=self._username,
                    password=self._password_attempt,
                    severity="HIGH",
                    method="PASSWORD_AUTH",
                )
            )
            self._write(b"Login incorrect\r\nLogin: ")
            self._state = "USERNAME"
        else:
            # This state should not be reached with current logic, but for future command handling
            logger.debug("[TELNET] Command | ip=%s cmd=%s", self._peer_ip, line)
            self._hp._post_event(
                self._hp._build_event(
                    source_ip=self._peer_ip,
                    source_port=self._peer_port,
                    username=self._username,
                    command=line,
                    severity="MEDIUM",
                    method="TELNET_COMMAND",
                )
            )
            self._write(b"Unknown command: " + line.encode() + b"\r\n")

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)


class TelnetHoneypot(BaseHoneypot):
    protocol = "TELNET"

    def __init__(self):
        super().__init__()
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self, port: int) -> None:
        loop = asyncio.get_event_loop()
        try:
            self._server = await loop.create_server(
                lambda: _TelnetSession(self),
                host="",
                port=port,
            )
            self._running = True
            logger.info("[TELNET] Honeypot listening on port %d", port)
        except Exception as exc:
            logger.error("[TELNET] Failed to start honeypot: %s", exc)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[TELNET] Honeypot stopped.")
