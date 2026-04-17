from __future__ import annotations

import asyncio
from typing import Optional

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

BANNER = b"220 honeypot.local ESMTP Postfix\r\n"

class _SMTPSession(asyncio.Protocol):
    def __init__(self, honeypot: SMTPHoneypot):
        self._hp = honeypot
        self._transport: Optional[asyncio.Transport] = None
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0
        self._state = "HELO"
        self._buffer = b""
        self._mail_from = ""
        self._rcpt_to = []
        self._data = []

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername", ("0.0.0.0", 0))
        self._peer_ip, self._peer_port = peer[0], peer[1]
        logger.info("[SMTP] Connection from %s:%d", self._peer_ip, self._peer_port)
        self._write(BANNER)

    def data_received(self, data: bytes):
        self._buffer += data
        if b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            self._handle_command(line.decode("utf-8", errors="ignore").strip())

    def connection_lost(self, exc):
        logger.debug("[SMTP] Connection closed: %s:%d", self._peer_ip, self._peer_port)

    def _handle_command(self, line: str):
        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        logger.debug("[SMTP] %s:%d → %s %s", self._peer_ip, self._peer_port, cmd, arg)

        handlers = {
            "HELO": self._cmd_helo,
            "EHLO": self._cmd_helo,
            "MAIL": self._cmd_mail,
            "RCPT": self._cmd_rcpt,
            "DATA": self._cmd_data,
            "QUIT": self._cmd_quit,
            "RSET": self._cmd_rset,
            "NOOP": lambda a: self._write(b"250 Ok\r\n"),
        }

        handler = handlers.get(cmd)
        if handler:
            handler(arg)
        else:
            self._hp._post_event(
                self._hp._build_event(
                    source_ip=self._peer_ip,
                    source_port=self._peer_port,
                    command=line,
                    severity="MEDIUM",
                    method="SMTP_COMMAND",
                )
            )
            self._write(b"500 Error: command not understood\r\n")

    def _cmd_helo(self, arg: str):
        self._write(b"250 honeypot.local\r\n")

    def _cmd_mail(self, arg: str):
        if arg.upper().startswith("FROM:"):
            self._mail_from = arg[5:].strip()
            self._write(b"250 Ok\r\n")
        else:
            self._write(b"501 Syntax: MAIL FROM:<address>\r\n")

    def _cmd_rcpt(self, arg: str):
        if arg.upper().startswith("TO:"):
            self._rcpt_to.append(arg[3:].strip())
            self._write(b"250 Ok\r\n")
        else:
            self._write(b"501 Syntax: RCPT TO:<address>\r\n")

    def _cmd_data(self, arg: str):
        self._write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        self._state = "DATA_RECEIVING"

    def _cmd_quit(self, arg: str):
        self._write(b"221 Bye\r\n")
        if self._transport:
            self._transport.close()

    def _cmd_rset(self, arg: str):
        self._mail_from = ""
        self._rcpt_to = []
        self._data = []
        self._write(b"250 Ok\r\n")

    def _write(self, data: bytes):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data)


class SMTPHoneypot(BaseHoneypot):
    protocol = "SMTP"

    def __init__(self):
        super().__init__()
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self, port: int) -> None:
        loop = asyncio.get_event_loop()
        try:
            self._server = await loop.create_server(
                lambda: _SMTPSession(self),
                host="",
                port=port,
            )
            self._running = True
            logger.info("[SMTP] Honeypot listening on port %d", port)
        except Exception as exc:
            logger.error("[SMTP] Failed to start honeypot: %s", exc)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[SMTP] Honeypot stopped.")
