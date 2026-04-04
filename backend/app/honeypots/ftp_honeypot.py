"""
FTP Honeypot – raw asyncio TCP server.
Emulates a real FTP server: captures credentials and commands.
No external library required beyond the stdlib.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

BANNER   = "220 Microsoft FTP Service\r\n"
FAKE_CWD = "/public"


class _FTPSession(asyncio.Protocol):
    """One FTP session per TCP connection."""

    def __init__(self, honeypot: FTPHoneypot):
        self._hp = honeypot
        self._transport: Optional[asyncio.Transport] = None
        self._peer_ip   = "0.0.0.0"
        self._peer_port = 0
        self._username  = ""
        self._buffer    = b""

    # ── asyncio.Protocol callbacks ─────────────────────────────────────────

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport
        peer = transport.get_extra_info("peername", ("0.0.0.0", 0))
        self._peer_ip, self._peer_port = peer[0], peer[1]
        logger.info("[FTP] Connection from %s:%d", self._peer_ip, self._peer_port)
        self._write(BANNER)

    def data_received(self, data: bytes):
        self._buffer += data
        while b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            self._handle_command(line.decode("utf-8", errors="ignore").strip())

    def connection_lost(self, exc):
        logger.debug("[FTP] Connection closed: %s:%d", self._peer_ip, self._peer_port)

    # ── FTP command dispatcher ──────────────────────────────────────────────

    def _handle_command(self, line: str):
        parts   = line.split(" ", 1)
        cmd     = parts[0].upper()
        arg     = parts[1] if len(parts) > 1 else ""

        logger.debug("[FTP] %s:%d → %s %s", self._peer_ip, self._peer_port, cmd, arg)

        handlers = {
            "USER": self._cmd_user,
            "PASS": self._cmd_pass,
            "SYST": lambda a: self._write("215 UNIX Type: L8\r\n"),
            "PWD":  lambda a: self._write(f'257 "{FAKE_CWD}" is current directory\r\n'),
            "LIST": lambda a: self._write("150 Opening data connection\r\n226 Transfer complete\r\n"),
            "RETR": self._cmd_retr,
            "STOR": self._cmd_stor,
            "QUIT": self._cmd_quit,
            "NOOP": lambda a: self._write("200 NOOP ok\r\n"),
            "TYPE": lambda a: self._write("200 Type set to I\r\n"),
            "PASV": lambda a: self._write("227 Entering Passive Mode (127,0,0,1,10,24)\r\n"),
        }

        handler = handlers.get(cmd)
        if handler:
            handler(arg)
        else:
            severity = self._hp._classify_command(line)
            self._hp._post_event(
                self._hp._build_event(
                    source_ip=self._peer_ip,
                    source_port=self._peer_port,
                    username=self._username,
                    command=line,
                    severity=severity,
                    method="FTP_COMMAND",
                )
            )
            self._write(f"500 '{cmd}': command not understood\r\n")

    # ── Individual command handlers ─────────────────────────────────────────

    def _cmd_user(self, username: str):
        self._username = username
        self._write(f"331 Password required for {username}\r\n")

    def _cmd_pass(self, password: str):
        logger.info("[FTP] Credentials | ip=%s user=%s pass=%s",
                    self._peer_ip, self._username, password)
        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer_ip,
                source_port=self._peer_port,
                username=self._username,
                password=password,
                severity="HIGH",
                method="PASSWORD_AUTH",
            )
        )
        self._write("230 User logged in.\r\n")

    def _cmd_retr(self, filename: str):
        logger.info("[FTP] File retrieval attempt | ip=%s file=%s", self._peer_ip, filename)
        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer_ip,
                source_port=self._peer_port,
                username=self._username,
                command=f"RETR {filename}",
                severity="HIGH",
                endpoint=filename,
            )
        )
        self._write("550 Permission denied.\r\n")

    def _cmd_stor(self, filename: str):
        logger.info("[FTP] File upload attempt | ip=%s file=%s", self._peer_ip, filename)
        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer_ip,
                source_port=self._peer_port,
                username=self._username,
                command=f"STOR {filename}",
                severity="CRITICAL",
                endpoint=filename,
            )
        )
        self._write("550 Permission denied.\r\n")

    def _cmd_quit(self, _arg: str):
        self._write("221 Goodbye.\r\n")
        if self._transport:
            self._transport.close()

    def _write(self, data: str):
        if self._transport and not self._transport.is_closing():
            self._transport.write(data.encode())


class FTPHoneypot(BaseHoneypot):
    protocol = "FTP"

    def __init__(self):
        super().__init__()
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self, port: int) -> None:
        loop = asyncio.get_event_loop()
        try:
            self._server = await loop.create_server(
                lambda: _FTPSession(self),
                host="",
                port=port,
            )
            self._running = True
            logger.info("[FTP] Honeypot listening on port %d", port)
        except Exception as exc:
            logger.error("[FTP] Failed to start honeypot: %s", exc)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[FTP] Honeypot stopped.")
