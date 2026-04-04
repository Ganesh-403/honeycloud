"""
SSH Honeypot – asyncssh-based implementation.
Emulates an Ubuntu 20.04 SSH server. Logs credentials and commands.

Requires: pip install asyncssh
"""
from __future__ import annotations

import asyncio
from typing import Optional

try:
    import asyncssh
    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False

from app.core.logging import get_logger
from app.honeypots.base import BaseHoneypot

logger = get_logger(__name__)

FAKE_BANNER = "Ubuntu 20.04.6 LTS"
FAKE_PROMPT = "$ "
FAKE_RESPONSES = {
    "whoami":   "root",
    "id":       "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu 5.15.0-76-generic #83-Ubuntu SMP x86_64 GNU/Linux",
    "ls":       "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  sys  tmp  usr  var",
    "pwd":      "/root",
}


class _HoneypotServerInterface(asyncssh.SSHServerInterface if HAS_ASYNCSSH else object):
    """Accepts ALL authentication attempts – that's the point of a honeypot."""

    def __init__(self, honeypot: SSHHoneypot, peer_addr: str, peer_port: int):
        self._hp = honeypot
        self._peer = (peer_addr, peer_port)
        self._username = ""

    def begin_auth(self, username: str):
        self._username = username
        return True   # require auth (so attacker submits credentials)

    def password_auth_supported(self):
        return True

    def validate_password(self, username: str, password: str) -> bool:
        logger.info("[SSH] Auth attempt | ip=%s user=%s pass=%s",
                    self._peer[0], username, password)
        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer[0],
                source_port=self._peer[1],
                username=username,
                password=password,
                severity="HIGH",
                method="PASSWORD_AUTH",
            )
        )
        return True   # always accept → honeypot


class _HoneypotSession(asyncssh.SSHServerSession if HAS_ASYNCSSH else object):
    def __init__(self, honeypot: SSHHoneypot, username: str,
                 peer_addr: str, peer_port: int):
        self._hp = honeypot
        self._username = username
        self._peer = (peer_addr, peer_port)
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        chan.write(f"\r\nWelcome to {FAKE_BANNER}\r\nLast login: Mon Jan 01 00:00:00 2024\r\n{FAKE_PROMPT}")

    def data_received(self, data: bytes, datatype):
        command = data.decode("utf-8", errors="ignore").strip()
        if not command:
            return

        severity = self._hp._classify_command(command)
        logger.info("[SSH] Command | ip=%s user=%s sev=%s cmd=%r",
                    self._peer[0], self._username, severity, command)

        self._hp._post_event(
            self._hp._build_event(
                source_ip=self._peer[0],
                source_port=self._peer[1],
                username=self._username,
                command=command,
                severity=severity,
                method="COMMAND",
            )
        )

        response = FAKE_RESPONSES.get(
            command, f"bash: {command}: command not found"
        )
        self._chan.write(f"\r\n{response}\r\n{FAKE_PROMPT}")

    def eof_received(self):
        if self._chan:
            self._chan.exit(0)


class SSHHoneypot(BaseHoneypot):
    protocol = "SSH"

    def __init__(self):
        super().__init__()
        self._server: Optional[asyncssh.SSHAcceptor] = None

    async def start(self, port: int) -> None:
        if not HAS_ASYNCSSH:
            logger.warning("[SSH] asyncssh not installed – SSH honeypot disabled.")
            return

        def server_factory():
            return _HoneypotServerInterface(self, "", 0)

        def session_factory(username=""):
            peer = ("0.0.0.0", 0)
            return _HoneypotSession(self, username, *peer)

        try:
            self._server = await asyncssh.create_server(
                server_factory,
                host="",
                port=port,
                server_host_keys=["ssh_host_key"],
                process_factory=None,
                session_factory=session_factory,
                server_version=f"SSH-2.0-OpenSSH_8.9p1 {FAKE_BANNER}",
            )
            self._running = True
            logger.info("[SSH] Honeypot listening on port %d", port)
        except Exception as exc:
            logger.error("[SSH] Failed to start honeypot: %s", exc)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self._running = False
        logger.info("[SSH] Honeypot stopped.")
