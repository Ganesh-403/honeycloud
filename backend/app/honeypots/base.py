"""
BaseHoneypot – abstract contract for all honeypot modules.

Every honeypot must:
- Declare a protocol name
- Implement start() / stop()
- Use _build_event() for a standardised event dict
- Call _post_event() to forward events to the ingest API
"""
from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class BaseHoneypot(abc.ABC):
    """Abstract base class for SSH, FTP, and HTTP honeypots."""

    protocol: str = "UNKNOWN"

    def __init__(self):
        self._settings = get_settings()
        self._running = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @abc.abstractmethod
    async def start(self, port: int) -> None:
        """Start listening on the given port."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the honeypot."""

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Event helpers ─────────────────────────────────────────────────────────

    def _build_event(
        self,
        source_ip: str,
        source_port: int,
        severity: str = "MEDIUM",
        **kwargs: Any,
    ) -> dict:
        """Return a standardised event payload ready for /api/v1/ingest."""
        return {
            "service":     self.protocol,
            "source_ip":   source_ip,
            "source_port": source_port,
            "severity":    severity,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }

    def _post_event(self, event: dict) -> None:
        """
        Forward event to the FastAPI ingest endpoint over localhost.
        Fire-and-forget; logs errors but never raises.
        """
        url = f"http://127.0.0.1:8000{self._settings.API_V1_PREFIX}/ingest"
        try:
            resp = requests.post(url, json=event, timeout=2)
            if not resp.ok:
                logger.warning(
                    "[%s] Ingest response %d: %s",
                    self.protocol, resp.status_code, resp.text[:200],
                )
        except Exception as exc:
            logger.error("[%s] Failed to post event: %s", self.protocol, exc)

    # ── Severity classification ────────────────────────────────────────────────

    @staticmethod
    def _classify_command(command: str) -> str:
        """Simple rule-based severity from command text."""
        cmd = command.lower()
        critical_kw = {"rm -rf", "/etc/shadow", "/etc/passwd", "wget", "curl",
                       "nc ", "netcat", "base64 --decode", "python -c", "perl -e"}
        high_kw     = {"sudo", "su ", "chmod", "chown", "netstat", "ps aux", "cat /etc"}

        if any(k in cmd for k in critical_kw) or len(command) > 200:
            return "CRITICAL"
        if any(k in cmd for k in high_kw):
            return "HIGH"
        if len(command) > 60:
            return "MEDIUM"
        return "LOW"
