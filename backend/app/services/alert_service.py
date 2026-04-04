"""
AlertService – dispatches Telegram notifications for high-severity events.
Completely driven by Settings; no tokens in source code.
"""
import requests

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.attack_event import AttackEvent

logger = get_logger(__name__)


class AlertService:
    """Send Telegram alerts. Silently no-ops if alerts are disabled."""

    def __init__(self):
        self._settings = get_settings()

    @property
    def _enabled(self) -> bool:
        s = self._settings
        return (
            s.TELEGRAM_ALERTS_ENABLED
            and bool(s.TELEGRAM_BOT_TOKEN)
            and bool(s.TELEGRAM_CHAT_ID)
        )

    # ── Public interface ──────────────────────────────────────────────────────

    def dispatch(self, event: AttackEvent) -> None:
        """Send alert for an event. Non-blocking; logs failures, never raises."""
        if not self._enabled:
            logger.debug("Telegram alerts disabled – skipping event id=%d", event.id)
            return
        message = self._format(event)
        self._send_message(message)

    def send_file(self, file_path: str, caption: str = "") -> bool:
        """Send a file (CSV/XLSX/TXT) to Telegram."""
        if not self._enabled:
            return False
        url = f"https://api.telegram.org/bot{self._settings.TELEGRAM_BOT_TOKEN}/sendDocument"
        try:
            with open(file_path, "rb") as fh:
                resp = requests.post(
                    url,
                    data={"chat_id": self._settings.TELEGRAM_CHAT_ID, "caption": caption},
                    files={"document": fh},
                    timeout=10,
                )
            if resp.ok:
                logger.info("File sent to Telegram: %s", file_path)
                return True
            logger.warning("Telegram file send failed: %s", resp.text)
        except Exception as exc:
            logger.error("Exception sending file to Telegram: %s", exc)
        return False

    # ── Private helpers ───────────────────────────────────────────────────────

    def _send_message(self, text: str) -> None:
        url = f"https://api.telegram.org/bot{self._settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        try:
            resp = requests.post(
                url,
                json={
                    "chat_id": self._settings.TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=5,
            )
            if resp.ok:
                logger.info("Telegram alert sent for severity=%s", "HIGH+")
            else:
                logger.warning("Telegram alert failed: %s", resp.text)
        except Exception as exc:
            logger.error("Exception sending Telegram alert: %s", exc)

    @staticmethod
    def _format(event: AttackEvent) -> str:
        geo = event.geolocation or {}
        lines = [
            "🚨 *HoneyCloud Security Alert*",
            "",
            f"*Service:* {event.service}",
            f"*Source IP:* `{event.source_ip}`",
            f"*Location:* {geo.get('city', '?')}, {geo.get('country', '?')} {geo.get('flag', '')}",
            f"*Username:* `{event.username or 'N/A'}`",
            f"*Severity:* *{event.severity}*",
            f"*AI Label:* {event.ai_label}",
            f"*Threat Score:* {event.threat_score:.2f}",
            f"*Timestamp:* {event.timestamp}",
        ]
        if event.command:
            lines.append(f"*Command:* `{event.command}`")
        return "\n".join(lines)
