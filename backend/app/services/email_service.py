"""
EmailAlertService – sends email security alerts on high-severity events.
Configured via Pydantic settings.
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.attack_event import AttackEvent

logger = get_logger(__name__)


class EmailAlertService:
    def __init__(self):
        self._settings = get_settings()

    @property
    def _enabled(self) -> bool:
        s = self._settings
        return (
            s.EMAIL_ALERTS_ENABLED
            and bool(s.SMTP_HOST)
            and bool(s.SMTP_USER)
            and bool(s.SMTP_PASSWORD)
            and bool(s.EMAIL_TO)
        )

    def dispatch(self, event: AttackEvent) -> None:
        """Send email alert. Non-blocking; logs exceptions but never raises."""
        if not self._enabled:
            logger.debug("Email alerts disabled – skipping event id=%d", event.id)
            return

        try:
            s = self._settings
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 HoneyCloud Security Alert - Severity: {event.severity}"
            msg["From"] = s.EMAIL_FROM or s.SMTP_USER
            msg["To"] = s.EMAIL_TO

            # Plain text body
            geo = event.geolocation or {}
            body_text = (
                f"HoneyCloud Security Alert\n\n"
                f"Service: {event.service}\n"
                f"Source IP: {event.source_ip}\n"
                f"Location: {geo.get('city', '?')}, {geo.get('country', '?')} {geo.get('flag', '')}\n"
                f"Username: {event.username or 'N/A'}\n"
                f"Severity: {event.severity}\n"
                f"AI Threat Label: {event.ai_label}\n"
                f"Threat Score: {event.threat_score:.2f}\n"
                f"Timestamp: {event.timestamp}\n"
            )
            if event.command:
                body_text += f"Command/Payload: {event.command}\n"

            msg.attach(MIMEText(body_text, "plain"))

            # Dispatch via smtplib
            with smtplib.SMTP(s.SMTP_HOST, s.SMTP_PORT, timeout=10) as server:
                server.ehlo()
                if s.SMTP_PORT == 587:
                    server.starttls()
                    server.ehlo()
                server.login(s.SMTP_USER, s.SMTP_PASSWORD)
                server.sendmail(msg["From"], [msg["To"]], msg.as_string())

            logger.info("Email alert successfully sent to %s for severity=%s", msg["To"], event.severity)
        except Exception as exc:
            logger.error("Exception dispatching email alert: %s", exc)
