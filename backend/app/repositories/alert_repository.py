"""
AlertRepository – database operations for Alert model.
"""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert


class AlertRepository:
    """Encapsulates all Alert DB queries."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, event_id: int, channel: str, recipient: str = None,
               subject: str = None, body: str = None,
               success: bool = True, error_msg: str = None) -> Alert:
        """Log a dispatched alert."""
        alert = Alert(
            event_id=event_id,
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            success=success,
            error_msg=error_msg,
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def count_by_channel(self) -> dict[str, int]:
        """Get count of alerts per channel."""
        rows = self.db.execute(
            select(Alert.channel, func.count(Alert.id))
            .group_by(Alert.channel)
        ).all()
        return {row[0]: row[1] for row in rows}

    def list_recent(self, limit: int = 50) -> list[Alert]:
        """Get the most recent alerts."""
        return list(self.db.scalars(
            select(Alert).order_by(Alert.dispatched_at.desc()).limit(limit)
        ).all())
