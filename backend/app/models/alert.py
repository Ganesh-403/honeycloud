"""
SQLAlchemy ORM model for Alert.
Maps to the 'alerts' table.
Logs all dispatched Telegram and Email alerts for audit purposes.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, Boolean

from app.db.session import Base


class Alert(Base):
    """Persists records of dispatched alerts (Telegram, Email, etc.)."""

    __tablename__ = "alerts"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id    = Column(Integer, nullable=False, index=True)

    channel     = Column(String(50),  nullable=False, index=True)   # TELEGRAM | EMAIL
    recipient   = Column(String(255), nullable=True)                 # email or chat_id
    subject     = Column(String(500), nullable=True)
    body        = Column(Text,        nullable=True)

    success     = Column(Boolean, nullable=False, default=True)
    error_msg   = Column(Text,    nullable=True)

    dispatched_at = Column(DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc),
                           index=True, nullable=False)

    def __repr__(self) -> str:
        return f"<Alert id={self.id} channel={self.channel} event={self.event_id} ok={self.success}>"
