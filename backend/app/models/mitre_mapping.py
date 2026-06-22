"""
SQLAlchemy ORM model for MitreMapping.
Maps to the 'mitre_mappings' table.
Links attack events to MITRE ATT&CK techniques.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db.session import Base


class MitreMapping(Base):
    """Persists MITRE ATT&CK technique mappings for each attack event."""

    __tablename__ = "mitre_mappings"

    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id        = Column(Integer, nullable=False, index=True)

    technique_id    = Column(String(20),  nullable=False, index=True)   # e.g. T1110
    technique_name  = Column(String(255), nullable=False)               # e.g. Brute Force
    tactic          = Column(String(100), nullable=False, index=True)   # e.g. Credential Access
    confidence      = Column(Integer, nullable=False, default=80)       # 0-100

    mapped_at       = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc),
                             nullable=False)

    def __repr__(self) -> str:
        return f"<MitreMapping event={self.event_id} technique={self.technique_id}>"
