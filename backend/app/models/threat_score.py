"""
SQLAlchemy ORM model for ThreatScore.
Maps to the 'threat_scores' table.
Persists historical IP reputation and threat scores (0–100 scale).
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from app.db.session import Base


class ThreatScore(Base):
    """Historical IP threat score tracking on a 0–100 scale."""

    __tablename__ = "threat_scores"

    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_ip       = Column(String(45),  nullable=False, index=True)
    score           = Column(Float,       nullable=False, default=0.0)     # 0–100

    # Scoring breakdown
    event_count     = Column(Integer, nullable=False, default=0)
    critical_count  = Column(Integer, nullable=False, default=0)
    high_count      = Column(Integer, nullable=False, default=0)
    mitre_techniques = Column(Integer, nullable=False, default=0)         # unique techniques seen

    last_seen       = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc),
                             nullable=False)
    created_at      = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc),
                             nullable=False)
    updated_at      = Column(DateTime(timezone=True),
                             default=lambda: datetime.now(timezone.utc),
                             onupdate=lambda: datetime.now(timezone.utc),
                             nullable=False)

    def __repr__(self) -> str:
        return f"<ThreatScore ip={self.source_ip} score={self.score}>"
