"""
SQLAlchemy ORM model for AttackEvent.
Maps to the 'attack_events' table.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Text
from sqlalchemy.sql import func

from app.db.session import Base


class AttackEvent(Base):
    __tablename__ = "attack_events"

    id           = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                          index=True, nullable=False)

    # Attack origin
    source_ip    = Column(String(45),  nullable=False, index=True)
    source_port  = Column(Integer,     nullable=False, default=0)

    # Protocol context
    service      = Column(String(20),  nullable=False, index=True)   # SSH | FTP | HTTP | EXTERNAL
    method       = Column(String(10),  nullable=True)
    endpoint     = Column(String(500), nullable=True)

    # Credential capture
    username     = Column(String(255), nullable=True)
    password     = Column(String(255), nullable=True)

    # Payload capture
    command      = Column(String(1000), nullable=True)
    payload      = Column(Text,         nullable=True)
    user_agent   = Column(String(500),  nullable=True)

    # Classification
    severity     = Column(String(20), nullable=False, index=True, default="MEDIUM")
    ai_label     = Column(String(20), nullable=True)
    threat_score = Column(Float,      nullable=False, default=0.0)

    # Enrichment
    geolocation  = Column(JSON, nullable=True)   # LocationInfo dict
    meta_data    = Column(JSON, nullable=True)    # arbitrary extra fields

    def __repr__(self) -> str:
        return f"<AttackEvent id={self.id} service={self.service} ip={self.source_ip}>"
