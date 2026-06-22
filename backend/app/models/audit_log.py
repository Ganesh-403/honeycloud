"""
SQLAlchemy ORM model for AuditLog.
Maps to the 'audit_logs' table.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.db.session import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
                         index=True, nullable=False)

    # Actor details
    username    = Column(String(255), nullable=False, index=True)
    client_ip   = Column(String(45),  nullable=True)

    # Action details
    action      = Column(String(100), nullable=False, index=True)
    target      = Column(String(255), nullable=True, index=True)
    description = Column(Text,        nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} user={self.username} action={self.action} target={self.target}>"
