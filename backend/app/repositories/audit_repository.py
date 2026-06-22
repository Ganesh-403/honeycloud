"""
AuditRepository – database operations for AuditLog.
"""
from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def log(
        self,
        username: str,
        action: str,
        client_ip: Optional[str] = None,
        target: Optional[str] = None,
        description: Optional[str] = None,
    ) -> AuditLog:
        """Create and commit a new audit log entry."""
        log_entry = AuditLog(
            username=username,
            action=action,
            client_ip=client_ip,
            target=target,
            description=description,
        )
        self.db.add(log_entry)
        self.db.commit()
        self.db.refresh(log_entry)
        return log_entry

    def list_filtered(
        self,
        limit: int = 100,
        username: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[AuditLog]:
        """Retrieve audit log entries sorted by timestamp descending."""
        stmt = select(AuditLog)
        if username:
            stmt = stmt.where(AuditLog.username == username)
        if action:
            stmt = stmt.where(AuditLog.action == action.upper())
        stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit)
        return list(self.db.scalars(stmt).all())
