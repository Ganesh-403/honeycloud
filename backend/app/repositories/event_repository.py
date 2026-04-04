"""
EventRepository – all database operations for AttackEvent.
Services call this; routes never call the DB directly.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.attack_event import AttackEvent
from app.schemas.event import EventFilters


class EventRepository:
    """Encapsulates all AttackEvent DB queries."""

    def __init__(self, db: Session):
        self.db = db

    # ── Write ─────────────────────────────────────────────────────────────────

    def create(self, data: dict) -> AttackEvent:
        event = AttackEvent(**data)
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_by_id(self, event_id: int) -> Optional[AttackEvent]:
        return self.db.get(AttackEvent, event_id)

    def list_filtered(self, filters: EventFilters) -> list[AttackEvent]:
        stmt = select(AttackEvent)
        if filters.service:
            stmt = stmt.where(AttackEvent.service == filters.service.upper())
        if filters.severity:
            stmt = stmt.where(AttackEvent.severity == filters.severity.upper())
        stmt = stmt.order_by(AttackEvent.timestamp.desc()).limit(filters.limit)
        return list(self.db.scalars(stmt).all())

    def count_all(self) -> int:
        return self.db.scalar(select(func.count()).select_from(AttackEvent)) or 0

    def count_by_service(self) -> dict[str, int]:
        rows = self.db.execute(
            select(AttackEvent.service, func.count().label("n"))
            .group_by(AttackEvent.service)
        ).all()
        return {row.service: row.n for row in rows}

    def count_by_severity(self) -> dict[str, int]:
        rows = self.db.execute(
            select(AttackEvent.severity, func.count().label("n"))
            .group_by(AttackEvent.severity)
        ).all()
        return {row.severity: row.n for row in rows}

    def count_by_ai_label(self) -> dict[str, int]:
        rows = self.db.execute(
            select(AttackEvent.ai_label, func.count().label("n"))
            .group_by(AttackEvent.ai_label)
        ).all()
        return {(row.ai_label or "unknown"): row.n for row in rows}

    def get_all(self) -> list[AttackEvent]:
        return list(self.db.scalars(select(AttackEvent).order_by(AttackEvent.timestamp.desc())).all())
