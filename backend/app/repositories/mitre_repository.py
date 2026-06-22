"""
MitreRepository – database operations for MitreMapping model.
"""
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.mitre_mapping import MitreMapping


class MitreRepository:
    """Encapsulates all MitreMapping DB queries."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, event_id: int, technique_id: str, technique_name: str,
               tactic: str, confidence: int = 80) -> MitreMapping:
        """Create a new MITRE ATT&CK mapping record."""
        mapping = MitreMapping(
            event_id=event_id,
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence=confidence,
        )
        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)
        return mapping

    def get_by_event(self, event_id: int) -> list[MitreMapping]:
        """Get all MITRE mappings for a specific event."""
        return list(self.db.scalars(
            select(MitreMapping).where(MitreMapping.event_id == event_id)
        ).all())

    def count_by_technique(self) -> dict[str, int]:
        """Get count of events per MITRE technique ID."""
        rows = self.db.execute(
            select(MitreMapping.technique_id, func.count(MitreMapping.id))
            .group_by(MitreMapping.technique_id)
        ).all()
        return {row[0]: row[1] for row in rows}

    def count_by_tactic(self) -> dict[str, int]:
        """Get count of events per MITRE tactic."""
        rows = self.db.execute(
            select(MitreMapping.tactic, func.count(MitreMapping.id))
            .group_by(MitreMapping.tactic)
        ).all()
        return {row[0]: row[1] for row in rows}

    def get_unique_techniques_for_ip(self, source_ip: str) -> int:
        """Count unique techniques seen for a given source IP (via event join)."""
        from app.models.attack_event import AttackEvent
        rows = self.db.execute(
            select(func.count(func.distinct(MitreMapping.technique_id)))
            .join(AttackEvent, AttackEvent.id == MitreMapping.event_id)
            .where(AttackEvent.source_ip == source_ip)
        ).scalar()
        return rows or 0
