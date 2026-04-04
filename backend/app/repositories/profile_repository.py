"""
ProfileRepository – all DB operations for AttackerProfile.
Uses upsert-style logic: get-or-create + incremental updates.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.attacker_profile import AttackerProfile


class ProfileRepository:
    def __init__(self, db: Session):
        self.db = db

    # ── Get / Create ──────────────────────────────────────────────────────────

    def get_by_ip(self, ip: str) -> Optional[AttackerProfile]:
        return self.db.scalar(
            select(AttackerProfile).where(AttackerProfile.ip_address == ip)
        )

    def get_or_create(self, ip: str) -> tuple[AttackerProfile, bool]:
        """Return (profile, created). Thread-safe for SQLite."""
        profile = self.get_by_ip(ip)
        if profile:
            return profile, False
        profile = AttackerProfile(ip_address=ip, services_targeted=[], username_counts={}, password_counts={})
        self.db.add(profile)
        self.db.flush()   # assign id without full commit
        return profile, True

    def save(self, profile: AttackerProfile) -> AttackerProfile:
        self.db.add(profile)
        self.db.commit()
        self.db.refresh(profile)
        return profile

    # ── List / Query ──────────────────────────────────────────────────────────

    def list_all(
        self,
        limit: int = 100,
        risk_tier: Optional[str] = None,
        blocked_only: bool = False,
    ) -> list[AttackerProfile]:
        stmt = select(AttackerProfile)
        if risk_tier:
            stmt = stmt.where(AttackerProfile.risk_tier == risk_tier.upper())
        if blocked_only:
            stmt = stmt.where(AttackerProfile.is_blocked.is_(True))
        stmt = stmt.order_by(AttackerProfile.total_events.desc()).limit(limit)
        return list(self.db.scalars(stmt).all())

    def top_by_events(self, limit: int = 10) -> list[AttackerProfile]:
        return list(
            self.db.scalars(
                select(AttackerProfile)
                .order_by(AttackerProfile.total_events.desc())
                .limit(limit)
            ).all()
        )

    def count_by_risk_tier(self) -> dict[str, int]:
        from sqlalchemy import func
        rows = self.db.execute(
            select(AttackerProfile.risk_tier, func.count().label("n"))
            .group_by(AttackerProfile.risk_tier)
        ).all()
        return {row.risk_tier: row.n for row in rows}

    def total_unique_ips(self) -> int:
        from sqlalchemy import func
        return self.db.scalar(
            select(func.count()).select_from(AttackerProfile)
        ) or 0
