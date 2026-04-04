"""
AttackerProfile – persistent per-IP threat profile.

One row per unique source IP. Updated on every ingest event so the
dashboard can show "who is hitting us most" without expensive aggregations.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String

from app.db.session import Base


class AttackerProfile(Base):
    __tablename__ = "attacker_profiles"

    # ── Identity ──────────────────────────────────────────────────────────────
    id         = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)

    # ── Timeline ──────────────────────────────────────────────────────────────
    first_seen = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen  = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # ── Activity counters ─────────────────────────────────────────────────────
    total_events   = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count     = Column(Integer, default=0, nullable=False)

    # ── Geographic enrichment (mirrored from first event for fast reads) ───────
    country      = Column(String(100), nullable=True)
    country_code = Column(String(4),   nullable=True)
    city         = Column(String(100), nullable=True)
    isp          = Column(String(255), nullable=True)

    # ── Behaviour fingerprint ─────────────────────────────────────────────────
    # JSON arrays / dicts stored as JSON column for flexibility
    services_targeted = Column(JSON, default=list)   # e.g. ["SSH", "HTTP"]
    top_username      = Column(String(255), nullable=True)
    top_password      = Column(String(255), nullable=True)
    username_counts   = Column(JSON, default=dict)   # {"root": 12, "admin": 7}
    password_counts   = Column(JSON, default=dict)

    # ── Risk ──────────────────────────────────────────────────────────────────
    risk_score = Column(Float, default=0.0, nullable=False)
    # UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL | BLOCKED
    risk_tier  = Column(String(20), default="UNKNOWN", nullable=False, index=True)

    # ── Pattern detection flags ───────────────────────────────────────────────
    brute_force_detected          = Column(Boolean, default=False)
    credential_stuffing_detected  = Column(Boolean, default=False)
    scanner_detected              = Column(Boolean, default=False)

    # ── Admin action ──────────────────────────────────────────────────────────
    is_blocked    = Column(Boolean, default=False, index=True)
    block_reason  = Column(String(500), nullable=True)
    blocked_at    = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AttackerProfile ip={self.ip_address} "
            f"events={self.total_events} tier={self.risk_tier}>"
        )
