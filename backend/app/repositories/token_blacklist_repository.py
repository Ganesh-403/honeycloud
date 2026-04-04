"""
TokenBlacklistRepository – manage revoked/blacklisted JWT tokens.
Used for logout and token invalidation.
"""
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from app.models.token_blacklist import TokenBlacklist


class TokenBlacklistRepository:
    """Encapsulates token blacklist operations."""

    def __init__(self, db: Session):
        self.db = db

    # ── Read ──────────────────────────────────────────────────────────────────

    def is_blacklisted(self, jti: str) -> bool:
        """Check if a JWT ID (jti) is blacklisted."""
        exists = bool(
            self.db.scalar(
                select(TokenBlacklist).where(TokenBlacklist.jti == jti).limit(1)
            )
        )
        return exists

    def get_by_jti(self, jti: str) -> Optional[TokenBlacklist]:
        """Get blacklist record by JWT ID."""
        return self.db.scalar(
            select(TokenBlacklist).where(TokenBlacklist.jti == jti)
        )

    # ── Write ─────────────────────────────────────────────────────────────────

    def add_to_blacklist(
        self,
        jti: str,
        username: str,
        expires_at: datetime,
    ) -> TokenBlacklist:
        """Add a token JWT ID to the blacklist."""
        record = TokenBlacklist(
            jti=jti,
            username=username,
            blacklisted_at=datetime.now(timezone.utc),
            expires_at=expires_at,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    # ── Maintenance ───────────────────────────────────────────────────────────

    def cleanup_expired(self) -> int:
        """Delete expired tokens from blacklist (cleanup task).
        Returns number of deleted records.
        """
        now = datetime.now(timezone.utc)
        result = self.db.execute(
            delete(TokenBlacklist).where(TokenBlacklist.expires_at <= now)
        )
        self.db.commit()
        return result.rowcount
