"""
SQLAlchemy ORM model for TokenBlacklist.
Used for token revocation (logout, token invalidation).
Maps to the 'token_blacklist' table.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Integer

from app.db.session import Base


class TokenBlacklist(Base):
    """Blacklisted JWT tokens (used for logout/revocation)."""
    
    __tablename__ = "token_blacklist"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    jti         = Column(String(500), nullable=False, unique=True, index=True)  # JWT ID
    username    = Column(String(255), nullable=False, index=True)
    blacklisted_at = Column(DateTime(timezone=True),
                           default=lambda: datetime.now(timezone.utc),
                           nullable=False)
    expires_at  = Column(DateTime(timezone=True), nullable=False, index=True)  # When token naturally expires

    def __repr__(self) -> str:
        return f"<TokenBlacklist jti={self.jti[:20]}... user={self.username}>"
