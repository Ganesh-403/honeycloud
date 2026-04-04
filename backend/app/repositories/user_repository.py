"""
UserRepository – all database operations for User.
Services call this; routes never call the DB directly for users.
"""
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    """Encapsulates all User DB queries."""

    def __init__(self, db: Session):
        self.db = db

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_by_username(self, username: str) -> Optional[User]:
        """Get active user by username."""
        return self.db.scalar(
            select(User).where(
                User.username == username,
                User.is_active.is_(True),
                User.is_deleted.is_(False),
            )
        )

    def get_by_id(self, user_id: int) -> Optional[User]:
        """Get active user by ID."""
        return self.db.scalar(
            select(User).where(
                User.id == user_id,
                User.is_active.is_(True),
                User.is_deleted.is_(False),
            )
        )

    def exists(self, username: str) -> bool:
        """Check if username already exists."""
        return bool(
            self.db.scalar(
                select(User).where(User.username == username).limit(1)
            )
        )

    # ── Write ─────────────────────────────────────────────────────────────────

    def create(
        self,
        username: str,
        plain_password: str,
        role: str = "analyst",
    ) -> User:
        """Create and persist a new user, hashing the plain password."""
        from app.core.security import hash_password
        hashed = hash_password(plain_password)
        user = User(
            username=username,
            hashed_password=hashed,
            role=role,
            is_active=True,
            is_deleted=False,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_last_login(self, user_id: int) -> None:
        """Update last_login timestamp for a user."""
        from datetime import datetime, timezone
        user = self.db.get(User, user_id)
        if user:
            user.last_login = datetime.now(timezone.utc)
            self.db.commit()

    def deactivate(self, user_id: int) -> None:
        """Deactivate a user (soft delete)."""
        user = self.db.get(User, user_id)
        if user:
            user.is_active = False
            self.db.commit()

    def list_all(self) -> list[User]:
        """Get all active, non-deleted users."""
        return list(
            self.db.scalars(
                select(User).where(
                    User.is_active.is_(True),
                    User.is_deleted.is_(False),
                )
            ).all()
        )
