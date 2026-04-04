"""
SQLAlchemy ORM model for User.
Maps to the 'users' table.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Boolean, Integer
from sqlalchemy.sql import func

from app.db.session import Base


class User(Base):
    """User account with hashed password, role, and audit fields."""
    
    __tablename__ = "users"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username    = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)  # bcrypt hash (~60 chars)
    role        = Column(String(50), nullable=False, default="analyst", index=True)  # admin | analyst
    
    is_active   = Column(Boolean, default=True, nullable=False, index=True)
    is_deleted  = Column(Boolean, default=False, nullable=False, index=True)
    
    created_at  = Column(DateTime(timezone=True), 
                        default=lambda: datetime.now(timezone.utc), 
                        nullable=False)
    updated_at  = Column(DateTime(timezone=True),
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc),
                        nullable=False)
    last_login  = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username} role={self.role}>"
