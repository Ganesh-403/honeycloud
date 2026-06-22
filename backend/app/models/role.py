"""
SQLAlchemy ORM model for Role.
Maps to the 'roles' table.
Implements a role hierarchy: owner > admin > analyst.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


# Role hierarchy: higher weight = more privileges
ROLE_HIERARCHY = {"owner": 30, "admin": 20, "analyst": 10}
DEFAULT_ROLES = [
    {"name": "owner",   "description": "Full platform control, user management, system configuration."},
    {"name": "admin",   "description": "Manage analysts, view all data, train ML models, generate reports."},
    {"name": "analyst", "description": "View dashboards, events, and profiles. Read-only access."},
]


class Role(Base):
    """Role definition with hierarchical weight for RBAC enforcement."""

    __tablename__ = "roles"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name        = Column(String(50), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    weight      = Column(Integer, nullable=False, default=10)
    created_at  = Column(DateTime(timezone=True),
                         default=lambda: datetime.now(timezone.utc),
                         nullable=False)

    # Back-reference to users with this role
    users = relationship("User", back_populates="role_rel", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name} weight={self.weight}>"
