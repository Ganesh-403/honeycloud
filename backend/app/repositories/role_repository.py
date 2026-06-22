"""
RoleRepository – database operations for Role model.
"""
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.role import Role


class RoleRepository:
    """Encapsulates all Role DB queries."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_name(self, name: str) -> Optional[Role]:
        """Get a role by its name."""
        return self.db.scalar(select(Role).where(Role.name == name))

    def get_by_id(self, role_id: int) -> Optional[Role]:
        """Get a role by ID."""
        return self.db.get(Role, role_id)

    def list_all(self) -> list[Role]:
        """Get all roles ordered by weight (highest first)."""
        return list(
            self.db.scalars(select(Role).order_by(Role.weight.desc())).all()
        )
