"""Audit-related Pydantic schemas."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    id: int
    timestamp: datetime
    username: str
    client_ip: Optional[str] = None
    action: str
    target: Optional[str] = None
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
